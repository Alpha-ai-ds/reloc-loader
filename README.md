# reloc-loader

> 在用户态「加载」一个 stripped ELF 并应用重定位，
> 让静态分析工具能读到**本来全是 0** 的虚表。
> 附带一套配套工具：枚举虚表、跨版本匹配、导出到 IDA/Ghidra。

```python
from so_loader import SoRuntime

rt = SoRuntime('libfoo.so')          # 解析 + 应用重定位
rt.read_ptr(0x1270fa98)              # -> 0xd5ac460   （文件里这里是 0）
rt.vtable_entries(0x1270fa98)        # -> [0xd5ac460, 0x747559c, ...]  273 槽
```

---

## 它解决什么问题

对 stripped 的共享库做静态分析，你迟早会撞上这堵墙：

```
想读某个类的 vtable
找到 vtable 地址 0x1270fa98
>>> read(0x1270fa98, 8)
b'\x00\x00\x00\x00\x00\x00\x00\x00'      ← 全是 0
>>> read(0x1270fa98 + 8, 8)
b'\x00\x00\x00\x00\x00\x00\x00\x00'      ← 还是 0
```

这不是地址算错了。**虚表槽位在文件里本来就是 0。**

C++ 的 vtable 放在 `.data.rel.ro`，每个槽位是一个指向代码段的绝对地址。
编译时不知道运行基址，所以链接器写 0，同时在 `.rela.dyn` 留一条
`R_*_RELATIVE`，让动态链接器在加载时填入 `base + addend`。

于是这个事实成立了：

> **不重定位就读不到 vtable；读不到 vtable 就分不清类、追不了虚调用、扫不了类布局。**

而动态链接器只存在于运行的进程里。做静态分析的人没有进程 —— 也没有
gdb、没有 adb、没有真机。

本工具就是把动态链接器的这一步重做一遍。纯数据操作：不 mmap、不执行代码、
不需要 root。

### 实测

一个 318MB 的真实世界 C++ 共享库：

```
重定位: 967,158 项
  R_AARCH64_RELATIVE : 774,934     ← 全部应用
  R_AARCH64_ABS64    : 145,847
  R_AARCH64_JUMP_SLOT:  38,690
  R_AARCH64_GLOB_DAT :   7,687

重定位前后 @0x1270fa98
  槽    文件里      加载后
  [0 ]  0           0xd5ac460     ← 被填充
  [1 ]  0           0x747559c     ← 被填充
  [2 ]  0           0xdc31488     ← 被填充
  ...

vtable @0x1270fa98 -> 273 槽   ✓
vtable @0x127275c8 -> 517 槽   ✓
```

---

## 安装

```bash
pip install -r requirements.txt       # numpy + capstone
```

- `numpy` —— `so_loader` 必需（分块解析重定位表）
- `capstone` —— `vtinfo` / `vtdiff` 需要（`so_loader` 本身不需要）

## 自检

```bash
python3 selftest.py                  # 用系统库跑 34 项断言
python3 selftest.py <big.so>         # 额外跑大文件完整流程
```

当前 34 项全通过。里面有两条特别有价值的回归测试（都曾经挂过）：
`base 不变性` 和 `指纹稳定性`，详见文末「踩过的坑」。

---

## 六个工具

| 工具 | 解决什么 |
|---|---|
| `so_loader.py` | **读得到** —— 应用重定位，给出加载后视图 |
| `vtfind.py` | **在哪儿** —— 全镜像枚举虚表，不需要预先知道地址 |
| `vtinfo.py` | **是什么** —— 从成员方法反解字段和容器 |
| `vtdiff.py` | **换版本后还在吗** —— 跨版本匹配 + 继承族聚类 |
| `dump.py` | **搬出去** —— 导出到 IDA / Ghidra / C 头文件 / 裸内存 |
| `selftest.py` | **没弄坏吧** —— 自动化验证 |

### so_loader.py

```python
rt = SoRuntime(path, base=0)
```

| 方法 | 说明 |
|---|---|
| `rt.read(va, size)` | 加载后视图读取。优先级：补丁表 → 文件 → 补零（.bss） |
| `rt.read_ptr(va)` / `read_u32(va)` | 读指针 / 读 4 字节 |
| `rt.read_ptr_array(va, n)` | 批量读，返回 numpy 数组（快两个数量级） |
| `rt.vtable_entries(vt)` | 读虚表，到第一个无效槽为止 |
| `rt.vtable_len(vt)` | 虚表槽位数（常用于判断「这是哪个类」） |
| `rt.dump_region(va, size)` | 导出一块内存，可直接喂给 Unicorn |
| `rt.is_code_ptr(p)` | 非 0 + 对齐 + 落在可执行段 |
| `rt.in_exec(va)` / `in_data(va)` | 地址落在哪个段 |
| `rt.v2o(va)` | 虚拟地址 → 文件偏移 |
| `rt.report()` | 打印段表 + 重定位统计 |

「槽位有效」的判据：非 0、4 字节对齐、落在可执行段。三条合起来能滤掉
绝大多数噪声 —— 尤其第一条，漏掉它会扫出成千上万个假 vtable。

### vtfind.py —— 全镜像枚举

```bash
python3 vtfind.py lib.so --min 30 --top 25
python3 vtfind.py lib.so --json out.json        # 导出，供 diff 用
```

判据是「数据段里一段连续的、全部指向可执行段的 8 字节指针」，
再用两条辅助信号打分：

- **前缀检查**：Itanium ABI 下 vtable 前有 `top_offset(0)` + `typeinfo`。
  命中 +20 分。
- **超长惩罚**：真实 C++ 类很少超过几百个虚函数。超过 300 槽停止线性加分
  并标 `suspect_merged` —— 那基本是「多张表连成一片」或干脆是函数指针数组。

实测在 318MB 的样本上扫出 1572 张（≥30 槽）。

**别只信榜首** —— 看 top-20，然后用 `vtinfo.py` 抽查。

### vtinfo.py —— 类结构

```bash
python3 vtinfo.py lib.so 0x127275c8
```

```python
ci = ClassInfo(rt, vt_addr)
ci.scan_getters()       # 找 ldr x0,[x0,#imm]; ret
ci.scan_containers()    # 找 ldp(begin,end) + lsr #k
ci.report()
```

**成员 getter**：`ldr x0, [x0, #0x340]; ret` —— 那个 `#0x340` 就是字段偏移，
直接可读，不用猜。

**容器**：内联 `vector.size()` 的编译形态是

```asm
ldp  x_a, x_b, [xN, #imm]     ; begin / end
sub  x,   x_b, x_a
lsr  x,   x,   #k             ; 元素宽度 = 1 << k
```

`imm` 是容器在对象内的偏移，`1<<k` 是元素宽度。

实测输出（一个类扫出 56 个 getter、3 个容器字段）：

```
成员指针 getter (56 个):
   slot 10   (0x0050)  fn=0xdd0c2a0    this+0x5d8
   slot 179  (0x0598)  fn=0xdd16c6c    this+0x340
   ...
容器字段:
   this+0x28    元素宽  8B   x5
   this+0x38    元素宽 32B   x5
```

### vtdiff.py —— 跨版本匹配

地址会变，代码不会（大部分时候）。这个工具就靠这一点工作。

指纹算法：取函数前 N 条指令，记 mnemonic + **非地址类的立即数**，
忽略寄存器名，FNV-1a 哈希。

```bash
python3 vtdiff.py old.so new.so --old-vts 0x1270fa98,0x127275c8
```

```
old 0x1270fa98  (273 槽)
   -> 0x1370fa98   匹配率 100.0%  (273/273)  [可信]
   -> 0x13acaa28   匹配率  85.2%  (173/203)  [可信]   ← 同族类
```

（上面这个例子是同一个 so 换个 base 当「新版」跑的 —— 自检用的就是它，
真实的跨版本匹配率取决于改了多少代码。）

判据：>80% 基本可信，50~80% 需抽查，<50% 当成没匹配上。

**继承族聚类**（同版本内，按前 N 槽指纹分组）：

```bash
python3 vtdiff.py lib.so --family --min 100 --prefix 6
```

同一族 = 这些类共享前若干个虚函数实现，通常是继承关系。

### dump.py —— 导出

```bash
python3 dump.py lib.so --peek 0x1270fa98 --n 8           # 快速看一眼
python3 dump.py lib.so --region 0x1270fa98:0x1000 -o v.bin
python3 dump.py lib.so --ida     0x1270fa98 --name Player -o player.idc
python3 dump.py lib.so --ghidra  0x1270fa98 --name Player -o player.py
python3 dump.py lib.so --cheader 0x127275c8 --name Level -o level.h
```

生成的 C 头文件是**骨架** —— 字段偏移来自 getter 反解，字段名是编的：

```c
typedef struct Level {
    char _pad_0[0x20];
    void* field_340;  /* vt[179],vt[180] */
    ...
    /* ---- 容器字段（元素宽度由 lsr 反解）---- */
    /* +0x28  元素  8 字节，出现 5 次 */
} Level;
```

它不能编译，用途是给你一个可编辑的起点，或者在 IDA 里当 Local Types 粘贴。

---

## 为什么「扫类代码」优于「扫实例内存」

想拿到一个对象里有哪些字段，直觉做法是扫实例内存。但**做不到**：
对象在堆上，地址每次运行都随机，静态文件里根本没有实例。

正确解法是扫**类的成员方法代码**。类的布局是编译期确定的，它的 getter、
它的容器访问，全都写在 `.text` 里，静态可读。

这不只是妥协 —— 它其实是**更好的跨版本锚点**：

| | 扫实例内存 | 扫类代码 |
|---|---|---|
| 需要活进程 | ✅ 必需 | ❌ 不需要 |
| 地址随机化影响 | ✅ 受影响 | ❌ 不受影响 |
| 换版本后能否复用 | ❌ 要重新 dump | ✅ 重新扫一遍即可 |
| 能反解出字段偏移 | 间接（要对齐观察） | ✅ 直接读立即数 |

---

## 原理

```
ELF 文件
  ├─ .text          （代码，静态可读）
  ├─ .data.rel.ro   （vtable，文件里全是 0）
  └─ .rela.dyn      （重定位表，告诉链接器该往哪儿填什么）
                          │
                          ▼
                    SoRuntime 读它
                          │
                          ▼
                    补丁表 {va: value}
                          │
                          ▼
              read() 时优先查补丁 → 得到加载后视图
```

`R_*_RELATIVE` 的语义是 `*addr = base + addend`。就这一行，
但要跑 774,934 遍。

---

## 支持范围

| | 状态 |
|---|---|
| AArch64 (`EM_AARCH64` = 183) | ✅ 完整 |
| x86-64 (`EM_X86_64` = 62) | ✅ 加载 + 重定位（`vtinfo` 的 getter/容器模式是 ARM 专属） |
| RELA (`SHT_RELA` = 4) | ✅ |
| REL (`SHT_REL` = 9) | ✅ 加数从目标位置隐式读出 |
| 32 位 ELF | ❌ 不支持（指针宽度不同，需另写） |

## 已知限制

- **只应用 RELATIVE 类**（重基址）。符号类重定位（GLOB_DAT / JUMP_SLOT /
  ABS64）涉及外部符号解析，不在范围内 —— 但对「读 vtable」这个目标，
  RELATIVE 就是全部所需。
- **不处理 IRELATIVE**。它需要执行 resolver 函数，纯静态无法确定结果。
  这类条目会被统计并明确标注为「跳过」，不静默丢弃。
- `vtfind` 无法区分 vtable 和其他函数指针数组 —— 这是静态分析的根本限制，
  只能靠长度和前缀打分排序，不能靠它下结论。
- 开了 `-fno-rtti` 或 LTO 的二进制，前缀检查会退化（typeinfo 被裁掉），
  打分里那 20 分就没了。
- 需要 `.rela.dyn` 存在。若 so 被特殊处理过（如自定义加载器），可能不适用。

---

## 踩过的坑

写这套工具时连续踩了几个，都记下来免得后来人重蹈。
前六个是 `so_loader` 的，后两个是后来加功能时新踩的 —— 而且新踩的这两个
更隐蔽，因为它们**不会报错，只会给出错误的结果**。

**1. ELF 头字段偏移**

`e_phentsize`/`e_phnum` 在 `0x36`，`e_shentsize`/`e_shnum`/`e_shstrndx`
在 `0x3A`。不要从 `0x3A` 连着读 5 个 `H`。

**2. 节名不可信**

某些 so 的 `.shstrtab` 被混淆成非 ASCII，节名读出来是乱码
（实测样本 28 个节只有 1 个名字可读）。所以**一律按 `sh_type` 定位关键节**，
不要靠名字。功能完全不受影响。

**3. 零指针陷阱**

判断「这个值是不是有效的代码指针」时写 `arr >= seg_start`，
而第一个可执行段从 `0x0` 开始 —— 于是 **`0` 被当成了有效指针**。
后果是扫出几千个「候选虚表」，全是假的。必须显式排除 0。

**4. lsr 的立即数是十进制**

capstone 对 `ldr` 输出十六进制（`[x0, #0x340]`），对 `lsr` 输出十进制
（`#3`）。正则只匹配 `0x` 前缀会漏掉全部 `lsr`，容器扫描静默返回 0 命中。

**5. 用 ldp 而非两条 ldr**

编译器取 `begin`/`end` 几乎总是用 `ldp` 一条指令搞定。
「两条连续 ldr」的假设会漏掉绝大多数情况。

**6. 区分对象字段和栈变量**

`[sp, #imm]` 和 `[x29, #imm]` 是栈上局部变量，不是对象字段。
`Rn ∈ {31(SP), 29(FP)}` 一律跳过。

---

**7. base 偏移后段地址没跟着走** （隐蔽，不报错）

`base` 参数只用在重定位的 `base + addend` 上，但段的 `va` 没有同步偏移。
结果：`in_exec()` 把重定位后的指针全判成「不在代码段」，
`vtable_len()` 返回 0，`read()` 读到垃圾。

```
base=0x1000000 时：
  vtable_len = 0              ← 应为 273
  read_ptr   = 0xc0c0c08b...  ← 垃圾
```

修法：段地址统一带 base，`v2o()` 里减回来，补丁表的 key 也加 base ——
三者必须在同一个坐标系。现在 `selftest.py` 有专门的回归测试盯着它。

**8. 指纹里混进了绝对地址** （更隐蔽，会给出"看起来合理"的错误答案）

capstone 会把 `bl #0x747559c` 这类**相对跳转**解析成绝对目标地址。
如果把这玩意儿当立即数收进指纹，那么同一个 so 换个加载基址，
指纹就全变了 —— 自匹配只有 57%。

可怕的地方在于：57% 看起来像「跨版本确实改了不少代码」，
很容易被当成正常结果放过。

修法：指纹里丢弃「落在 exec/data 段范围内」的大立即数，
只保留小常量和字段偏移这种真正稳定的东西。修完自匹配 100%。

---

## 文件

| 文件 | 行数 | 作用 |
|---|---|---|
| `so_loader.py` | ~420 | 核心：ELF 解析 + 重定位 + 加载后读取 |
| `vtfind.py` | ~230 | 全镜像枚举虚表 |
| `vtinfo.py` | ~208 | 类结构分析：成员 getter + 容器 |
| `vtdiff.py` | ~290 | 行为指纹 + 跨版本匹配 + 继承族聚类 |
| `dump.py` | ~249 | 导出到 IDA / Ghidra / C 头文件 / 裸内存 |
| `selftest.py` | ~230 | 自动化验证（34 项断言） |
| `demo.py` | ~109 | 端到端演示 |

---

## License

MIT
