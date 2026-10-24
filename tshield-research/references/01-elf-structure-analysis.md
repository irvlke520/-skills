# ELF 结构深度分析

基于真实 T盾 样本（T1_904_0414.sh，46MB ARM64）的实际分析结果。

## 1. ELF 头分析

### 真实样本 ELF 头

```
Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
Class:   ELF64
Data:    2's complement, little endian
Type:    DYN (Position-Independent Executable file)
Machine: AArch64
Entry point address: 0x4be1920
Start of program headers: 64 (bytes into file)
Start of section headers: 47301928 (bytes into file)
Size of program headers: 56 (bytes)
Number of program headers: 12
Size of section headers: 64 (bytes)
Number of section headers: 4
Section header string table index: 3
```

### T盾 特征分析

| 字段 | 值 | T盾 特征 | 说明 |
|------|-----|----------|------|
| e_type | ET_DYN (3) | ✓ | PIE 可执行文件，加壳后通常保持 PIE |
| e_machine | EM_AARCH64 (0xB7) | - | ARM64 架构 |
| e_entry | 0x4be1920 | ✓ | 高地址入口点，在加密 payload 段内 |
| e_phoff | 64 | - | Program Header 在文件开头，正常 |
| e_shoff | 47301928 | ✓ | Section Header 在文件末尾，接近文件大小 |
| e_phnum | 12 | - | 12个 Program Header，正常范围 |
| e_shnum | 4 | ✓✓✓ | **只有4个 Section！典型 T盾 特征** |
| e_shstrndx | 3 | - | Section 名字符串表索引 |

### 关键判断：e_shnum = 4

正常未加壳的 ARM64 ELF 通常有 20+ 个 section：
- .text（代码段）
- .data（已初始化数据）
- .rodata（只读数据）
- .bss（未初始化数据）
- .got / .got.plt（全局偏移表）
- .plt（过程链接表）
- .dynsym / .dynstr（动态符号/字符串）
- .rela.*（重定位表）
- .dynamic（动态段）
- .init / .fini / .init_array / .fini_array
- .note.* / .eh_frame / .eh_frame_hdr
- .shstrtab（section名字符串表）
- ...

T盾 加壳后只保留 4 个最基本的 section：
1. NULL section（空）
2. .dynstr（动态字符串表，必须保留，动态链接需要）
3. .dynamic（动态段，必须保留，动态链接需要）
4. .shstrtab（section名字符串表，必须保留，section解析需要）

**为什么只保留这4个？**
- 动态链接器（linker64）需要 .dynamic 和 .dynstr 来解析依赖库和导入函数
- .shstrtab 是 section 名字符串表，保留它让 section 表看起来"正常"
- 其他 section（.text/.data/.rodata等）被 T盾 合并/加密到 payload 段中，不需要单独的 section 描述

## 2. Program Headers 分析

### 真实样本 Program Headers

```
Type      Offset    VirtAddr   PhysAddr   FileSiz   MemSiz    Flags  Align
PHDR      0x00000040 0x00000040 0x00000040 0x00002a0 0x00002a0 R      0x8
INTERP    0x029a33d4 0x05a7b3d4 0x05a7b3d4 0x0000015 0x0000015 R      0x1
LOAD      0x00000000 0x00000000 0x00000000 0x00003c0 0x00926ac0 R E    0x4000
LOAD      0x000003c0 0x009283c0 0x009283c0 0x0000000 0x00007c40 RW     0x4000
LOAD      0x000003c0 0x009303c0 0x009303c0 0x0000000 0x000ca980 RW     0x4000
LOAD      0x000003c0 0x015dc3c0 0x015dc3c0 0x0000000 0x01afb638 R E    0x4000
LOAD      0x000003c0 0x030d83c0 0x030d83c0 0x02c93c40 0x02c93c40 R E    0x4000
LOAD      0x02c94000 0x05d6c000 0x05d6c000 0x00005874 0x00005874 RW     0x4000
LOAD      0x02c99880 0x05d75880 0x05d75880 0x00082c88 0x00082c88 RW     0x4000
DYNAMIC   0x02d1c2f8 0x05df82f8 0x05df82f8 0x00000210 0x00000210 RW     0x8
GNU_EH_FRAME 0x02c9ae98 0x05d76e98 0x05d76e98 0x00016f84 0x00016f84 R  0x4
GNU_STACK 0x00000000 0x00000000 0x00000000 0x0000000 0x0000000 RW     0x0
```

### T盾 特征分析

#### 特征1：第一个 LOAD 段 filesz << memsz

```
LOAD[0]: offset=0x00000000 vaddr=0x00000000 filesz=0x000003c0 memsz=0x00926ac0 flags=RE
```

- **filesz = 0x3c0（960字节）**：文件中只有 960 字节
- **memsz = 0x926ac0（约9.4MB）**：运行时分配 9.4MB 内存
- **比例**：memsz 是 filesz 的约 10000 倍！

**这是什么？**
- 文件中的 960 字节是 T盾 的**第一阶段加载器/壳代码**（明文，可直接执行）
- 运行时分配的 9.4MB 内存是**解密后的原始代码/数据**的存放区域
- 壳代码执行时，会把加密的 payload 解密到这块内存中

**为什么 p_offset = 0 且 p_vaddr = 0？**
- 这个段从文件开头和虚拟地址 0 开始
- 文件开头是 ELF 头 + Program Headers（共 0x3c0 字节）
- 这 0x3c0 字节被映射到虚拟地址 0
- 但实际上 ELF 头和 PHDR 不是代码，真正的壳代码可能在这个段的其他位置

#### 特征2：多个 LOAD 段 filesz = 0

```
LOAD[1]: offset=0x3c0 vaddr=0x009283c0 filesz=0x0000000 memsz=0x00007c40 flags=RW
LOAD[2]: offset=0x3c0 vaddr=0x009303c0 filesz=0x0000000 memsz=0x000ca980 flags=RW
LOAD[3]: offset=0x3c0 vaddr=0x015dc3c0 filesz=0x0000000 memsz=0x01afb638 flags=RE
```

这三个段的 **filesz = 0**，意味着文件中没有数据，运行时才分配内存并填充。

| 段 | 权限 | 大小 | 用途推测 |
|----|------|------|----------|
| LOAD[1] | RW | 32KB | 小数据段（.data/.bss） |
| LOAD[2] | RW | ~12.8MB | 大数据段（解密后的数据） |
| LOAD[3] | RE | ~27.6MB | 大代码段（解密后的代码） |

**关键点**：LOAD[3] 是可执行（RE）的，大小约 27.6MB，这很可能是**解密后的原始代码段**。T盾 运行时会把加密的函数代码解密到这个段。

#### 特征3：大的高熵 payload 段

```
LOAD[4]: offset=0x3c0 vaddr=0x030d83c0 filesz=0x02c93c40 memsz=0x02c93c40 flags=RE
```

- **filesz = memsz = 0x2c93c40（约46.6MB）**：文件和内存大小相同
- **权限 = RE**：可读可执行
- **熵 = 7.98 bits/byte**（高熵，接近随机）

**这是什么？**
- 这是 T盾 的**加密 payload 段**，包含：
  - 所有函数的 Stub（5指令桩）
  - 统一解密器（OLLVM混淆）
  - 函数ID→加密代码映射表
  - 加密的函数代码体
- 因为大部分内容是加密的，所以熵很高（7.98）
- 这个段是文件中最大的段，占了文件的绝大部分

#### 特征4：入口点在 payload 段内

```
入口点: 0x4be1920
LOAD[4] 范围: 0x030d83c0 ~ 0x030d83c0 + 0x02c93c40 = 0x05d6c000
```

入口点 0x4be1920 在 LOAD[4]（payload 段）范围内：
- 段内偏移 = 0x4be1920 - 0x030d83c0 = 0x1b09560
- 文件偏移 = 0x3c0 + 0x1b09560 = 0x1b09920

这意味着入口点在加密 payload 段内，但入口点本身是**明文的 Stub**（5指令桩），不是加密的。

### Program Headers 总结

| 段 | 类型 | 文件大小 | 内存大小 | 权限 | 用途 |
|----|------|----------|----------|------|------|
| LOAD[0] | 壳代码 | 960B | 9.4MB | RE | 第一阶段加载器 + 解密后代码区 |
| LOAD[1] | 数据 | 0 | 32KB | RW | 小数据段 |
| LOAD[2] | 数据 | 0 | 12.8MB | RW | 大数据段 |
| LOAD[3] | 代码 | 0 | 27.6MB | RE | 解密后代码段 |
| LOAD[4] | payload | 46.6MB | 46.6MB | RE | 加密payload（Stub+解密器+加密函数） |
| LOAD[5] | 数据 | 22KB | 22KB | RW | 动态链接数据 |
| LOAD[6] | 数据 | 523KB | 523KB | RW | 字符串/符号表 |

**关键洞察**：
- 文件中只有 LOAD[0]（960B壳代码）和 LOAD[4]（46.6MB加密payload）有实际内容
- 其他段（LOAD[1/2/3]）运行时才分配内存，由壳代码解密填充
- LOAD[3]（27.6MB RE）是解密后代码的主要存放区域

## 3. Section Headers 分析

### 真实样本 Section Headers

```
[Nr] Name      Type      Address          Offset   Size
[ 0]           NULL      0000000000000000 00000000 00000000
[ 1] .dynstr   STRTAB    0000000005d766f0 02c9a6f0 00000608
[ 2] .dynamic  DYNAMIC   0000000005df82f8 02d1c2f8 00000210
[ 3] .shstrtab STRTAB    0000000000000000 02d1c508 0000001c
```

只有 4 个 section，这是 T盾 的典型特征。

### 为什么保留这4个？

| Section | 类型 | 必须保留的原因 |
|---------|------|----------------|
| NULL | SHT_NULL | ELF 规范要求第一个 section 必须是 NULL |
| .dynstr | SHT_STRTAB | 动态链接器需要它来解析动态符号的字符串（库名、函数名） |
| .dynamic | SHT_DYNAMIC | 动态链接器需要它来获取动态链接信息（依赖库、重定位、符号表地址等） |
| .shstrtab | SHT_STRTAB | section 名字符串表，让 section 表能被正常解析 |

### 缺失的 section 去哪了？

正常 ELF 中应该有的 section（.text/.data/.rodata/.bss/.got/.plt等）在 T盾 加壳后：
1. **被合并到 payload 段**：代码和数据被加密后存放在 LOAD[4]（payload段）
2. **运行时才还原**：壳代码解密后，把代码放到 LOAD[3]，数据放到 LOAD[1/2]
3. **不需要 section 描述**：因为运行时由壳代码管理内存布局，不需要 section 表来描述

**对逆向分析的影响**：
- 无法通过 section 名快速定位代码段/数据段
- 必须通过 Program Headers 和动态段来推断内存布局
- 脱壳后需要重建 section 表才能用 IDA 正常分析

## 4. 动态段分析

### 真实样本动态段

```
Tag        Type                         Name/Value
0x00000001 (NEEDED)                     Shared library: [liblog.so]
0x00000001 (NEEDED)                     Shared library: [libz.so]
0x00000001 (NEEDED)                     Shared library: [libc.so]
0x00000001 (NEEDED)                     Shared library: [libm.so]
0x00000001 (NEEDED)                     Shared library: [libdl.so]
0x0000001e (FLAGS)                      BIND_NOW
0x6ffffffb (FLAGS_1)                    Flags: NOW PIE
0x00000015 (DEBUG)                      0x0
0x00000007 (RELA)                       0x5df7170
0x00000008 (RELASZ)                     1896 (bytes)
0x00000009 (RELAENT)                    24 (bytes)
0x00000006 (SYMTAB)                     0x5d758b0
0x0000000b (SYMENT)                     24 (bytes)
0x00000005 (STRTAB)                     0x5d766f0
0x0000000a (STRSZ)                      1544 (bytes)
0x00000020 (PREINIT_ARRAY)              0x5d6c5e8
0x00000021 (PREINIT_ARRAYSZ)            24 (bytes)
0x00000019 (INIT_ARRAY)                 0x92aad0
0x0000001b (INIT_ARRAYSZ)               80 (bytes)
0x0000001a (FINI_ARRAY)                 0x92ab20
0x0000001c (FINI_ARRAYSZ)               16 (bytes)
```

### 关键发现

#### 1. 依赖库很少

只依赖 5 个基础库：
- liblog.so（Android 日志）
- libz.so（压缩）
- libc.so（C标准库）
- libm.so（数学库）
- libdl.so（动态链接）

**说明**：T盾 壳代码本身不依赖复杂的库，原始程序的依赖可能被静态链接或延迟加载。

#### 2. PREINIT_ARRAY 内容可读取

```
PREINIT_ARRAY: vaddr=0x5d6c5e8, size=24 (3个指针)
```

PREINIT_ARRAY 中的函数会在 main 之前执行。真实样本中：
```
PREINIT_ARRAY[0] = 0x4be5a68  ← 这也是一个 Stub！
PREINIT_ARRAY[1] = 0xffffffffffffffff  ← 结束标记
PREINIT_ARRAY[2] = 0x0
```

**关键发现**：PREINIT_ARRAY[0] = 0x4be5a68，反汇编后发现这也是一个 5 指令 Stub，和入口点 Stub 模式完全相同，只是函数ID不同。

这意味着 T盾 不仅把入口点改成了 Stub，连 PREINIT_ARRAY 中的初始化函数也改成了 Stub。

#### 3. INIT_ARRAY 在 filesz=0 的段中

```
INIT_ARRAY: vaddr=0x92aad0, size=80
```

INIT_ARRAY 位于 LOAD[1]（vaddr=0x009283c0, filesz=0），这个段文件中没有内容，运行时才填充。

**说明**：T盾 运行时会动态构造 INIT_ARRAY，把原始程序的初始化函数地址填进去。静态分析时读不到 INIT_ARRAY 的内容。

## 5. 虚拟地址→文件偏移转换

### 转换公式

```
文件偏移 = p_offset + (虚拟地址 - p_vaddr)

前提：虚拟地址在 [p_vaddr, p_vaddr + p_filesz) 范围内
```

### 真实样本转换示例

#### 入口点 0x4be1920

```
入口点在 LOAD[4] 中：
  LOAD[4].p_offset = 0x3c0
  LOAD[4].p_vaddr  = 0x030d83c0
  LOAD[4].p_filesz = 0x02c93c40

段内偏移 = 0x4be1920 - 0x030d83c0 = 0x1b09560
文件偏移 = 0x3c0 + 0x1b09560 = 0x1b09920
```

验证：读取文件偏移 0x1b09920 的内容，应该是入口点 Stub 的第一条指令。

#### 统一解密器 0x4b7e3c8

```
统一解密器也在 LOAD[4] 中：
段内偏移 = 0x4b7e3c8 - 0x030d83c0 = 0x1aa6008
文件偏移 = 0x3c0 + 0x1aa6008 = 0x1aa63c8
```

#### PREINIT 函数 0x4be5a68

```
段内偏移 = 0x4be5a68 - 0x030d83c0 = 0x1b0d6a8
文件偏移 = 0x3c0 + 0x1b0d6a8 = 0x1b0da68
```

### Python 实现

```python
import struct

def parse_elf_phdrs(data):
    """解析 ELF Program Headers"""
    if data[:4] != b'\x7fELF' or data[4] != 2:
        raise ValueError('仅支持 64 位 ELF')
    
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
        phdrs.append({
            'type': p_type, 'flags': p_flags,
            'offset': p_offset, 'vaddr': p_vaddr,
            'filesz': p_filesz, 'memsz': p_memsz,
        })
    return phdrs

def vaddr_to_offset(vaddr, phdrs):
    """虚拟地址转文件偏移"""
    for p in phdrs:
        if p['type'] == 1 and p['vaddr'] <= vaddr < p['vaddr'] + p['filesz']:
            return p['offset'] + (vaddr - p['vaddr'])
    return None

# 使用示例
with open('sample.elf', 'rb') as f:
    data = f.read()

phdrs = parse_elf_phdrs(data)
entry = struct.unpack_from('<Q', data, 0x18)[0]
offset = vaddr_to_offset(entry, phdrs)
print(f'入口点 0x{entry:x} -> 文件偏移 0x{offset:x}')
```

## 6. 快速分析命令汇总

```bash
# ELF 头
readelf -h sample.elf

# Program Headers（重点看 filesz/memsz）
readelf -l sample.elf

# Section Headers（重点看数量，T盾通常≤4）
readelf -S sample.elf

# 动态段
readelf -d sample.elf

# 入口点反汇编
objdump -d sample.elf | head -20

# 特征字符串
strings -a sample.elf | grep -i "T-Protector\|tshield"

# 熵分析（需要安装 binwalk 或自定义脚本）
binwalk -E sample.elf

# 用专用工具
python3 scripts/tshield_analyzer.py sample.elf
```
