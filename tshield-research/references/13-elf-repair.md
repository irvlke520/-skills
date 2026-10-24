# ELF 结构修复完整指南

基于真实 T盾 样本（T1_904_0414.sh）动态 dump 后的修复流程。

## 1. 修复概述

### 为什么需要修复

动态内存 dump 得到的是原始内存内容，不是完整的 ELF 文件：
- ELF 头可能被修改或不完整
- Program Headers 的 p_offset/p_filesz 不正确（基于内存布局，不是文件布局）
- 没有 Section Headers（T盾 加壳时移除了）
- 重定位可能未修复
- 导入表可能不完整

### 修复目标

修复后的 ELF 文件应该：
- 可以被 IDA/Ghidra 正常加载分析
- 函数列表完整
- 字符串可见
- 交叉引用正确
- （可选）可以在设备上运行

### 修复优先级

| 优先级 | 修复项 | 目的 |
|--------|--------|------|
| ⭐⭐⭐⭐⭐ | ELF 头 | 文件能被识别为 ELF |
| ⭐⭐⭐⭐⭐ | Program Headers | 段能被正确加载 |
| ⭐⭐⭐⭐ | Section Headers | IDA 能识别段名 |
| ⭐⭐⭐ | 重定位 | 交叉引用正确 |
| ⭐⭐⭐ | 导入表 | 函数名可见 |
| ⭐⭐ | 符号表 | 函数名完整 |

## 2. ELF 头修复

### 2.1 ELF 头结构

```c
typedef struct {
    unsigned char e_ident[16];  // 魔数+标识
    uint16_t e_type;             // 文件类型
    uint16_t e_machine;          // 架构
    uint32_t e_version;          // 版本
    uint64_t e_entry;            // 入口点
    uint64_t e_phoff;            // Program Header 偏移
    uint64_t e_shoff;            // Section Header 偏移
    uint32_t e_flags;            // 标志
    uint16_t e_ehsize;           // ELF 头大小
    uint16_t e_phentsize;        // Program Header 条目大小
    uint16_t e_phnum;            // Program Header 数量
    uint16_t e_shentsize;        // Section Header 条目大小
    uint16_t e_shnum;            // Section Header 数量
    uint16_t e_shstrndx;         // Section 名字符串表索引
} Elf64_Ehdr;
```

### 2.2 修复步骤

#### 步骤1：修复 e_ident（魔数）

```python
# e_ident 前4字节必须是 7f 45 4c 46
data[0:4] = b'\x7fELF'

# 第5字节：1=32位, 2=64位
data[4] = 2  # 64位

# 第6字节：1=小端, 2=大端
data[5] = 1  # 小端

# 第7字节：版本（通常=1）
data[6] = 1
```

#### 步骤2：修复 e_type 和 e_machine

```python
import struct

# e_type: 2=可执行, 3=共享对象(PIE)
struct.pack_into('<H', data, 0x10, 3)  # ET_DYN (PIE)

# e_machine: 0xB7=ARM64, 0x3E=x86_64
struct.pack_into('<H', data, 0x12, 0xB7)  # EM_AARCH64
```

#### 步骤3：修复 e_entry（入口点）

入口点应该是解密后的原始程序入口，而不是 T盾 的 Stub：

```python
# 方法1：从动态分析获取（统一解密器解密入口点后的地址）
entry_point = 0x<decrypted_entry>

# 方法2：从内存 dump 中查找（寻找正常的函数序言）
# 正常 ARM64 函数序言: stp x29, x30, [sp, #-0x20]! ; mov x29, sp

struct.pack_into('<Q', data, 0x18, entry_point)
```

#### 步骤4：修复 e_phoff 和 e_phnum

```python
# Program Header 通常紧跟在 ELF 头后面
# e_phoff = 64 (ELF 头大小)
struct.pack_into('<Q', data, 0x20, 64)

# e_phnum = Program Header 数量（根据实际段数）
struct.pack_into('<H', data, 0x38, phnum)

# e_phentsize = 56 (64位 Program Header 大小)
struct.pack_into('<H', data, 0x36, 56)
```

#### 步骤5：修复 e_shoff 和 e_shnum（如果重建 Section Headers）

```python
# Section Header 放在文件末尾
struct.pack_into('<Q', data, 0x28, shoff)
struct.pack_into('<H', data, 0x3C, shnum)
struct.pack_into('<H', data, 0x3A, 64)  # e_shentsize
struct.pack_into('<H', data, 0x3E, shstrndx)
```

### 2.3 验证

```bash
# 验证 ELF 头
readelf -h repaired.elf

# 应该显示正确的架构、类型、入口点
```

## 3. Program Headers 修复

### 3.1 Program Header 结构

```c
typedef struct {
    uint32_t p_type;     // 段类型
    uint32_t p_flags;    // 权限
    uint64_t p_offset;   // 文件偏移
    uint64_t p_vaddr;    // 虚拟地址
    uint64_t p_paddr;    // 物理地址
    uint64_t p_filesz;   // 文件大小
    uint64_t p_memsz;    // 内存大小
    uint64_t p_align;    // 对齐
} Elf64_Phdr;
```

### 3.2 修复核心问题

动态 dump 后，Program Headers 的主要问题：
- **p_offset 不正确**：dump 是按内存布局拼接的，p_offset 需要重新计算
- **p_filesz 不正确**：可能等于 p_memsz（内存大小），但文件中可能没有 .bss 内容
- **段顺序可能不对**：需要按虚拟地址排序

### 3.3 修复步骤

#### 步骤1：收集所有内存段信息

从 `/proc/pid/maps` 获取所有段的信息：

```python
segments = [
    # {'start': 0x0, 'end': 0x927000, 'perms': 'r-xp', 'offset': 0x0, 'path': 'sample'},
    # {'start': 0x928000, 'end': 0x930000, 'perms': 'rw-p', 'offset': 0x0, 'path': ''},
    # ...
]
```

#### 步骤2：按虚拟地址排序

```python
segments.sort(key=lambda x: x['start'])
```

#### 步骤3：计算文件偏移

将所有段按顺序拼接到文件中，计算每个段的文件偏移：

```python
file_offset = 0  # 从 ELF 头 + Program Headers 之后开始
file_offset = 64 + phnum * 56  # ELF头 + PHDR

for seg in segments:
    seg['p_offset'] = file_offset
    seg['p_filesz'] = seg['end'] - seg['start']
    
    # .bss 段（文件中无内容）特殊处理
    if seg['path'] == '' and 'w' in seg['perms'] and seg['offset'] == 0:
        # 可能是 .bss，文件大小为0
        seg['p_filesz'] = 0
    else:
        file_offset += seg['p_filesz']
    
    # 对齐到 0x1000
    file_offset = (file_offset + 0xFFF) & ~0xFFF
```

#### 步骤4：设置权限

```python
def perms_to_flags(perms):
    flags = 0
    if 'r' in perms: flags |= 4  # PF_R
    if 'w' in perms: flags |= 2  # PF_W
    if 'x' in perms: flags |= 1  # PF_X
    return flags
```

#### 步骤5：写入 Program Headers

```python
import struct

phoff = 64  # Program Header 偏移
phentsize = 56

for i, seg in enumerate(segments):
    offset = phoff + i * phentsize
    
    # p_type: 1=PT_LOAD
    struct.pack_into('<I', data, offset, 1)
    
    # p_flags
    struct.pack_into('<I', data, offset + 4, perms_to_flags(seg['perms']))
    
    # p_offset
    struct.pack_into('<Q', data, offset + 8, seg['p_offset'])
    
    # p_vaddr
    struct.pack_into('<Q', data, offset + 16, seg['start'])
    
    # p_paddr (通常等于 p_vaddr)
    struct.pack_into('<Q', data, offset + 24, seg['start'])
    
    # p_filesz
    struct.pack_into('<Q', data, offset + 32, seg['p_filesz'])
    
    # p_memsz
    struct.pack_into('<Q', data, offset + 40, seg['end'] - seg['start'])
    
    # p_align (通常=0x1000)
    struct.pack_into('<Q', data, offset + 48, 0x1000)
```

### 3.4 特殊段处理

#### INTERP 段

```python
# 如果有动态链接器路径，需要添加 INTERP 段
interp_path = b'/system/bin/linker64\x00'
# 添加一个 PT_INTERP 段，包含这个路径
```

#### DYNAMIC 段

```python
# 动态段包含动态链接信息
# 需要确保 .dynamic 段的地址正确
# p_type = 2 (PT_DYNAMIC)
```

#### GNU_EH_FRAME / GNU_STACK 段

```python
# 这些是可选的，不影响基本分析
# 可以保留原始的，也可以移除
```

### 3.5 验证

```bash
# 验证 Program Headers
readelf -l repaired.elf

# 验证段可以被正确加载
# 用 IDA 加载，看段是否正确识别
```

## 4. Section Headers 重建

### 4.1 为什么重建 Section Headers

T盾 加壳后只有4个 section，脱壳后需要重建：
- IDA/Ghidra 用 section 名来识别代码段/数据段
- 有 section 名后，分析更方便
- 字符串、符号表等需要 section 来定位

### 4.2 常见 Section

| Section | 类型 | 权限 | 内容 |
|---------|------|------|------|
| .text | SHT_PROGBITS | R-X | 代码段 |
| .data | SHT_PROGBITS | RW- | 已初始化数据 |
| .rodata | SHT_PROGBITS | R-- | 只读数据 |
| .bss | SHT_NOBITS | RW- | 未初始化数据 |
| .got | SHT_PROGBITS | RW- | 全局偏移表 |
| .got.plt | SHT_PROGBITS | RW- | PLT的GOT |
| .plt | SHT_PROGBITS | R-X | 过程链接表 |
| .dynsym | SHT_DYNSYM | R-- | 动态符号表 |
| .dynstr | SHT_STRTAB | R-- | 动态字符串表 |
| .rela.* | SHT_RELA | R-- | 重定位表 |
| .dynamic | SHT_DYNAMIC | RW- | 动态段 |
| .init | SHT_PROGBITS | R-X | 初始化代码 |
| .fini | SHT_PROGBITS | R-X | 终止代码 |
| .init_array | SHT_INIT_ARRAY | RW- | 初始化函数数组 |
| .fini_array | SHT_FINI_ARRAY | RW- | 终止函数数组 |
| .eh_frame | SHT_PROGBITS | R-- | 异常处理帧 |
| .shstrtab | SHT_STRTAB | R-- | section名字符串表 |

### 4.3 重建步骤

#### 步骤1：识别段内容

根据内存段的权限和内容，识别每个段对应哪个 section：

```python
def identify_section(seg, data):
    """识别段对应的 section"""
    start = seg['start']
    end = seg['end']
    perms = seg['perms']
    
    # 可执行段 → .text
    if 'x' in perms and 'r' in perms:
        # 检查是否包含 PLT
        # ...
        return '.text'
    
    # 可读可写段 → .data / .bss
    if 'r' in perms and 'w' in perms:
        if seg['p_filesz'] == 0:
            return '.bss'
        else:
            return '.data'
    
    # 只读段 → .rodata
    if 'r' in perms and 'w' not in perms and 'x' not in perms:
        return '.rodata'
    
    return None
```

#### 步骤2：构建 Section Header 表

```python
sections = []

# NULL section（必须是第一个）
sections.append({
    'name': 0, 'type': 0, 'flags': 0,
    'addr': 0, 'offset': 0, 'size': 0,
    'link': 0, 'info': 0, 'addralign': 0, 'entsize': 0
})

# .text
sections.append({
    'name': name_offset, 'type': 1, 'flags': 6,  # SHF_ALLOC | SHF_EXECINSTR
    'addr': text_start, 'offset': text_offset, 'size': text_size,
    'link': 0, 'info': 0, 'addralign': 16, 'entsize': 0
})

# ... 其他 section

# .shstrtab（最后一个）
sections.append({
    'name': shstrtab_name_offset, 'type': 3, 'flags': 0,
    'addr': 0, 'offset': shstrtab_offset, 'size': shstrtab_size,
    'link': 0, 'info': 0, 'addralign': 1, 'entsize': 0
})
```

#### 步骤3：构建 Section 名字符串表

```python
# 构建 .shstrtab
shstrtab = b'\x00'  # 第一个字符串是空
name_offsets = {}

for name in ['.text', '.data', '.rodata', '.bss', '.dynsym', '.dynstr', '.dynamic', '.shstrtab']:
    name_offsets[name] = len(shstrtab)
    shstrtab += name.encode() + b'\x00'
```

#### 步骤4：写入 Section Headers

```python
shoff = <section_header_offset>
shentsize = 64

for i, sec in enumerate(sections):
    offset = shoff + i * shentsize
    
    struct.pack_into('<I', data, offset, sec['name'])       # sh_name
    struct.pack_into('<I', data, offset + 4, sec['type'])    # sh_type
    struct.pack_into('<Q', data, offset + 8, sec['flags'])   # sh_flags
    struct.pack_into('<Q', data, offset + 16, sec['addr'])   # sh_addr
    struct.pack_into('<Q', data, offset + 24, sec['offset']) # sh_offset
    struct.pack_into('<Q', data, offset + 32, sec['size'])   # sh_size
    struct.pack_into('<I', data, offset + 40, sec['link'])   # sh_link
    struct.pack_into('<I', data, offset + 44, sec['info'])   # sh_info
    struct.pack_into('<Q', data, offset + 48, sec['addralign'])  # sh_addralign
    struct.pack_into('<Q', data, offset + 56, sec['entsize'])    # sh_entsize

# 更新 ELF 头
struct.pack_into('<Q', data, 0x28, shoff)  # e_shoff
struct.pack_into('<H', data, 0x3C, len(sections))  # e_shnum
struct.pack_into('<H', data, 0x3E, len(sections) - 1)  # e_shstrndx（最后一个是 .shstrtab）
```

### 4.4 验证

```bash
# 验证 Section Headers
readelf -S repaired.elf

# 应该显示所有 section，名字正确
```

## 5. 重定位修复

### 5.1 为什么需要修复重定位

PIE 可执行文件加载时，动态链接器会根据重定位表修复地址：
- 函数指针
- 全局变量引用
- GOT/PLT 条目

如果重定位未修复，IDA 中的交叉引用会不正确。

### 5.2 常见重定位类型

| 类型 | 值 | 说明 |
|------|-----|------|
| R_AARCH64_RELATIVE | 1027 | 相对重定位（基址 + 加数） |
| R_AARCH64_GLOB_DAT | 1025 | 全局数据（GOT条目） |
| R_AARCH64_JUMP_SLOT | 1026 | 跳转槽（PLT条目） |
| R_AARCH64_ABS64 | 257 | 绝对64位 |
| R_AARCH64_ABS32 | 258 | 绝对32位 |

### 5.3 修复步骤

#### 步骤1：定位重定位表

```python
# 从 .dynamic 段获取重定位表地址
# DT_RELA (7) = 重定位表地址
# DT_RELASZ (8) = 重定位表大小
# DT_RELAENT (9) = 重定位条目大小
```

#### 步骤2：应用相对重定位

```python
# R_AARCH64_RELATIVE: *ptr = base_addr + addend
for reloc in relocations:
    if reloc['type'] == 1027:  # R_AARCH64_RELATIVE
        ptr = reloc['offset']  # 重定位位置（虚拟地址）
        addend = reloc['addend']  # 加数
        value = base_addr + addend  # 修复后的值
        
        # 写入修复后的值
        file_offset = vaddr_to_offset(ptr)
        struct.pack_into('<Q', data, file_offset, value)
```

#### 步骤3：应用全局数据重定位

```python
# R_AARCH64_GLOB_DAT: *ptr = symbol_addr
# 需要符号表来获取符号地址
for reloc in relocations:
    if reloc['type'] == 1025:  # R_AARCH64_GLOB_DAT
        sym = symbols[reloc['sym']]
        value = sym['value'] + base_addr  # 符号地址
        
        file_offset = vaddr_to_offset(reloc['offset'])
        struct.pack_into('<Q', data, file_offset, value)
```

### 5.4 验证

```bash
# 验证重定位
readelf -r repaired.elf

# 用 IDA 加载，检查交叉引用是否正确
```

## 6. 导入表修复

### 6.1 导入表结构

导入表包括：
- .dynsym：动态符号表（函数名、变量名）
- .dynstr：动态字符串表（符号名字符串）
- .got：全局偏移表
- .got.plt：PLT的GOT
- .plt：过程链接表

### 6.2 修复步骤

#### 步骤1：保留原始动态段

T盾 加壳后保留了 .dynamic 和 .dynstr，可以直接使用：

```python
# 从原始文件复制 .dynamic 和 .dynstr
# 确保它们的地址和大小正确
```

#### 步骤2：重建符号表（如果需要）

如果 .dynsym 不完整，需要重建：

```python
# 从 .dynamic 段获取导入函数列表
# 从 PLT/GOT 推断函数名
# 构建 .dynsym 和 .dynstr
```

#### 步骤3：修复 PLT

```python
# PLT 条目结构（ARM64）：
#   adrp x16, <got_page>
#   ldr x17, [x16, #<got_offset>]
#   add x16, x16, #<got_offset>
#   br x17

# 确保 PLT 条目正确指向 GOT 条目
```

### 6.3 验证

```bash
# 验证导入表
readelf -d repaired.elf
readelf --dyn-syms repaired.elf

# 用 IDA 加载，检查导入函数名是否正确
```

## 7. 完整修复脚本

详见 `scripts/elf_repair.py`，功能包括：
- 自动修复 ELF 头
- 自动修复 Program Headers
- 自动重建 Section Headers
- 自动应用重定位
- 自动修复导入表
- 生成修复报告

使用方法：
```bash
python3 scripts/elf_repair.py --input dump.bin --output repaired.elf --base 0x0
python3 scripts/elf_repair.py --input dump.bin --output repaired.elf --maps maps.txt
python3 scripts/elf_repair.py --verify repaired.elf
```

## 8. 修复验证清单

- [ ] ELF 头正确（魔数、架构、类型、入口点）
- [ ] Program Headers 正确（段类型、权限、偏移、大小）
- [ ] 所有段都有对应的文件内容
- [ ] Section Headers 完整（.text/.data/.rodata/.bss等）
- [ ] Section 名字正确
- [ ] 重定位已应用（相对重定位、全局数据重定位）
- [ ] 导入表完整（.dynsym/.dynstr/.got/.plt）
- [ ] IDA 可以正常加载
- [ ] 函数列表完整
- [ ] 字符串可见
- [ ] 交叉引用正确
- [ ] （可选）可以在设备上运行

## 9. 常见问题

### 问题1：IDA 加载后显示 "Corrupt section header"

**原因**：Section Header 偏移或大小不正确。

**解决**：
1. 检查 e_shoff 是否指向文件末尾的有效位置
2. 检查 e_shnum 是否正确
3. 检查每个 Section Header 的 offset/size 是否在文件范围内

### 问题2：函数列表不完整

**原因**：
- 入口点不正确
- .text 段识别错误
- 函数序言识别失败

**解决**：
1. 确认入口点是解密后的原始入口
2. 确认 .text 段的地址范围正确
3. 在 IDA 中手动分析（按 P 键创建函数）

### 问题3：字符串显示为乱码

**原因**：
- .rodata 段识别错误
- 字符串还没解密
- 编码问题

**解决**：
1. 确认 .rodata 段的地址范围正确
2. 确认所有函数都已触发（字符串可能在函数解密时才解密）
3. 检查字符串编码（UTF-8/UTF-16）

### 问题4：交叉引用不正确

**原因**：重定位未正确应用。

**解决**：
1. 检查重定位表是否完整
2. 确认基址（base address）正确
3. 重新应用所有重定位

### 问题5：修复后无法运行

**原因**：
- 入口点不正确
- 段权限不正确
- 动态链接信息损坏
- 缺少必要的初始化代码

**解决**：
1. 确认入口点是原始程序入口（不是 T盾 Stub）
2. 确认段权限正确（代码段 R-X，数据段 RW-）
3. 确认 .dynamic 段完整
4. 如果只是用于静态分析，可以不要求能运行
