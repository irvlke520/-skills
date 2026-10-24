# Stub 模式与函数ID分析

基于真实 T盾 样本（T1_904_0414.sh）的实际分析结果。

## 1. Stub 模式概述

T盾 的核心机制之一是**函数级加密**：每个函数的原始代码被加密，函数入口被替换为一个 5 指令的 Stub（桩代码）。

### Stub 通用模式

```armasm
; 函数入口（虚拟地址 = func_vaddr）
str x13, [sp, #-0x10]!    ; 1. 保存 x13 到栈（预递减）
mov w13, #<imm16>          ; 2. w13 = 函数ID低16位
movk w13, #<imm16>, lsl #16 ; 3. w13 = 函数ID高16位（合并为32位）
str x13, [sp, #8]          ; 4. 保存函数ID到栈（sp+8位置）
b #<unified_decryptor>      ; 5. 跳转到统一解密器
```

### 每条指令的作用

| 序号 | 指令 | 作用 | 大小 |
|------|------|------|------|
| 1 | `str x13, [sp, #-0x10]!` | 保存 x13 寄存器到栈，同时分配16字节栈空间 | 4字节 |
| 2 | `mov w13, #<imm16>` | 设置 w13 的低16位为函数ID低16位 | 4字节 |
| 3 | `movk w13, #<imm16>, lsl #16` | 设置 w13 的高16位为函数ID高16位（保持低16位不变） | 4字节 |
| 4 | `str x13, [sp, #8]` | 把函数ID（w13的值）保存到栈的 sp+8 位置 | 4字节 |
| 5 | `b #<unified_decryptor>` | 无条件跳转到统一解密器 | 4字节 |

**总大小**：5条指令 × 4字节 = 20字节

### 为什么用 x13 寄存器？

- ARM64 调用约定中，x13 是临时寄存器（IP1），不需要保存恢复
- 用 x13 传递函数ID，不影响函数的参数（x0-x7）和返回值（x0）
- 统一解密器可以从 x13 或栈上读取函数ID

### 为什么保存到栈上？

- 统一解密器可能会修改 x13（执行解密逻辑时需要用寄存器）
- 保存到栈上可以确保函数ID不被覆盖
- 栈位置 sp+8 是固定的，统一解密器知道从哪里读取

## 2. 真实样本 Stub 分析

### 入口点 Stub（0x4be1920）

**反汇编结果**：
```armasm
0x4be1920: str x13, [sp, #-0x10]!
0x4be1924: mov w13, #0x2fe8
0x4be1928: movk w13, #0xb306, lsl #16
0x4be192c: str x13, [sp, #8]
0x4be1930: b #0x4b7e3c8
```

**分析**：
- 函数ID = 0xb3062fe8（高16位 0xb306，低16位 0x2fe8）
- 统一解密器地址 = 0x4b7e3c8
- 这是程序入口点的 Stub，对应原始程序的 `_start` 或 `main`

**原始字节**：
```
文件偏移 0x1b09920:
ed 0f 1f f8  ; str x13, [sp, #-0x10]!
0d fd 85 52  ; mov w13, #0x2fe8
cd 60 b6 72  ; movk w13, #0xb306, lsl #16
ed 07 00 f9  ; str x13, [sp, #8]
a6 72 fe 17  ; b #0x4b7e3c8
```

### PREINIT 函数 Stub（0x4be5a68）

**反汇编结果**：
```armasm
0x4be5a68: str x13, [sp, #-0x10]!
0x4be5a6c: mov w13, #0x643e
0x4be5a70: movk w13, #0x730c, lsl #16
0x4be5a74: str x13, [sp, #8]
0x4be5a78: b #0x4b7e3c8
```

**分析**：
- 函数ID = 0x730c643e（高16位 0x730c，低16位 0x643e）
- 统一解密器地址 = 0x4b7e3c8（和入口点相同！）
- 这是 PREINIT_ARRAY[0] 指向的函数，在 main 之前执行

### 两个 Stub 的对比

| 项目 | 入口点 Stub | PREINIT Stub |
|------|-------------|--------------|
| 虚拟地址 | 0x4be1920 | 0x4be5a68 |
| 函数ID | 0xb3062fe8 | 0x730c643e |
| 统一解密器 | 0x4b7e3c8 | 0x4b7e3c8 |
| 指令模式 | 完全相同 | 完全相同 |
| 大小 | 20字节 | 20字节 |

**关键结论**：
1. 所有 Stub 的指令模式完全相同，只有函数ID不同
2. 所有 Stub 都跳转到同一个统一解密器地址（0x4b7e3c8）
3. 函数ID是每个函数的唯一标识，用于在映射表中查找加密的函数代码

## 3. 函数ID 提取方法

### 方法一：手动反汇编提取

1. 反汇编函数入口：
   ```bash
   objdump -d --start-address=0x4be1920 --stop-address=0x4be1940 sample.elf
   ```

2. 从 `mov` 和 `movk` 指令提取函数ID：
   - `mov w13, #<imm16>` → 低16位
   - `movk w13, #<imm16>, lsl #16` → 高16位
   - 函数ID = (高16位 << 16) | 低16位

### 方法二：原始字节提取

Stub 的原始字节有固定模式，可以直接从文件中提取：

```
偏移 0:  ed 0f 1f f8   ; str x13, [sp, #-0x10]! (固定)
偏移 4:  0d fd 85 52   ; mov w13, #imm16 (imm16 在字节5-6)
偏移 8:  cd 60 b6 72   ; movk w13, #imm16, lsl #16 (imm16 在字节9-10)
偏移 12: ed 07 00 f9   ; str x13, [sp, #8] (固定)
偏移 16: a6 72 fe 17   ; b #target (target 编码在字节16-19)
```

**提取函数ID**：
```python
import struct

def extract_func_id(data, offset):
    """从 Stub 提取函数ID"""
    # mov w13, #imm16: 编码 0x52800000 | (imm16 << 5) | rd
    mov_inst = struct.unpack_from('<I', data, offset + 4)[0]
    low16 = (mov_inst >> 5) & 0xffff
    
    # movk w13, #imm16, lsl #16: 编码 0x72800000 | (hw << 21) | (imm16 << 5) | rd
    movk_inst = struct.unpack_from('<I', data, offset + 8)[0]
    high16 = (movk_inst >> 5) & 0xffff
    
    func_id = (high16 << 16) | low16
    return func_id

# 使用示例
with open('sample.elf', 'rb') as f:
    data = f.read()

# 入口点文件偏移 = 0x1b09920
func_id = extract_func_id(data, 0x1b09920)
print(f'函数ID: 0x{func_id:08x}')
```

### 方法三：批量扫描提取

扫描整个 payload 段，识别所有 Stub 并提取函数ID：

```python
def is_stub(data, offset):
    """检查指定位置是否是 Stub"""
    if offset + 20 > len(data):
        return False
    
    # 检查第一条指令: str x13, [sp, #-0x10]! = 0xf81f0fed
    inst0 = struct.unpack_from('<I', data, offset)[0]
    if inst0 != 0xf81f0fed:
        return False
    
    # 检查第二条指令: mov w13, #imm16 = 0x52800000 | (imm16 << 5) | 13
    inst1 = struct.unpack_from('<I', data, offset + 4)[0]
    if (inst1 & 0xff80001f) != 0x5280000d:  # 掩码检查
        return False
    
    # 检查第三条指令: movk w13, #imm16, lsl #16 = 0x72800000 | (1 << 21) | (imm16 << 5) | 13
    inst2 = struct.unpack_from('<I', data, offset + 8)[0]
    if (inst2 & 0xff80001f) != 0x72a0000d:  # hw=1, 掩码检查
        return False
    
    # 检查第四条指令: str x13, [sp, #8] = 0xf90007ed
    inst3 = struct.unpack_from('<I', data, offset + 12)[0]
    if inst3 != 0xf90007ed:
        return False
    
    # 第五条指令: b #target = 0x14000000 | (offset >> 2)
    inst4 = struct.unpack_from('<I', data, offset + 16)[0]
    if (inst4 & 0xfc000000) != 0x14000000:
        return False
    
    return True

def scan_stubs(data, start, end):
    """扫描指定范围内的所有 Stub"""
    stubs = []
    offset = start
    while offset < end - 20:
        if is_stub(data, offset):
            func_id = extract_func_id(data, offset)
            # 提取跳转目标
            inst4 = struct.unpack_from('<I', data, offset + 16)[0]
            b_offset = (inst4 & 0x03ffffff) << 2
            if b_offset & 0x02000000:
                b_offset -= 0x04000000
            target = (offset + 16) + b_offset  # 注意：这是文件偏移，需要转换为虚拟地址
            
            stubs.append({
                'file_offset': offset,
                'func_id': func_id,
                'decryptor_target': target,
            })
            offset += 20  # Stub 大小固定20字节
        else:
            offset += 4  # 按指令对齐扫描
    return stubs
```

## 4. Stub → 函数ID 映射表构建

### 映射表格式

```tsv
virtual_address    file_offset    func_id      decryptor_target
0x0000000004be1920    0x0000000001b09920    0xb3062fe8    0x0000000004b7e3c8
0x0000000004be5a68    0x0000000001b0da68    0x730c643e    0x0000000004b7e3c8
...
```

### 构建步骤

1. **确定 payload 段范围**：
   - 从 Program Headers 获取 LOAD[4] 的范围
   - 虚拟地址范围：0x030d83c0 ~ 0x05d6c000
   - 文件偏移范围：0x3c0 ~ 0x2c94000

2. **扫描所有 Stub**：
   - 用 `scan_stubs()` 函数扫描整个 payload 段
   - 提取每个 Stub 的虚拟地址、文件偏移、函数ID、解密器目标

3. **验证一致性**：
   - 所有 Stub 应该跳转到同一个统一解密器地址
   - 函数ID应该是唯一的（每个函数一个ID）
   - 如果有重复的函数ID，可能是扫描错误或特殊函数

4. **输出映射表**：
   - 保存为 TSV/JSON 格式
   - 用于后续的解密器分析和脱壳

## 5. 函数ID 的作用

### 函数ID → 加密代码映射

统一解密器根据函数ID查找对应的加密函数代码：

```
函数ID (32位)
    ↓
查找映射表 (函数ID → 加密代码地址/大小)
    ↓
获取加密函数代码
    ↓
解密算法解密
    ↓
得到原始函数代码
    ↓
复制到可执行内存
    ↓
跳转到解密后的函数执行
```

### 函数ID 的可能编码方式

| 编码方式 | 说明 | 识别方法 |
|----------|------|----------|
| 顺序索引 | 函数ID = 函数在表中的索引 | 函数ID连续递增 |
| 哈希值 | 函数ID = 函数名或地址的哈希 | 函数ID随机分布 |
| 加密索引 | 函数ID = 加密后的索引 | 需要解密才能得到索引 |
| 直接地址 | 函数ID = 加密代码的偏移 | 函数ID在 payload 段范围内 |

**真实样本分析**：
- 入口点函数ID = 0xb3062fe8
- PREINIT 函数ID = 0x730c643e
- 这两个值看起来是随机的，不像顺序索引
- 可能是哈希值或加密索引

### 函数ID 映射表的位置

映射表可能在以下位置：
1. **payload 段内的固定位置**：统一解密器中有一个硬编码的映射表地址
2. **动态构建**：运行时由壳代码扫描所有 Stub 构建映射表
3. **加密存储**：映射表本身被加密，运行时才解密
4. **算法推导**：不需要映射表，通过函数ID直接计算加密代码地址

**定位方法**：
- 逆向统一解密器，看它如何根据函数ID查找加密代码
- 动态跟踪解密器，记录函数ID和对应的内存访问
- 在 payload 段中搜索函数ID的值，看是否有表存储这些值

## 6. Stub 模式的识别特征

### 快速识别 Stub

在反汇编中看到以下模式，基本可以确认是 T盾 Stub：

```armasm
str x13, [sp, #-0x10]!    ; 必须是 x13，必须是预递减
mov w13, #<imm16>          ; 必须是 w13
movk w13, #<imm16>, lsl #16 ; 必须是 w13，必须是 lsl #16
str x13, [sp, #8]          ; 必须是 sp+8
b #<target>                 ; 必须是无条件跳转
```

### 与其他代码的区别

| 特征 | T盾 Stub | 正常函数序言 |
|------|----------|-------------|
| 第一条指令 | `str x13, [sp, #-0x10]!` | `stp x29, x30, [sp, #-0x20]!` |
| 寄存器 | x13（临时寄存器） | x29/x30（帧指针/返回地址） |
| 栈分配 | 固定16字节 | 可变大小 |
| 后续指令 | mov/movk/str/b | 各种函数体指令 |
| 结尾 | b（跳转到解密器） | 正常函数体或ret |
| 大小 | 固定20字节 | 可变 |

### 误判避免

以下情况可能被误判为 Stub，需要注意：
1. **使用 x13 的正常代码**：某些编译器可能用 x13 做临时寄存器，但不会有完整的 5 指令模式
2. **手动汇编的桩代码**：某些程序可能手动写类似的桩，但函数ID不会统一跳转到同一个解密器
3. **其他加壳器的 Stub**：其他加壳器也可能用类似的 Stub 模式，需要结合其他特征判断

**验证方法**：
- 找到多个 Stub，确认它们都跳转到同一个地址（统一解密器）
- 确认跳转目标是一个复杂的、被混淆的函数（OLLVM混淆）
- 确认文件中有 T-Protector 字符串或其他 T盾 特征

## 7. 实用工具

### Stub 提取器脚本

详见 `scripts/stub_extractor.py`，功能包括：
- 扫描整个 payload 段，识别所有 Stub
- 提取每个 Stub 的函数ID
- 构建 Stub → 函数ID 映射表
- 输出 TSV/JSON 格式
- 统计分析（函数ID分布、Stub数量等）

### 使用方法

```bash
python3 scripts/stub_extractor.py sample.elf --output stubs.tsv
python3 scripts/stub_extractor.py sample.elf --output stubs.json --format json
python3 scripts/stub_extractor.py sample.elf --stats  # 只显示统计信息
```
