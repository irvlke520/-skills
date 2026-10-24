# 静态逆向脱壳（难度高）

## 1. 概述

静态逆向脱壳是指不运行程序，完全通过静态分析理解解密算法，然后批量解密所有函数。

**优点**：
- 不需要运行环境
- 可以完全理解解密机制
- 不受反调试影响

**缺点**：
- 难度高（统一解密器被 OLLVM 混淆）
- 工作量大
- 需要逆向映射表和加密算法
- 可能有无法识别的加密算法

## 2. 整体流程

```
1. 去混淆统一解密器
   ↓
2. 理解解密算法
   ↓
3. 定位函数ID映射表
   ↓
4. 提取密钥
   ↓
5. 编写解密脚本
   ↓
6. 批量解密所有函数
   ↓
7. 替换 Stub 为真实函数
   ↓
8. 修复 ELF 结构
   ↓
9. 验证
```

## 3. 去混淆统一解密器

### 3.1 OLLVM 混淆类型

T盾 的统一解密器使用了 OLLVM 的**指令替换（Instruction Substitution）**混淆：

- 恒等操作：`orr x,x,x`（无操作）、连续两次 `neg`（恢复原值）、连续两次 `rev`（恢复原值）
- 等价变换：`ror`、`orn`、`eon`、`ubfx`、`asr`、`bic`、`lsl`、`sxtw`
- 死代码：计算结果从未被使用

### 3.2 去混淆方法

#### 方法1：符号执行（推荐）

用 angr/miasm/Triton 等符号执行工具，模拟执行混淆代码，自动化简表达式。

```python
# angr 示例（伪代码）
import angr

proj = angr.Project('sample.elf', auto_load_libs=False)
state = proj.factory.blank_state(addr=0x4b7e3c8)
simgr = proj.factory.simulation_manager(state)

# 模拟执行到 bl #0x5a90278
simgr.explore(find=0x4b7e478)

if simgr.found:
    found = simgr.found[0]
    # 查看化简后的寄存器状态
    print(found.regs)
```

#### 方法2：模式匹配

针对常见的 OLLVM 混淆模式，写脚本识别和替换：

```python
def deobfuscate(instructions):
    result = []
    i = 0
    while i < len(instructions):
        # 连续两次 neg（恢复原值）
        if (i+1 < len(instructions) and
            instructions[i].mnemonic == 'neg' and
            instructions[i+1].mnemonic == 'neg' and
            instructions[i].operands[0] == instructions[i+1].operands[0]):
            i += 2
            continue
        
        # 连续两次 rev（恢复原值）
        if (i+1 < len(instructions) and
            instructions[i].mnemonic == 'rev' and
            instructions[i+1].mnemonic == 'rev'):
            i += 2
            continue
        
        # orr x,x,x（无操作）
        if (instructions[i].mnemonic == 'orr' and
            len(instructions[i].operands) >= 3 and
            instructions[i].operands[0] == instructions[i].operands[1] == instructions[i].operands[2]):
            i += 1
            continue
        
        # eor x,x,x（结果为0）
        if (instructions[i].mnemonic == 'eor' and
            len(instructions[i].operands) >= 3 and
            instructions[i].operands[1] == instructions[i].operands[2]):
            result.append(('mov', instructions[i].operands[0], 0))
            i += 1
            continue
        
        result.append(instructions[i])
        i += 1
    
    return result
```

#### 方法3：手动分析

对于关键部分，手动分析：
1. 标记混淆指令（ror/orn/eon/rev/ubfx/neg等）
2. 忽略无意义的操作
3. 关注真正有意义的指令（ldr/str/bl/分支）
4. 重建控制流

### 3.3 去混淆后的预期结果

去混淆后，统一解密器的核心逻辑应该类似：

```c
void unified_decryptor() {
    // 1. 从栈读取函数ID
    uint32_t func_id = *(uint32_t*)(original_sp + 8);
    
    // 2. 查找映射表
    MappingEntry *entry = find_in_mapping_table(func_id);
    
    // 3. 分配解密后内存
    void *decrypted_addr = allocate_memory(entry->decrypted_size);
    
    // 4. 解密函数代码
    decrypt(entry->encrypted_data, entry->encrypted_size,
            decrypted_addr, entry->decrypted_size, func_id);
    
    // 5. 刷新指令缓存
    __builtin___clear_cache(decrypted_addr, decrypted_addr + entry->decrypted_size);
    
    // 6. 恢复寄存器
    restore_registers();
    
    // 7. 跳转到解密后的函数
    goto *decrypted_addr;
}
```

## 4. 定位映射表

详见 `references/04-mapping-table-analysis.md`

方法：
1. 从去混淆后的解密器中，跟踪函数ID的使用
2. 找到函数ID → 加密代码地址的查找逻辑
3. 确定映射表的基址和结构

## 5. 逆向加密算法

详见 `references/05-encryption-algorithm.md`

方法：
1. 反汇编解密子函数（0x5a90278）
2. 识别加密算法特征（XOR/流密码/AES/自定义）
3. 提取密钥（固定密钥/函数ID派生）
4. 复现解密算法

## 6. 编写解密脚本

```python
#!/usr/bin/env python3
"""
T盾 静态解密脚本（示例，需要根据实际算法修改）
"""

import struct

def generate_key(func_id):
    """根据函数ID生成密钥（需要根据实际算法修改）"""
    # 示例：简单的函数ID变换
    key = struct.pack('<I', func_id) * 4
    return key

def decrypt_function(encrypted_data, func_id):
    """解密单个函数（需要根据实际算法修改）"""
    key = generate_key(func_id)
    decrypted = bytearray(len(encrypted_data))
    for i in range(len(encrypted_data)):
        decrypted[i] = encrypted_data[i] ^ key[i % len(key)]
    return bytes(decrypted)

def unpack_tshield(input_file, output_file, mapping_table):
    """
    批量解密所有函数
    
    mapping_table: list of dict {func_id, encrypted_offset, encrypted_size, stub_offset}
    """
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    for entry in mapping_table:
        # 读取加密的函数代码
        encrypted = data[entry['encrypted_offset']:entry['encrypted_offset'] + entry['encrypted_size']]
        
        # 解密
        decrypted = decrypt_function(encrypted, entry['func_id'])
        
        # 替换 Stub 为解密后的代码
        # 注意：需要确保解密后的代码大小不超过 Stub 区域
        # 如果超过，需要重新分配段布局
        stub_offset = entry['stub_offset']
        data[stub_offset:stub_offset + len(decrypted)] = decrypted
    
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print(f"[+] 解密完成，输出: {output_file}")

# 使用示例（需要根据实际情况修改）
# mapping_table = [
#     {'func_id': 0xb3062fe8, 'encrypted_offset': 0x????, 'encrypted_size': 0x????, 'stub_offset': 0x1b09920},
#     ...
# ]
# unpack_tshield('sample.elf', 'unpacked.elf', mapping_table)
```

## 7. 替换 Stub 为真实函数

解密所有函数后，需要用解密后的代码替换 Stub：

1. **直接替换**：如果解密后的代码大小 ≤ Stub 区域大小，直接覆盖
2. **重新布局**：如果解密后的代码更大，需要重新组织段布局
3. **跳转表**：保留 Stub 位置，用跳转指令指向新的代码位置

## 8. 修复 ELF 结构

详见 `references/13-elf-repair.md`

- 修复入口点（指向解密后的原始入口）
- 修复 Program Headers
- 重建 Section Headers
- 修复重定位
- 修复导入表

## 9. 验证

1. **反汇编验证**：用 IDA/Ghidra 加载，看函数是否正常
2. **字符串验证**：明文字符串是否可见
3. **函数数量验证**：函数数量是否合理
4. **运行验证**：能否在设备上运行（可选）

## 10. 已知样本的静态脱壳难度

对于 T1_904_0414.sh 样本：
- 统一解密器被 OLLVM 混淆，75% 指令是无意义的
- 映射表位置未知（可能被加密或通过算法计算）
- 加密算法未知（需要动态分析确定）
- 静态脱壳难度高，建议优先使用动态内存 dump

## 11. 总结

静态逆向脱壳是最彻底的方法，但难度最高：
- 需要去混淆 OLLVM
- 需要逆向映射表
- 需要逆向加密算法
- 需要复现解密逻辑
- 工作量大，容易出错

**建议**：优先使用动态内存 dump（详见 10-unpacking-dynamic-dump.md），静态逆向作为补充和验证。
