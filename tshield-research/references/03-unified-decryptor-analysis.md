# 统一解密器深度分析

基于真实 T盾 样本（T1_904_0414.sh）的实际分析结果。

## 1. 统一解密器概述

### 什么是统一解密器

统一解密器（Unified Decryptor）是 T盾 的核心组件，所有函数 Stub 都跳转到这个地址。它的功能是：
1. 从栈上读取函数ID
2. 根据函数ID查找对应的加密函数代码
3. 解密函数代码到内存
4. 跳转到解密后的函数执行

### 真实样本统一解密器信息

| 项目 | 值 |
|------|-----|
| 虚拟地址 | 0x4b7e3c8 |
| 文件偏移 | 0x1aa63c8 |
| 所在段 | LOAD[4]（payload段） |
| 混淆类型 | OLLVM（指令替换+控制流混淆） |
| 被调用次数 | 所有函数第一次被调用时 |

### 定位方法

1. **从 Stub 跳转目标定位**：
   - 反汇编任意一个 Stub，提取 `b` 指令的目标地址
   - 所有 Stub 应该跳转到同一个地址，这个地址就是统一解密器

2. **从入口点跟踪**：
   - 反汇编入口点 Stub
   - 跟踪 `b` 指令的目标

3. **特征搜索**：
   - 搜索 OLLVM 混淆特征（大量 ror/orn/eon/rev/ubfx 指令）
   - 搜索被大量函数调用的地址

## 2. 统一解密器反汇编

### 真实样本统一解密器前80条指令

```armasm
0x4b7e3c8: mov w13, #0x35ae
0x4b7e3cc: movk w13, #0x1ab1, lsl #16   ; w13 = 0x1ab135ae
0x4b7e3d0: ror w13, w13, w13             ; 循环右移（混淆）
0x4b7e3d4: orr x13, x13, x13             ; 无意义或操作（混淆）
0x4b7e3d8: neg w13, w13                   ; 取负（混淆）
0x4b7e3dc: neg x13, x13                   ; 再取负（恢复原值，混淆）
0x4b7e3e0: stp x7, x11, [sp, #-0x10]!   ; 保存寄存器
0x4b7e3e4: mov w7, w13
0x4b7e3e8: orn w13, w7, w13               ; 或非（混淆）
0x4b7e3ec: ubfx x11, x7, #0, #0x20       ; 位域提取（混淆）
0x4b7e3f0: stp x30, x29, [sp, #-0x10]!   ; 保存返回地址和帧指针
0x4b7e3f4: stp x25, x2, [sp, #-0x10]!    ; 保存寄存器
0x4b7e3f8: ubfx x13, x11, #0, #0x20       ; 位域提取（混淆）
0x4b7e3fc: ror x7, x11, x13                ; 循环右移（混淆）
0x4b7e400: stp x15, x28, [sp, #-0x10]!    ; 保存寄存器
0x4b7e404: asr w25, w11, w13               ; 算术右移（混淆）
0x4b7e408: rev x7, x13                      ; 字节序反转（混淆）
0x4b7e40c: rev x11, x7                      ; 再反转（恢复原值，混淆）
0x4b7e410: eor x15, x11, x11                ; 异或（x15=0，混淆）
0x4b7e414: sub x25, x25, x11                ; 减法（混淆）
0x4b7e418: stp x19, x22, [sp, #-0x10]!    ; 保存寄存器
0x4b7e41c: eon x13, x15, x7                 ; 异或非（混淆）
0x4b7e420: orr w22, w13, w25                ; 或操作（混淆）
0x4b7e424: orr w28, w7, w13                 ; 或操作（混淆）
0x4b7e428: mvn w29, w11                      ; 取反（混淆）
0x4b7e42c: eon x30, x11, x13                 ; 异或非（混淆）
0x4b7e430: stp x1, x20, [sp, #-0x10]!     ; 保存寄存器
0x4b7e434: stp x0, x23, [sp, #-0x10]!      ; 保存寄存器
0x4b7e438: orn x0, x29, x11                  ; 或非（混淆）
0x4b7e43c: and w29, w11, w25                 ; 与操作（混淆）
0x4b7e440: eor w29, w13, w28                 ; 异或（混淆）
0x4b7e444: sub w23, w11, #0x324              ; 减法（可能是关键计算）
0x4b7e448: stp x16, x4, [sp, #-0x10]!      ; 保存寄存器
0x4b7e44c: lsl w30, w15, w0                   ; 逻辑左移（混淆）
0x4b7e450: rev w30, w22                        ; 字节序反转（混淆）
0x4b7e454: orn x1, x25, x0                    ; 或非（混淆）
0x4b7e458: bic x20, x29, x30                  ; 位清除（混淆）
0x4b7e45c: ubfx x28, x23, #0, #0x20          ; 位域提取（混淆）
0x4b7e460: orn x20, x29, x7                   ; 或非（混淆）
0x4b7e464: stp x12, x8, [sp, #-0x10]!       ; 保存寄存器
0x4b7e468: stp x14, x5, [sp, #-0x10]!        ; 保存寄存器
0x4b7e46c: rev x4, x7                          ; 字节序反转（混淆）
0x4b7e470: ror x28, x28, x4                    ; 循环右移（混淆）
0x4b7e474: sxtw x14, w11                       ; 符号扩展（混淆）
0x4b7e478: bl #0x5a90278                       ; 调用子函数（关键！）
```

### 关键观察

#### 1. OLLVM 指令替换混淆

前40条指令中，大量是无意义的混淆指令：

| 混淆指令 | 出现次数 | 说明 |
|----------|----------|------|
| `ror`（循环右移） | 3次 | 无意义的循环移位 |
| `orr`（按位或） | 3次 | 包括 `orr x,x,x`（无操作） |
| `neg`（取负） | 2次 | 连续两次取负恢复原值 |
| `orn`（或非） | 4次 | 无意义的或非操作 |
| `ubfx`（位域提取） | 3次 | 无意义的位域提取 |
| `rev`（字节序反转） | 4次 | 连续两次反转恢复原值 |
| `eor`（异或） | 2次 | 包括 `eor x,x,x`（结果为0） |
| `eon`（异或非） | 2次 | 无意义的异或非 |
| `mvn`（取反） | 1次 | 无意义的取反 |
| `asr`（算术右移） | 1次 | 无意义的右移 |
| `bic`（位清除） | 1次 | 无意义的位清除 |
| `lsl`（逻辑左移） | 1次 | 无意义的左移 |
| `sxtw`（符号扩展） | 1次 | 无意义的符号扩展 |

**40条指令中，约30条是混淆指令！** 真正有意义的指令只有约10条（主要是保存寄存器和最后的 `bl` 调用）。

#### 2. 大量寄存器保存

统一解密器保存了大量寄存器到栈：
```
stp x7, x11, [sp, #-0x10]!
stp x30, x29, [sp, #-0x10]!
stp x25, x2, [sp, #-0x10]!
stp x15, x28, [sp, #-0x10]!
stp x19, x22, [sp, #-0x10]!
stp x1, x20, [sp, #-0x10]!
stp x0, x23, [sp, #-0x10]!
stp x16, x4, [sp, #-0x10]!
stp x12, x8, [sp, #-0x10]!
stp x14, x5, [sp, #-0x10]!
```

保存了 x0, x1, x4, x5, x7, x8, x11, x12, x14, x15, x16, x19, x20, x22, x23, x25, x28, x29, x30 等寄存器。

**为什么保存这么多寄存器？**
- 统一解密器会修改这些寄存器（执行解密逻辑）
- 解密完成后需要恢复这些寄存器，确保跳转到解密后的函数时寄存器状态正确
- 这是函数调用约定的要求（被调用者保存的寄存器必须恢复）

#### 3. 关键调用：bl #0x5a90278

在第40条指令处，有一个关键的函数调用：
```armasm
0x4b7e478: bl #0x5a90278
```

这个调用很可能是**真正的解密函数**。统一解密器前面做了大量混淆和寄存器保存，然后调用真正的解密子函数。

**0x5a90278 这个地址需要进一步分析**：
- 它在 payload 段范围内（0x030d83c0 ~ 0x05d6c000）
- 可能是另一个被混淆的函数
- 也可能是系统函数调用（通过 PLT）

## 3. 统一解密器的执行流程

### 推测的执行流程

基于反汇编结果和 T盾 的工作原理，统一解密器的执行流程推测如下：

```
统一解密器入口 (0x4b7e3c8)
    │
    ├─ 1. OLLVM混淆预热（大量无意义指令）
    │     - 对常量 0x1ab135ae 做各种混淆运算
    │     - 实际可能是在计算某个密钥或索引
    │
    ├─ 2. 保存所有寄存器到栈
    │     - stp x7, x11, ...
    │     - stp x30, x29, ...
    │     - ... (保存约20个寄存器)
    │
    ├─ 3. 从栈读取函数ID
    │     - 函数ID由 Stub 保存在 sp+8 位置
    │     - 但因为前面有大量 stp，栈指针已经变化
    │     - 需要计算函数ID在栈中的实际位置
    │
    ├─ 4. 根据函数ID查找加密函数代码
    │     - 查找映射表（函数ID → 加密代码地址/大小）
    │     - 映射表可能在 payload 段的固定位置
    │     - 也可能是通过算法计算地址
    │
    ├─ 5. 调用真正的解密函数 (bl #0x5a90278)
    │     - 传入参数：加密代码地址、大小、解密目标地址
    │     - 解密算法可能是 XOR、AES 或自定义算法
    │
    ├─ 6. 解密后处理
    │     - 刷新指令缓存（icache）
    │     - 设置内存为可执行（mprotect）
    │     - 可能设置原值守卫（检测代码是否被修改）
    │
    ├─ 7. 恢复所有寄存器
    │     - 从栈恢复之前保存的寄存器
    │     - 确保跳转到解密后的函数时寄存器状态正确
    │
    └─ 8. 跳转到解密后的函数执行
          - 可能是 br xN（间接跳转）
          - 也可能是修改返回地址后 ret
```

### 关键待分析点

| 待分析点 | 方法 | 重要性 |
|----------|------|--------|
| 函数ID在栈中的实际位置 | 动态跟踪（gdb单步） | 高 |
| 映射表的位置和结构 | 逆向解密函数 + 动态跟踪 | 高 |
| 解密算法（0x5a90278） | 反汇编 + 动态跟踪 | 高 |
| 解密后内存分配位置 | 动态跟踪（mmap/mprotect） | 中 |
| 跳转方式（br/ret） | 动态跟踪 | 中 |
| 是否有原值守卫 | 静态分析 + 动态验证 | 中 |

## 4. OLLVM 混淆分析

### 混淆类型识别

统一解密器使用了 OLLVM 的**指令替换（Instruction Substitution）**混淆：

#### 1. 恒等操作（Identity Operations）

这些操作的结果等于输入，没有实际意义：

```armasm
orr x13, x13, x13    ; x13 = x13 | x13 = x13（无操作）
neg w13, w13          ; w13 = -w13
neg x13, x13          ; x13 = -x13 = -(-w13) = w13（恢复原值）
rev x7, x13           ; x7 = 字节序反转(x13)
rev x11, x7           ; x11 = 字节序反转(x7) = x13（恢复原值）
eor x15, x11, x11     ; x15 = x11 ^ x11 = 0（结果为0）
```

#### 2. 等价变换（Equivalent Transformations）

这些操作虽然改变了中间值，但最终结果可以通过代数化简：

```armasm
ror w13, w13, w13     ; 循环右移，移位量是 w13 本身
ubfx x11, x7, #0, #0x20  ; 提取低32位（等于原值）
asr w25, w11, w13     ; 算术右移
orn w13, w7, w13      ; 或非：~(w7 | w13)
eon x13, x15, x7      ; 异或非：~(x15 ^ x7)
mvn w29, w11          ; 取反：~w11
bic x20, x29, x30     ; 位清除：x29 & ~x30
```

#### 3. 死代码（Dead Code）

这些指令的结果从未被使用：

```armasm
; 大量计算后，结果被后续指令覆盖或从未使用
lsl w30, w15, w0      ; w15=0（前面 eor x15,x11,x11），所以 w30=0
rev w30, w22           ; 反转0还是0
orn x1, x25, x0        ; 结果可能未被使用
```

### 去混淆方法

#### 方法一：符号执行（推荐）

用 angr/miasm/Triton 等符号执行工具，模拟执行混淆代码，自动化简表达式：

```python
# 伪代码
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

#### 方法二：模式匹配

针对常见的 OLLVM 混淆模式，写脚本识别和替换：

```python
# 伪代码
def deobfuscate(instructions):
    result = []
    i = 0
    while i < len(instructions):
        # 识别连续两次 neg（恢复原值）
        if (instructions[i].mnemonic == 'neg' and
            i+1 < len(instructions) and
            instructions[i+1].mnemonic == 'neg' and
            instructions[i].operands[0] == instructions[i+1].operands[0]):
            # 两次 neg = 无操作，跳过
            i += 2
            continue
        
        # 识别连续两次 rev（恢复原值）
        if (instructions[i].mnemonic == 'rev' and
            i+1 < len(instructions) and
            instructions[i+1].mnemonic == 'rev'):
            i += 2
            continue
        
        # 识别 orr x,x,x（无操作）
        if (instructions[i].mnemonic == 'orr' and
            len(instructions[i].operands) >= 3 and
            instructions[i].operands[0] == instructions[i].operands[1] == instructions[i].operands[2]):
            i += 1
            continue
        
        # 识别 eor x,x,x（结果为0）
        if (instructions[i].mnemonic == 'eor' and
            len(instructions[i].operands) >= 3 and
            instructions[i].operands[1] == instructions[i].operands[2]):
            # 结果为0，可以替换为 mov x, #0
            result.append(('mov', instructions[i].operands[0], 0))
            i += 1
            continue
        
        result.append(instructions[i])
        i += 1
    
    return result
```

#### 方法三：动态跟踪

在调试器中单步执行，记录每个指令执行后的寄存器状态，忽略无意义的混淆指令：

```gdb
# gdb 脚本
set pagination off
set logging on

break *0x4b7e3c8
commands
    silent
    # 单步执行，记录寄存器
    while $pc < 0x4b7e478
        stepi
        printf "PC=0x%lx x0=0x%lx x1=0x%lx x13=0x%lx\n", $pc, $x0, $x1, $x13
    end
    continue
end

run
```

## 5. 动态跟踪统一解密器

### gdb 动态跟踪方法

#### 1. 在解密器入口下断点

```gdb
# 连接到 Android 设备
target remote :1234

# 在统一解密器入口下断点
break *0x4b7e3c8

# 运行
continue
```

#### 2. 记录函数ID

当断点命中时，函数ID已经被 Stub 保存在栈上。需要找到函数ID在栈中的位置：

```gdb
# 查看栈指针
printf "SP = 0x%lx\n", $sp

# 查看栈内容（从 sp 开始，向前查看）
x/20gx $sp

# 函数ID可能在某个位置
# Stub 中是 str x13, [sp, #8]，但解密器开头有大量 stp，sp 已经变化
# 需要计算原始 sp 和当前 sp 的差值
```

#### 3. 单步跟踪到解密函数调用

```gdb
# 单步执行到 bl #0x5a90278
while $pc != 0x4b7e478
    stepi
end

# 查看调用参数（x0-x7）
printf "x0=0x%lx x1=0x%lx x2=0x%lx x3=0x%lx\n", $x0, $x1, $x2, $x3
printf "x4=0x%lx x5=0x%lx x6=0x%lx x7=0x%lx\n", $x4, $x5, $x6, $x7
```

#### 4. 在解密函数返回时下断点

```gdb
# 在 bl #0x5a90278 的下一条指令下断点
break *0x4b7e47c

continue

# 查看返回值（x0）
printf "解密函数返回: x0=0x%lx\n", $x0
# x0 可能是解密后的函数地址
```

#### 5. 验证解密后的代码

```gdb
# 查看解密后的内存
x/20i $x0

# 应该是正常的 ARM64 指令，而不是 Stub
```

### Frida hook 方法（需授权注入）

```javascript
// Frida 脚本：hook 统一解密器
const decryptorAddr = ptr("0x4b7e3c8");

Interceptor.attach(decryptorAddr, {
    onEnter: function(args) {
        // 读取栈上的函数ID
        // 需要根据实际栈布局计算偏移
        const sp = this.context.sp;
        const funcId = sp.add(0x??).readU32();  // 偏移需要动态确定
        console.log(`[Decryptor] funcId=0x${funcId.toString(16)}`);
        
        this.funcId = funcId;
    },
    onLeave: function(retval) {
        // retval 可能是解密后的函数地址
        console.log(`[Decryptor] funcId=0x${this.funcId.toString(16)} -> decrypted at ${retval}`);
        
        // dump 解密后的函数（前100字节）
        try {
            const code = retval.readByteArray(100);
            console.log(hexdump(code, { offset: 0, length: 100, header: true, ansi: true }));
        } catch(e) {
            console.log("  dump failed:", e);
        }
    }
});
```

## 6. 统一解密器的弱点

### 弱点1：所有函数共用一个解密器

**弱点**：所有函数 Stub 都跳转到同一个统一解密器地址。

**利用**：
- 只需要 hook 一个地址就能拦截所有函数的解密
- 可以批量收集所有解密后的函数
- 动态脱壳时只需要在一个地址下断点

### 弱点2：函数ID在栈上明文传递

**弱点**：Stub 把函数ID明文保存在栈上，统一解密器从栈上读取。

**利用**：
- 动态跟踪时可以直接从栈上读取函数ID
- 可以建立函数ID → 解密后地址的映射表
- 不需要逆向映射表就能知道每个函数ID对应哪个解密后的函数

### 弱点3：解密后代码在内存中明文

**弱点**：函数解密后，代码在内存中是明文的（可执行）。

**利用**：
- 动态内存 dump 可以直接获取解密后的代码
- 不需要逆向解密算法
- 这是动态脱壳最根本的基础

### 弱点4：OLLVM混淆可以被符号执行化简

**弱点**：统一解密器被 OLLVM 混淆，但混淆主要是指令替换，可以被符号执行工具自动化简。

**利用**：
- 用 angr/miasm 等工具可以自动去混淆
- 去混淆后可以理解真正的解密逻辑
- 为静态脱壳打下基础

### 弱点5：第一次调用才解密

**弱点**：函数级加密，每个函数第一次被调用时才解密。

**利用**（对保护方）：
- 减少了同时在内存中的明文代码量
- 增加了动态 dump 的难度（需要触发所有功能）

**弱点**（对攻击方）：
- 只要触发所有功能，所有函数都会被解密
- 可以用自动化工具（UI自动化、压力测试）触发所有功能
- 解密后的代码会保留在内存中（除非执行后重新加密）

## 7. 进一步分析建议

### 短期（动态分析）

1. **用 gdb 动态跟踪统一解密器**：
   - 在解密器入口下断点
   - 记录函数ID和参数
   - 单步跟踪到解密函数调用
   - 记录解密后的函数地址

2. **用 Frida hook 统一解密器**（需授权）：
   - 拦截所有函数的解密
   - 收集函数ID → 解密后地址的映射
   - dump 所有解密后的函数

3. **触发所有功能，收集所有解密函数**：
   - 手动操作所有功能菜单
   - 或用 UI 自动化工具
   - 确保所有函数都被调用和解密

### 中期（静态分析）

1. **逆向解密函数 0x5a90278**：
   - 反汇编这个函数
   - 识别解密算法（XOR/AES/自定义）
   - 提取密钥

2. **定位映射表**：
   - 跟踪解密函数的参数来源
   - 找到函数ID → 加密代码的映射表
   - 分析映射表结构

3. **写静态解密脚本**：
   - 复现解密算法
   - 批量解密所有函数
   - 替换 Stub 为真实函数

### 长期（完整脱壳）

1. **动态内存 dump**：
   - 触发所有功能
   - dump 所有可执行内存段
   - 修复 ELF 结构

2. **ELF 修复**：
   - 修复 ELF 头
   - 修复 Program Headers
   - 重建 Section Headers
   - 修复重定位和导入表

3. **验证**：
   - 反汇编验证
   - 字符串验证
   - 运行验证

详见 `references/10-unpacking-dynamic-dump.md` 和 `references/13-elf-repair.md`
