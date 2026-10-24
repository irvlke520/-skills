# 统一解密器动态跟踪

## 1. 概述

动态跟踪统一解密器是理解 T盾 解密机制、定位映射表、收集解密后函数的关键方法。

## 2. gdb 动态跟踪

### 2.1 基本跟踪流程

```gdb
# 1. 连接到目标进程
target remote :1234

# 2. 在统一解密器入口下断点
break *0x4b7e3c8

# 3. 运行
continue
```

### 2.2 记录函数ID

当断点命中时，函数ID已经被 Stub 保存在栈上。需要找到函数ID在栈中的位置。

```gdb
# 查看栈指针
printf "SP = 0x%lx\n", $sp

# 查看栈内容（从 sp 开始，向前查看）
x/20gx $sp

# 函数ID可能在某个位置
# Stub 中是 str x13, [sp, #8]，但解密器开头有大量 stp，sp 已经变化
# 需要计算原始 sp 和当前 sp 的差值
```

### 2.3 自动跟踪脚本

```gdb
# tshield_trace.gdb
set pagination off
set logging on

# 定义断点命令
break *0x4b7e3c8
commands
    silent
    # 记录调用次数
    set $count = $count + 1
    
    # 查看栈（寻找函数ID）
    # printf "=== Decryptor call #%d ===\n", $count
    # printf "SP = 0x%lx\n", $sp
    # x/10gx $sp
    
    # 继续
    continue
end

# 在解密函数调用处下断点
break *0x4b7e478
commands
    silent
    # 查看参数（x0-x7）
    # printf "bl 0x5a90278: x0=0x%lx x1=0x%lx x2=0x%lx x3=0x%lx\n", $x0, $x1, $x2, $x3
    continue
end

# 在解密函数返回处下断点
break *0x4b7e47c
commands
    silent
    # 查看返回值（x0）
    # printf "decrypted addr = 0x%lx\n", $x0
    # 反汇编解密后的函数
    # x/10i $x0
    continue
end

# 初始化计数器
set $count = 0

# 运行
continue
```

### 2.4 单步跟踪解密过程

```gdb
# 在统一解密器入口下断点
break *0x4b7e3c8
continue

# 命中断点后，单步执行
stepi
# 记录每条指令的寄存器变化
# 特别关注：
# - 函数ID从哪里读取
# - 映射表地址在哪里
# - 解密算法的关键步骤

# 单步到 bl #0x5a90278
# 然后进入解密函数
stepi
# 单步跟踪解密函数
```

## 3. Frida 动态跟踪（需授权注入）

### 3.1 Hook 统一解密器

```javascript
// tshield_trace.js
const decryptorAddr = ptr("0x4b7e3c8");

let callCount = 0;
const funcIdMap = {};

Interceptor.attach(decryptorAddr, {
    onEnter: function(args) {
        callCount++;
        this.callId = callCount;
        
        // 读取栈上的函数ID（需要确定偏移）
        const sp = this.context.sp;
        // 尝试不同的偏移
        for (let offset = 0; offset < 0x100; offset += 8) {
            const val = sp.add(offset).readU64();
            // 函数ID通常是 0x???????? 形式（32位）
            if ((val >> 32) === 0 && val !== 0) {
                // 可能是函数ID
            }
        }
        
        console.log(`[Decryptor] call #${callCount}`);
    },
    onLeave: function(retval) {
        // retval 可能是解密后的函数地址
        const decryptedAddr = retval;
        console.log(`[Decryptor] #${this.callId} -> decrypted at ${decryptedAddr}`);
        
        // dump 解密后的函数（前64字节）
        try {
            const code = decryptedAddr.readByteArray(64);
            console.log(hexdump(code, { offset: 0, length: 64, header: false, ansi: false }));
        } catch(e) {
            console.log("  dump failed:", e);
        }
    }
});

console.log("[+] T盾 解密器跟踪已启动");
```

### 3.2 收集所有解密函数

```javascript
// collect_all_functions.js
const decryptorAddr = ptr("0x4b7e3c8");
const decryptedFunctions = {};

Interceptor.attach(decryptorAddr, {
    onEnter: function(args) {
        // 记录函数ID（需要确定栈偏移）
        this.sp = this.context.sp;
    },
    onLeave: function(retval) {
        const addr = retval.toString();
        if (!decryptedFunctions[addr]) {
            decryptedFunctions[addr] = {
                addr: addr,
                size: 0,  // 需要另外确定大小
                count: 1,
            };
            console.log(`[+] New function: ${addr}`);
        } else {
            decryptedFunctions[addr].count++;
        }
    }
});

// 定期输出统计
setInterval(function() {
    console.log(`\n[*] Decrypted functions: ${Object.keys(decryptedFunctions).length}`);
}, 5000);

// 退出时输出完整列表
process.on('detached', function() {
    console.log("\n=== Decrypted Functions ===");
    for (const addr in decryptedFunctions) {
        console.log(`${addr} (called ${decryptedFunctions[addr].count} times)`);
    }
});
```

## 4. 关键观察点

### 4.1 函数ID的位置

- Stub 把函数ID保存在 `sp+8`
- 但统一解密器开头有大量 `stp` 指令，sp 会变化
- 需要计算：原始 sp - 当前 sp = 所有 stp 保存的总大小
- 函数ID的实际位置 = 当前 sp + 原始偏移 + stp 总大小

### 4.2 映射表的访问

- 统一解密器会根据函数ID查找映射表
- 观察内存读取指令（ldr）
- 如果读取的地址在 payload 段内，可能就是映射表

### 4.3 解密后的内存分配

- 解密后的代码写到哪里？
- 观察内存写入指令（str）
- 如果写入的地址在解密后代码段（0x15dc3c0-0x30d8000），就是正确的
- 可能是 mmap 分配的新内存

### 4.4 跳转方式

- 解密完成后，如何跳转到解密后的函数？
- 可能是 `br xN`（间接跳转）
- 也可能是修改返回地址后 `ret`
- 观察解密器末尾的指令

## 5. 跟踪技巧

### 5.1 减少干扰

- 只跟踪前 N 次调用，避免日志过多
- 只记录特定函数ID的调用
- 使用条件断点

```gdb
# 条件断点：只在特定函数ID时中断
break *0x4b7e3c8 if $count == 1
```

### 5.2 硬件断点

- 如果软件断点被检测到，使用硬件断点
- `hbreak *0x4b7e3c8`

### 5.3 对比分析

- 跟踪两个不同函数的解密过程
- 对比哪些步骤相同，哪些不同
- 相同的步骤是解密器框架，不同的步骤是函数特定的

## 6. 输出与记录

### 6.1 记录格式

```
=== Decryptor Call #1 ===
函数ID: 0xb3062fe8
映射表条目: 0x???????
加密代码地址: 0x???????
加密代码大小: ???
解密后地址: 0x15dc???
解密后大小: ???
耗时: ??? 指令
```

### 6.2 批量收集

- 触发所有功能
- 记录每次解密调用
- 建立函数ID → 解密后地址的完整映射表
- 用于后续的 ELF 重建

## 7. 工具脚本

详见 `scripts/decryptor_trace.py`，功能包括：
- 生成 gdb 跟踪脚本
- 生成 Frida 跟踪脚本
- 解析跟踪日志，建立函数ID映射表
- 统计解密调用次数
