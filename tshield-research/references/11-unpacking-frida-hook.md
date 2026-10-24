# Frida Hook 脱壳（需授权注入）

## 1. 概述

Frida hook 统一解密器是一种主动脱壳方法。通过 hook 解密器，可以拦截每个函数的解密过程，收集解密后的代码。

**注意**：Frida 注入需要明确授权，仅用于合法的安全研究。

## 2. 原理

```
函数被调用 → Stub 跳转到统一解密器 → Frida hook 拦截
    ↓
记录函数ID和参数
    ↓
解密器执行解密
    ↓
Frida onLeave 拦截返回值
    ↓
记录解密后的函数地址和代码
    ↓
跳转到解密后的函数执行
```

## 3. 基本 Hook 脚本

### 3.1 Hook 统一解密器

```javascript
// tshield_unpack.js
// T盾 统一解密器 Hook 脱壳脚本

const decryptorAddr = ptr("0x4b7e3c8");  // 替换为实际地址
const outputDir = "/data/local/tmp/tshield_unpack/";

// 确保输出目录存在
const fs = require('fs');
try { fs.mkdirSync(outputDir, { recursive: true }); } catch(e) {}

let callCount = 0;
const decryptedFunctions = new Map();

Interceptor.attach(decryptorAddr, {
    onEnter: function(args) {
        callCount++;
        this.callId = callCount;
        
        // 读取函数ID（需要根据实际栈布局确定偏移）
        const sp = this.context.sp;
        // 尝试常见偏移
        this.funcId = 0;
        for (let offset = 0; offset < 0x200; offset += 8) {
            try {
                const val = sp.add(offset).readU64();
                // 函数ID特征：32位，高32位为0
                if (val > 0x10000 && val < 0xffffffff && (val >> 32) === 0) {
                    // 可能是函数ID，记录第一个匹配的
                    if (this.funcId === 0) {
                        this.funcId = val;
                        this.funcIdOffset = offset;
                    }
                }
            } catch(e) {}
        }
    },
    
    onLeave: function(retval) {
        const addr = retval;
        const funcId = this.funcId;
        
        if (funcId === 0) {
            return;
        }
        
        // 记录解密后的函数
        if (!decryptedFunctions.has(funcId)) {
            decryptedFunctions.set(funcId, {
                funcId: funcId,
                addr: addr.toString(),
                callCount: 1,
                firstCall: this.callId,
            });
            
            console.log(`[+] New function: ID=0x${funcId.toString(16)} addr=${addr} (call #${this.callId})`);
            
            // dump 解密后的函数（前256字节）
            try {
                const code = addr.readByteArray(256);
                const filename = `${outputDir}func_0x${funcId.toString(16)}.bin`;
                const file = new File(filename, "wb");
                file.write(code);
                file.flush();
                file.close();
            } catch(e) {
                console.log("  dump failed:", e);
            }
        } else {
            decryptedFunctions.get(funcId).callCount++;
        }
    }
});

// 定期输出统计
setInterval(function() {
    console.log(`\n[*] Stats: ${callCount} calls, ${decryptedFunctions.size} unique functions`);
}, 10000);

// 退出时输出完整映射表
process.on('detached', function() {
    console.log("\n=== Decrypted Functions Mapping ===");
    console.log("func_id,address,call_count");
    for (const [funcId, info] of decryptedFunctions) {
        console.log(`0x${funcId.toString(16)},${info.addr},${info.callCount}`);
    }
});

console.log("[+] T盾 Frida 脱壳脚本已启动");
console.log(`[+] 解密器地址: ${decryptorAddr}`);
console.log(`[+] 输出目录: ${outputDir}`);
```

### 3.2 使用方法

```bash
# 1. 启动 frida-server
adb shell su -c /data/local/tmp/frida-server &

# 2. 启动目标应用
# （手动启动或用 frida spawn）

# 3. 注入脚本
frida -U -n <process_name> -l tshield_unpack.js

# 或 spawn 模式（从启动开始跟踪）
frida -U -f <package_name> -l tshield_unpack.js --no-pause

# 4. 触发所有功能
# （手动操作应用）

# 5. 退出 Frida（Ctrl+C）
# 脚本会输出完整的函数映射表

# 6. 拉取 dump 的函数
adb pull /data/local/tmp/tshield_unpack/ ./unpacked/
```

## 4. 高级 Hook 技术

### 4.1 确定函数ID的栈偏移

函数ID的栈偏移需要动态确定。方法：

1. 在解密器入口下断点
2. 已知某个函数的函数ID（如入口点 0xb3062fe8）
3. 在栈中搜索这个值
4. 记录偏移

```javascript
// 自动确定函数ID偏移
let funcIdOffset = -1;
const knownFuncId = 0xb3062fe8;  // 入口点函数ID

Interceptor.attach(decryptorAddr, {
    onEnter: function(args) {
        const sp = this.context.sp;
        
        // 搜索已知函数ID
        if (funcIdOffset === -1) {
            for (let offset = 0; offset < 0x300; offset += 4) {
                try {
                    const val = sp.add(offset).readU32();
                    if (val === knownFuncId) {
                        funcIdOffset = offset;
                        console.log(`[+] funcId offset found: sp+${offset}`);
                        break;
                    }
                } catch(e) {}
            }
        }
        
        if (funcIdOffset !== -1) {
            this.funcId = sp.add(funcIdOffset).readU32();
        }
    },
    // ...
});
```

### 4.2 确定函数大小

函数大小不容易直接获取。方法：

1. **反汇编分析**：从函数开始反汇编，直到遇到函数序言（下一个函数的开始）
2. **映射表**：如果能定位映射表，从中读取大小
3. **固定大小**：dump 固定大小（如 4KB），足够覆盖大多数函数

### 4.3 批量 Dump 所有函数

```javascript
// 在所有函数都解密后，批量 dump
function dumpAllFunctions() {
    console.log("[*] Dumping all decrypted functions...");
    
    for (const [funcId, info] of decryptedFunctions) {
        try {
            const addr = ptr(info.addr);
            const code = addr.readByteArray(4096);  // dump 4KB
            const filename = `${outputDir}func_0x${funcId.toString(16)}_${info.addr}.bin`;
            const file = new File(filename, "wb");
            file.write(code);
            file.flush();
            file.close();
        } catch(e) {
            console.log(`  failed to dump 0x${funcId.toString(16)}: ${e}`);
        }
    }
    
    console.log("[+] All functions dumped");
}

// 可以通过 RPC 调用
rpc.exports = {
    dumpall: dumpAllFunctions,
    getstats: function() {
        return {
            calls: callCount,
            functions: decryptedFunctions.size,
        };
    }
};
```

## 5. 重建 ELF

收集所有解密后的函数后，需要重建 ELF 文件：

1. **获取原始 ELF 结构**：从原始文件复制 ELF 头和 Program Headers
2. **替换 Stub 为真实函数**：用解密后的代码替换 Stub
3. **修复入口点**：入口点应该是解密后的原始入口
4. **修复重定位**：确保地址引用正确
5. **验证**：用 IDA/Ghidra 加载验证

详见 `references/13-elf-repair.md`

## 6. 注意事项

### 6.1 反 Frida 检测

T盾 可能检测 Frida：
- 扫描 /proc/self/maps 中的 frida-agent.so
- 检测异常的内存映射
- 检测 ptrace

**绕过方法**：
- 使用 frida-server 的 stealth 模式
- 重命名 frida-agent.so
- 使用内核级隐藏
- 先绕过反调试（详见 14-anti-debug-and-bypass.md）

### 6.2 性能影响

Frida hook 会影响性能：
- 每次函数调用都会触发 hook
- 大量函数调用时可能导致卡顿
- 建议只在脱壳阶段使用，完成后移除

### 6.3 完整性

- 确保触发所有功能，否则有些函数不会被解密
- 多次运行对比，确保收集完整
- 未解密的函数需要用其他方法处理

## 7. 工具脚本

详见 `scripts/frida_hook_decryptor.js`，功能包括：
- 自动确定函数ID栈偏移
- Hook 统一解密器
- 收集解密后的函数
- 批量 dump 函数代码
- 生成函数映射表
- RPC 接口（dumpall/getstats）
