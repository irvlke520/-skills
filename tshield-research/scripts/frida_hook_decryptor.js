// T盾 统一解密器 Frida Hook 脱壳脚本
// 需授权注入，仅用于合法安全研究
//
// 功能：
// 1. 自动确定函数ID栈偏移
// 2. Hook 统一解密器，拦截每次函数解密
// 3. 收集解密后的函数地址和代码
// 4. 批量 dump 所有解密后的函数
// 5. 生成函数ID映射表
// 6. RPC 接口（dumpall/getstats/stop）
//
// 用法：
//   frida -U -n <process_name> -l frida_hook_decryptor.js
//   frida -U -f <package_name> -l frida_hook_decryptor.js --no-pause
//
// 配置：修改下面的 CONFIG 对象

'use strict';

// ============================================================
// 配置
// ============================================================

const CONFIG = {
    // 统一解密器地址（必须修改为实际地址）
    decryptorAddr: "0x4b7e3c8",

    // 已知函数ID（用于自动确定栈偏移，如入口点函数ID）
    knownFuncId: 0xb3062fe8,

    // 输出目录
    outputDir: "/data/local/tmp/tshield_unpack/",

    // 每个函数 dump 的最大字节数
    maxDumpSize: 4096,

    // 是否自动 dump 新发现的函数
    autoDump: true,

    // 是否打印详细日志
    verbose: false,
};

// ============================================================
// 全局状态
// ============================================================

let callCount = 0;
let funcIdOffset = -1;
const decryptedFunctions = new Map();
let hookEnabled = true;

// ============================================================
// 工具函数
// ============================================================

function ensureOutputDir() {
    try {
        // 尝试创建目录
        const file = new File(CONFIG.outputDir + ".test", "w");
        if (file) {
            file.close();
            try { new File(CONFIG.outputDir + ".test", "w").close(); } catch(e) {}
        }
    } catch(e) {
        // 目录可能已存在
    }
}

function hexdump(data, options) {
    // Frida 内置 hexdump
    return global.hexdump(data, options);
}

function dumpFunction(addr, funcId, size) {
    try {
        const code = ptr(addr).readByteArray(size);
        const filename = CONFIG.outputDir + "func_0x" + funcId.toString(16) + "_" + addr + ".bin";
        const file = new File(filename, "wb");
        file.write(code);
        file.flush();
        file.close();
        return true;
    } catch(e) {
        if (CONFIG.verbose) {
            console.log("  dump failed:", e);
        }
        return false;
    }
}

// ============================================================
// 自动确定函数ID栈偏移
// ============================================================

function findFuncIdOffset(sp) {
    if (funcIdOffset !== -1) {
        return funcIdOffset;
    }

    // 在栈中搜索已知函数ID
    for (let offset = 0; offset < 0x400; offset += 4) {
        try {
            const val = sp.add(offset).readU32();
            if (val === CONFIG.knownFuncId) {
                funcIdOffset = offset;
                console.log("[+] funcId offset found: sp+" + offset);
                return offset;
            }
        } catch(e) {}
    }

    return -1;
}

// ============================================================
// Hook 统一解密器
// ============================================================

function hookDecryptor() {
    const decryptorAddr = ptr(CONFIG.decryptorAddr);

    Interceptor.attach(decryptorAddr, {
        onEnter: function(args) {
            if (!hookEnabled) return;

            callCount++;
            this.callId = callCount;

            const sp = this.context.sp;
            this.sp = sp;

            // 确定函数ID偏移
            if (funcIdOffset === -1) {
                findFuncIdOffset(sp);
            }

            // 读取函数ID
            this.funcId = 0;
            if (funcIdOffset !== -1) {
                try {
                    this.funcId = sp.add(funcIdOffset).readU32();
                } catch(e) {}
            }

            if (CONFIG.verbose) {
                console.log("[Decryptor] #" + callCount +
                    " funcId=0x" + this.funcId.toString(16) +
                    " sp=" + sp);
            }
        },

        onLeave: function(retval) {
            if (!hookEnabled) return;

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
                    dumped: false,
                });

                console.log("[+] New function: ID=0x" + funcId.toString(16) +
                    " addr=" + addr + " (call #" + this.callId + ")");

                // 自动 dump
                if (CONFIG.autoDump) {
                    const dumped = dumpFunction(addr, funcId, CONFIG.maxDumpSize);
                    decryptedFunctions.get(funcId).dumped = dumped;
                }
            } else {
                decryptedFunctions.get(funcId).callCount++;
            }
        }
    });

    console.log("[+] Hook 已安装: " + decryptorAddr);
}

// ============================================================
// 批量 Dump
// ============================================================

function dumpAllFunctions() {
    console.log("[*] Dumping all " + decryptedFunctions.size + " functions...");

    let success = 0;
    let failed = 0;

    for (const [funcId, info] of decryptedFunctions) {
        const dumped = dumpFunction(info.addr, funcId, CONFIG.maxDumpSize);
        if (dumped) {
            info.dumped = true;
            success++;
        } else {
            failed++;
        }
    }

    console.log("[+] Dump complete: " + success + " success, " + failed + " failed");
    return { success: success, failed: failed, total: decryptedFunctions.size };
}

// ============================================================
// 生成映射表
// ============================================================

function generateMapping() {
    const mapping = [];
    for (const [funcId, info] of decryptedFunctions) {
        mapping.push({
            func_id: "0x" + funcId.toString(16),
            address: info.addr,
            call_count: info.callCount,
            first_call: info.firstCall,
            dumped: info.dumped,
        });
    }
    return mapping;
}

function saveMapping() {
    try {
        const mapping = generateMapping();
        const filename = CONFIG.outputDir + "function_mapping.json";
        const file = new File(filename, "w");
        file.write(JSON.stringify(mapping, null, 2));
        file.flush();
        file.close();
        console.log("[+] Mapping saved: " + filename);
        return true;
    } catch(e) {
        console.log("[-] Failed to save mapping:", e);
        return false;
    }
}

// ============================================================
// 统计信息
// ============================================================

function getStats() {
    return {
        total_calls: callCount,
        unique_functions: decryptedFunctions.size,
        func_id_offset: funcIdOffset,
        hook_enabled: hookEnabled,
        output_dir: CONFIG.outputDir,
    };
}

// ============================================================
// RPC 接口
// ============================================================

rpc.exports = {
    // 批量 dump 所有函数
    dumpall: function() {
        return dumpAllFunctions();
    },

    // 获取统计信息
    getstats: function() {
        return getStats();
    },

    // 获取函数映射表
    getmapping: function() {
        return generateMapping();
    },

    // 保存映射表到文件
    savemapping: function() {
        return saveMapping();
    },

    // 启用/禁用 hook
    sethook: function(enabled) {
        hookEnabled = enabled;
        return hookEnabled;
    },

    // dump 单个函数
    dumpfunc: function(funcId) {
        const info = decryptedFunctions.get(funcId);
        if (info) {
            return dumpFunction(info.addr, funcId, CONFIG.maxDumpSize);
        }
        return false;
    },
};

// ============================================================
// 定期输出统计
// ============================================================

setInterval(function() {
    const stats = getStats();
    console.log("\n[*] Stats: " + stats.total_calls + " calls, " +
        stats.unique_functions + " functions" +
        (hookEnabled ? "" : " (hook paused)"));
}, 15000);

// ============================================================
// 退出时保存
// ============================================================

process.on('detached', function() {
    console.log("\n=== T盾 Frida 脱壳完成 ===");
    const stats = getStats();
    console.log("总调用次数: " + stats.total_calls);
    console.log("唯一函数数: " + stats.unique_functions);
    console.log("函数ID偏移: sp+" + stats.func_id_offset);
    console.log("");

    // 保存映射表
    saveMapping();

    // 输出映射表
    console.log("=== Function ID Mapping ===");
    console.log("func_id,address,call_count");
    const mapping = generateMapping();
    for (const item of mapping) {
        console.log(item.func_id + "," + item.address + "," + item.call_count);
    }
});

// ============================================================
// 启动
// ============================================================

ensureOutputDir();
console.log("========================================");
console.log("  T盾 Frida Hook 脱壳脚本");
console.log("========================================");
console.log("[+] 解密器地址: " + CONFIG.decryptorAddr);
console.log("[+] 已知函数ID: 0x" + CONFIG.knownFuncId.toString(16));
console.log("[+] 输出目录: " + CONFIG.outputDir);
console.log("[+] 自动 dump: " + CONFIG.autoDump);
console.log("[+] 详细日志: " + CONFIG.verbose);
console.log("");

hookDecryptor();

console.log("[+] 脚本已启动，触发应用功能以解密函数...");
console.log("[+] 使用 RPC 接口:");
console.log("    script.exports.dumpall()   - 批量 dump");
console.log("    script.exports.getstats()  - 获取统计");
console.log("    script.exports.getmapping() - 获取映射表");
console.log("    script.exports.savemapping() - 保存映射表");
