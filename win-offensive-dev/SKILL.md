---
name: win-offensive-dev
description: Windows 攻击性安全开发完整知识库 — 涵盖 shellcode 加载、进程注入、API 哈希/IAT 隐藏、syscall 存根、NTDLL unhooking、sleep 混淆、反射加载、BOF、ETW/AMSI 绕过、持久化机制、C2 植入物、Token 操纵、横向移动、UAC 绕过等。当用户讨论 shellcode、注入、免杀、loader、syscall、PEB walk、API hash、IAT hiding、process hollowing、APC injection、fiber/callback execution、PPID spoofing、persistence、C2/implant/beacon、token/impersonation、UAC bypass、lateral movement、免杀/权限维持/横向移动/提权 时自动触发。
version: 2.1.0
source: 信益安信息安全研究院 | XinYiAn Security Research Institute
description_zh: 用于 win-offensive-dev 相关工作流。
description_en: Skill for win-offensive-dev workflows.
author: Xiaotao
---

# Windows 攻击性安全开发 (Windows Offensive Development)

> 信益安信息安全研究院出品 | XinYiAn Security Research Institute

完整的 Windows 红队工具开发知识库，涵盖 C/C++ 和 Rust 实现。所有技术均包含自包含实现、OPSEC 评级和检测分析。

---

## 工作流

### 1. 理解需求
根据用户需求识别所需技术类别 — 使用下方的**决策树**处理复杂请求。

### 2. 选择技术
读取 `references/` 中对应的参考文件获取实现细节。检查每个技术中的 **OPSEC 元数据**以匹配操作环境。

### 3. 应用组合模式
对于实战工具，组合多种技术。参见**技术组合模式**获取已验证的组合方案。

### 4. 生成代码
- **C/C++** (主要): MSVC 兼容代码，使用 `windows.h`, `winternl.h`, `tlhelp32.h`
- **Rust** (次要): 使用 `windows-sys` crate 配合 `unsafe` FFI 块
- 默认对敏感 API 应用 IAT 隐藏
- 使用随机密钥 XOR/AES/ChaCha20 加密嵌入载荷
- 参考**构建模板**获取编译器/链接器标志

### 5. 生成 README
每次批量生成 loader/工具后，在输出目录创建 `README.md` 总结技术组合、OPSEC 档案和检测面。

---

## 决策树

### Q1: 攻击链阶段？
- **初始访问/执行** → `references/execution.md`
- **防御规避** → `references/defense_evasion.md`, `references/memory_evasion.md`
- **持久化** → `references/persistence.md`
- **权限提升** → `references/token_privilege.md`
- **凭证访问** → `references/credential_access.md`
- **横向移动** → `references/lateral_movement.md`
- **发现/枚举** → `references/enumeration.md`
- **命令与控制** → `references/networking.md`

### Q2: 是否需要管理员权限？
- **是** → Service persistence, HKLM keys, IFEO, Scheduled Task (SYSTEM), NTDLL unhooking from disk
- **否** → HKCU Run, COM Hijacking, DLL Sideloading, Scheduled Task (User), fiber/callback execution

### Q3: 目标是否有 EDR？
- **是 (重度)** → Indirect syscalls + NTDLL unhooking + Sleep obfuscation + ETW bypass + HBP hooks + Stack spoofing
- **是 (轻度)** → IAT hiding + Indirect syscalls + ETW bypass
- **否** → 标准 API 调用配合 IAT hiding 即可

### Q4: 执行类型？
- **仅本地** → Fiber / Callback (CertEnumSystemStore, EnumFontsW, EnumSystemGeoID) / Mapping Injection / Phantom DLL Hollowing / Thread Pool (TP_WORK)
- **远程注入** → Threadless Injection / PoolParty / Dirty Vanity / Phantom DLL Remote
- **无文件** → Reflective DLL / BOF / CLR hosting → `references/reflective_loading.md`
- **分阶段(Staged)** → Stager (networking) → Download → Decrypt → Execute

### Q5: 持久化机制？
- **无需管理员, 隐蔽** → COM CLSID hijacking (HKCU)
- **无需管理员, 简单** → HKCU Run key
- **管理员, 事件驱动** → WMI Event Subscription / Service with device trigger
- **管理员, 简单** → Scheduled Task (SYSTEM) / HKLM Run

---

## 技术组合模式

### 模式 1: 隐蔽远程 Loader (EDR 环境)
```
IAT Hiding (Djb2 constexpr) → Indirect Syscalls (HellsHall)
→ ETW Bypass (HBP patchless) → PPID Spoofing → Block DLL Policy
→ Early Bird APC Injection → Sleep Obfuscation (Ekko)
```
- 所有 API 通过 hash 解析，无可疑 IAT
- Syscalls 绕过用户态 hook，注入前静默 ETW
- 目标进程伪装为 explorer.exe 子进程
- 休眠期间内存加密

### 模式 2: OPSEC 安全持久化
```
COM CLSID Hijacking (HKCU) → Proxy DLL (export forwarding)
→ AES-encrypted shellcode in .rsrc → HBP ETW bypass
→ Anti-debug + Anti-VM → Callback execution (no CreateThread)
```
- 无需管理员 (HKCU 注册表)
- Proxy DLL 保持原始 COM 功能
- 环境验证通过后才解密载荷
- 无线程创建痕迹

### 模式 3: 无文件植入物
```
HTTP/S Stager (WinHTTP) → Download encrypted payload
→ Reflective DLL Injection (manual mapping) → In-memory execution
→ Named Pipe C2 → PE Fluctuation during sleep
```
- 无磁盘写入
- 网络流量伪装合法 HTTPS
- DLL 通过手动 PE 解析完全在内存中加载
- 休眠期间加密内存中的整个映像

### 模式 4: 权限提升链
```
Enumerate privileges → UAC Bypass (Fodhelper/COM Elevation)
→ Enable SeDebugPrivilege → Token stealing (SYSTEM)
→ Impersonate → Execute privileged operation
```
- 根据 Windows 版本自动选择 UAC bypass
- SeDebugPrivilege 允许访问 LSASS 及其他受保护进程
- 从 winlogon.exe 或 lsass.exe 窃取 SYSTEM token

### 模式 5: 横向移动套件
```
Enumerate network (shares, sessions) → Token impersonation
→ WMI remote exec OR PsExec (SCM) → Deploy stager
→ Remote host calls back to C2
```
- 发现阶段识别活跃目标
- 多种执行方法增加灵活性
- Stager 在远程主机引导完整植入物

### 模式 6: 凭证获取
```
ETW bypass → AMSI bypass → Enable SeDebugPrivilege
→ LSASS handle duplication (avoid direct OpenProcess)
→ MiniDumpWriteDump to memory → Encrypt dump → Exfil via C2
```
- 避免直接 OpenProcess LSASS 防止 Sysmon Event ID 10
- Dump 保留在内存中，不落盘
- 网络传输前加密

### 模式 7: 单文件嵌入 (Enhanced)
```
Read .bin → Generate random key → AES/XOR/ChaCha20 encrypt
→ Embed as array in source → Anti-debug guard
→ IAT hiding for all APIs → Decrypt at runtime → Execute
→ Post-execution cleanup (wipe key/payload or self-unmap)
```
- 独立 .exe，零外部依赖
- **暴力破解变体**: 部分密钥 + CRC32 校验 = 反沙箱 + 反静态分析
- 反分析检查在解密前执行
- 所有敏感 API 动态解析
- 执行后清理擦除内存中的解密痕迹

### 模式 8: EDR 杀手/致盲
```
ETW Session Hijacking → AMSI bypass (HBP)
→ NTDLL unhooking (KnownDlls) → Kernel callback removal (BYOVD)
→ Minifilter disable
```
- 渐进式方法: 先用户态，必要时内核态
- 基于 HBP 的补丁不留内存修改痕迹
- NTDLL unhooking 恢复干净 syscall stubs

### 模式 9: EDR 实测最优组合 (基于 edr_profiles)
```
XOR encryption (runtime key derivation) → UUID string array encoding
→ PEB walk + DJB2 hash → Indirect syscall memory ops
→ CreateThreadpoolWait callback execution → Legitimate version info (RC resource)
```
- 已验证: 对火绒 100% 绕过率 (2026-05-07)
- 零 IAT 导入 (完全空的导入表)
- 零明文字符串 (所有 API 名通过 hash 解析)
- UUID 编码降低熵值至 ~4.7 (远低于 6.5 阈值)
- Thread pool wait callback 避免 CreateThread/NtCreateThreadEx 遥测
- Nt 级内存操作绕过 kernel32 用户态 hook
- 参考 `edr_profiles/` 获取目标 EDR 特定优化

---

## 技术专题索引

### Shellcode 加载与执行
- 本地执行: Fiber, Callback (CertEnumSystemStore/EnumFontsW/EnumSystemGeoID), Mapping Injection, Phantom DLL Hollowing, Thread Pool (TP_WORK), CreateThreadpoolWait (TpAllocWait+TpSetWait) ★
- 远程注入: Threadless Injection, PoolParty, Dirty Vanity
- 载荷加密: XOR, RC4, AES (BCrypt), ChaCha20 (Pure C), XOR Brute-Force, ChaCha20 Brute-Force
- 载荷编码: UUID string array, IPv4 string array, MAC address array
- 执行后清理: None, Memory Wipe, Self-Unmap
- **参考**: `references/execution.md`

### API 解析与 IAT 隐藏
- PEB walk (自定义 GetModuleHandle)
- 导出表遍历 (自定义 GetProcAddress)
- Hash 算法: Djb2, CRC32, JenkinsOneAtATime
- 编译时常量 hashing
- Stack strings, XOR-encrypted strings, dispatch tables
- API Set Schema 解析
- **参考**: `references/iat_hiding.md`

### Syscalls 与 Hook 规避
- Indirect syscalls (HellsHall + Halo's Gate + RecycledGate)
- HWSyscalls (HWBP + kernel32 trampoline)
- LayeredSyscall (VEH-based)
- Call Stack Spoofing (Fortra HWBP)
- NTDLL Fresh Copy (KnownDlls)
- NTDLL unhooking (disk, KnownDlls, suspended process)
- **参考**: `references/syscalls.md`

### 进程操纵
- Process hollowing, ghost injection, herpaderping
- Threadless injection, module stomping/overloading
- PPID spoofing, argument spoofing, Block DLL policy
- **参考**: `references/process_manipulation.md`

### 内存逃逸
- Sleep obfuscation: Ekko, Zilean, Foliage
- PE fluctuation, heap encryption
- Stack spoofing, anti-debugging, anti-VM
- **参考**: `references/memory_evasion.md`

### 防御规避
- ETW bypass (byte patching, HBP patchless, session hijacking)
- AMSI bypass (byte patching, HBP patchless)
- Binary metadata modification, entropy reduction
- CRT removal, IAT camouflage
- **参考**: `references/defense_evasion.md`

### 凭证访问
- LSASS dumping (MiniDump, handle duplication, SilentProcessExit)
- SAM dumping (local, remote, from disk)
- Browser credential extraction (Chrome/Firefox cookies & passwords)
- Keylogging
- **参考**: `references/credential_access.md`

### 持久化机制
- Registry: Run/RunOnce, Active Setup, IFEO, Winlogon, AppInit_DLLs
- Task Scheduler (COM API), WMI Event Subscriptions
- COM CLSID hijacking, Windows Services, DLL sideloading
- **参考**: `references/persistence.md`

### C2 通信与网络
- HTTP/HTTPS callbacks (WinHTTP)
- DNS tunneling, Named Pipe C2, SMB C2
- Raw TCP/UDP, domain fronting, traffic shaping
- Sleep jitter, data encoding/chunking
- **参考**: `references/networking.md`

### 反射加载与内存执行
- Reflective DLL injection, sRDI
- Manual PE mapping, .NET CLR hosting
- BOF (Beacon Object File) loader
- Transacted Hollowing
- **参考**: `references/reflective_loading.md`

### Token 操纵与权限提升
- Token stealing, impersonation, privilege enabling
- UAC Bypass: Fodhelper, CMSTP, COM Elevation Moniker, Event Viewer
- Named pipe impersonation, Potato family overview
- **参考**: `references/token_privilege.md`

### 横向移动
- WMI remote exec, PsExec (SCM), DCOM
- WinRM, remote scheduled tasks
- SMB + SCM combo, Pass-the-Hash/Ticket overview
- **参考**: `references/lateral_movement.md`

### 主机与网络枚举
- Process, network connection, user/group enumeration
- Domain discovery (LDAP), installed software/patches
- AV/EDR detection, network share enumeration
- **参考**: `references/enumeration.md`

---

## OPSEC 快速参考

| 技术 | OPSEC | 主要检测 |
|------|-------|----------|
| Fiber/Callback execution | 🟢 Low | Minimal telemetry |
| Mapping injection (NtCreateSection) | 🟢 Low | No VirtualAlloc pattern |
| Phantom DLL Hollowing | 🟢 Low | File-backed MEM_IMAGE |
| Thread Pool (TP_WORK) | 🟢 Low | Legitimate pool mechanism |
| CreateThreadpoolWait (TP_WAIT) | 🟢 Low | Waitable timer callback, bypassed Huorong |
| UUID/IPv4/MAC payload encoding | 🟢 Low | Low entropy (~4.7), no byte pattern match |
| Threadless injection | 🟢 Low | No thread creation |
| PoolParty | 🟢 Low | Thread pool internals |
| Dirty Vanity (fork) | 🟢 Low | No cross-process write |
| Indirect syscalls (HellsHall) | 🟢 Low | Return address in ntdll |
| HWSyscalls | 🟢 Low | Legitimate call stack |
| ETW/AMSI HBP bypass | 🟢 Low | Zero memory patches |
| NTDLL unhooking | 🟡 Medium | File I/O on ntdll.dll |
| Sleep obfuscation (Ekko) | 🟢 Low | Timer queue artifacts |
| ETW bypass (byte patch) | 🟡 Medium | Integrity check detects |
| Process hollowing | 🔴 High | Sysmon 1+25, ETW-TI |
| COM hijacking | 🟢 Low | Registry change only |
| Reflective DLL | 🟡 Medium | PE header in memory |
| Token stealing | 🟡 Medium | Sysmon 10, event 4624 |
| LSASS dump (direct) | 🔴 High | Sysmon 10, PPL blocks |
| LSASS dump (handle dup) | 🟡 Medium | NtDuplicateObject hook |

---

## 构建模板

### C/C++ (MSVC) — Release Build
```bat
:: Minimal size, no CRT, no stack cookies
cl /O2 /Os /GS- /MT /GL /DNDEBUG loader.c /link /ENTRY:main /NODEFAULTLIB /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF /MERGE:.rdata=.text
:: With CRT (when needed)
cl /O2 /MT /GL /DNDEBUG loader.c /link /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF
:: DLL build
cl /O2 /GS- /MT /GL /DNDEBUG /LD proxy.c /link /ENTRY:DllMain /NODEFAULTLIB /DEF:exports.def
```

### C/C++ (MinGW) — Cross-compile
```bash
x86_64-w64-mingw32-gcc -O2 -s -nostdlib -e main -o loader.exe loader.c -lkernel32 -lntdll
```

### Rust — Cargo.toml Release Profile
```toml
[profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
strip = true           # Strip symbols
panic = "abort"        # No unwinding overhead
codegen-units = 1      # Better optimization
```

---

## 代码规范

### C/C++ 约定
```c
// Type definitions for dynamically resolved APIs
typedef BOOL(WINAPI* tCreateProcessA)(LPCSTR,LPSTR,...);
// PEB walk
HMODULE hK32 = PebMod(HASH_KERNEL32);
// Export walk
auto fCPA = (tCreateProcessA)ProcH(hK32, djb2c("CreateProcessA"));
```

### Rust 约定
```rust
// FFI type alias
type CPA = unsafe extern "system" fn(*const u8, *mut u8, ...) -> i32;
// Resolve via export walk or GetProcAddress
let f: CPA = std::mem::transmute(proc_djb2(base, djb2(b"CreateProcessA")));
```

### OPSEC 元数据格式 (参考文件中)
每个技术段包含:
```
> OPSEC: 🟢 Low / 🟡 Medium / 🔴 High
> Sysmon: [相关 Event IDs]
> ETW: [provider 名称]
> EDR Hooks: [被 hook 的 NT 函数]
> Signature: [检测模式]
> Mitigation: [如何降低检测]
```

---

## Loader 生成硬性约束 (malfuzz)

所有生成的 loader 必须满足:
- IAT: 仅 3-6 个无害导入函数
- 零明文字符串 (使用 stack strings 或 XOR 加密)
- 所有敏感 API 通过 PEB walk + hash 动态解析
- 内存 RW→RX 分离 (不使用 RWX)
- 无 CRT 依赖 (`/ENTRY:main /NODEFAULTLIB`)
- Shannon 熵值 < 6.5

## 技术组合维度

每个 loader 从以下 9 个维度随机选取技术:

| 维度 | 可选项 |
|------|--------|
| 加密 | XOR, RC4, AES, ChaCha20, XOR-BF, ChaCha20-BF |
| 执行 | Fiber, CertEnumSystemStore, EnumFontsW, EnumSystemGeoID, Mapping, Phantom DLL, TP_WORK, TP_WAIT |
| API解析 | Djb2 hash, CRC32, Jenkins |
| 字符串 | Stack strings, XOR encrypted |
| 防御规避 | ETW HBP, AMSI HBP, Both, None |
| 反分析 | 从 10+ 检查中随机选 3-4 个 |
| 熵值降低 | 英文填充, 字典填充, None |
| 载荷编码 | UUID, IPv4, MAC, Raw |
| 执行后清理 | None, Memory Wipe, Self-Unmap |

---

## EDR 检测特征收集方法

1. 使用不同技术组合生成 loader (malfuzz)
2. 在目标 EDR 环境测试每个 loader
3. 记录哪些组合被检测、哪些绕过
4. 分析检测模式共性
5. 更新 `edr_profiles/<edr_name>/profile.md`
6. 后续生成时通过 `target:<edr_name>` 自动参考知识库

## 沙箱指纹收集方法

VBS 脚本收集以下维度并通过 temp.sh 回传:
- 系统身份 (计算机名, 用户名, 域, OS, MachineGuid, BIOS)
- 硬件 (CPU, RAM, 磁盘, 屏幕分辨率)
- 网络 (MAC, IP)
- 环境 (时区, 运行时间, 进程列表)
- 用户活动指标 (Recent files, Desktop files, 常见程序)
- 已安装软件

## VirusTotal 分析流程

- VT API v3 集成: 上传 → 等待分析完成 → 读取检测结果
- VT Tag → 源码修复映射 (如 `detect-debug-environment` → 减少反调试检查)
- 基于检测率的优化策略:
  - 0/70 = 完美! 记录到 EDR profile
  - 1-5/70 = 微调: 增加 junk code + 改 timing + 增 padding
  - 6-15/70 = 中度: 换执行方式 + 换加密 + 增加编码层
  - 16-30/70 = 重度: 换 brute-force 加密 + polymorphism + self-unmap
  - 30+/70 = 重构: 完全重新生成

---

## 与其他技能的协作

本技能是 Windows 免杀开发的主知识库，建议配合以下技能:
- **av-evasion** — AV 静态/动态/行为/内存免杀综合技术
- **amsi-bypass** — PowerShell/.NET/脚本 AMSI 绕过
- **string-obfuscation** — XOR/AES/RC4 字符串混淆
- **syscall-techniques** — 直接系统调用绕过 EDR hook
- **process-injection** — 远程线程/APC/Process Hollowing 注入
- **sandbox-detection** — 沙箱环境检测与规避
- **ai-av-evasion** — AI 生成免杀 Loader 和 Shellcode 处理
- **phishing-kb** — 钓鱼基础设施与免杀交付

## 参考文件结构

```
win-offensive-dev/
├── SKILL.md                    # 本文件 - 主技能
├── references/                 # 15 个技术参考文件
│   ├── execution.md            # Shellcode 加载与执行技术
│   ├── iat_hiding.md           # API 解析与 IAT 隐藏
│   ├── syscalls.md             # Syscall 与 Hook 规避
│   ├── process_manipulation.md # 进程操纵
│   ├── memory_evasion.md       # 内存逃逸
│   ├── defense_evasion.md      # 防御规避 (ETW/AMSI)
│   ├── credential_access.md    # 凭证访问
│   ├── persistence.md          # 持久化机制
│   ├── networking.md           # C2 通信与网络
│   ├── reflective_loading.md   # 反射加载
│   ├── token_privilege.md      # Token 操纵与提权
│   ├── lateral_movement.md     # 横向移动
│   ├── enumeration.md          # 主机与网络枚举
│   ├── malfuzz.md              # /malfuzz 技术池与模板
│   └── reverse_analysis.md     # /reverse 分析流程
├── edr_profiles/               # EDR 检测特征知识库
│   ├── README.md
│   └── huorong/profile.md
└── sandbox_profiles/           # 沙箱环境指纹
```

---

> 信益安信息安全研究院出品 | XinYiAn Security Research Institute
