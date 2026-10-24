# /reverse — Malware Analysis & Enhancement

## Command Syntax

```
/reverse <exe路径|文件夹路径>
```

- 单个 EXE：直接分析
- 文件夹：扫描所有 .exe 文件逐个分析

---

## Analysis Pipeline

```
Phase 1: Static Analysis
    strings64 (ASCII + Unicode 双趟) + sigcheck64 (CSV) + PE IAT 解析
    ↓
Phase 2: Dynamic Analysis
    Procmon64 (行为监控) + Listdlls64 (DLL 枚举) + handle64 (句柄) + pipelist64 (管道)
    ↓
Phase 2.5: Persistence Check
    autorunsc64 执行前后 diff
    ↓
Phase 3: Report Generation
    per-EXE markdown 报告
    ↓
Phase 4: Auto-Enhancement Plan
    detection → fix 映射, 自动修复建议
```

---

## Phase 1: Static Analysis

### Tool: strings64.exe — 字符串提取

分 ASCII 和 Unicode 两趟扫描，带文件偏移定位。

```powershell
# Pass 1: ASCII 字符串 + 文件偏移
$asciiStrings = & .\SysinternalsSuite\strings64.exe -accepteula -a -n 4 -o -nobanner $targetExe
# Pass 2: Unicode 字符串 + 文件偏移
$unicodeStrings = & .\SysinternalsSuite\strings64.exe -accepteula -u -n 4 -o -nobanner $targetExe
```

**参数说明:**
| Flag | 作用 |
|------|------|
| `-accepteula` | 跳过首次 EULA 弹窗 (自动化必需) |
| `-a` | 仅 ASCII 字符串 |
| `-u` | 仅 Unicode 字符串 |
| `-n 4` | 最短 4 字符 |
| `-o` | 显示文件偏移 (定位字符串在哪个 PE section) |
| `-nobanner` | 无版权横幅 |

**检测规则:**
| 发现 | 严重性 | 含义 |
|------|--------|------|
| API 函数名 (VirtualAlloc, CreateThread 等) | ❌ Critical | 明文 API 字符串泄露 |
| DLL 名 (ntdll.dll, kernel32.dll) | ❌ Critical | 模块名未加密 |
| URL / IP / 域名 | ❌ Critical | C2 指标明文暴露 |
| 注册表路径 | ⚠️ Warning | 持久化指标 |
| 文件路径 (C:\, %APPDATA%) | ⚠️ Warning | 文件系统活动指标 |
| 恶意关键词 (inject, hook, payload, shellcode) | ❌ Critical | 关键词检测 |
| Base64 模式 (==$, 长字母数字串) | ⚠️ Warning | 编码数据指标 |

**敏感 API 监控列表:**
```
VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx,
WriteProcessMemory, ReadProcessMemory, CreateRemoteThread,
NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory,
NtCreateThreadEx, NtQueueApcThread, NtTestAlert, NtCreateSection,
NtMapViewOfSection, OpenProcess, CreateProcess, QueueUserAPC,
SetThreadContext, GetThreadContext, ResumeThread, SuspendThread,
LoadLibrary, GetProcAddress, CreateFiber, SwitchToFiber,
ConvertThreadToFiber, EtwEventWrite, AmsiScanBuffer,
AddVectoredExceptionHandler, TpAllocWait, TpSetWait
```

**偏移值分析 (利用 -o 输出):**
- 偏移在 .text section 范围内: 字符串嵌入代码段 — 可能是 stack string 残留
- 偏移在 .rdata section 范围内: 只读数据 — 编译器放置的常量
- 偏移在 .data section 范围内: 可写数据 — 运行时使用的字符串

### Tool: sigcheck64.exe — 签名/熵值/版本信息

```powershell
# 标准分析 (人工阅读)
& .\SysinternalsSuite\sigcheck64.exe -accepteula -a -h -i -nobanner $targetExe

# CSV 格式 (自动化解析)
$sigInfo = & .\SysinternalsSuite\sigcheck64.exe -accepteula -a -h -c -nobanner $targetExe | ConvertFrom-Csv
```

**参数说明:**
| Flag | 作用 |
|------|------|
| `-accepteula` | 跳过 EULA |
| `-a` | 扩展版本信息 + 熵值 (bits per byte) |
| `-h` | 显示文件 hash (MD5, SHA1, SHA256) |
| `-i` | 显示签名目录和签名链 |
| `-c` | CSV 输出 (逗号分隔, 配合 ConvertFrom-Csv 自动解析) |
| `-nobanner` | 无横幅 |

**关键字段检查:**
| 字段 | 检查 | 通过标准 |
|------|------|----------|
| Verified | 签名状态 | "Signed" (如果使用了 sign 选项) |
| Entropy | Shannon 熵值 | < 6.5 |
| Publisher | 证书发行者 | 存在且合理 (如果 sign) |
| Description | 文件描述 | 存在且看起来合法 |
| File version | 版本号 | 存在 |
| Product | 产品名 | 存在 |
| Company | 公司名 | 存在 |
| MD5/SHA256 | Hash | 记录用于追踪 |

### PE IAT 分析 — PowerShell 自动解析

无需 dumpbin (不依赖 Visual Studio), 直接读取 PE 结构:

```powershell
function Parse-PeImports {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $br = New-Object System.IO.BinaryReader(New-Object System.IO.MemoryStream(,$bytes))

    # DOS Header → e_lfanew
    $br.BaseStream.Position = 0x3C
    $e_lfanew = $br.ReadInt32()

    # NT Headers → OptionalHeader
    $br.BaseStream.Position = $e_lfanew + 4  # skip Signature
    $machine = $br.ReadUInt16()
    $numSections = $br.ReadUInt16()
    $br.BaseStream.Position += 12  # skip rest of FILE_HEADER
    $optHeaderSize = $br.ReadUInt16()
    $br.BaseStream.Position += 2  # skip Characteristics

    # Determine PE32 vs PE64
    $optStart = $br.BaseStream.Position
    $magic = $br.ReadUInt16()
    $is64 = ($magic -eq 0x20B)

    # DataDirectory[1] = Import Directory
    if ($is64) {
        $br.BaseStream.Position = $optStart + 120  # offset to ImportTable in PE64
    } else {
        $br.BaseStream.Position = $optStart + 104  # offset to ImportTable in PE32
    }
    $importRVA = $br.ReadUInt32()
    $importSize = $br.ReadUInt32()

    if ($importRVA -eq 0) {
        return @{ TotalImports = 0; DLLs = @() }
    }

    # Read section headers to convert RVA → file offset
    $br.BaseStream.Position = $optStart + $optHeaderSize
    $sections = @()
    for ($i = 0; $i -lt $numSections; $i++) {
        $name = [System.Text.Encoding]::ASCII.GetString($br.ReadBytes(8)).TrimEnd("`0")
        $virtualSize = $br.ReadUInt32()
        $virtualAddr = $br.ReadUInt32()
        $rawSize = $br.ReadUInt32()
        $rawOffset = $br.ReadUInt32()
        $br.BaseStream.Position += 16  # skip remaining fields
        $sections += @{ Name=$name; VA=$virtualAddr; RawSize=$rawSize; RawOffset=$rawOffset; VSize=$virtualSize }
    }

    function RVA-ToOffset($rva) {
        foreach ($s in $sections) {
            if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) {
                return $rva - $s.VA + $s.RawOffset
            }
        }
        return $rva
    }

    function Read-AsciiString($offset) {
        $br.BaseStream.Position = $offset
        $sb = New-Object System.Text.StringBuilder
        while ($true) {
            $b = $br.ReadByte()
            if ($b -eq 0) { break }
            [void]$sb.Append([char]$b)
        }
        return $sb.ToString()
    }

    # Parse IMAGE_IMPORT_DESCRIPTOR array
    $importOffset = RVA-ToOffset $importRVA
    $dlls = @()
    $totalFuncs = 0

    $br.BaseStream.Position = $importOffset
    while ($true) {
        $origFirstThunk = $br.ReadUInt32()  # OriginalFirstThunk (INT)
        $timeDateStamp = $br.ReadUInt32()
        $forwarderChain = $br.ReadUInt32()
        $nameRVA = $br.ReadUInt32()
        $firstThunk = $br.ReadUInt32()      # FirstThunk (IAT)

        if ($nameRVA -eq 0) { break }  # end of array

        $dllName = Read-AsciiString (RVA-ToOffset $nameRVA)
        $functions = @()

        # Read INT entries
        $intRVA = if ($origFirstThunk -ne 0) { $origFirstThunk } else { $firstThunk }
        $intOffset = RVA-ToOffset $intRVA
        $br.BaseStream.Position = $intOffset

        while ($true) {
            if ($is64) { $entry = $br.ReadUInt64() } else { $entry = $br.ReadUInt32() }
            if ($entry -eq 0) { break }

            $isOrdinal = if ($is64) { ($entry -band 0x8000000000000000) -ne 0 } else { ($entry -band 0x80000000) -ne 0 }
            if ($isOrdinal) {
                $ordinal = $entry -band 0xFFFF
                $functions += "Ordinal #$ordinal"
            } else {
                $hintNameRVA = [uint32]($entry -band 0x7FFFFFFF)
                $hintNameOffset = RVA-ToOffset $hintNameRVA
                $funcName = Read-AsciiString ($hintNameOffset + 2)  # skip Hint (2 bytes)
                $functions += $funcName
            }
            $savedPos = $br.BaseStream.Position
            $br.BaseStream.Position = $savedPos
        }

        $totalFuncs += $functions.Count
        $dlls += @{ DLL = $dllName; Functions = $functions }

        # Restore position to next IMAGE_IMPORT_DESCRIPTOR
        $importOffset += 20  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
        $br.BaseStream.Position = $importOffset
    }

    $br.Close()
    return @{ TotalImports = $totalFuncs; DLLs = $dlls }
}

# 使用:
# $imports = Parse-PeImports -Path $targetExe
# $imports.TotalImports  → 导入函数总数
# $imports.DLLs          → @{ DLL="kernel32.dll"; Functions=@("GetSystemTimeAsFileTime",...) }
```

**IAT 允许列表:**
```
GetSystemTimeAsFileTime, QueryPerformanceCounter, GetCurrentProcessId,
GetCurrentThreadId, IsProcessorFeaturePresent, GetStartupInfoW
```

**检查逻辑:**
- 导入函数总数: ✅ 3-6 个 / ❌ > 6 或 < 3
- 所有函数在允许列表中: ✅ / ❌ 有非允许函数
- 导入 DLL 数量: ✅ 仅 kernel32.dll / ⚠️ 多个 DLL

### Section 熵值计算

```powershell
function Get-SectionEntropy {
    param([byte[]]$Data)
    $freq = @{}
    foreach ($b in $Data) {
        if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
    }
    $entropy = 0.0
    $len = $Data.Length
    foreach ($count in $freq.Values) {
        $p = [double]$count / $len
        if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
    }
    return [Math]::Round($entropy, 3)
}

# 对每个 PE section 分别计算熵值
# .text:  预期 6.0-6.8 (编译代码)
# .rdata: 预期 < 6.0 (如果有熵值填充)
# .data:  预期 < 5.0
# .rsrc:  预期 < 5.0 (资源)
# 整体:   必须 < 6.5
```

---

## Phase 2: Dynamic Analysis

### Tool: Procmon64.exe — 行为监控 (自动化)

**重要**: Procmon 的 /BackingFile 和 /SaveAs 必须使用**绝对路径**。

```powershell
# Step 0: 解析绝对路径 (CRITICAL)
$outputDir = (Resolve-Path $targetDir).Path
$pmlFile = Join-Path $outputDir "procmon_capture.pml"
$csvFile = Join-Path $outputDir "procmon_capture.csv"
$exeName = [System.IO.Path]::GetFileName($targetExe)

# Step 1: 启动 Procmon (无 filter — 后续 CSV 中过滤)
& .\SysinternalsSuite\Procmon64.exe /Quiet /Minimized /BackingFile $pmlFile /AcceptEula

# Step 2: 等待 Procmon 初始化
Start-Sleep -Seconds 3

# Step 3: 运行目标 EXE
$proc = Start-Process -FilePath $targetExe -PassThru

# Step 4: 等待执行完成
Start-Sleep -Seconds 8

# Step 5: 终止目标进程
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

# Step 6: 停止 Procmon 监控实例
& .\SysinternalsSuite\Procmon64.exe /Terminate
Start-Sleep -Seconds 3

# Step 7: 导出 PML → CSV (新 Procmon 进程)
& .\SysinternalsSuite\Procmon64.exe /OpenLog $pmlFile /SaveAs $csvFile /AcceptEula
Start-Sleep -Seconds 5

# Step 8: 用 PowerShell 过滤 CSV (替代 PMC binary filter)
$allEvents = Import-Csv $csvFile
$targetEvents = $allEvents | Where-Object { $_."Process Name" -eq $exeName }
```

**注意事项:**
- **不使用 /LoadConfig PMC filter** — PMC 是二进制格式, 不能用 XML 生成
- 改为 CSV 导出后用 PowerShell `Where-Object` 按进程名过滤
- `/Terminate` 停止监控实例, 然后新进程 `/OpenLog` + `/SaveAs` 转换格式
- 两步之间需要 3s 等待确保 PML 文件写入完毕

**事件分类分析:**

```powershell
# 注册表活动
$regEvents = $targetEvents | Where-Object { $_.Operation -match "Reg" }
$regWrites = $regEvents | Where-Object { $_.Operation -match "RegSetValue|RegCreateKey" }

# 文件活动
$fileEvents = $targetEvents | Where-Object { $_.Operation -match "CreateFile|WriteFile|ReadFile" }
$fileWrites = $fileEvents | Where-Object { $_.Operation -match "WriteFile" }

# 网络活动
$netEvents = $targetEvents | Where-Object { $_.Operation -match "TCP|UDP|Connect|Send|Recv" }

# 进程活动
$procEvents = $targetEvents | Where-Object { $_.Operation -match "Process Create|Thread Create" }
```

| 类别 | 操作 | 可疑条件 |
|------|------|----------|
| Registry | RegSetValue, RegCreateKey | 写入 Run/IFEO/COM 键 |
| File | WriteFile, CreateFile | 写入 %TEMP%、释放文件 |
| Network | TCP Connect, UDP Send | 任何出站连接 |
| Process | Process Create, Thread Create | 创建子进程 |
| Memory | VirtualProtect (调用栈中) | RW→RX 转换 (预期但需记录) |

### Tool: Listdlls64.exe — DLL 枚举

在目标进程运行期间捕获已加载的 DLL 列表:

```powershell
# 启动目标后立即运行 (在 Procmon 监控期间)
$proc = Start-Process -FilePath $targetExe -PassThru
Start-Sleep -Seconds 2

# 捕获已加载 DLL
$dllList = & .\SysinternalsSuite\Listdlls64.exe -accepteula $proc.Id 2>&1 | Out-String

# 解析输出: 每行包含 DLL 路径和是否签名
# 标记异常:
# - 非 System32 目录的 DLL
# - 未签名的 DLL (如果 Listdlls 支持 -u flag)
# - 非预期的 DLL (如 winhttp.dll 在 local-only loader 中)
```

**检测规则:**
| 发现 | 严重性 | 含义 |
|------|--------|------|
| 仅 ntdll + kernel32 | ✅ Pass | 最小 DLL 依赖 |
| 加载 user32/gdi32/crypt32 | ⚠️ Info | 对应 callback 执行方式, 预期行为 |
| 加载 winhttp/wininet | ⚠️ Warning | 网络通信 (staged loader 预期) |
| 加载未签名 DLL | ❌ Fail | 可能注入或加载恶意模块 |
| 从非 System32 加载 DLL | ❌ Fail | DLL 劫持或侧载 |

### Tool: handle64.exe — 句柄枚举

```powershell
# 在目标运行期间捕获打开的句柄
$handles = & .\SysinternalsSuite\handle64.exe -accepteula -p $proc.Id -nobanner 2>&1 | Out-String
```

**检测规则:**
| 发现 | 严重性 | 含义 |
|------|--------|------|
| 仅标准句柄 (File, Event, Key) | ✅ Pass | 正常 |
| Process 句柄指向其他进程 | ❌ Critical | 跨进程操作 (注入指标) |
| Section 句柄 | ⚠️ Info | Mapping injection 使用 Section 对象 |
| 大量 Registry Key 句柄 | ⚠️ Warning | 可能进行注册表枚举 |

### Tool: pipelist64.exe — 命名管道枚举

```powershell
# 执行前快照
$pipesBefore = & .\SysinternalsSuite\pipelist64.exe -accepteula -nobanner 2>&1 | Out-String

# 启动目标, 等待执行
Start-Sleep -Seconds 5

# 执行后快照
$pipesAfter = & .\SysinternalsSuite\pipelist64.exe -accepteula -nobanner 2>&1 | Out-String

# Diff: 新增的管道
$newPipes = Compare-Object ($pipesBefore -split "`n") ($pipesAfter -split "`n") |
    Where-Object { $_.SideIndicator -eq "=>" } |
    Select-Object -ExpandProperty InputObject
```

**检测规则:**
| 发现 | 严重性 | 含义 |
|------|--------|------|
| 无新增管道 | ✅ Pass | 无 IPC 通道 |
| 新增命名管道 | ⚠️ Warning | 可能是 C2 通道 (Named Pipe C2) |
| 管道名匹配已知 C2 模式 | ❌ Critical | 已知恶意 IPC |

---

## Phase 2.5: Persistence Check

### Tool: autorunsc64.exe — 自启动项对比

```powershell
# 执行前基线
$autorunsBefore = & .\SysinternalsSuite\autorunsc64.exe -accepteula -a * -c -nobanner -h 2>&1 |
    Out-String

# [... 运行目标 EXE ...]

# 执行后扫描
$autorunsAfter = & .\SysinternalsSuite\autorunsc64.exe -accepteula -a * -c -nobanner -h 2>&1 |
    Out-String

# Diff
$beforeLines = ($autorunsBefore -split "`n") | Sort-Object
$afterLines = ($autorunsAfter -split "`n") | Sort-Object
$newEntries = Compare-Object $beforeLines $afterLines |
    Where-Object { $_.SideIndicator -eq "=>" } |
    Select-Object -ExpandProperty InputObject
```

**autorunsc 参数:**
| Flag | 作用 |
|------|------|
| `-a *` | 扫描所有自启动类型 (boot, logon, explorer, DLL, services, tasks, WMI, Winlogon 等) |
| `-c` | CSV 输出 |
| `-h` | 包含文件 hash |
| `-nobanner` | 无横幅 |

**自启动类型覆盖 (-a * 包含):**
- `b` Boot execute
- `d` AppInit DLLs
- `e` Explorer 插件
- `h` Image hijacks (IFEO)
- `k` Known DLLs
- `l` Logon startups (Run/RunOnce)
- `m` WMI entries
- `o` Office addins
- `s` Services + drivers
- `t` Scheduled tasks
- `w` Winlogon entries

**检测规则:**
| 发现 | 严重性 | 含义 |
|------|--------|------|
| 无新增自启动项 | ✅ Pass | 无持久化 |
| 新增 Run/RunOnce 键 | ❌ Critical | 注册表持久化 |
| 新增 Scheduled Task | ❌ Critical | 计划任务持久化 |
| 新增 Service | ❌ Critical | 服务持久化 |
| 新增 COM CLSID | ⚠️ Warning | COM 劫持 (可能是预期) |
| 新增 WMI Subscription | ❌ Critical | WMI 事件持久化 |
| 新增 IFEO | ❌ Critical | Image File Execution Options 劫持 |

---

## Phase 3: Report Format

### Per-EXE Report Template

```markdown
# Analysis: [filename]

## Static Analysis

### Strings (strings64)
- **ASCII 敏感字符串**: [count] 个
- **Unicode 敏感字符串**: [count] 个
- **详情**: [list flagged strings with section offsets]
- **判定**: ✅ PASS / ❌ FAIL

### Signature & Entropy (sigcheck64)
- **签名**: Yes/No [预期: Yes (如果 sign)]
- **熵值**: [value] [✅ < 6.5 / ❌ >= 6.5]
- **发行者**: [value or N/A]
- **文件描述**: [value or N/A]
- **产品名**: [value or N/A]
- **公司名**: [value or N/A]
- **MD5**: [hash]
- **SHA256**: [hash]

### Import Table (PE IAT)
- **导入总数**: [count] [✅ 3-6 / ❌ otherwise]
- **导入 DLL**: [list]
- **导入函数**: [list]
- **标记**: [any non-allowlist imports]
- **判定**: ✅ PASS / ❌ FAIL

### Section Entropy
| Section | Size | Entropy | 判定 |
|---------|------|---------|------|
| .text | [size] | [val] | ✅/⚠️ |
| .rdata | [size] | [val] | ✅/⚠️ |
| .data | [size] | [val] | ✅/⚠️ |
| .rsrc | [size] | [val] | ✅/⚠️ |

## Dynamic Analysis

### Procmon 行为监控
- **注册表操作**: [list or "None ✅"]
- **文件操作**: [list or "None ✅"]
- **网络活动**: [list or "None ✅"]
- **进程操作**: [list — calc.exe expected ✅]
- **内存操作**: [VirtualProtect RW→RX — expected ⚠️]

### DLL 加载分析 (Listdlls64)
- **加载 DLL 总数**: [count]
- **详情**: [list with paths]
- **异常 DLL**: [any unexpected modules]
- **判定**: ✅ PASS / ⚠️ WARNING / ❌ FAIL

### 句柄分析 (handle64)
- **标准句柄**: [count] 个
- **跨进程句柄**: [count] 个 [✅ 0 / ❌ > 0]
- **Section 句柄**: [count] 个
- **判定**: ✅ PASS / ❌ FAIL

### 命名管道 (pipelist64)
- **新增管道**: [list or "None ✅"]
- **判定**: ✅ PASS / ⚠️ WARNING

### 持久化扫描 (autorunsc64)
- **新增自启动项**: [list or "None ✅"]
- **判定**: ✅ PASS / ❌ FAIL

## Risk Score: [LOW / MEDIUM / HIGH]

## Improvement Suggestions
- [specific actionable suggestions based on findings]

---
> 信益安信息安全研究院出品 | XinYiAn Security Research Institute
```

---

## Phase 4: Auto-Enhancement Rules

### Detection → Fix Mapping

| 检测项 | 根因 | 修复方案 |
|--------|------|----------|
| strings: 明文 API 名 | 字符串未加密 | 改用 stack strings 或 XOR 加密字符串 |
| strings: 明文 DLL 名 | 模块名字面量 | 使用 stack string 构建 DLL 名 |
| 熵值 > 6.5 | 加密 payload 随机性高 | 添加英文填充段 (~4KB) |
| 熵值 > 7.0 | 无熵值降低措施 | 添加文本填充 + 字典数组 |
| IAT 含 VirtualAlloc | API 未隐藏 | 改用 PEB walk + hash 解析 |
| IAT > 6 个导入 | 静态导入过多 | 移除多余, 动态解析 |
| Procmon: RegSetValue Run 键 | 持久化痕迹 | 移除或改用 COM 劫持 |
| Procmon: 网络连接 | C2 回调可见 | staged loader 预期, 标注 |
| Procmon: 文件写入 | 磁盘痕迹 | 改为纯内存执行 |
| sigcheck: 未签名 (预期签名) | 签名掠夺失败 | 重试不同源 EXE |
| .text entropy > 7.5 | 代码段包含加密 blob | 确保代码是编译代码, payload 在 .data |
| **Listdlls: 非预期 DLL** | 运行时加载多余模块 | 检查执行方式是否需要该 DLL |
| **Listdlls: 未签名 DLL** | 注入或加载恶意模块 | 排查来源 |
| **handle: 跨进程句柄** | 远程注入痕迹 | local-only loader 不应有 |
| **autorunsc: 新增自启动** | 持久化代码 | 移除或标注预期行为 |
| **pipelist: 新增管道** | IPC/C2 通道 | 标注预期行为 (C2 loader) |

### Auto-Plan Generation

分析完成后自动生成修复方案:
1. 列出所有 ❌ FAIL 项
2. 每项映射到上表的具体修复方案
3. 评估修复对检测面的影响
4. 进入 plan mode 展示代码修改建议
5. 用户确认 → 修改代码 → 重新编译 → 再次分析

---

## Sysinternals Tool Paths

所有工具位于: `.\SysinternalsSuite\`

| 工具 | 路径 | 用途 | 阶段 |
|------|------|------|------|
| strings64.exe | `.\SysinternalsSuite\strings64.exe` | 字符串提取 (ASCII + Unicode) | Phase 1 |
| sigcheck64.exe | `.\SysinternalsSuite\sigcheck64.exe` | 签名 + 熵值 + 版本信息 | Phase 1 |
| Procmon64.exe | `.\SysinternalsSuite\Procmon64.exe` | 运行时行为监控 | Phase 2 |
| Listdlls64.exe | `.\SysinternalsSuite\Listdlls64.exe` | DLL 枚举 | Phase 2 |
| handle64.exe | `.\SysinternalsSuite\handle64.exe` | 句柄枚举 | Phase 2 |
| pipelist64.exe | `.\SysinternalsSuite\pipelist64.exe` | 命名管道枚举 | Phase 2 |
| autorunsc64.exe | `.\SysinternalsSuite\autorunsc64.exe` | 自启动项扫描 | Phase 2.5 |
| procexp64.exe | `.\SysinternalsSuite\procexp64.exe` | 进程检查 (手动) | Manual |

---

## Quick Reference: Expected Good Results

一个合格的 loader 应产生:
- **strings64**: 0 敏感字符串 (仅英文填充可见)
- **sigcheck64**: 熵值 < 6.5, 有效版本信息 (如果 sign)
- **IAT**: 3-6 个良性导入 (仅 kernel32.dll)
- **Procmon**: 仅 VirtualProtect RW→RX + calc.exe 子进程 (测试 payload)
- **Listdlls**: 仅 ntdll.dll + kernel32.dll (+ 执行方式依赖的 DLL)
- **handle64**: 无跨进程句柄
- **pipelist**: 无新增命名管道
- **autorunsc**: 无新增自启动项
- **无注册表写入, 无文件释放, 无网络连接**
