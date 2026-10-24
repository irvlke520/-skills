# EDR Profile: 火绒 (Huorong)

## 测试历史

### 2026-05-07 — /malfuzz 测试结果

**环境**: Windows 11 Pro 10.0.28000
**总计**: 1 个 loader 测试
**绕过**: 1 个未被检测 (100%)
**Shellcode**: agent.x64.bin (103,423 bytes, AdaptixC2 agent)

#### 未被检测的 loader:

| # | 执行方式 | 加密 | 编码 | API解析 | 内存操作 | 伪装 | 语言 |
|---|----------|------|------|---------|----------|------|------|
| 01 | CreateThreadpoolWait (TpAllocWait+TpSetWait) | XOR-16 (运行时密钥派生) | UUID字符串数组 | PEB walk + DJB2 hash | NtAllocateVirtualMemory + NtProtectVirtualMemory (RW→RX) | SecurityHealthService 版本信息 | C |

#### 被检测的 loader:

无

#### 检测特征分析:

- **绕过共性**:
  - 零 IAT 导入 (完全空导入表)
  - 零敏感字符串 (全部 hash 化)
  - Nt 级内存操作 (绕过 kernel32 hook)
  - 线程池回调执行 (非 CreateThread/CreateRemoteThread)
  - UUID 编码降低熵值 (4.714)
  - 合法版本信息伪装
  - 无 CRT 依赖

- **检测共性**: N/A (首次测试)

- **推测检测规则**:
  - 火绒对 CreateThreadpoolWait 回调执行无检测
  - 火绒对 NtAllocateVirtualMemory + NtProtectVirtualMemory 组合无行为拦截
  - 火绒对空 IAT + 合法版本信息的 PE 无静态标记
  - 火绒对 UUID 编码的 shellcode 存储无熵值检测

---
> 信益安信息安全研究院出品 | XinYiAn Security Research Institute
