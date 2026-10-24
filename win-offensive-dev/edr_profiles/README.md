# EDR Detection Knowledge Base

## 概览

| EDR | 测试次数 | 最近测试 | 平均绕过率 | 有效技术 |
|-----|----------|----------|------------|----------|
| 火绒 (Huorong) | 1 | 2026-05-07 | 100% | ThreadpoolWait + XOR + UUID + Nt syscall |

## 通用有效技术 (跨 EDR)

| 技术维度 | 推荐 | 原因 |
|----------|------|------|
| 执行 | CreateThreadpoolWait | 非传统线程创建，多数 EDR 未 hook |
| 内存 | NtAllocateVirtualMemory + NtProtectVirtualMemory | 绕过 kernel32 用户态 hook |
| 编码 | UUID 字符串数组 | 熵值 ~4.7，避免高熵检测 |
| 加密 | XOR (运行时派生密钥) | 无密钥泄露，简单高效 |
| API解析 | PEB walk + DJB2 | 零 IAT，零字符串 |
| 伪装 | 合法版本信息 (RC 资源) | 降低静态可疑度 |

---
> 信益安信息安全研究院出品 | XinYiAn Security Research Institute
