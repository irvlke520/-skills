# 236skills — AI 安全技能库（311 个技能）

一个面向 AI 助手（Skill 格式）的安全/红队技能合集。每个技能是一个独立目录，内含 `SKILL.md`（YAML frontmatter + 方法论、payload、命令、排错、关联技能链）。

覆盖：漏洞狩猎、红队渗透、逆向工程、CTF、信息收集、报告撰写。所有技能描述里焊入了**中文触发词**——用中文说话即可命中，不用记英文技能名。

> 索引文件 `_中文索引.md` 里写的是「236 个」，这是旧版本数量；当前目录实际共 **311 个技能** + 索引文件。

---

## 目录结构

```
236skills/
├── <技能名>/SKILL.md        # 每个技能一个目录
├── _中文索引.md              # 中文技能总索引（分类 + 触发词）
├── _文件清单.txt             # 全部文件清单
└── _MERGE-MANIFEST.tsv       # 合并清单
```

## 快速开始

- **直接说中文**：「帮我挖 SQL 注入」「过一下 WAF」「分析这个 APK」
- **强制指定**：「用 `hunt-sqli` 这个技能」
- **不知道该用哪个**：说「用 `bb-methodology`」或「用 `bug-bounty`」，它们会按阶段自动路由

## 分类概览

| 类别 | 代表技能 |
|---|---|
| 核心（打网站/进后台/拿数据） | `hunt-auth-bypass` `hunt-idor` `api-noauth-hunt` `hunt-ato` `jwt-attack` |
| 常见站点系统 | `hunt-wordpress` `wp-plugin-cve-hunt` `hunt-firebase` `hunt-supabase` |
| 漏洞挖掘 | `hunt-sqli` `hunt-xss` `hunt-ssrf` `hunt-rce` `hunt-xxe` `hunt-ssti` `hunt-deserialization` `hunt-graphql` 等 70+ |
| 信息收集 | `recon-playbook` `web2-recon` `subdomain-enumeration` `offensive-osint` `js-secrets-extraction` |
| 免杀/内网/提权 | `offensive-edr-evasion` `offensive-c2-frameworks` `offensive-windows-privesc` `offensive-active-directory` `offensive-lateral-movement` |
| 报告与验证 | `triage-validation` `report-writing` `evidence-hygiene` `redteam-report-template` |
| 逆向工程 | `reverse-engineering` `ghidra-reverse` `ida-reverse` `rev-frida` `apk-reverse` `dotnet-reverse` |
| CTF | `ctf-web` `ctf-pwn` `ctf-crypto` `ctf-reverse` `ctf-forensics` `ctf-misc` 等 |
| 漏洞赏金 | `bb-methodology` `bug-bounty` `bugcrowd-reporting` `triage-validation` |

## 技能格式

每个 `SKILL.md` 的结构：

```markdown
---
name: hunt-sqli
description: 中文触发：SQL 注入、注入、报错注入、盲注 ｜ ...
tags: [sql, injection, hunt, redteam]
---

## When to Use
## Attack Surface Signals
## Step-by-Step Hunting Methodology
## Payload & Detection Patterns
## Pitfalls
## Related Skills & Chains
```

## 在 AI 助手中使用

- **DeepSeek Harness（DSH）**：把技能目录放到 `~/.dsh/skills/`（全局技能根，所有会话可见）。
- **Claude Code 等**：放到 `~/.agents/skills/`（需在 agent 配置中开启默认技能根扫描）。
- 技能加载器扫描 `SKILL.md` 的 frontmatter（`name` 必须为 ASCII 且与目录名一致）。

## 免责声明

本仓库仅用于**授权范围内的**安全测试、CTF 竞赛、红队演练与安全研究。禁止用于任何未授权的攻击行为。使用者需自行确保测试行为符合当地法律法规与目标方的书面授权。
