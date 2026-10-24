---
name: fakesign-driver-signing
description: FakeSign 驱动免签名工具 — 自签证书绕过 Windows 驱动签名强制(DSE)、Cloudflare Workers 时间戳服务器 Docker一键部署。覆盖 RFC-3161 时间戳伪造、SignTool Hook、WDAC 绕过、EV 证书内核签名、测试证书套件。红队作业中用于加载未签名内核驱动、绕过 EDR 内核回调。触发词：驱动签名、DSE绕过、self-sign、代码签名、测试证书、fakesign、内核驱动、rootkit、Windows签名。
version: 1.0.0
description_zh: 用于 fakesign-driver-signing 相关工作流。
description_en: Skill for fakesign-driver-signing workflows.
author: Xiaotao
---

# FakeSign — 驱动免签名工具

## 概述

FakeSign 是一个 **Windows 驱动签名绕过工具集**，用于在未获得 Microsoft 官方签名的情况下为驱动程序/内核模块/可执行文件创建"有效"的数字签名。核心原理是 **利用 EV(Extended Validation) 证书的 RFC-3161 时间戳特权 + 自签 CA 链**，骗过 Windows 的驱动签名强制(DSE)机制。

### 什么时候用

| 场景 | 用法 |
|------|------|
| **红队实战** | 签名 Rootkit/内核驱动, 绕过 DSE 加载 |
| **免杀对抗** | 签名恶意驱动, 绕过杀软/EDR 内核回调检测 |
| **漏洞利用** | 签名内核 exploit 驱动, 获取 Ring0 权限 |
| **持久化** | 签名启动级驱动, 实现开机自启 |
| **WDAC 绕过** | 结合 WDACTool 绕过 Windows Defender Application Control |

### 什么时候不用

| 场景 | 原因 |
|------|------|
| 用户态 EXE/DLL | 不需要驱动签名, 数字签名即可 |
| 生产环境 | 仅限已授权的渗透测试 |
| Linux/macOS | 本工具仅针对 Windows |

---

## 核心原理

```
Windows 驱动签名验证流程 (简化)

① Microsoft 签名驱动（CAT文件）
     └→ 受信任根证书 → ✅ 通过

② EV 证书签名驱动
     └→ 受信任根证书 + 时间戳在证书有效期内 → ✅ 通过

③ 自签证书签名驱动
     └→ 证书不在受信任根 → ❌ 拒绝

④ FakeSign 攻击链 ⚡
     ├── 步骤1: 自签 Root CA
     ├── 步骤2: 签发 Code Signing CA
     ├── 步骤3: 签发最终代码签名证书 + 设定证书有效期为特定时间段
     ├── 步骤4: 利用 EV 证书的时间戳服务器 → RFC-3161 时间戳回填
     └── 步骤5: 内核验证时间戳时发现 "签名在有效期内" → ✅ 通过！
```

**关键 trick**: Windows 内核驱动签名验证只看签名证书是否在签名时间有效，而**时间戳来自 EV 证书绑定**。FakeSign 用合法 EV 证书的公开时间戳服务器给自签证书打时间戳，让系统误以为"签名时证书有效"。

---

## 组件清单

```
/root/CyberStrikeAI-1.7.1/tools/fakesign/
├── DockerUI/              # 🐳 Docker 一键部署(本服务器可用)
│   ├── dockerfile          #   Python Flask + BouncyCastle
│   ├── app/AuthCode.py     #   授权码管理
│   ├── app/RFC-3161.py     #   RFC-3161 时间戳服务器核心
│   └── app/worker.py       #   Cloudflare Worker 请求处理
│
├── TimeSign/              # 🖥️ Windows 本地时间戳服务器
│   ├── RFC-3161.py         #   Python 实现
│   ├── AuthCode.py         #   授权验证
│   └── request.tsq         #   测试请求
│
├── TSWorker/              # ☁️ Cloudflare Workers 部署
│   ├── src/index.ts        #   Hono 框架 API
│   └── wrangler.toml       #   部署配置
│
├── SignTool/              # 🔧 SignTool Hook (C++)
│   ├── main.cpp            #   DLL 注入代码
│   ├── mssign32.h          #   签名 API 头文件
│   ├── signtool.exe        #   被 Hook 的原始 SignTool
│   └── TimeSignTool.exe    #   时间戳签名工具
│
├── WDACTool/              # 🛡️ WDAC 绕过工具
│
├── Releases/              # 📦 预编译二进制
│   ├── PikachuTestCert.exe #   测试证书一键安装器
│   ├── TimestampAllin1.zip #   时间戳全家桶(17.7MB)
│   ├── TimestampClient.zip #   时间戳客户端
│   └── TimestampServer.zip #   时间戳服务器(4.9MB)
│
└── docs/                  # 📚 完整中文文档(VitePress)
    └── zh/guide/
        ├── introduction.md #   项目介绍
        ├── quick-start.md  #   快速开始
        ├── principles.md   #   攻击原理详解
        ├── public-server.md #  公共服务
        ├── own-server.md   #   自建服务器
        ├── build-docker.md #   Docker 构建
        ├── deploy-tsw.md   #   CF Workers 部署
        ├── signtool-deploy.md # SignTool 部署
        ├── manual-key.md   #   手动签名步骤
        └── faq.md          #   常见问题
```

---

## 在渗透测试中的用法

### 场景1: 本服务器部署 Docker 时间戳服务

```bash
# 在本服务器上启动 FakeSign Docker 时间戳服务
cd /root/CyberStrikeAI-1.7.1/tools/fakesign/DockerUI
ALL_PROXY='' docker build -t fakesign-ts .
docker run -d -p 8080:8080 --name fakesign-ts fakesign-ts

# 验证
curl http://localhost:8080/
```

### 场景2: Windows 上签名驱动 (需要 Windows 环境)

```powershell
# 步骤1: 安装测试证书
.\PikachuTestCert.exe

# 步骤2: 生成自签代码证书
# (通过 Docker 时间戳服务或 Cloudflare Worker)

# 步骤3: 用 SignTool 签名驱动
signtool sign /fd SHA256 /a /tr http://YOUR-TS-SERVER:8080 /td SHA256 mydriver.sys

# 步骤4: 加载驱动
sc create MyDriver type=kernel binPath=C:\Windows\System32\drivers\mydriver.sys
sc start MyDriver
```

### 场景3: 利用公开时间戳服务

```
FakeSign 公共时间戳服务器:
├── https://ts.certimate.me          (推荐, 基于 CF Workers)
├── https://ts.certimate.me/api/v1/timestamp
├── https://timestamp.digicert.com   (DigiCert 官方 EV)
└── http://timestamp.sectigo.com     (Sectigo 官方 EV)
```

---

## 测试证书套件 (PikachuTestCert)

```
预装证书:
├── Pikachu Root CA           (根证书 → 受信任根证书颁发机构)
├── Pikachu EV Codesigning CA (代码签名中间 CA)
├── Pikachu Timestamp CA      (时间戳 CA)
├── Pikachu KEK CA            (安全启动 KEK CA)
├── Pikachu DB CA             (安全启动 DB CA)
├── Pikachu UEFI Codesigning  (UEFI 代码签名)
├── Pikachu Shim              (Shim 引导)
├── Pikachu MOK               (MOK 管理)
└── Pikachu Test Kernel       (测试内核 → 受信任发布者)
```

---

## 注意事项

1. **仅限已授权测试**: 在未授权系统上安装测试证书/加载未签名驱动属于违法行为
2. **测试模式**: Windows 需开启测试模式 (`bcdedit /set testsigning on`) 才能加载自签驱动
3. **安全启动**: Secure Boot 开启状态下需额外绕过 (UEFI CA 需写入 NVRAM)
4. **杀软检测**: 多数杀软会拦截自签证书的安装行为
5. **Docker 部署**: 本服务器可直接部署 Docker 时间戳服务供 Windows 客户端使用
