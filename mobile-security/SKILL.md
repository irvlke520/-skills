---
name: "mobile-security"
description: "分析移动应用的权限、组件、存储、通信和崩溃安全问题，包括有明确问题的游戏构建。按证据选择静态或动态验证；普通文件结构识别优先使用格式专项。"
description_zh: "围绕具体问题分析移动应用权限、组件、数据与崩溃。"
description_en: "Assess specific mobile application security questions using artifacts and bounded validation."
version: "1.1.0"
author: "Xiaotao"
---

# 移动应用安全分析

本技能面向具体问题，例如导出组件如何被调用、敏感数据流向哪里、某次崩溃是否由状态不同步引起。游戏属于可分析的应用类别；不要仅因它是游戏就停止，也不要仅因它是游戏就启动全部保护规避步骤。

## 选择证据

记录实际设备/系统版本、ABI、构建哈希和有关配置；已给出的信息直接复用。静态样本可先读，不需要为每个问题取得完整设备环境。

- 权限与组件：从 manifest/plist、入口及调用者确定真正可达路径。
- 存储：区分本地显示、缓存和权威状态；根据具体文件、序列化代码与读写路径分析。
- 通信：优先解释已提供流量、编码与身份上下文；连接外部服务需另有任务依据。
- 崩溃：关联线程、堆栈、对象生命周期和模块映射，避免凭一个错误码断言原因。
- 完整性检查：解释检测输入、结果与误报条件；记录 root、模拟器或插桩的存在不等于归因，也不自动要求隐藏它。

## 工具与分流

APK 清单或反编译用 [apk-reverse](../apk-reverse/SKILL.md)，一般移动调用关系用 [mobile-reverse](../mobile-reverse/SKILL.md)，游戏运行时证据用 [game-runtime-analysis](../game-runtime-analysis/SKILL.md)。

动态验证只引入回答当前问题所需的动作。安装驱动、改变 SELinux、修改 TLS 校验或重新签名都不是静态分析的默认前提。具备 root 也不代表所有路径可读或所有行为已获准。

交付用户需要的原因分析、结构说明、复现脚本或修复建议；根据实际请求决定输出类型，不把允许的实施请求机械替换成泛泛建议。未验证条件明确说明。
