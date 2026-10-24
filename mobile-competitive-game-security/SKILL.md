---
name: mobile-competitive-game-security
description: 分析 Android/iOS 游戏样本中的崩溃、组件交互、本地存储、状态同步和完整性检测问题。用于明确的移动游戏安全评估；普通 APK 解包或引擎元数据提取使用相应专项技能。
description_zh: 分析移动游戏的崩溃、组件、存储与状态同步证据。
description_en: Assess mobile game crashes, component interactions, storage and state synchronization.
version: 1.1.0
author: Xiaotao
---

# 移动游戏样本分析

以 APK/IPA、原生库、元数据、崩溃日志、回放或已提供报文为证据。通过样本确认引擎与版本，不根据作品名推断 Unity、Unreal 或特定保护方案。

明确当前问题属于文件结构、运行时崩溃、数据同步还是检测误报。只读取该问题所需材料，不因一个 APK 自动启动全部安全测试。

## 选择分析方式

- 包结构：安全问题需要时检查 manifest、ABI、资源、DEX 与原生模块。若需求仅为列出 APK 架构或库清单，直接用 [apk-reverse](../apk-reverse/SKILL.md) 完成所需检查，不继续本安全流程。区分资源解包、DEX 反汇编与源码近似恢复。
- 引擎数据：根据 [engine-internals](../engine-internals/SKILL.md) 区分元数据、方法与字段地址。
- 崩溃或运行时状态：先关联线程、调用栈、模块映射和对象生命周期，再按 [game-runtime-analysis](../game-runtime-analysis/SKILL.md) 核对。
- 报文与回放：从现有数据恢复长度、序列号、编码和状态关系；连接服务端或重放请求是另一个操作，需有实际请求与范围依据。
- 完整性检测：解释检查来源、输入、结果和误报条件；分析原因不自动增加隐藏调试、修改保护组件或规避检测的实现。

## 实测与结论

使用当前上下文已经确定的设备、构建和测试范围。静态样本分析不要求先取得 root、装内核模块或禁用系统保护；动态操作仅在问题需要时选择。

最小复现可使用已有开发构建、录制数据或本地测试工具。明确复现覆盖的行为以及尚未验证的现场条件，不能用演示结果替代目标实测。

交付与用户问题对应的调用关系、字段说明、解析器、崩溃定位或检测结论。记录可复现命令和实际失败原因；不要求固定的案例目录、报告模板或本包未提供的脚本。
