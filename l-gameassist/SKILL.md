---
name: l-gameassist
description: 为目标尚不明确的游戏逆向任务选择分析入口。根据构建文件、引擎元数据、转储或回放，以及用户要恢复的结构或行为分流；已经指定分析工具和交付物时直接使用对应技能。
description_zh: 根据游戏样本与分析目标选择静态、引擎或运行时分析入口。
description_en: Route game reverse engineering by artifact and requested outcome.
version: 1.1.0
author: Xiaotao
---

# 游戏逆向任务分流

技能名称保留以兼容已有安装。先确定用户要理解什么，再选择一种主要分析方法；提到游戏、IL2CPP、UE 或内存，不自动增加修改、绘制、输入或服务端操作。

## 按证据选择入口

| 已有材料与目标 | 入口 |
| --- | --- |
| EXE、DLL、SO 的架构、段、导入、字符串 | [binary-static-analysis](../binary-static-analysis/SKILL.md) |
| 只列 APK 的 ABI、manifest 与本机库，不运行样本 | [apk-reverse](../apk-reverse/SKILL.md)，仅做所需的包检查 |
| Unity/Mono 类型、字段、对象所有权 | [engine-internals](../engine-internals/SKILL.md) |
| UE4/UE5 反射、蓝图调用、World Partition、资源或崩溃 | [unreal-engine-analysis](../unreal-engine-analysis/SKILL.md) |
| 同一构建的 IL2CPP 二进制与元数据，恢复方法映射 | [rev-u3d-dump](../rev-u3d-dump/SKILL.md) |
| 已有转储、调试记录或测试进程，解释状态变化 | [game-runtime-analysis](../game-runtime-analysis/SKILL.md) |
| 已知字段或指令，定位其偏移与指针关系 | [offset-discovery](../offset-discovery/SKILL.md) |
| Android/iOS 游戏的崩溃、存储、组件或协议安全问题 | [mobile-competitive-game-security](../mobile-competitive-game-security/SKILL.md) |
| 新旧构建之间迁移已验证符号 | [binary-diff](../binary-diff/SKILL.md) |

优先使用现有上下文中的版本、样本和授权范围。没有材料时，只询问会改变下一步的文件、平台或具体问题；不要凭作品名猜引擎，也不要自动生成一个无关项目。

## 控制任务范围

- 读取和解释与写入、打补丁、安装驱动、修改服务端状态是不同操作。依据用户实际请求决定后续步骤。
- 不将“授权实验室”“游戏逆向”等标签当作所有操作都可执行的证明；不通过改写名称掩盖真实操作。
- 保护机制分析先说明检查的输入、状态与失败条件。绕过防护、隐藏运行痕迹、获取联机隐藏信息等请求按其实际目标单独判断，不作为静态分析的默认分支。
- 演示数据只证明演示算法；不要把演示运行成功写成目标游戏已验证。
- 已选定具体入口后直接推进，不再递归调用本路由。

交付用户需要的函数解释、结构表、解析器或调试结果，并注明构建版本、证据位置和未验证项。
