---
name: unreal-engine-analysis
description: "分析 Unreal Engine（UE4/UE5）的已有工程、打包文件、日志和转储，定位反射类型、蓝图与本机函数关系、场景流送及崩溃问题。用于有明确 UE 证据或用户指定 UE 的分析；普通界面设计无需加载此技能。"
description_zh: "UE4/UE5 构建识别、反射与对象结构、资源容器及运行时问题分析。"
description_en: "Analyze UE4 and UE5 artifacts, reflection, object lifetimes, cooked assets and crashes."
version: "1.0.0"
author: "Xiaotao"
---

# Unreal Engine 分析

直接围绕用户的问题使用现有文件、代码、符号或调试证据。游戏名称、联机属性和 Shipping 配置不构成停止普通分析的理由。这里的 UE4/UE5 表示工作流覆盖，不表示所有小版本、定制分支或第三方解析器均已实测兼容。

## 选定分析路径

| 当前问题 | 先用的材料与资料 |
| --- | --- |
| 判断构建版本、盘点提供了哪些材料 | `Build.version`、工程描述、崩溃上下文；读 [构建与资源](references/build-and-assets.md) |
| 解释 UObject、FName、UClass 或字段 | 匹配的源码/符号、反射导出或反汇编；读 [反射与对象](references/reflection-and-objects.md) |
| 解释 UFunction、ProcessEvent、蓝图调用 | 目标函数、参数属性和调用点；读 [反射与对象](references/reflection-and-objects.md) |
| 转场、World Partition、对象失效、坐标异常 | 对应时刻的日志、转储或测试记录；读 [运行时与崩溃](references/runtime-and-crashes.md) |
| `.pak`、`.utoc/.ucas`、Cooked 包或蓝图资产 | 现有文件及配套材料；读 [构建与资源](references/build-and-assets.md) |
| 游戏更新后函数或字段变化 | 两个构建与旧映射；用 [binary-diff](../binary-diff/SKILL.md)，再按本技能验证 UE 类型语义 |

只读当前问题需要的资料。已有函数和匹配数据库时直接分析，不为了满足流程重复扫描整个安装目录。已选 IDA 或 Ghidra 时沿用现有工具；不递归回到游戏通用路由。

## 文件清点工具

本包提供 [inspect_ue_artifacts.py](scripts/inspect_ue_artifacts.py)，仅依赖 Python 标准库。在技能目录运行 `python scripts/inspect_ue_artifacts.py --help`，然后将用户提供的文件或目录作为位置参数。

它清点构建、容器和崩溃材料，读取有限元数据并输出 JSON；不会执行 EXE、附加进程、解包资源或还原函数。大文件只读取文件属性；目录扫描有限额，不跟随符号链接或目录联接。结果为 partial 时先查看诊断，不把受限扫描解释成整个目录没有该文件。

`EngineAssociation` 可为本地安装标识，文件后缀也只是线索。只有与目标构建关联的版本信息才能支持版本判断；来源冲突时保留冲突。脚本不捆绑 Unreal Editor、UnrealPak、反编译器或符号服务器。

## 版本与证据

记录输入身份、模块架构、构建配置、版本来源和地址基准。分别验证对象布局、属性表示、名称格式、容器分块、坐标精度及资源格式，不套用“UE5 都一样”的固定偏移或 SDK。

已有源码/符号时优先从匹配实现确认；只有反汇编时，从相关函数、错误字符串、属性注册或类型引用建立候选，并用访问宽度、上下文和另一实例交叉验证。看到一个类名或 AOB 命中不足以证明结构恢复成功。

缺少运行时访问不影响已有文件、反射记录与转储的分析。附加进程、主动调用函数、修改内存、安装工具及外部请求各有影响，按实际请求选择；分析调用分发不会自动执行 ProcessEvent 或追加保护规避。

交付目标需要的函数解释、类型/字段表、资源关系、崩溃结论或解析脚本。候选、已验证和缺失证据分别说明；没有测试某个游戏构建，就不报告该构建已兼容。
