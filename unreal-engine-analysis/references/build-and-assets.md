# 构建识别与 Cooked 资源

## 版本判据

先关联要分析的那个构建，再解释版本线索。保留文件路径与原始字段，多个游戏目录、Editor 和 Shipping 文件不能拼成一份版本结论。

| 材料 | 可以支持的判断 | 容易误判的地方 |
| --- | --- | --- |
| 匹配的 `Build.version` | 引擎主次版本、补丁与 changelist 等声明 | 目录里附带的 SDK/工具版本不一定属于目标游戏 |
| `CrashContext.runtime-xml` 与当次日志 | 崩溃所用版本、配置及构建标识 | 缺字段并不证明不使用 UE；旧崩溃包可能来自旧更新 |
| `.uproject` 的 `EngineAssociation` | 工程声明的引擎关联 | GUID、本地注册标识或修改过的文件不能单独确认精确版本 |
| PDB、模块、构建产物 | 匹配符号与代码布局 | 文件名相同不等于匹配；核对模块身份和调试标识 |
| `.pak`、`.utoc`、`.uasset` 等后缀 | 容器或资源类型的候选 | 不能单凭后缀推断 UE 小版本、加密、完整性或可解析性 |

只有初查需求时，使用 [清点脚本](../scripts/inspect_ue_artifacts.py) 输出材料与版本提示即可。它不验证容器头、不解析包摘要，也不检查 PDB 匹配；需要这些结论时再选相应解析器。

## 容器与加载格式

区分容器格式、包序列化版本、项目 Custom Version 和加密/压缩配置。引擎版本相同也可能使用不同 Cook 与打包选项。

- Pak：先使用匹配构建工具的帮助与只读列表功能；不要假定 Pak footer 位于固定距离，也不要在没有解析日志时宣称支持某版本。
- IoStore / Zen Loader：同时清点 `.utoc`、`.ucas`、分卷及相关容器。TOC、数据块与包依赖需要合起来解释；未发现同名 `.ucas` 时先核对分卷、复制范围和布局，不立即判损坏。
- Pak 和 IoStore 可以共存。不要把看到 `.pak` 解释成“这一定不是 UE5”，也不要用面向传统 `.uasset` 的解析结果直接代表 Zen 包布局。
- `.uasset/.umap` 可能依赖 `.uexp/.ubulk`、关联包或额外映射；Asset Registry 的目录记录不等于完整对象内容。

优先使用当前已安装且支持目标格式的 UnrealPak、Editor 命令工具或用户已有解析器。核对真实版本、输入和命令帮助后再执行；本包不提供一条对所有 UE4/UE5 构建都有效的解包命令。按用户要求选择列目录、读取元数据或导出必要对象，避免为查询一个资源先解包整款游戏。

加密索引、未知压缩方法或定制序列化导致失败时，保留错误及工具版本；使用用户已有的匹配构建配置、密钥或映射，或继续分析可读材料。不把格式解析失败当成游戏整体不可分析，也不默认从进程或第三方服务获取缺失材料。

## 蓝图与资产解释

明确目标是资源名称/依赖、默认值、运行时类/函数，还是编辑器中的节点图。Cooked 数据、反射导出和字节码通常只覆盖其中一部分；不能仅凭函数名称清单报告“完整蓝图源码已恢复”。

对应 `UBlueprintGeneratedClass`、CDO、实例覆盖值与相关 `UFunction`，区分默认配置和实际运行状态。需要解释执行行为时按 [反射与对象](reflection-and-objects.md) 对照本机入口、脚本与调用者。目标包缺失或工具不识别时，报告恢复到哪一层、缺少哪份配套材料。

## 依据

Epic 的 [Zen Loader](https://dev.epicgames.com/documentation/en-us/unreal-engine/zen-loader-in-unreal-engine) 说明 IoStore 容器、Pak 共存及包依赖预处理；[Crash Reporting](https://dev.epicgames.com/documentation/en-us/unreal-engine/crash-reporting-in-unreal-engine) 说明崩溃上下文包含的构建与运行证据。API/工具说明需切换到目标版本，当前在线文档不能证明旧构建兼容。
