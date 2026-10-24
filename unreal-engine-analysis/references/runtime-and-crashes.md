# 场景、精度与崩溃分析

## 世界与对象生命周期

先关联具体 world/context、关卡状态、线程和采样时刻。Editor/PIE 可能有多个世界；不要把第一个可读 UWorld 或网络上给出的全局偏移当成目标场景。

检查问题是否发生在关卡切换、流送、对象销毁或 GC 附近。从访问失败处反查对象的创建、持有者和失效时刻；上一帧可读的地址并不能保证下一帧仍属于同一对象。区别空指针、过期引用、重复使用的对象槽位和采集过程中的变化。

`PersistentLevel` 不是任意构建里全部已加载 Actor 的完整清单。传统子关卡与 UE5 World Partition 分开处理：确认流送是否开启、关联 Data Layers、加载单元和相应时间点；资产或 Actor 描述记录也不等于当前驻留的 Actor 实例。世界分区项目也可能关闭流送，不能仅凭 UE5 标签假定它正在启用。

## UE5 坐标精度与变换

UE5 Large World Coordinates 引入双精度类型。核对目标实际的 `FVector/FTransform` 别名及字段访问宽度，不继续套用 UE4 的三 float / 固定结构尺寸；也不要反向假定所有 UE5 CPU、GPU、网络或自定义数据都使用 double。

恢复坐标异常时同时检查数据类型、局部/组件/世界空间、相机所在世界、世界原点或渲染相对坐标，以及采样是否来自同一帧。精度类型选错导致的异常数值不能直接当成数据加密。

骨骼分析使用匹配 Mesh/Skeleton 的名称与父子层级，按实际 LOD 和索引映射解释。局部姿态、组件空间结果与世界变换分别核对；固定“某骨骼总是第几个”的表不跨资产通用。图形投影问题参见 [投影验证](../../game-runtime-analysis/references/w2s-overlay.md)。

## 崩溃、日志与性能

1. 对齐同一次崩溃的 CrashContext、日志、转储、模块与符号。核对构建身份，区分 crash、assert、ensure 和普通错误日志。
2. 从异常/失败点和崩溃线程的调用栈找相关生产者与消费者；分清引擎、项目和插件帧。栈顶位于 CoreUObject 或渲染线程并不单独证明引擎有缺陷。
3. 结合场景切换、对象销毁、异步加载、线程任务和资产依赖解释时序；反射类名存在不证明实例存活。
4. 未匹配符号时保留模块 RVA 和原始栈，给出可验证的候选。转储可能没有包含所需内存，缺页或缺对象不等于对象从未存在。
5. 已有 `.utrace` 需要性能分析时，使用实际可用、支持该 trace 版本的 Unreal Insights。清点脚本只确认材料存在；不能据此宣称完成帧耗时或卡顿分析。

只要求解释日志或转储时，无需运行游戏、重新采集或附加调试器。确需新证据时，围绕尚未解决的假设选择最小采集范围，并说明哪些结论依赖它。

## 跨更新复核

版本更新后分别核对名称表示、属性类型、容器布局、坐标精度与对象生命周期。保留旧地址到新候选的语义依据，不把旧 SDK 或同一字符串命中当成全部字段仍有效。具体符号迁移使用 [binary-diff](../../binary-diff/SKILL.md)。

## 依据

Epic 的 [World Partition](https://dev.epicgames.com/documentation/en-us/unreal-engine/world-partition-in-unreal-engine)、[Large World Coordinates](https://dev.epicgames.com/documentation/en-us/unreal-engine/large-world-coordinates-in-unreal-engine-5)、[Object Handling](https://dev.epicgames.com/documentation/en-us/unreal-engine/unreal-object-handling-in-unreal-engine) 和 [Crash Reporting](https://dev.epicgames.com/documentation/en-us/unreal-engine/crash-reporting-in-unreal-engine) 用于核对机制。源码、日志和工具版本仍须与被分析构建匹配。
