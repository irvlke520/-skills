---
name: "dotnet-reverse"
author: "SeaGull"
description: "分析 .NET/Mono 程序集中的类型、IL、状态机和托管调用关系，包括 Unity 托管游戏代码。根据真实格式选择反编译器；IL2CPP 与 NativeAOT 使用本机代码分析入口。"
license: "MIT"
compatibility: "Needs access to the supplied assembly and a compatible metadata or IL analysis tool. Use the installed tool on its supported host; a debugger, runtime or download is required only for the selected method."
allowed-tools: "Bash Read Write Edit Glob Grep Task WebFetch WebSearch"
metadata: {"user-invocable":"false"}
description_zh: "解析 .NET 与 Mono 程序集的 IL、类型和调用关系。"
description_en: "Analyze .NET and Mono assemblies, including managed game code, using format evidence."
version: "1.1.0"
---

# .NET / Mono 程序集分析

以 CLR 元数据、程序集身份与方法体为依据确认格式。扩展名、System 字符串或某个导入只是线索。游戏中的托管程序集正常按本流程分析，不因其用途停止。

## 定位实现

使用当前已安装且支持目标格式的 ILSpy、dnSpyEx 或元数据工具。核对程序集版本、依赖、类型全名和方法重载。C# 视图用于理解，关键结论通过 IL、元数据 token、异常处理区域和实际调用验证。

处理 async、迭代器、编译器生成类或闭包时，恢复状态转换和捕获变量。解释函数即可满足的任务，不强制创建补丁、重建程序集或启动调试器。

## 混淆与格式区别

先确认混淆实际影响的名称、字符串或控制流；按工具版本选择局部分析方法，不把 de4dot 视作任何混淆器的通用解。处理副本并保留原件与解析错误。

Unity Mono 的字段定义不直接等于进程内的固定偏移。IL2CPP 的本机模块与元数据交给 [rev-u3d-dump](../rev-u3d-dump/SKILL.md)；NativeAOT 等本机代码交给 [reverse-engineering](../reverse-engineering/SKILL.md)。不要因为反编译器不支持输入就断言该程序完全不可分析。

## 调试与交付

只有现有静态证据无法回答目标问题且范围允许时，才进入对应进程的动态调试。样本运行、方法修改和网络行为单独评估；不默认获取凭据或修改许可校验。

交付类型/方法定位、IL 支持的逻辑解释、关键调用与验证结果。编辑 IL 也可能破坏栈平衡、异常区域或签名；实际修改必须验证产物，不能保证“几乎不会失真”。
