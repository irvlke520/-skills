---
name: l-reverse
description: 为尚未确定工具的逆向任务选择静态分析、反编译或调试入口。用于需要根据文件格式和待解释行为分流的请求；已经明确使用 IDA、Ghidra 或某个引擎专项时无需重复路由。
description_zh: 按样本格式和分析目标选择逆向工具与验证方法。
description_en: Route reverse engineering by artifact format, requested behavior and available tools.
version: 1.1.0
author: Xiaotao
---

# 逆向任务分流

读取现有材料与需求，确认分析对象、平台、希望解释的行为和结果形式。沿用明确的任务范围；一个本地文件足以开始文件结构分析，不代表自动授权连接其服务端或修改运行中的目标。

已明确为游戏但尚未选定方法的请求优先使用 [l-gameassist](../l-gameassist/SKILL.md) 分流一次；已有专项结论时直接继续，不在两个路由之间往返。

## 选择一个主要入口

| 目标 | 技能 |
| --- | --- |
| 文件格式、段、导入导出、字符串 | [binary-static-analysis](../binary-static-analysis/SKILL.md) |
| 已选 IDA 或需要分析 IDB | [ida-reverse](../ida-reverse/SKILL.md) |
| 已选 Ghidra | [ghidra-reverse](../ghidra-reverse/SKILL.md) |
| Unity / Mono 数据结构 | [engine-internals](../engine-internals/SKILL.md) |
| UE4 / UE5 反射、资源与运行时结构 | [unreal-engine-analysis](../unreal-engine-analysis/SKILL.md) |
| IL2CPP 元数据与本机代码映射 | [rev-u3d-dump](../rev-u3d-dump/SKILL.md) |
| .NET / Mono 托管程序集 | [dotnet-reverse](../dotnet-reverse/SKILL.md) |
| APK 资源、manifest、DEX 调用关系 | [apk-reverse](../apk-reverse/SKILL.md) |
| 新旧版本符号迁移 | [binary-diff](../binary-diff/SKILL.md) |
| 已提供 PCAP 或二进制报文的字段恢复 | [protocol-reverse](../protocol-reverse/SKILL.md) |

解包资源、反汇编字节码、反编译和重打包是不同交付物。按用户需要选择，分析完成后不自动修改样本或发起报文重放。

先用少量字符串、导入、交叉引用建立假设，再深入相关函数或数据结构。反编译结果是推断的代码表示；使用原始指令和调用关系核对关键结论。

## 工具与交付

按当前环境发现工具，遵守实际暴露的参数。相对链接以本技能文件为基准；不假设盘符、MCP 名称、工具数量或另一台机器的安装路径。

报告样本哈希、构建版本、文件偏移/RVA/VA 的区别、关键发现与验证命令。未运行的命令标注未执行。动态调试、样本修改和网络交互仅在实际请求需要且范围允许时进行；不通过重命名任务规避判断。
