---
name: ida-reverse
description: 使用已可用的 IDA Pro、IDALib 或 IDA MCP 分析二进制、调用关系、类型与反编译结果。用于明确选择 IDA 或已有 IDB 的任务，不因出现 EXE、游戏或逆向关键词而强制接管所有分析。
description_zh: 在已有 IDA 环境中定位函数、追踪引用并恢复类型。
description_en: Analyze functions, references and types using an available IDA environment.
version: 1.1.0
author: Xiaotao
---

# IDA 分析工作流

本包没有捆绑 IDA 本体或启动服务器脚本。先使用环境实际提供的 IDA/IDALib/MCP 工具及其文档；工具前缀、数量、参数和会话管理能力随安装而变。

## 确认数据库

确认当前数据库对应用户指定文件、架构和构建哈希。已有 IDB 优先复用；自动分析正在进行时读状态或日志，不因等待超时就删除数据库、重启全部 Python 进程或认定分析失败。

工具不可用时说明缺少的组件；能从现有文件完成的部分可使用 [binary-static-analysis](../binary-static-analysis/SKILL.md)。安装软件、修改 MCP 配置或结束其它会话不属于默认分析步骤。

## 从问题定位函数

用有关的导入、字符串、符号、常量或调用点缩小范围，再追踪引用和数据流。不要为解释一个函数强制导出全库。

反编译得到的签名和类型是分析假设。对关键分支核对原始指令、访问宽度、调用约定与参数来源。遇到混淆时先识别影响当前问题的部分，再选择局部处理方法。

为已验证符号添加名称和注释时保留自动名称/原始地址的对应关系；保存数据库的变更与修改原二进制文件分别对待。读取权限错误、数据库锁定、工具 schema 错误按真实原因排查，不引用另一台机器的脚本作为已存在能力。

## 相关任务

- 批量 IDAPython 自动化：按需读 [rev-idapython](../rev-idapython/SKILL.md)。
- 类型和字段恢复：按需读 [rev-struct](../rev-struct/SKILL.md)。
- 引擎对象解释：按需读 [engine-internals](../engine-internals/SKILL.md)。
- 符号映射与跨版本匹配：按需读 [binary-diff](../binary-diff/SKILL.md)。

交付关键地址及其基准、函数行为、支持结论的引用和实际验证结果。静态理解不自动追加进程附加、修改指令、凭据读取或保护规避；按用户实际任务决定后续工作。
