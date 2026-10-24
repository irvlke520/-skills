---
name: "radare2"
description: "使用 radare2、rabin2、radiff2 或 r2pipe 进行命令行二进制结构、反汇编和差分分析，包括游戏产物。用于明确 CLI 工具需求，网页 JavaScript 使用其专项入口。"
description_zh: "用 radare2 工具链做定向静态检查、反汇编和差分。"
description_en: "Inspect and compare binaries, including games, with the radare2 command-line tools."
version: "1.1.0"
author: "Xiaotao"
---

# radare2 命令行分析

先确认实际命令与版本。游戏 EXE、DLL、SO 按同样结构和函数证据分析，不仅凭应用类别停止。

本包没有 recon.ps1 或自动安装脚本。可以直接使用现有 CLI；缺工具时说明具体缺项并继续其它可完成的文件检查。

## 常用只读入口

参数以本机工具帮助为准，文件路径按所用 shell 正确引用。

| 操作 | 工具与命令 |
| --- | --- |
| 格式与架构 | rabin2 的 -I |
| 节区、导入、导出 | rabin2 的 -S、-i、-E |
| 字符串 | rabin2 的 -z |
| 查看函数 | r2 的 afl、pdf |
| 字符串与交叉引用 | r2 的 iz、axt |
| 字节与指令 | r2 的 px、pd |
| 新旧文件差分 | radiff2，按目标选择字节或函数层 |

默认以普通文件分析模式打开，调试模式会运行或附加目标，写模式会影响输入文件，两者不自动开启。大型样本可以从相关区段和调用点做局部分析，避免为了一个报错字符串先运行最重的全量分析。

## 确认结论

核对文件偏移与分析地址的映射、架构和指令边界；函数列表可能受分析覆盖率影响。缺少数据库或插件的告警需要结合实际输出判断，既不全盘忽略也不直接认定样本不可分析。

写 r2pipe 自动化时处理子进程退出、超时、JSON 解析与空结果。只有用户要修改时才另行处理备份、原字节核对和写入后验证。

交付目标相关发现、真实地址和可复现命令。网页 JS 任务使用 [js-reverse](../js-reverse/SKILL.md)，类型/引擎问题按需读 [engine-internals](../engine-internals/SKILL.md)；无需因查到字符串就强制切换另一套工具。
