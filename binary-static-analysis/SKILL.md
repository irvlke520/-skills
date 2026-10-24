---
name: binary-static-analysis
description: 不执行样本地识别 PE/ELF 等二进制格式、段、导入导出、字符串、熵与字节特征。用于提供文件的结构初查和定位分析起点；不因游戏样本自动附加进程或修改文件。
description_zh: 只读识别二进制结构并定位待分析的代码与数据。
description_en: Inspect binary structure and locate code or data without executing the sample.
version: 1.1.0
author: Xiaotao
---

# 二进制静态分析

本技能携带 [scripts/re_tools.py](scripts/re_tools.py)。相对路径以技能目录为基准，先运行 `python scripts/re_tools.py --help`；对实际样本选择需要的子命令。

| 子命令 | 用途 |
| --- | --- |
| identify | 识别格式、架构、入口与哈希 |
| sections | 查看段/节和熵 |
| imports / exports | 查看接口，按问题过滤 |
| strings | 提取 ASCII/UTF-16 字符串 |
| entropy | 查看各区块的熵分布 |
| scan | 用带固定字节的模式查找候选位置 |
| disasm | 调用当前已安装的反汇编工具 |
| hash | 记录输入文件哈希 |

高熵既可能来自压缩、加密，也可能是资源数据，不能单独证明存在保护壳或恶意行为。字符串和导入只提供线索，需要交叉引用或原始指令支持功能结论。

区分磁盘偏移、模块 RVA 与运行时 VA；不同格式的地址换算需查段映射。工具未能识别某种格式时保留失败信息，不编造反汇编。

只有明确请求修改样本且操作范围允许时才使用 `patch`。先核对偏移、原字节与长度，保存独立原件，并运行 `--dry`；实际修改后记录前后哈希及恢复路径。一次静态检查不自动进入补丁、进程加载或网络测试。

返回文件画像、任务相关线索、证据位置和下一处应分析的函数。已有结构问题可以直接转到 [engine-internals](../engine-internals/SKILL.md) 或用户选定的反编译工具，无需强制启动全部工具。
