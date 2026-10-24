---
name: "windows-memory-analysis"
description: "观察已指定 Windows 进程的模块、内存值、映射与指针关系，用于调试和结构验证，包括游戏测试进程。仅有磁盘文件时优先做文件分析，不自动要求修改目标。"
description_zh: "根据实际 PID、模块和访问权限验证 Windows 内存结构。"
description_en: "Inspect specified Windows process state and validate memory structures for debugging."
version: "1.1.0"
author: "Xiaotao"
---

# Windows 进程内存观察

按明确进程与分析问题工作，游戏名称不构成跳过观察的理由。先确认 PID、路径、位数与模块版本，避免重启后的 PID 或旧地址误用。

本技能携带 [scripts/mem_tools.py](scripts/mem_tools.py)，先查看 `--help` 和所用子命令帮助。脚本存在不等于它在所有位数、系统和受保护进程上都能成功。

## 读取与验证

- `ps`、`modules`：确认对象与模块，不猜测 PID。
- `read`：按证据确定数据类型、字节数与地址基准。
- `scan`：保留多个候选，检查指令语义后再选择。
- `chain`：每次解引用记录地址、指针宽度与有效性。
- `dump`：只导出当前问题所需区域，记录布局、采样时刻和输出路径。

磁盘文件偏移、RVA、运行时 VA 与实例偏移不可混用。读取失败不能用零值代表成功；结构推断需关联正常状态变化与生命周期。矩阵问题按 [投影验证](../game-runtime-analysis/references/w2s-overlay.md) 说明实际约定，不仅凭引擎名选择排列。

## 权限和修改

`OpenProcess` 或读取失败时记录真实 Win32 错误，检查进程是否退出、地址是否映射、目标位数和现有访问条件。管理员身份也不保证读取所有受保护进程；失败不是“游戏不能分析”的证明，已有二进制和转储可继续用于独立分析。

`write` 是单独的修改动作。只有请求确实包含该动作且范围允许时使用，核对原字节、备份与恢复条件；不为了完成普通读取自动改变防护、加载驱动或执行隐藏操作。

交付实际读值、结构关系和验证证据。缺少运行时访问时，准确标注动态部分未执行，不声称已成功读取目标。
