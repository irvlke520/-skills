---
name: "android-memory-analysis"
description: "结合 Android 模块映射、日志、转储及已指定设备中的进程状态验证地址与结构。用于 Android 调试问题，包括游戏；包文件分析无需先加载内核模块或修改系统策略。"
description_zh: "从 Android 映射与进程证据验证地址、指针和结构。"
description_en: "Validate Android memory structures from maps, dumps, logs and specified test processes."
version: "1.1.0"
author: "Xiaotao"
---

# Android 映射与内存分析

先确认用户当前问题是已有转储分析还是设备现场观察。游戏包和进程同样根据具体技术动作处理，不以名称停止分析，也不自动引入修改系统环境。

本技能携带 [scripts/android_tools.py](scripts/android_tools.py)。先读 `--help`；现场任务按实际设备序列号和 PID/包名选择，参数以所用子命令为准。没有设备时仍可分析已有包、SO 与转储。

## 模块与地址

目标进程可能不同于系统默认 ABI，按实际模块确认指针宽度和大小端。解析 maps 时核对映射路径、文件偏移和 ELF PT_LOAD 的对应关系；可执行段起点不一定就是整个模块的 load bias。

分别记录文件偏移、模块相对地址和现场 VA。AOB 命中只是一处候选指令；结合架构正确解码 PC 相对寻址，再判断得到的是地址、槽位还是需要继续解引用的指针。不要把 x86 指纹直接当成 ARM64 函数定位证据。

## 最小观察

按需要使用设备信息、进程、映射、读取、链解析或区域导出。固定设备与快照上下文；对不可读区、短读、空指针和进程退出明确报错。root 状态和 SELinux 状态只是环境事实，不直接证明操作成功。

现有脚本含写入、模块管理和 SELinux 子命令；这些是额外系统变更，不作为普通调试的默认步骤。驱动设备接口仅在本机确实存在且任务明确需要时使用，不假定其它电脑也具备用户的设备配置。

坐标问题使用 [投影验证](../game-runtime-analysis/references/w2s-overlay.md)；字段问题使用 [offset-discovery](../offset-discovery/SKILL.md)。`/proc` 访问失败时保留原因并继续可独立完成的静态分析，不自行部署规避方案。

输出设备/构建、映射基准、数据读取与假设验证结果。没有执行的现场步骤保持未执行状态，不以演示数据代替实测。
