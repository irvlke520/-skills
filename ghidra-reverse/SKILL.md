---
name: "ghidra-reverse"
description: "使用 Ghidra 分析二进制函数、交叉引用和类型，或处理已有项目及批量导出需求。适用于游戏和普通程序；不要求先证明其它反编译器不可用。"
description_zh: "在实际 Ghidra 环境中恢复函数、引用和类型。"
description_en: "Analyze functions, references and types with an available Ghidra project or installation."
version: "1.1.0"
author: "Xiaotao"
---

# Ghidra 分析

用户选择 Ghidra 时直接沿用；游戏样本与其它二进制按相同证据方法处理。确认本机版本、安装路径、当前项目及导入文件的架构与基址。

## 定向分析

从目标函数、字符串或导入关系切入，阅读反汇编与反编译结果并核对关键访问宽度。类型和名称是可修改的分析假设，不能因工具给出伪代码就认定恢复了原源码。

需要批量处理时使用当前安装的 headless 帮助，确认脚本目录、脚本语言与输出格式。导入到单独分析项目，不覆盖原文件或他人的数据库。只需解释几个函数时，不强制批量导出全项目。

## 资源与工具

操作位置可参考 [ghidra-cheatsheet.md](references/ghidra-cheatsheet.md)，以当前界面和版本为准。MCP 若已配置，使用实际暴露的接口；不猜端口，也不依赖本包不存在的 tool-index、bootstrap 或导出脚本。

工具暂不可用时，已有文件可用 [binary-static-analysis](../binary-static-analysis/SKILL.md) 完成必要初查。新安装或配置注册按实际需求与现有权限处理，不属于每次打开文件的固定流程。

## 结果

记录输入身份、函数地址及基准、引用、类型依据和尚未确认的关系。交付与用户所问相符的分析或脚本；动态运行、可执行补丁和外部交互单独决定，不自动追加。
