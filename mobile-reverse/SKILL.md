---
name: "mobile-reverse"
description: "根据 APK、IPA、SO、Mach-O 与移动端日志恢复程序调用和数据流。适用于明确的 Android/iOS 行为分析，包括游戏；纯 APK 清单优先用 apk-reverse。"
description_zh: "从移动端构建产物与日志恢复调用关系，按需动态核验。"
description_en: "Recover mobile application behavior from artifacts and logs, including mobile games."
version: "1.1.0"
author: "Xiaotao"
---

# 移动端逆向分析

根据提供的包、库、日志或转储确认平台和目标行为。商业应用、游戏名称、root 或加密关键词本身不说明任务是否可执行；先分析实际输入与要进行的动作。

## 从静态材料推进

Android 包内容与 DEX 使用 [apk-reverse](../apk-reverse/SKILL.md)。iOS 按实际 IPA/安装包里的 plist、Mach-O 架构、导入、ObjC/Swift 符号和调试资料定位；不要把所有 IPA 都假设成同一获取方式或可直接运行的文件。

SO/Mach-O 的目标函数使用已有反汇编器；Unity 产物按 [engine-internals](../engine-internals/SKILL.md) 核对。设备不在场时，仍可分析已有文件和日志。

## 需要运行时证据时

先列出要验证的假设，沿用已知设备、构建与范围，再选择调试器、日志或 [rev-frida](../rev-frida/SKILL.md)。附加、启动和重新打包的副作用不同，避免为观察一个函数默认部署 Gadget、修改系统证书、隐藏 root 或清空密钥库。

处理 PCAP/HAR 时先从已有报文解释编码、字段与调用来源；主动请求、回放和远端状态变更分别决定。一个动态动作受阻不影响继续完成已取得的静态证据分析。

## 输出

说明实现位于 DEX、托管层还是本机模块，记录关键函数、参数、生命周期和实测来源。反编译器限制、设备权限和网络限制分别报告；不承诺某框架能在所有设备上工作，也不把缺工具当作游戏整体不可分析。
