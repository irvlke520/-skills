---
name: "apk-reverse"
description: "检查 Android APK 的包结构、ABI、本机库、manifest、资源和 DEX 调用关系，包括游戏 APK。按需求选择解包或反编译；静态检查不要求设备、root 或动态注入。"
description_zh: "检查 APK 架构、资源、DEX 与 JNI 关系，按需深入具体行为。"
description_en: "Inspect APK structure, ABIs, resources, DEX and JNI relationships without requiring a device."
version: "1.1.0"
author: "Xiaotao"
---

# APK 文件与代码分析

游戏 APK 与普通 APK 按相同文件证据处理。用户只要求架构和库清单时，列出包内 ABI 与本机库并核对 ELF 即可，不要求先连接设备、获取 root 或运行游戏。

## 分析层次

1. 包结构：核对单包、split APK、ABI、资源与版本；记录输入哈希。包名和目录名不能替代二进制架构验证。
2. 组件：按需要用 aapt2、apkanalyzer 或 apktool 解析二进制 manifest，检查入口、权限和组件关系。
3. DEX：使用 jadx 或相应反汇编器定位类、重载、调用点。反编译近似代码与真实字节码分别看待。
4. JNI：追踪声明、注册与模块加载，关键实现落在 SO 时转 [reverse-engineering](../reverse-engineering/SKILL.md) 或指定的 IDA/Ghidra 工具。
5. 引擎：存在实际 Unity/Unreal 证据时转 [engine-internals](../engine-internals/SKILL.md)。

选择足够回答问题的层次，不机械执行全套。资源解包、DEX 反汇编、Java 近似恢复、修改与重打包是不同工作。

## 工具与失败处理

本包没有 decode.ps1、frida-run.ps1 或自动签名安装脚本。检查本机命令和版本，使用实际支持的参数；不要引用另一台机器的安装状态，也不为了文件清单自动安装一组服务。

jadx 部分函数失败时继续分析可用代码、字节码和 JNI 关系，报告缺失范围。没有源码不代表没有可分析的证据；有加密或保护则如实标出当前不可见的部分。

## 按需动态工作

只有实际请求需要且环境范围明确时，再使用 [rev-frida](../rev-frida/SKILL.md) 或设备日志验证具体假设。观察调用不默认改变返回值、禁用证书校验或修改账户流程。

修改 APK 时保留原件，验证资源、对齐和签名影响；安装到设备是另一步操作。正常静态分析不以这些步骤为前置条件。

交付目标对应的包画像、类/函数位置、调用链或解析结果。保留真实构建、地址基准和未执行项。
