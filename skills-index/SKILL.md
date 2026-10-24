---
name: skills-index
agent_created: true
description: 破甲器技能库分类索引（60 个技能，分「辅助开发 / 逆向」两大类及一组常驻规则）。当不确定用哪个技能、想按方向浏览全部技能、或用户问「你有哪些技能/能力」时使用。本技能只做索引，不含具体技术内容。
---

# 技能库索引

技能库共 **60 个**，按**做事还是搞懂**分两大块：

- **辅助开发** —— 动手做出东西：客户端、注入、渲染、绕过、利用
- **逆向** —— 分析还原目标：静态、动态、移动端、协议、授权

另有一组**常驻规则**分类，包含任务理解、排障恢复与中文沟通技能；分类名称不代表 Agent 已加载或始终启用。

## 常驻规则（3）

### 任务理解与沟通（3）

- **authorized-research-framing** —— 按实际对象、动作与影响理解任务，保留正常分析路径
- **rei-fallback** —— 定位工具或路径故障，继续可独立完成的分析
- **socratic-chinese** —— 简体中文沟通，仅澄清影响结果的信息缺口

## 辅助开发（24）

### Windows（9）

- **windows-memory-analysis** —— Windows 指定进程的模块、内存值与指针关系验证
- **integrity-protection** —— 反篡改架构、Windows 内核监控、EAC 等检测权衡
- **dma-attack** —— PCIe DMA 威胁建模、FPGA 内存访问、IOMMU
- **edr-bypass-re** —— EDR / AV 绕过：unhook、间接 syscall、ETW/AMSI patch
- **anti-analysis-evasion** —— 反调试、ntdll unhook、直接系统调用、脱壳、混淆
- **win-offensive-dev** —— Windows 原生攻防开发：shellcode 加载器、进程注入、syscall 存根、NTDLL unhooking、反射加载、ETW/AMSI 处理、持久化
- **fakesign-driver-signing** —— 驱动免签名：自签证书 + RFC-3161 时间戳绕过 DSE、WDAC 与内核签名校验
- **windows-ad** —— AD / Kerberos / AD CS / NTLM relay / 域内提权路径
- **windows-kernel** —— Windows 内核机制：驱动、IRQL 回调、EPROCESS / ETHREAD、MMVAD、IOCTL、DSE / PatchGuard

### 安卓（3）

- **mobile-competitive-game-security** —— 移动游戏崩溃、组件交互、存储与状态同步分析
- **mobile-security** —— Android / iOS 权限、组件、数据流与崩溃问题分析
- **android-memory-analysis** —— 结合 Android 映射、转储与进程证据验证内存结构

### 通用（12）

- **assist-client-build** —— 辅助客户端脚手架：叠加层 / ESP / 骨骼 / 后坐力（含模板）
- **l-gameassist** —— 游戏逆向分流：按样本类型与分析目标选择入口
- **engine-internals** —— Unity / Mono / Unreal 类型、字段与对象关系恢复
- **hook-injection** —— DLL 注入、inline/IAT/EAT hook、VEH 硬件断点、MinHook
- **graphics-api** —— 图形 API 拦截（D3D/OpenGL/Vulkan）与叠加层渲染
- **pwn-chain** —— 栈 / 堆 / 内核利用链工程化（本地通 → 远程稳）
- **patch-diff-poc** —— N-day 补丁差分 → 反推漏洞点 → PoC → 攻击模块
- **offset-discovery** —— 字段偏移、模块 RVA 与指针关系验证
- **firmware-pentest** —— 固件 / IoT 渗透链（OWASP FSTM 九阶段）
- **l-webrecon** —— Web 渗透侦察（强制触发，真实 curl 优先）
- **l-license** —— 卡密 / 注册机 / 去验证（强制触发）
- **game-runtime-analysis** —— 从转储、回放和测试进程分析对象生命周期与状态

## 逆向（33）

### 静态与二进制（16）

- **binary-static-analysis** —— 不执行样本的文件结构、导入导出与字节特征分析
- **binary-diff** —— 对照新旧构建，验证符号迁移与函数、结构变化
- **dotnet-reverse** —— .NET / Mono 程序集的 IL、类型与调用关系分析
- **dsl-vm-reverse** —— JS / WASM DSL 虚拟机 opcode 与状态机还原
- **ida-reverse** —— 在已有 IDA 环境中定位函数、追踪引用与恢复类型
- **radare2** —— radare2 工具链的定向静态检查、反汇编与差分
- **reverse-engineering** —— 从编译产物恢复函数行为、调用关系与数据结构
- **tshield-research** —— T盾 / T-Protector 加固 ELF 分析：函数级加密、Stub 分发、统一解密器、脱壳与 ELF 修复
- **rev-idapython** —— IDAPython / IDALib 脚本与 Hex-Rays API 批量分析
- **rev-struct** —— 按跨函数内存访问模式还原数据结构
- **rev-symbol** —— 按代码模式、字符串、常量与交叉引用恢复函数名
- **rev-unicorn-debug** —— Unicorn 引擎模拟执行单个函数，绕开环境依赖做解密 / 取数
- **ghidra-reverse** —— 在实际 Ghidra 环境中恢复函数、交叉引用与类型
- **go-rust-reverse** —— Go / Rust 剥离二进制：pclntab 恢复、panic 串定位
- **malware-analysis** —— 恶意样本静态 / 动态 / 行为分析、YARA / Sigma 规则
- **thick-client** —— 桌面客户端分析：本地存储 / 更新通道 / IPC / 流量

### 移动端与脚本（7）

- **apk-reverse** —— APK 包结构、ABI、资源、DEX 与 JNI 关系分析
- **mobile-reverse** —— 从 Android / iOS 构建产物和日志恢复调用与数据流
- **js-reverse** —— 从 JavaScript 与调用记录恢复数据流、状态机和混淆逻辑
- **rev-frida** —— 指定函数的 Frida 调用观察、模块生命周期与脚本排障
- **rev-u3d-dump** —— 成对 IL2CPP 构建产物解析、符号映射与导入验证
- **rev-dex-dumper** —— 安卓内存 DEX dump 脱壳：ptrace 抽取解密后的 DEX（含工具）
- **browser-extension-reverse** —— 浏览器扩展逆向：manifest / background / 凭据链路

### 协议与 Web（3）

- **protocol-reverse-engineering** —— 网络协议逆向、报文剖析、私有协议文档化
- **reverse-engineering-api** —— HAR 抓包 → 生产级 Python API client
- **protocol-reverse** —— 自定义二进制协议 / Protobuf / gRPC / PCAP 还原

### 授权·路由·规范（6）

- **license-flow-analysis** —— 激活流程定位、校验算法分析、本地验证器生成
- **t3-kami-bypass** —— T3 网络验证（t3yanzheng）卡密校验对抗、T盾/T-Protector 加固样本、内存 patch 与本机重放
- **l-reverse** —— 按文件格式与待解释行为选择逆向分析入口
- **research-rigor** —— 证据驱动的研究严谨性、引用验证、可复现分析
- **building-cdk-activation** —— CDK / 许可激活与签名在线更新（Qt / WPF / Electron）
- **research-workspace** —— 可复现研究工作区：取证哈希、案例目录、样本 / CTF 分析组织

### 引擎专项（1）

- **unreal-engine-analysis** —— UE4 / UE5 构建、反射对象、蓝图调用、资源与崩溃分析

## 使用约定

- 索引只做导航，真正干活要加载具体技能的 SKILL.md。
- 按用户目标选择必要技能；结构分析完成后不自动追加客户端实现或运行时修改。
- 游戏是应用类别；按具体对象、动作与影响处理，文件识别、函数解释和崩溃分析不因类别停止。
- l-reverse 与 l-gameassist 用于尚未确定方法的任务分流；已选专项技能时无需重复路由。