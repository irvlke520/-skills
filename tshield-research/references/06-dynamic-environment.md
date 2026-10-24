# 动态分析环境准备

## 1. 环境选择

### 1.1 Android 模拟器 vs 真机

| 选项 | 优点 | 缺点 | 推荐度 |
|------|------|------|--------|
| Android Studio AVD | 配置灵活，支持快照，x86_64速度快 | ARM 二进制需要转译，可能有兼容性问题 | ⭐⭐⭐⭐ |
| Genymotion | 速度快，支持多种设备 | 商业软件，免费版有限制 | ⭐⭐⭐ |
| 真机 | 最真实的环境，无兼容性问题 | 需要 root，可能有风险 | ⭐⭐⭐⭐⭐ |
| Android x86 | 原生 x86，速度快 | ARM 二进制无法运行 | ⭐⭐ |

### 1.2 推荐配置

**首选：已 root 的 Android 真机（ARM64）**
- Android 8.0+
- 已 root（Magisk 或其他）
- 开发者模式已开启
- USB 调试已开启

**备选：Android Studio AVD**
- API 28+ (Android 9+)
- ARM64 镜像（如果主机是 ARM）或 x86_64 镜像（如果主机是 x86）
- 可写系统分区（`-writable-system`）

## 2. 工具安装

### 2.1 ADB

```bash
# Ubuntu/Debian
sudo apt install android-tools-adb

# 验证
adb version
adb devices
```

### 2.2 gdb + gdbserver

```bash
# 1. 安装 gdb-multiarch
sudo apt install gdb-multiarch

# 2. 获取 gdbserver (ARM64)
# 从 Android NDK 中复制
# ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/bin/aarch64-linux-android-gdbserver

# 3. 推送到设备
adb push gdbserver /data/local/tmp/
adb shell chmod +x /data/local/tmp/gdbserver
```

### 2.3 Frida（需授权注入）

```bash
# 1. 安装 frida-tools
pip install frida-tools

# 2. 下载 frida-server (ARM64)
# 从 https://github.com/frida/frida/releases 下载
# frida-server-<version>-android-arm64.xz

# 3. 推送到设备
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server

# 4. 启动 frida-server
adb shell su -c /data/local/tmp/frida-server &

# 5. 验证
frida-ps -U
```

### 2.4 其他工具

```bash
# readelf / objdump (binutils)
sudo apt install binutils binutils-aarch64-linux-gnu

# IDA Pro / Ghidra (静态分析)
# 自行安装

# Python 库
pip install capstone pyelftools
```

## 3. 设备配置

### 3.1 启用 root

```bash
# 验证 root
adb shell su -c id
# 应该显示 uid=0(root)

# 如果没有 root，需要先 root 设备
# Magisk: https://github.com/topjohnwu/Magisk
```

### 3.2 关闭 SELinux（临时）

```bash
# 临时关闭（重启后恢复）
adb shell su -c setenforce 0

# 验证
adb shell getenforce
# 应该显示 Permissive
```

### 3.3 配置工作目录

```bash
# 创建工作目录
adb shell mkdir -p /data/local/tmp/tshield
adb shell chmod 777 /data/local/tmp/tshield

# 推送样本
adb push sample.elf /data/local/tmp/tshield/
adb shell chmod +x /data/local/tmp/tshield/sample.elf
```

## 4. 运行样本

### 4.1 直接运行

```bash
# 运行
adb shell /data/local/tmp/tshield/sample.elf

# 后台运行
adb shell /data/local/tmp/tshield/sample.elf &

# 获取 PID
adb shell pidof sample.elf
```

### 4.2 用 gdbserver 运行

```bash
# 方式1：gdbserver 启动程序
adb shell /data/local/tmp/gdbserver :1234 /data/local/tmp/tshield/sample.elf

# 方式2：附加到已运行的程序
adb shell /data/local/tmp/gdbserver --attach :1234 <pid>

# 端口转发
adb forward tcp:1234 tcp:1234

# 连接 gdb
gdb-multiarch
(gdb) target remote :1234
```

### 4.3 用 Frida 运行（需授权）

```bash
# 启动并注入
frida -U -f com.example.app -l script.js --no-pause

# 附加到已运行的程序
frida -U -n <process_name> -l script.js

# Spawn 模式（从启动开始跟踪）
frida -U -f <package_name> -l script.js
```

## 5. 常见问题

### 问题1：程序运行后立即退出

**可能原因**：
- 反调试检测触发
- 缺少依赖库
- 权限不足

**解决**：
1. 检查是否有反调试（用 strace 跟踪）
2. 检查依赖库：`readelf -d sample.elf | grep NEEDED`
3. 确保有 root 权限

### 问题2：gdb 附加后程序崩溃

**可能原因**：
- 反调试检测
- gdb 版本不兼容

**解决**：
1. 先绕过反调试（详见 14-anti-debug-and-bypass.md）
2. 使用 NDK 自带的 gdbserver
3. 尝试用硬件断点

### 问题3：Frida 无法注入

**可能原因**：
- frida-server 未启动
- 版本不匹配
- SELinux 阻止

**解决**：
1. 确认 frida-server 正在运行
2. 确认 frida-tools 和 frida-server 版本一致
3. 临时关闭 SELinux：`setenforce 0`

## 6. 环境检查清单

- [ ] ADB 已安装，设备已连接
- [ ] 设备已 root
- [ ] gdbserver 已推送到设备
- [ ] gdb-multiarch 已安装
- [ ] （可选）Frida 已安装，frida-server 已启动
- [ ] 样本已推送到设备，有执行权限
- [ ] 样本可以正常运行（无反调试触发）
- [ ] 工作目录已创建
