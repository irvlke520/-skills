# 动态内存 Dump 脱壳（推荐方法）

基于真实 T盾 样本（T1_904_0414.sh）的实际分析结果。

## 1. 方法概述

### 为什么推荐动态内存 dump

| 优点 | 说明 |
|------|------|
| 不需要逆向解密算法 | 直接从内存获取解密后的代码 |
| 适用于复杂壳 | 无论加密算法多复杂，运行时代码都是明文 |
| 技术成熟 | gdb/Frida 都可以实现 |
| 成功率高 | 只要能运行程序，就能 dump |

| 缺点 | 说明 |
|------|------|
| 需要运行环境 | Android 模拟器/真机 |
| 需要触发所有功能 | 函数级加密，第一次调用才解密 |
| 需要修复 ELF | dump 后的内存需要修复才能正常分析 |
| 可能有反调试 | 需要绕过反调试检测 |

### 核心原理

T盾 是函数级加密：
- 每个函数第一次被调用时，统一解密器会把它解密到内存
- 解密后的代码在内存中是明文的（可执行）
- 只要触发所有函数，所有代码都会在内存中明文存在
- dump 这些内存，就得到了解密后的代码

```
运行程序 → 触发所有功能 → 所有函数被解密 → 内存中是明文代码 → dump 内存 → 修复 ELF
```

## 2. 环境准备

### 2.1 Android 模拟器

推荐使用 Android Studio AVD（Android Virtual Device）：

```bash
# 1. 安装 Android Studio
# 2. 创建 AVD（推荐 API 28+，arm64 或 x86_64）
# 3. 启动模拟器
emulator -avd <avd_name> -writable-system

# 4. 验证
adb devices
adb shell getprop ro.product.cpu.abi
```

### 2.2 Root 环境

T盾 样本通常需要 root 权限运行：

```bash
# 方法1：使用 root 镜像的 AVD
# 方法2：使用 Magisk  root
# 方法3：使用已 root 的真机

# 验证 root
adb shell su -c id
```

### 2.3 gdb 配置

```bash
# 1. 推送 gdbserver 到设备
adb push gdbserver /data/local/tmp/
adb shell chmod +x /data/local/tmp/gdbserver

# 2. 端口转发
adb forward tcp:1234 tcp:1234

# 3. 启动 gdb
gdb-multiarch
(gdb) target remote :1234
```

### 2.4 Frida 配置（需授权注入）

```bash
# 1. 安装 frida-tools
pip install frida-tools

# 2. 推送 frida-server 到设备
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server

# 3. 启动 frida-server
adb shell su -c /data/local/tmp/frida-server &

# 4. 验证
frida-ps -U
```

## 3. 运行时内存分析

### 3.1 获取进程内存映射

```bash
# 获取进程 PID
adb shell pidof <package_name>
# 或
adb shell ps | grep <keyword>

# 查看内存映射
adb shell cat /proc/<pid>/maps > maps.txt
```

### 3.2 真实样本内存映射分析

T盾 样本运行后，内存映射大致如下：

```
地址范围            权限  偏移    设备    inode   路径
00000000-00927000  r-xp  00000000  b3:00  1234    /data/local/tmp/sample
00928000-00930000  rw-p  00000000  00:00  0       [anon:.bss]
00930000-015da000  rw-p  00000000  00:00  0       [anon:.bss]
015dc000-030d8000  r-xp  00000000  00:00  0       [anon:.scs]  ← 解密后代码段！
030d8000-05d6c000  r-xp  000003c0  b3:00  1234    /data/local/tmp/sample  ← payload段
05d6c000-05d72000  rw-p  02c94000  b3:00  1234    /data/local/tmp/sample
05d72000-05df5000  rw-p  02c99880  b3:00  1234    /data/local/tmp/sample
...
```

### 3.3 关键内存段识别

| 内存段 | 权限 | 大小 | 内容 | dump 优先级 |
|--------|------|------|------|-------------|
| 0x015dc000-0x030d8000 | r-xp | ~27.6MB | **解密后代码段** | ⭐⭐⭐⭐⭐ 最高 |
| 0x030d8000-0x05d6c000 | r-xp | ~46.6MB | payload段（含Stub+解密器） | ⭐⭐⭐⭐ 高 |
| 0x00000000-0x00927000 | r-xp | ~9.4MB | 壳代码段 | ⭐⭐⭐ 中 |
| 0x00930000-0x015da000 | rw-p | ~12.8MB | 数据段（解密后数据） | ⭐⭐⭐ 中 |
| 0x05d72000-0x05df5000 | rw-p | ~523KB | 动态链接数据 | ⭐⭐ 低 |

**最关键的是 0x015dc000-0x030d8000 这个段**：
- 它是运行时分配的（文件中没有对应内容）
- 权限是 r-xp（可读可执行）
- 大小约 27.6MB
- 这是 T盾 解密后的原始代码存放的位置

### 3.4 验证解密后代码

```gdb
# 在解密后的代码段下断点，验证是否是正常代码
break *0x015dc000
continue

# 反汇编
x/20i 0x015dc000

# 应该看到正常的 ARM64 指令（函数序言、bl 调用等）
# 而不是 Stub 模式（str x13/mov/movk/str/b）
```

## 4. 功能触发策略

### 4.1 为什么需要触发所有功能

T盾 是函数级加密：
- 每个函数第一次被调用时才解密
- 未被调用的函数仍然是加密的（在 payload 段中）
- 如果不触发所有功能，dump 的内存中会缺少未解密的函数

```
函数A（被调用）→ 解密 → 内存中明文 ✓
函数B（未调用）→ 未解密 → 内存中密文 ✗
```

### 4.2 触发方法

#### 方法1：手动操作（最可靠）

```
1. 启动程序
2. 进入每个功能菜单
3. 点击每个按钮/选项
4. 进入每个子页面
5. 执行每个操作
6. 返回主菜单，继续下一个功能
7. 重复直到所有功能都被触发
```

**注意事项**：
- 不仅要进入功能，还要实际执行操作（让函数被调用）
- 有些函数可能在特定条件下才被调用（如错误处理、超时处理）
- 有些函数可能在后台线程中被调用（如网络请求、定时任务）

#### 方法2：UI 自动化

用 Android UI 自动化工具自动触发所有功能：

```python
# 使用 uiautomator2（需要安装）
import uiautomator2 as u2

d = u2.connect()

# 启动应用
d.app_start("<package_name>")

# 自动点击所有可点击元素
def click_all_elements(depth=0):
    if depth > 3:
        return
    
    # 获取所有可点击元素
    elements = d(resourceId="")  # 所有元素
    for elem in elements:
        try:
            if elem.clickable:
                elem.click()
                time.sleep(1)
                # 递归处理子页面
                click_all_elements(depth + 1)
                # 返回
                d.press("back")
                time.sleep(0.5)
        except:
            pass

click_all_elements()
```

#### 方法3：压力测试/模糊测试

用 Monkey 工具随机触发所有功能：

```bash
# 使用 Android Monkey 工具
adb shell monkey -p <package_name> -v 10000

# 或使用更智能的模糊测试工具
# 如 Drozer、AppCrawler 等
```

#### 方法4：代码覆盖分析

用代码覆盖工具确认哪些函数被调用了：

```bash
# 方法1：使用 SimplePerformanceMonitor
# 方法2：使用 Frida hook 所有函数
# 方法3：使用 gdb 批量下断点
```

### 4.3 未解密函数的处理

如果某些函数无法通过正常操作触发，可以：

1. **手动调用**：用 gdb/Frida 手动调用这些函数
   ```gdb
   # 手动调用函数（需要知道参数）
   call (void)0x<function_addr>()
   ```

2. **静态解密**：对未解密的函数，用静态方法解密（详见 `references/12-unpacking-static-reverse.md`）

3. **接受不完整**：如果某些函数不重要，可以接受 dump 不完整

## 5. 内存 Dump 方法

### 方法1：gdb dump（推荐）

#### 5.1.1 单段 dump

```gdb
# 连接到进程
target remote :1234

# dump 解密后代码段
dump memory decrypted_code.bin 0x015dc000 0x030d8000

# dump payload 段
dump memory payload.bin 0x030d8000 0x05d6c000

# dump 数据段
dump memory data.bin 0x00930000 0x015da000
```

#### 5.1.2 批量 dump 所有可执行段

写一个 gdb 脚本批量 dump：

```gdb
# dump_all.gdb
set pagination off
set logging on

# 定义 dump 函数
define dump_segment
    dump memory $arg0 $arg1 $arg2
    printf "Dumped 0x%lx-0x%lx -> %s\n", $arg1, $arg2, $arg0
end

# dump 所有关键段
dump_segment code.bin 0x015dc000 0x030d8000
dump_segment payload.bin 0x030d8000 0x05d6c000
dump_segment shell.bin 0x00000000 0x00927000
dump_segment data1.bin 0x00928000 0x00930000
dump_segment data2.bin 0x00930000 0x015da000
dump_segment dynamic.bin 0x05d6c000 0x05df5000

printf "All segments dumped\n"
quit
```

使用：
```bash
gdb-multiarch -x dump_all.gdb
```

#### 5.1.3 自动获取内存映射并 dump

```python
# Python 脚本：自动解析 /proc/pid/maps 并 dump
import subprocess
import re

def get_maps(pid):
    """获取进程内存映射"""
    result = subprocess.run(
        ['adb', 'shell', 'cat', f'/proc/{pid}/maps'],
        capture_output=True, text=True
    )
    maps = []
    for line in result.stdout.strip().split('\n'):
        match = re.match(
            r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s*(.*)',
            line
        )
        if match:
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            perms = match.group(3)
            offset = int(match.group(4), 16)
            path = match.group(5).strip()
            maps.append({
                'start': start, 'end': end,
                'perms': perms, 'offset': offset,
                'path': path
            })
    return maps

def dump_segment(pid, start, end, output):
    """dump 指定内存段"""
    size = end - start
    cmd = (
        f'adb shell "dd if=/proc/{pid}/mem of=/data/local/tmp/dump.bin '
        f'bs=1 skip={start} count={size}"'
    )
    subprocess.run(cmd, shell=True)
    subprocess.run(['adb', 'pull', '/data/local/tmp/dump.bin', output])

# 使用
pid = "<pid>"
maps = get_maps(pid)

# dump 所有可执行段
for m in maps:
    if 'x' in m['perms'] and m['path']:  # 可执行且有文件映射
        output = f"code_{m['start']:x}_{m['end']:x}.bin"
        dump_segment(pid, m['start'], m['end'], output)
        print(f"Dumped: {output}")

# dump 所有匿名可执行段（解密后代码）
for m in maps:
    if 'x' in m['perms'] and not m['path']:  # 可执行且匿名
        output = f"anon_code_{m['start']:x}_{m['end']:x}.bin"
        dump_segment(pid, m['start'], m['end'], output)
        print(f"Dumped: {output}")
```

### 方法2：dd 直接 dump

```bash
# 方法1：在设备上 dump，然后 pull 到电脑
adb shell "dd if=/proc/<pid>/mem of=/data/local/tmp/code.bin bs=1 skip=$((0x015dc000)) count=$((0x030d8000-0x015dc000))"
adb pull /data/local/tmp/code.bin

# 方法2：直接重定向到电脑
adb shell "dd if=/proc/<pid>/mem bs=1 skip=$((0x015dc000)) count=$((0x030d8000-0x015dc000))" > code.bin
```

### 方法3：Frida dump（需授权注入）

```javascript
// Frida 脚本：dump 内存段
function dumpMemory(start, end, filename) {
    const size = end - start;
    const data = ptr(start).readByteArray(size);
    
    // 写入文件
    const file = new File(filename, "wb");
    file.write(data);
    file.flush();
    file.close();
    
    console.log(`Dumped 0x${start.toString(16)}-0x${end.toString(16)} (${size} bytes) -> ${filename}`);
}

// dump 解密后代码段
dumpMemory(0x015dc000, 0x030d8000, "/data/local/tmp/decrypted_code.bin");

// dump payload 段
dumpMemory(0x030d8000, 0x05d6c000, "/data/local/tmp/payload.bin");

// dump 所有可执行段
const ranges = Process.enumerateRanges('r-x');
ranges.forEach(range => {
    const filename = `/data/local/tmp/code_${range.base.toString(16)}.bin`;
    dumpMemory(range.base, range.base.add(range.size), filename);
});
```

### 方法4：自定义 dump 工具

写一个原生的 dump 工具，注入到目标进程中 dump 内存：

```c
// dump_tool.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void dump_memory(unsigned long start, unsigned long end, const char *filename) {
    size_t size = end - start;
    unsigned char *buf = malloc(size);
    if (!buf) {
        perror("malloc");
        return;
    }
    
    memcpy(buf, (void *)start, size);
    
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        free(buf);
        return;
    }
    
    write(fd, buf, size);
    close(fd);
    free(buf);
    
    printf("Dumped 0x%lx-0x%lx (%zu bytes) -> %s\n", start, end, size, filename);
}

// 被注入后调用这个函数
void __attribute__((constructor)) dump_init() {
    // dump 解密后代码段（地址需要根据实际情况修改）
    dump_memory(0x015dc000, 0x030d8000, "/data/local/tmp/decrypted_code.bin");
}
```

## 6. Dump 时机选择

### 6.1 最佳时机

**最佳 dump 时机**：所有功能都触发完毕，程序处于空闲状态时。

原因：
- 所有函数都已被解密
- 没有正在执行的函数（不会 dump 到不一致的状态）
- 内存布局稳定

### 6.2 避免的时机

| 时机 | 问题 |
|------|------|
| 程序刚启动时 | 很多函数还没被解密 |
| 正在执行某个功能时 | 可能有函数正在解密中，内存状态不一致 |
| 程序退出时 | 可能已经开始清理内存 |
| 反调试检测触发时 | 可能已经退出或崩溃 |

### 6.3 多次 dump 验证

为了确保 dump 完整，可以多次 dump 并对比：

```bash
# 第一次 dump（触发部分功能后）
dump code_v1.bin

# 触发更多功能
# ...

# 第二次 dump
dump code_v2.bin

# 对比
diff code_v1.bin code_v2.bin

# 如果有差异，说明第一次 dump 时有函数还没解密
# 继续触发功能，直到两次 dump 完全一致
```

## 7. Dump 后的验证

### 7.1 基本验证

```bash
# 检查文件大小
ls -lh decrypted_code.bin

# 检查文件类型
file decrypted_code.bin

# 检查熵（解密后代码熵应该较低，约5-6）
binwalk -E decrypted_code.bin

# 反汇编验证
objdump -d -b binary -m aarch64 decrypted_code.bin | head -50
```

### 7.2 函数验证

```gdb
# 在 dump 前，记录一些已知函数的地址
# 比如入口点解密后的地址

# dump 后，在 dump 文件中验证这些函数
# 反汇编对应偏移，看是否是正常函数
```

### 7.3 字符串验证

```bash
# 从 dump 中提取字符串
strings -a decrypted_code.bin | head -50

# 应该能看到解密后的明文字符串
# 比如 URL、路径、错误信息、函数名等
```

### 7.4 完整性验证

```bash
# 对比两次 dump 的 MD5
md5sum code_v1.bin code_v2.bin

# 如果一致，说明 dump 完整
# 如果不一致，说明还有函数没解密，继续触发功能
```

## 8. 常见问题与解决

### 问题1：dump 的代码仍然是加密的

**原因**：
- 功能没有全部触发，有些函数还没解密
- dump 的段不对，解密后代码在其他段
- 函数执行后被重新加密了

**解决**：
1. 确认所有功能都已触发
2. 用 `cat /proc/pid/maps` 确认解密后代码段的地址
3. 在统一解密器返回时下断点，确认解密后的代码地址
4. 多次 dump 对比，确保所有函数都已解密

### 问题2：dump 后无法反汇编

**原因**：
- dump 的起始地址不对（没有对齐到函数入口）
- dump 的是数据段，不是代码段
- 代码被混淆了（OLLVM）

**解决**：
1. 确认 dump 的段权限是 r-xp（可执行）
2. 从已知函数地址开始反汇编
3. OLLVM 混淆的代码需要先去混淆

### 问题3：程序运行时崩溃

**原因**：
- 反调试检测触发
- gdb 附加导致程序异常
- dump 操作影响了程序运行

**解决**：
1. 先绕过反调试（详见 `references/14-anti-debug-and-bypass.md`）
2. 用硬件断点代替软件断点
3. 用 Frida 代替 gdb（影响更小）
4. 在 dump 前暂停程序，dump 后恢复

### 问题4：无法触发某些功能

**原因**：
- 需要特定条件（如登录、付费、特定设备）
- 功能在后台线程中，UI 操作无法触发
- 功能已经被移除或禁用

**解决**：
1. 用 gdb/Frida 手动调用这些函数
2. 用静态方法解密这些函数
3. 接受不完整，优先 dump 主要功能

## 9. 完整流程总结

```
1. 环境准备
   ├─ 启动 Android 模拟器/真机
   ├─ 配置 root 权限
   ├─ 配置 gdb/Frida
   └─ 部署 T盾 样本

2. 启动程序
   ├─ 启动目标程序
   ├─ 获取 PID
   └─ 附加调试器（gdb/Frida）

3. 绕过反调试（如果需要）
   ├─ 识别反调试检测
   ├─ patch 反调试函数
   └─ 验证程序正常运行

4. 触发所有功能
   ├─ 手动操作所有功能菜单
   ├─ 或用 UI 自动化工具
   ├─ 或用 Monkey 压力测试
   └─ 确认所有函数都被调用

5. 分析内存映射
   ├─ cat /proc/pid/maps
   ├─ 识别解密后代码段（匿名 r-xp）
   ├─ 识别 payload 段
   └─ 记录所有关键段的地址范围

6. Dump 内存
   ├─ dump 解密后代码段
   ├─ dump payload 段
   ├─ dump 数据段
   └─ dump 动态链接段

7. 验证 dump
   ├─ 检查文件大小和类型
   ├─ 反汇编验证
   ├─ 字符串验证
   └─ 多次 dump 对比

8. 修复 ELF（详见 references/13-elf-repair.md）
   ├─ 修复 ELF 头
   ├─ 修复 Program Headers
   ├─ 重建 Section Headers
   ├─ 修复重定位
   └─ 修复导入表

9. 最终验证
   ├─ 用 IDA/Ghidra 加载修复后的文件
   ├─ 确认函数列表完整
   ├─ 确认字符串可见
   └─ 确认核心功能可分析
```

## 10. 工具脚本

详见 `scripts/memory_dumper.py`，功能包括：
- 自动获取进程内存映射
- 自动识别解密后代码段
- 批量 dump 所有关键段
- 生成 dump 报告
- 多次 dump 对比验证

使用方法：
```bash
python3 scripts/memory_dumper.py --pid <pid> --output ./dump_output/
python3 scripts/memory_dumper.py --package <package_name> --auto-trigger
python3 scripts/memory_dumper.py --verify dump1/ dump2/
```
