# 反调试与绕过

基于 T盾 样本的实际分析结果。

## 1. T盾 常见反调试检测

### 1.1 ptrace 检测

**原理**：进程调用 `ptrace(PTRACE_TRACEME, ...)`，如果已经被调试器附加，调用会失败。

```c
if (ptrace(PTRACE_TRACEME, 0, NULL, 0) < 0) {
    // 已经被调试，退出
    exit(1);
}
```

**识别特征**：
- 导入 `ptrace` 函数
- 调用 `ptrace(PTRACE_TRACEME, ...)`
- 调用失败后 `exit`/`kill`

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook ptrace | 让 `PTRACE_TRACEME` 总是返回0 |
| 补丁条件分支 | 把检测后的条件分支改为无条件跳转 |
| 补丁函数返回 | 在函数开始处直接返回0 |
| 硬件调试器 | 用硬件调试器（如 JTAG），不通过 ptrace |

**Hook 示例（Frida，需授权注入）**：
```javascript
const ptrace = Module.findExportByName(null, "ptrace");
Interceptor.attach(ptrace, {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) {  // PTRACE_TRACEME
            retval.replace(0);  // 总是返回成功
        }
    }
});
```

### 1.2 TracerPid 检测

**原理**：读取 `/proc/self/status`，检查 `TracerPid` 字段，如果非0说明被调试。

```c
FILE *f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) {
            exit(1);  // 被调试
        }
    }
}
```

**识别特征**：
- 打开 `/proc/self/status`
- 搜索 `TracerPid:` 字符串
- 解析后比较是否为0

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook fopen/read | 修改 `/proc/self/status` 的内容，让 TracerPid 为0 |
| 补丁条件分支 | 把检测后的条件分支改为无条件跳转 |
| 修改 /proc | 用修改过的 /proc 文件系统（如在容器中） |

**Hook 示例（Frida）**：
```javascript
// Hook fopen，当打开 /proc/self/status 时返回修改后的内容
const fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        const path = args[0].readUtf8String();
        if (path && path.includes("/proc/self/status")) {
            this.isStatus = true;
        }
    },
    onLeave: function(retval) {
        if (this.isStatus) {
            // 可以在这里替换文件内容
            // 或者 hook fread 来修改读取的内容
        }
    }
});
```

### 1.3 /proc/self/maps 扫描

**原理**：读取 `/proc/self/maps`，检查是否有调试器/注入工具的库被映射（如 frida-agent.so、libxposed.so、libhook.so）。

```c
FILE *f = fopen("/proc/self/maps", "r");
char line[512];
while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "frida") || strstr(line, "xposed") || 
        strstr(line, "hook") || strstr(line, "substrate")) {
        exit(1);  // 检测到注入工具
    }
}
```

**识别特征**：
- 打开 `/proc/self/maps`
- 搜索调试器/注入工具名称
- 常见关键词：frida、xposed、hook、substrate、magisk、zygisk

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook fopen/read | 过滤包含关键词的行 |
| 重命名注入库 | 把 frida-agent.so 重命名为正常名称 |
| 内核级隐藏 | 用内核模块隐藏特定的内存映射 |

### 1.4 父进程检测

**原理**：读取 `/proc/self/status` 的 `PPid`，然后读取父进程的 `/proc/<ppid>/comm`，检查是否是调试器（gdb、lldb、strace等）。

```c
int ppid = getppid();
char path[256];
sprintf(path, "/proc/%d/comm", ppid);
FILE *f = fopen(path, "r");
char comm[256];
fgets(comm, sizeof(comm), f);
if (strstr(comm, "gdb") || strstr(comm, "lldb") || strstr(comm, "strace")) {
    exit(1);  // 父进程是调试器
}
```

**识别特征**：
- 调用 `getppid()`
- 打开 `/proc/<ppid>/comm`
- 比较调试器名称

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook getppid | 返回假的 PPID |
| Hook fopen/read | 修改父进程名称 |
| 重命名调试器 | 把 gdb 重命名为正常名称 |

### 1.5 时间差检测

**原理**：在代码段前后记录时间，如果执行时间超过阈值，说明被单步调试。

```c
struct timeval start, end;
gettimeofday(&start, NULL);
// 关键代码段
gettimeofday(&end, NULL);
long elapsed = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
if (elapsed > 1000) {  // 超过1ms，可能被单步
    exit(1);
}
```

**识别特征**：
- 调用 `gettimeofday`/`clock_gettime`/`time`
- 两次调用之间有代码
- 比较时间差

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook 时间函数 | 返回假的时间，让时间差总是很小 |
| 补丁时间比较 | 把时间比较后的条件分支改为无条件跳转 |
| 硬件断点 | 用硬件断点代替单步（不影响执行时间） |

### 1.6 断点检测（内存扫描）

**原理**：读取自身代码段的内存，检查是否有断点指令（x86的 `0xCC`，ARM的 `0xD4200000`）。

```c
// 检查函数开始是否被替换为断点
unsigned char *func = (unsigned char *)target_function;
if (func[0] == 0xCC) {  // x86 int3
    exit(1);  // 被下了断点
}
```

**ARM64 断点指令**：
- `BRK #0`：`0xD4200000`
- `HLT #0`：`0xD4400000`

**识别特征**：
- 读取自身代码段内存
- 比较断点指令
- 可能计算代码哈希

**绕过方法**：

| 方法 | 说明 |
|------|------|
| 硬件断点 | 用硬件断点代替软件断点（不修改内存） |
| Hook 内存读取 | 返回原始字节 |
| 补丁检测逻辑 | 跳过断点检测 |

### 1.7 信号陷阱

**原理**：安装信号处理器，主动触发断点信号（SIGTRAP），如果信号处理器被调用，说明没有被调试（调试器会拦截信号）。

```c
signal(SIGTRAP, sigtrap_handler);
raise(SIGTRAP);
// 如果 sigtrap_handler 被调用，说明没有被调试
// 如果被调试，调试器会拦截 SIGTRAP，处理器不会被调用
```

**识别特征**：
- 调用 `signal`/`sigaction` 安装 SIGTRAP 处理器
- 调用 `raise(SIGTRAP)` 或执行断点指令
- 检查处理器是否被调用

**绕过方法**：

| 方法 | 说明 |
|------|------|
| 配置调试器传递信号 | `gdb: handle SIGTRAP pass` |
| 补丁信号检测 | 跳过信号检测逻辑 |

### 1.8 多线程反调试

**原理**：创建一个独立线程，持续检测调试状态，即使主线程被调试，检测线程也能发现并退出。

```c
void *anti_debug_thread(void *arg) {
    while (1) {
        // 检测 ptrace
        if (ptrace(PTRACE_TRACEME, 0, NULL, 0) < 0) {
            kill(getpid(), 9);
        }
        // 检测 TracerPid
        // 检测 /proc/self/maps
        sleep(1);
    }
}
pthread_create(&thread, NULL, anti_debug_thread, NULL);
```

**识别特征**：
- 调用 `pthread_create`
- 线程函数中有反调试检测
- 检测到调试后 `kill(getpid(), 9)`

**绕过方法**：

| 方法 | 说明 |
|------|------|
| Hook pthread_create | 不创建反调试线程 |
| 补丁线程函数 | 在线程函数开始处直接返回 |
| Hook kill | 阻止自杀 |
| 冻结线程 | `gdb: set scheduler-locking on` |

## 2. 反调试检测的定位方法

### 2.1 静态定位

#### 方法1：导入表分析

```bash
# 查看导入的反调试相关函数
readelf -d sample.elf | grep -E "ptrace|gettimeofday|signal|kill"
nm -D sample.elf | grep -E "ptrace|gettimeofday|signal|kill|exit"
```

#### 方法2：字符串分析

```bash
# 搜索反调试相关字符串
strings -a sample.elf | grep -E "/proc/self|TracerPid|gdb|lldb|strace|frida|xposed"
```

#### 方法3：交叉引用

- 对 `ptrace`、`gettimeofday`、`fopen`（/proc路径）做交叉引用
- 找到调用这些函数的函数，这些函数很可能是反调试检测

### 2.2 动态定位

#### 方法1：函数断点

```gdb
# 在反调试相关函数下断点
break ptrace
break gettimeofday
break fopen
break kill

# 运行，看哪些地方调用了这些函数
continue
```

#### 方法2：系统调用跟踪

```bash
# 跟踪系统调用
strace -f -e trace=ptrace,openat,read,gettimeofday,kill ./sample

# 跟踪库调用
ltrace -f -e ptrace+gettimeofday+fopen+signal+kill ./sample
```

#### 方法3：调用栈分析

```gdb
# 在反调试函数下断点，命中时查看调用栈
break ptrace
commands
    silent
    bt
    continue
end
```

## 3. 绕过策略

### 3.1 策略一：Hook 函数（推荐）

用 `LD_PRELOAD` 或 Frida hook 反调试函数，让它们返回"正常"结果。

**优点**：
- 不需要修改二进制文件
- 可以动态启用/禁用
- 适用于多个反调试检测

**缺点**：
- 需要注入权限
- 可能被检测到（/proc/maps 扫描）

### 3.2 策略二：补丁条件分支

在反调试检测后，把条件分支改为无条件跳转，跳过失败路径。

**优点**：
- 不需要注入
- 补丁后可以独立运行

**缺点**：
- 需要修改二进制文件
- 可能有完整性校验
- 需要找到所有反调试检测点

### 3.3 策略三：补丁函数返回

在反调试函数开始处直接返回"正常"结果。

**优点**：
- 补丁范围小
- 不容易影响其他逻辑

**缺点**：
- 需要找到所有反调试函数
- 可能有完整性校验

### 3.4 策略四：硬件断点/硬件调试器

用硬件断点代替软件断点，用硬件调试器（如 JTAG）代替 ptrace。

**优点**：
- 不修改内存（不会被断点检测发现）
- 不通过 ptrace（不会被 ptrace 检测发现）
- 最难被检测到

**缺点**：
- 需要硬件支持
- 配置复杂

## 4. T盾 反调试的特点

### 4.1 反调试代码被加密

T盾 的反调试代码也被函数级加密，静态分析时看不到，需要动态分析或先脱壳。

### 4.2 多线程检测

T盾 可能使用多线程反调试，一个线程被调试还有其他线程检测。

### 4.3 运行时完整性校验

T盾 可能校验自身代码的哈希，发现被补丁就退出。

### 4.4 反 Frida/Xposed 检测

T盾 可能检测 Frida、Xposed 等注入框架的特征。

## 5. 完整绕过流程

```
1. 静态分析
   ├─ 导入表分析（ptrace/gettimeofday/signal/kill）
   ├─ 字符串分析（/proc/self/TracerPid/gdb/frida）
   └─ 交叉引用（找到反调试函数）

2. 动态分析
   ├─ 函数断点（在反调试函数下断点）
   ├─ 系统调用跟踪（strace/ltrace）
   └─ 调用栈分析（找到调用反调试函数的地方）

3. 选择绕过策略
   ├─ Hook 函数（Frida/LD_PRELOAD）
   ├─ 补丁条件分支
   ├─ 补丁函数返回
   └─ 硬件断点/硬件调试器

4. 实施绕过
   ├─ 编写 Hook 脚本/补丁脚本
   ├─ 应用绕过
   └─ 验证绕过效果

5. 验证
   ├─ 程序正常运行（不退出/不崩溃）
   ├─ 可以正常下断点/单步
   ├─ 可以正常 dump 内存
   └─ 没有其他反调试检测触发
```

## 6. 注意事项

1. **反调试检测可能有多个**：需要全部绕过，漏掉一个就会失败
2. **检测可能嵌套**：一个检测函数可能调用另一个
3. **可能有运行时完整性校验**：补丁后可能被检测到
4. **可能有服务端验证**：客户端反调试只是第一层
5. **绕过反调试仅用于授权的安全研究**：不得用于破解商业软件或制作外挂
6. **遵守法律法规**：逆向分析和调试需要获得合法授权
