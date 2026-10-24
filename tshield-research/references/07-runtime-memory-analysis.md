# 运行时内存分析

## 1. 概述

T盾 加壳的程序运行时，内存布局与静态文件有很大差异。分析运行时内存是动态脱壳的关键。

## 2. 获取内存映射

### 2.1 /proc/pid/maps

```bash
# 获取进程内存映射
adb shell cat /proc/<pid>/maps > maps.txt
```

### 2.2 典型内存布局

T盾 程序运行后的典型内存布局：

```
地址范围            权限  路径
00000000-00927000  r-xp  /data/local/tmp/sample    (壳代码段)
00928000-00930000  rw-p  [anon:.bss]               (小数据段)
00930000-015da000  rw-p  [anon:.bss]               (大数据段)
015dc000-030d8000  r-xp  [anon:.scs]               (★解密后代码段★)
030d8000-05d6c000  r-xp  /data/local/tmp/sample    (payload段，含Stub+解密器)
05d6c000-05d72000  rw-p  /data/local/tmp/sample    (动态链接数据)
05d72000-05df5000  rw-p  /data/local/tmp/sample    (字符串/符号表)
...
[heap]
[stack]
/dev/ashmem
/system/lib64/*.so    (系统库)
```

### 2.3 关键段识别

| 段特征 | 识别方法 | 重要性 |
|--------|----------|--------|
| 匿名 r-xp 段 | path 为空，权限 r-xp | ⭐⭐⭐⭐⭐ 解密后代码 |
| 文件映射 r-xp 段 | path 指向样本文件 | ⭐⭐⭐⭐ payload段 |
| 匿名 rw-p 段 | path 为空，权限 rw-p | ⭐⭐⭐ 解密后数据 |
| [anon:scs] | 影子调用栈 | ⭐⭐ 可能是解密后代码 |

## 3. 内存内容分析

### 3.1 验证解密后代码

```gdb
# 在解密后代码段的起始地址反汇编
x/20i 0x015dc000

# 应该看到正常的 ARM64 指令：
# - 函数序言: stp x29, x30, [sp, #-0x20]!
# - bl 调用
# - 正常的算术/逻辑指令
# 而不是 Stub 模式: str x13/mov/movk/str/b
```

### 3.2 字符串提取

```bash
# 从内存 dump 中提取字符串
strings -a decrypted_code.bin | head -50

# 应该能看到：
# - URL、路径
# - 错误信息、日志
# - 函数名（如果未 strip）
# - 配置信息
```

### 3.3 函数识别

```python
# 识别 ARM64 函数序言
def find_functions(data, base_addr):
    functions = []
    # ARM64 函数序言常见模式:
    # stp x29, x30, [sp, #-N]!  = 0xa9b???7d (N 可变)
    # mov x29, sp                = 0x910003fd
    for i in range(0, len(data) - 8, 4):
        insn1 = struct.unpack_from('<I', data, i)[0]
        insn2 = struct.unpack_from('<I', data, i + 4)[0]
        # stp x29, x30, [sp, #-N]!
        if (insn1 & 0xffc003ff) == 0xa98003fd:
            # mov x29, sp 或其他指令
            functions.append(base_addr + i)
    return functions
```

## 4. 内存变化监控

### 4.1 对比两次 dump

```bash
# 第一次 dump（程序刚启动）
dump memory dump1.bin 0x015dc000 0x030d8000

# 触发一些功能后，第二次 dump
dump memory dump2.bin 0x015dc000 0x030d8000

# 对比
cmp dump1.bin dump2.bin
# 或用 vbindiff/010editor 可视化对比
```

### 4.2 监控内存写入

```gdb
# 在解密后代码段设置写入断点
watch *0x015dc000

# 当有写入时，说明有函数正在被解密
# 查看调用栈，确认是统一解密器在写入
bt
```

## 5. 内存 Dump 时机

### 5.1 最佳时机

- 所有功能都已触发完毕
- 程序处于空闲状态
- 没有正在执行的函数

### 5.2 避免的时机

- 程序刚启动（很多函数未解密）
- 正在执行功能（函数可能正在解密）
- 反调试触发后（程序可能已退出）

### 5.3 多次 Dump 验证

```bash
# 多次 dump，对比 MD5
# 如果两次 dump 完全一致，说明所有函数都已解密
md5sum dump1.bin dump2.bin
```

## 6. 工具

详见 `scripts/memory_dumper.py`，功能包括：
- 自动解析 /proc/pid/maps
- 自动识别解密后代码段
- 生成 gdb dump 脚本
- 生成 Frida dump 脚本
- 生成 dump 报告
