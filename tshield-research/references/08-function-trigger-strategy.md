# 功能触发策略

## 1. 概述

T盾 是函数级加密，每个函数第一次被调用时才解密。要完整脱壳，必须触发所有函数的执行。

## 2. 为什么需要触发所有功能

### 2.1 函数级加密的特点

```
函数A（被调用）→ 统一解密器解密 → 内存中明文 ✓
函数B（未调用）→ 仍在 payload 段中加密 → 内存中密文 ✗
```

如果不触发所有功能，dump 的内存中会缺少未解密的函数，导致脱壳不完整。

### 2.2 未解密函数的影响

- IDA 中函数列表不完整
- 某些功能的代码缺失
- 交叉引用断裂
- 无法完整分析程序逻辑

## 3. 触发方法

### 3.1 手动操作（最可靠）

**步骤**：
1. 启动程序
2. 进入每个功能菜单
3. 点击每个按钮/选项
4. 进入每个子页面
5. 执行每个操作（不仅要进入，还要实际执行）
6. 返回主菜单，继续下一个功能
7. 重复直到所有功能都被触发

**注意事项**：
- 不仅要进入功能页面，还要实际执行操作（让函数被调用）
- 有些函数可能在特定条件下才被调用（错误处理、超时处理）
- 有些函数可能在后台线程中被调用（网络请求、定时任务）
- 设置页面、关于页面、帮助页面也要进入

### 3.2 UI 自动化

**工具**：uiautomator2、Appium、ADB Monkey

**uiautomator2 示例**：
```python
import uiautomator2 as u2
import time

d = u2.connect()

# 启动应用
d.app_start("<package_name>")
time.sleep(3)

def click_all_clickable(depth=0, max_depth=3):
    """递归点击所有可点击元素"""
    if depth > max_depth:
        return
    
    # 获取所有可点击元素
    elements = d(resourceId="")
    clicked = set()
    
    for elem in elements:
        try:
            if elem.clickable and elem.info.get('text', '') not in clicked:
                text = elem.info.get('text', '')
                clicked.add(text)
                print(f"  {'  '*depth}点击: {text}")
                elem.click()
                time.sleep(1)
                
                # 递归处理子页面
                click_all_clickable(depth + 1, max_depth)
                
                # 返回
                d.press("back")
                time.sleep(0.5)
        except Exception as e:
            pass

click_all_clickable()
```

### 3.3 Monkey 压力测试

```bash
# 使用 Android Monkey 工具随机触发
adb shell monkey -p <package_name> -v 10000

# 指定事件类型比例
adb shell monkey -p <package_name> \
    --pct-touch 50 \
    --pct-motion 20 \
    --pct-nav 10 \
    --pct-majornav 10 \
    --pct-appswitch 10 \
    -v 5000
```

**优点**：简单快速，能触发很多边缘情况
**缺点**：随机，可能无法触发所有功能，可能导致崩溃

### 3.4 代码覆盖分析

**方法**：用工具监控哪些函数被调用了

```gdb
# gdb 方法：批量下断点
# 1. 从 Stub 提取器获取所有函数ID和 Stub 地址
# 2. 对每个 Stub 地址下断点
# 3. 运行程序，记录哪些断点被命中

# 示例脚本
break *0x4be1920
commands
    silent
    printf "函数被调用: 入口点 (0xb3062fe8)\n"
    continue
end
```

## 4. 特殊函数的触发

### 4.1 错误处理函数

- 输入无效数据
- 断网操作
- 权限拒绝
- 内存不足（难以触发）

### 4.2 后台线程函数

- 等待定时任务执行
- 触发网络请求
- 切换应用再切回
- 锁屏再解锁

### 4.3 初始化/清理函数

- 启动时自动调用（INIT_ARRAY）
- 退出时调用（FINI_ARRAY）
- 模块加载/卸载时调用

## 5. 未解密函数的处理

如果某些函数无法通过正常操作触发：

### 方法1：手动调用

```gdb
# 用 gdb 手动调用函数
# 需要知道函数地址和参数
call (void)0x<function_addr>()
```

### 方法2：静态解密

- 对未解密的函数，用静态方法解密（详见 05-encryption-algorithm.md）
- 需要先逆向加密算法

### 方法3：接受不完整

- 如果某些函数不重要，可以接受 dump 不完整
- 在报告中说明哪些函数未解密

## 6. 触发完整性验证

### 6.1 多次 Dump 对比

```bash
# 第一次 dump
dump code1.bin

# 触发更多功能
# ...

# 第二次 dump
dump code2.bin

# 对比 MD5
md5sum code1.bin code2.bin

# 如果一致，说明所有函数都已解密
# 如果不一致，继续触发功能
```

### 6.2 函数数量对比

- 静态分析：从 Stub 提取器获取函数总数
- 动态分析：从 dump 中识别函数数量
- 如果动态函数数 < 静态函数数，说明有函数未解密

## 7. 触发清单模板

```
[ ] 启动应用（触发 INIT_ARRAY 函数）
[ ] 主页面所有按钮
[ ] 每个功能菜单
[ ] 每个子页面
[ ] 设置页面所有选项
[ ] 关于/帮助页面
[ ] 搜索功能
[ ] 分享功能
[ ] 登录/注册
[ ] 个人中心
[ ] 网络请求（触发后台线程）
[ ] 错误情况（无效输入、断网）
[ ] 退出应用（触发 FINI_ARRAY 函数）
[ ] 多次启动/退出（确保所有初始化函数被调用）
```
