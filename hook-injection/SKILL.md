---
name: hook-injection
description: 进程注入与 API/函数 Hook。覆盖 DLL 注入（CreateRemoteThread / 反射式 / 手动映射）、inline hook 与 trampoline、IAT/EAT hook、VEH 硬件断点、MinHook/Detours 用法、x64 长度反汇编、以及游戏函数 Hook（UE ProcessEvent / Unity IL2CPP）。Use when the user asks about 注入 DLL注入 hook inlinehook 钩子 IAT hook EAT hook 远程线程 反射式注入 手动映射 trampoline MinHook Detours 拦截函数 修改函数行为 VEH 硬件断点; or when they need code to run inside a target process.
description_zh: 用于 hook-injection 相关工作流。
description_en: Skill for hook-injection workflows.
version: 1.0.0
author: Xiaotao
---

# 注入与 Hook

**注入解决"怎么让代码跑进目标进程"，Hook 解决"怎么拦截/改写它的行为"。**

## 先选方案

| 目的 | 推荐方案 | 理由 |
|---|---|---|
| 只是想读内存 | **不需要注入** | 外部 `ReadProcessMemory` 够用，风险低 |
| 要每帧拿到引擎数据 | 注入 + Hook 引擎更新函数 | 外部读也要遍历结构，不如 Hook 直接拿 |
| 要改游戏逻辑 | inline hook | 唯一能改函数行为的方式 |
| 要隐藏自己 | 手动映射 / 反射式注入 | 不留下模块列表条目 |
| 只是想监视调用 | VEH / 硬件断点 | 不改代码，最难被检测 |

## 一、DLL 注入

### 1. CreateRemoteThread + LoadLibrary（最简单，也最容易被检测）
```cpp
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(h, mem, dllPath, len, NULL);
HANDLE t = CreateRemoteThread(h, NULL, 0,
    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW"),
    mem, 0, NULL);
WaitForSingleObject(t, INFINITE);
VirtualFreeEx(h, mem, 0, MEM_RELEASE);
```
**检测面**：模块列表里会出现你的 DLL（PEB Ldr 链表、工具能枚举）、`LoadLibrary` 调用被监控。

### 2. 手动映射 / 反射式注入（不出现在模块列表）
自己实现 PE 加载器：在目标进程分配内存 → 手写节表 → 重定位 → 解析导入表 → 调用入口点。

```cpp
// 核心步骤（简化）
// 1. 读 DLL 文件到内存（本地）
// 2. NtAllocateVirtualMemory 在目标分配 ImageSize
// 3. 按节表写入各节（.text/.rdata/.data）
// 4. 重定位：base = 分配地址, 遍历 .reloc
// 5. 解析导入表：LoadLibrary/GetProcAddress 逐个填 IAT
// 6. 设置正确内存保护（.text = PAGE_EXECUTE_READ）
// 7. CreateRemoteThread 到入口点（DllMain）
// 8. 抹掉 PE 头（可选，防内存扫描）
```
**注意**：TLS 回调、异常处理（SEH）、延迟导入都要自己处理，否则会崩。

### 3. 其他入口
- `SetWindowsHookEx`（需目标有消息循环，全局钩子广播）
- `QueueUserAPC`（需要目标线程进入可警告等待状态）
- `NtCreateThreadEx` + 直接 shellcode（不落 DLL 文件）
- 线程劫持（`SuspendThread` → 改 RIP → `ResumeThread`）

## 二、Inline Hook（改函数行为）

### x86/x64 基本做法
```cpp
// 目标函数开头覆写跳转
// x64:  FF 25 00 00 00 00  [8字节绝对地址]   (14 字节)
// x86:  E9 [4字节相对偏移]                   (5 字节)
```

**关键：x64 下必须做长度反汇编**，因为要覆盖的指令长度不定，不能简单覆盖 5 字节。

```cpp
// 1. 反汇编目标函数开头，累计长度 >= 14 字节（跳转指令大小）
// 2. 保存被覆盖的原始字节（stolen bytes）
// 3. 构造 trampoline：
//      [原始字节] + [跳回 目标函数+已覆盖长度]
// 4. 目标函数开头写入 [跳到 你的hook函数]
// 5. 调用原函数 = 调用 trampoline
```

### 用现成库（推荐）
- **MinHook**：轻量，支持 x86/x64，`MH_CreateHook` / `MH_EnableHook`
- **Detours**（微软）：功能全，支持事务式批量 hook

```cpp
// MinHook 典型用法
#include <MinHook.h>
typedef void (__fastcall* fnProcessEvent)(void* obj, void* func, void* params);
fnProcessEvent oProcessEvent = nullptr;

void __fastcall hkProcessEvent(void* obj, void* func, void* params) {
    // 你的逻辑：记录、过滤、修改参数
    return oProcessEvent(obj, func, params);
}

MH_Initialize();
MH_CreateHook((LPVOID)targetAddr, &hkProcessEvent, (LPVOID*)&oProcessEvent);
MH_EnableHook(MH_ALL_HOOKS);
```

### 常见坑
1. **指令被截断** —— 覆盖长度必须落在指令边界上，否则后面的字节变成非法指令 → 崩溃
2. **相对跳转/相对调用被搬走** —— trampoline 里的相对地址要重算
3. **多线程竞争** —— hook 的瞬间另一个线程正好执行到被改的字节 → 先 `SuspendThread` 所有线程
4. **递归/重入** —— hook 函数里又调用了被 hook 的函数 → 用 TLS 标记防重入
5. **W^X / CFG** —— 改 `.text` 要先 `VirtualProtect` 成可写，改完改回；CFG 会把你的跳板地址当非法间接调用目标（需绕过 CFG 或 hook 已验证的函数指针）

## 三、IAT / EAT Hook

不改代码段，只改导入地址表——**检测难度低但隐蔽性高**。

```cpp
// IAT hook：遍历目标模块的导入表，找到目标函数条目，改成你的地址
// 适用于：目标进程调用的系统 API（如 DirectX 的 Present、GetAsyncKeyState）
```

| | IAT Hook | Inline Hook |
|---|---|---|
| 改代码段 | 否 | 是 |
| 能 hook 内部函数 | ❌ 只能 hook 导入的函数 | ✅ 任意地址 |
| 被 CRC 检测 | ❌ 不易 | ✅ 容易 |
| 难度 | 低 | 高 |

**典型用途**：hook `IDXGISwapChain::Present` 或 `wglSwapBuffers` 来在每帧渲染后画 ESP（这是最常见的 overlay 注入点）。

## 四、VEH（向量化异常处理）与硬件断点

不改任何代码，用调试寄存器（DR0-DR3）下断点：

```cpp
// 1. AddVectoredExceptionHandler 注册异常处理
// 2. 设置线程 CONTEXT 的 Dr0 = 目标地址, Dr7 = 启用执行断点
// 3. 目标执行到该地址 → 触发 EXCEPTION_SINGLE_STEP
// 4. 在你的 handler 里读/改寄存器、内存
// 5. 恢复执行（设置单步或清除断点）
```

**优点**：零代码修改，内存扫描和 CRC 都发现不了。
**缺点**：只支持 4 个断点（DR0-DR3）；部分反runtime modification会检测调试寄存器被占用。

## 五、游戏引擎常见 Hook 点

| 引擎 | Hook 点 | 拿到的东西 |
|---|---|---|
| UE（任意版本） | `UObject::ProcessEvent` | 所有 UFunction 调用（开火、命中、移动） |
| UE | `UGameViewportClient::Draw` / `PostRender` | 每帧渲染回调（画 ESP） |
| UE | `APlayerController::SetViewTarget` / `UpdateRotation` | 视角（view-angle computation写入点） |
| Unity IL2CPP | 具体方法（dump 后按偏移量算地址） | 游戏逻辑函数 |
| Unity | `Camera::get_main` / 渲染循环 | 相机矩阵（W2S 用） |
| DirectX 通用 | `IDXGISwapChain::Present` | 每帧渲染（内挂 overlay） |
| OpenGL 通用 | `wglSwapBuffers` | 同上 |

## 六、注入后的自我保护（简述，详见 anti-analysis-evasion）

- 抹掉 PE 头（防 `MZ` 特征扫描）
- 抹掉 DLL 在 PEB Ldr 链表里的条目（断链）
- hook 函数返回后清理栈上的痕迹
- 用直接系统调用避免被用户态 hook 拦截

## 验证清单

- [ ] 注入后目标进程没崩（先在不重要的进程上试）
- [ ] hook 函数被调用到了（打日志或弹提示验证）
- [ ] 调用原函数（trampoline）不会死循环
- [ ] 覆盖长度落在指令边界（用反汇编器确认）
- [ ] 卸载 hook 能恢复原样（否则进程退出时崩）
- [ ] 多线程场景稳定（跑几分钟不崩）

## 常见坑补充

1. **x64 fastcall** —— 前 4 个参数在 RCX/RDX/R8/R9，hook 函数签名必须匹配，否则栈错乱
2. **浮点参数** —— 在 XMM0-XMM3，别当整数寄存器处理
3. **栈对齐** —— x64 调用约定要求调用前 RSP 16 字节对齐，shellcode 里最容易漏
4. **被反runtime modification的 hook 检测** —— 常见检查：模块列表、`.text` CRC、跳板地址是否在合法模块内、线程起始地址
