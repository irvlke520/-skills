# Android Overlay · 内核automation渲染端

完整的 Android Studio 工程。内核模块负责内存访问，JNI 层负责结构解析与投影，Java 层负责悬浮窗绘制，三层通过 ioctl 和 localhost TCP 解耦。

## 数据流

```
内核模块 (/dev/kmem_hub)
    │  ioctl: KMEM_READ
    ▼
libkernel_bridge.so          ← JNI，读矩阵/实体，做 W2S 投影
    │  TCP 127.0.0.1:61234
    ▼
OverlayService               ← SurfaceView 悬浮窗，只画矩形
    │
    ▼
屏幕
```

渲染层**完全不接触目标进程**。它只接收已经算好的屏幕坐标，这样绘制逻辑与数据来源彻底分离，也便于单独调试任一层。

## 目录

```
overlay/
├── settings.gradle / build.gradle / gradle.properties
├── gradle/wrapper/gradle-wrapper.properties
├── app/
│   ├── build.gradle                  compileSdk 36, minSdk 29, arm64-v8a
│   └── src/main/
│       ├── AndroidManifest.xml       SYSTEM_ALERT_WINDOW + service
│       ├── java/lab/overlay/
│       │   ├── KernelBridge.java     JNI 声明
│       │   ├── OverlayService.java   悬浮窗 + TCP 客户端 + 绘制
│       │   └── MainActivity.java     权限、配置、启停
│       ├── cpp/
│       │   ├── driver.h              ioctl 协议（需与内核模块一致）
│       │   ├── kernel_bridge.c       JNI + ioctl + 投影 + socket
│       │   └── CMakeLists.txt
│       └── res/                      layout / values
├── verify_project.py                 工程交叉校验
└── check_c.py                        C 语法编译检查
```

## 编译

需要：Android SDK 36、NDK（含 CMake 3.22.1+）、JDK 17。

```bash
cd overlay
./gradlew assembleDebug          # Linux/macOS
gradlew.bat assembleDebug        # Windows
```

或用 Android Studio 直接打开 `overlay/` 目录。

产物：`app/build/outputs/apk/debug/app-debug.apk`

## 内核模块对接

`cpp/driver.h` 定义的是**协议模板**，必须与你的模块实际实现一致：

```c
struct kmem_req {
    int32_t pid;
    uint32_t flags;
    uint64_t addr;
    uint64_t size;
    uint64_t buf;      // 用户态缓冲地址
};

#define KMEM_MAGIC 'k'
#define KMEM_READ  _IOWR(KMEM_MAGIC, 1, struct kmem_req)
#define KMEM_WRITE _IOWR(KMEM_MAGIC, 2, struct kmem_req)
#define KMEM_PID   _IOWR(KMEM_MAGIC, 3, struct kmem_req)
```

模块侧要实现：`KMEM_READ` 从目标进程 `pid` 的 `addr` 拷贝 `size` 字节到用户态 `buf`。

如果你的模块已经是别的结构，改 `driver.h` 即可，C 层其余部分不用动。设备路径默认 `/dev/kmem_hub`，在 `MainActivity.DEVICE` 改。

## 配置偏移

`MainActivity.java` 顶部这段是唯一需要为目标填的部分：

```java
private static final long MODULE_BASE = 0L;
private static final long MATRIX_OFF  = 0L;
private static final long ENTITY_BASE = 0L;
private static final int  STRIDE      = 0;
private static final int  COUNT       = 0;
private static final int  POS_OFF     = 0;
private static final int  HEALTH_OFF  = 0;
private static final int  TEAM_OFF    = 0;
private static final float BOX_RATIO  = 0.5f;
private static final float HEIGHT     = 1.8f;
```

用 `tools/android_tools.py` 定位：

```bash
python ../tools/android_tools.py ps    --filter <game>
python ../tools/android_tools.py maps  --pid <pid> --filter <so>
python ../tools/android_tools.py scan  --pid <pid> --module <so> --pattern "48 8B ?? ?? A1"
python ../tools/android_tools.py chain --pid <pid> --base <so>+0x1A2B3C --offsets "0x20,0x8,0x14"
```

- `MODULE_BASE`：从 maps 拿，`r-xp` 段起点
- `ENTITY_BASE`：填绝对地址（已解过指针链的）
- `BOX_RATIO`：框宽 / 框高，人物一般 0.5
- `HEIGHT`：实体世界高度

## 运行

```bash
# 1. 加载内核模块并放开设备权限
adb push drv.ko /sdcard/
adb shell su -c insmod /sdcard/drv.ko
adb shell su -c chmod 666 /dev/kmem_hub

# 2. 安装并授权悬浮窗
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell appops set lab.overlay SYSTEM_ALERT_WINDOW allow

# 3. 启动
adb shell am start -n lab.overlay/.MainActivity
```

App 里填目标 pid，点 Start。状态栏会显示 `running pid=... port=61234`。

日志：

```bash
adb logcat -s KernelBridge
```

## 校验

```bash
python verify_project.py     # 38 项交叉检查
python check_c.py            # gcc -fsyntax-only 真实语法检查
```

`check_c.py` 会生成桩头文件（MinGW 没有 Android/POSIX 的 socket、jni、ioctl 头），再调 gcc。只在开发机上做语法验证，Android 上的真实编译仍需 NDK。

**已验证**（本机实跑）：

| 项目 | 结果 |
|---|---|
| `verify_project.py` | PASS，38 项检查，0 错误 0 警告 |
| `check_c.py` | PASS，`-Wall -Wextra` 零警告零错误 |

**未验证**：未在真机上编译安装（本机无 Android SDK/NDK），`gradlew` 未执行过。

## 已知限制

- 驱动协议是模板，需按你的模块调整 `driver.h`
- 只画方框 + 距离，没有血条、骨骼、名称
- socket 只接受一个客户端，重连需等上一帧收尾
- 投影用 column-major / row-major 通用式（等价于 unity / opengl / directx），`source` 系引擎需改 `project()`
- 实体列表假设是连续数组（`base + i * stride`），链表结构要改遍历逻辑
- `nativeStop` 用 `pthread_join`，若驱动 ioctl 阻塞会有延迟
