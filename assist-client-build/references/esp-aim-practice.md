# ESP / view-angle computation实战参考

写给「已经拿到偏移，要落代码」这一步。前面的定位工作由
`android-memory-analysis` / `windows-memory-analysis` / `binary-static-analysis` 完成。

---

## 1. 世界坐标 → 屏幕

### 矩阵从哪来

- 静态地址：`module_base + VIEW_MATRIX_OFFSET`
- 动态：扫 `ViewMatrix` 字符串附近，或对矩阵更新代码做 AOB
- Unity IL2CPP：通常在 `Camera.main` 或渲染器单例下
- UE：`PlayerController → PlayerCameraManager → CameraCache`

### 投影（两种写法等价，已验证）

C 二维数组写法：

```cpp
bool WorldToScreen(Vec3 p, Vec2& out, float m[4][4], int sw, int sh) {
    float w = m[0][3]*p.x + m[1][3]*p.y + m[2][3]*p.z + m[3][3];
    if (w < 0.001f) return false;              // 在相机背后
    float x = m[0][0]*p.x + m[1][0]*p.y + m[2][0]*p.z + m[3][0];
    float y = m[0][1]*p.x + m[1][1]*p.y + m[2][1]*p.z + m[3][1];
    out.x = sw * 0.5f + sw * 0.5f * x / w;
    out.y = sh * 0.5f - sh * 0.5f * y / w;
    return true;
}
```

展平数组写法（`float m[16]`，行主序）——**与上式完全等价**：

```cpp
float w  = m[3]*p.x + m[7]*p.y  + m[11]*p.z + m[15];
float cx = m[0]*p.x + m[4]*p.y  + m[8]*p.z  + m[12];
float cy = m[1]*p.x + m[5]*p.y  + m[9]*p.z  + m[13];
out.x = (cx / w * 0.5f + 0.5f) * sw;
out.y = (-cy / w * 0.5f + 0.5f) * sh;
```

**关键事实**：`directx` / `opengl` / `unity` / `source` 四种约定化简后都是这个表达式，
差别只在上游的左右手系。只有 `rowcol`（行主序存储 + 列向量数学 `M*v`）不同：

```cpp
cx = m[0]*x + m[1]*y + m[2]*z  + m[3];
cy = m[4]*x + m[5]*y + m[6]*z  + m[7];
cw = m[12]*x + m[13]*y + m[14]*z + m[15];
```

判据：屏幕中心 (0,0,-5) 应投到 `(sw/2, sh/2)` 且 `w == 5.0`。投不出来就换 layout 试四种。

### 包围盒（没有骨骼时）

```cpp
Vec3 head = { feet.x, feet.y + height, feet.z };   // height 单位跟世界坐标一致
Vec2 sFeet, sHead;
W2S(feet, sFeet, m, sw, sh); W2S(head, sHead, m, sw, sh);
float boxH = sFeet.y - sHead.y;
float boxW = boxH * 0.4f;      // 0.35~0.5 之间按观感调
```

---

## 2. 实体列表怎么找

| 模式 | 做法 |
|---|---|
| 静态指针链 | `base+OFF1 → A`，`A+OFF2 → EntityManager`，`+0x8` 列表，`+0x10` 数量 |
| AOB 回溯 | 对已知坐标下写断点 → 看谁写的 → 反推基址链 |
| Unity IL2CPP | Il2CppDumper 出 `dump.cs`，搜 `PlayerController` / `EntityManager` |
| UE | `GUObjectArray + 0x10` 是 `FUObjectItem` 数组，`+0x14` 是数量 |

### Unity IL2CPP 典型布局

```cpp
struct PlayerController {
    char   pad_0000[0x48];
    Vec3   position;      // 0x48
    char   pad_0054[0x0C];
    float  health;        // 0x60
    int    teamId;        // 0x78
};
```

偏移**必须按目标 dump 出来的为准**，上面只是常见形态。

### 骨骼

```cpp
Vec3 GetBonePos(uintptr_t ent, int idx) {
    uintptr_t list = RPM<uintptr_t>(ent + BONE_ARRAY_OFFSET);
    uintptr_t bone = RPM<uintptr_t>(list + idx * 0x8);
    uintptr_t mat  = RPM<uintptr_t>(bone + 0x38);
    return RPM<Vec3>(mat + 0x68);   // local-to-world 的平移列
}
```

常用索引（按游戏，用 dump.cs 核对）：`HEAD=7  NECK=6  CHEST=5  PELVIS=0  L_HAND=20  R_HAND=15`

---

## 3. 角度计算

```cpp
struct Vec2 { float pitch, yaw; };   // 单位：度

Vec2 CalcAngle(Vec3 from, Vec3 to) {
    Vec3 d = { to.x-from.x, to.y-from.y, to.z-from.z };
    float dist = sqrtf(d.x*d.x + d.y*d.y + d.z*d.z);
    return { -asinf(d.y / dist) * (180.f/3.14159265f),
              atan2f(d.x, d.z)  * (180.f/3.14159265f) };
}

float NormAngle(float a) {
    while (a >  180.f) a -= 360.f;
    while (a < -180.f) a += 360.f;
    return a;
}
```

注意 pitch 的符号：上式假设 +Y 向上、yaw 从 +Z 轴起算。有的引擎 pitch 要取反，
用「目标在正上方时应输出 pitch = -90」这条做校验。

### FOV 过滤与选靶

```cpp
float FOVDist(Vec2 s, int sw, int sh) {
    float dx = s.x - sw*0.5f, dy = s.y - sh*0.5f;
    return sqrtf(dx*dx + dy*dy);
}
// 半径换算：fovRadius_px = tan(fov_deg/2) / tan(camFov/2) * (sw/2)
```

选靶顺序：先按 `isAlive && teamId != localTeam` 过滤 → 投影成功的按 FOV 距离排序取最小。

### 平滑

```cpp
// 线性：factor 越大越慢
cur.x += (tgt.x - cur.x) / factor;
cur.y += (tgt.y - cur.y) / factor;

// 贝塞尔：走弧线，更接近人手
Vec2 Bezier(Vec2 s, Vec2 e, Vec2 c, float t) {
    float u = 1.f - t;
    return { u*u*s.x + 2*u*t*c.x + t*t*e.x,
             u*u*s.y + 2*u*t*c.y + t*t*e.y };
}
```

---

## 4. 输入方式

| 方式 | 说明 |
|---|---|
| `SendInput` / `mouse_event` | 最常见，内核 AC 普遍挂钩，易被识别 |
| 驱动级鼠标 | 绕过 `SendInput` 钩子（interception 驱动、GHUB 手法等） |
| 直接写视角内存 | 最安静。算出角度写回 `viewAngles` 地址，不发输入事件 |

写视角内存时注意：多数引擎对 pitch 有 clamp（通常 ±89），且有的用弧度不是度。

### 无后坐力

```cpp
Vec2 view  = RPM<Vec2>(localPlayer + VIEW_ANGLE_OFFSET);
Vec2 punch = RPM<Vec2>(localPlayer + PUNCH_ANGLE_OFFSET);
Vec2 delta = { (prev.x - punch.x) * 2.f, (prev.y - punch.y) * 2.f };
MoveMouse(delta.y, delta.x);      // 补偿量
prev = punch;
```

`*2.f` 是 Source 引擎的惯例系数，其他引擎要实测（`punchAngle` 与视角的比例）。

---

## 5. 反runtime modification检测面

| AC | 层级 | 主要手段 |
|---|---|---|
| BattlEye | 内核 | 驱动扫描、内存扫描、截图哈希 |
| 商业完整性保护 | 内核 | 模块扫描、完整性校验、行为 |
| Vanguard | 内核（开机启动） | 虚拟机监控程序级 |
| VAC | 用户层 | 周期性进程内存扫描 |
| PunkBuster | 用户层 | 截图、进程列表、文件扫描 |
| ACE（腾讯） | 内核 | 类 BE/EAC |

检测分三类：

1. **内存扫描** — 特征码、代码完整性、注入 DLL
2. **进程/模块检查** — 模块枚举、手动映射（无 LDR 项）、ntdll 钩子
3. **行为** — 鼠标轨迹过于完美、速度/位置异常、来自未知线程的内存访问

## 6. 绕过路径（研究分类）

1. **内核驱动（ring-0）** — 借有漏洞的签名驱动（BYOVD）加载；或直接读物理内存规避内核读检测
2. **DMA（PCIe 硬件）** — 从硬件层读目标内存，对任何软件 AC 不可见；需要物理硬件
3. **手动映射** — DLL 不进 `PEB.Ldr` 的 `InMemoryOrderModuleList`，自己解导入和重定位
4. **虚拟机监控程序** — 拦截 `RDMSR`/`CPUID`/页表查询，伪造硬件 ID、隐藏内存区

## 7. 服务端检测（客户端无法绕过）

- 位置 / 速度 / 伤害校验
- 跨会话命中率统计
- 输入到动作的时序分析

这几项只能靠**行为拟真**降低风险（随机化平滑、限制触发率、加人类噪声），
不存在技术手段绕开。写之前先接受这一点。

---

## 校验清单

落地后逐条确认：

- [ ] 屏幕中心投影到 `(sw/2, sh/2)`，`w` 等于 -z
- [ ] 目标在相机背后时 `w <= 0` 被剔除，不出现镜像点
- [ ] 距离越远方框越小，且贴合人物高度
- [ ] 队伍过滤正确（队友不画 / 换色）
- [ ] 目标消失后不残留上一帧方框
- [ ] view-angle computation不会在准星已命中时抖动（加死区）
- [ ] pitch 被 clamp 在引擎允许范围内
