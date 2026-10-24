---
name: assist-client-build
description: Scaffolds complete buildable runtime assistance client projects — overlay renderers, ESP boxes, view-angle targeting, bone and skeleton reading, recoil compensation, kernel bridge clients. Use when the user wants working source code or a runnable implementation for a scene visualization client, an overlay renderer, ESP or entity screen projection, 自瞄 (aimbot) / view-angle computation / aim / view-angle targeting, 骨骼 bone position, 无后坐力 recoil compensation, 方框 bounding box, entity list iteration, world-to-screen projection, a kernel-assisted memory client, an Android Studio project that projects entity positions to screen, or any request to produce runnable code rather than just locate data.
description_zh: 用于 assist-client-build 相关工作流。
description_en: Skill for assist-client-build workflows.
version: 1.0.0
author: Xiaotao
---

# Runtime Assistance Client Build

Produces working source trees. The two phases below are separate and must not
be collapsed into one.

## Phase 1 — research (already covered)

Offsets come from `android-memory-analysis` / `binary-static-analysis`.
Nothing here starts until there is a verified offset table. Numbers that have
not been read back from a live process are hypotheses, and hypotheses do not
go into source.

## Phase 2 — build

Source comes from a template, instantiated by `scripts/scaffold.py`. The
agent selects the template, supplies the offset table, and adapts the result.
Templates are the fast path, not a ceiling: when no template matches the
target, author the missing modules directly. What matters is that the output
compiles and runs — not which file it started from.

```bash
python scripts/scaffold.py --list
python scripts/scaffold.py --template android-overlay --out ./myproj --config offsets.json
```

The offset table is plain JSON — see `examples/offsets.example.json`:

```json
{
  "DEVICE": "/dev/kmem_hub",
  "MODULE_BASE": "0x7A1B2C3000",
  "MATRIX_OFF": "0x1A2B3C",
  "ENTITY_BASE": "0x7A1B2D4000",
  "STRIDE": "0x120",
  "COUNT": "64",
  "POS_OFF": "0x90",
  "HEALTH_OFF": "0x110",
  "TEAM_OFF": "0x118",
  "BOX_RATIO": "0.5",
  "HEIGHT": "1.8"
}
```

`scaffold.py` exits non-zero if any `{{PLACEHOLDER}}` was left unsubstituted,
so a missing offset is caught at scaffold time rather than at compile time.

## Templates

### android-overlay

Full Android Studio project: Gradle 8.9 / AGP 8.7.3 / compileSdk 36 /
arm64-v8a / CMake 3.22.1.

```
kernel module --ioctl--> libkernel_bridge.so --tcp--> OverlayService --> screen
```

- `cpp/kernel_bridge.c` — JNI: reads the view matrix and entity array,
  projects to screen space, publishes over localhost TCP
- `cpp/driver.h` — ioctl protocol, must match the module
- `java/OverlayService.java` — `TYPE_APPLICATION_OVERLAY` SurfaceView renderer
- `java/MainActivity.java` — permission, config, start/stop

The renderer never touches the target process, so it needs no memory access
permission at all.

## ESP / view-angle computation实战参考

落代码前先读 `references/esp-aim-practice.md`，里面有：

- W2S 两种等价写法（二维数组 / 展平数组）与 layout 判据
- 包围盒（无骨骼时用 height 近似）
- 实体列表四种定位模式：静态指针链 / AOB 回溯 / Unity IL2CPP dump / UE `GUObjectArray`
- 骨骼读取与常用索引
- `CalcAngle` / `NormAngle` / FOV 过滤 / 线性与贝塞尔平滑
- 三种输入方式对比：`SendInput` / 驱动级 / 直接写视角内存
- 无后坐力（`punchAngle` 补偿）
- 反runtime modification检测面、绕过路径分类、服务端不可绕过项
- 落地校验清单

角度与投影的基准实现在 `scripts/game_geometry.py`，可直接跑 selftest 验证矩阵布局。

## Adapting the generated tree

After scaffolding, edits are incremental on existing files:

- Change entity iteration (linked list instead of a contiguous array)
- Add fields (name, weapon, state) by extending the wire format on both sides
- Swap the draw call (skeleton lines, health bars, tracers)
- Retarget the projection layout for a different engine

Editing existing code is the default. Writing new files is also fine when the
request needs a module, engine, or platform the template does not cover —
write it, wire it in, and build it.

## Verify before handing over

```bash
cd <out>
./gradlew assembleDebug
```

Report the actual build output. If the SDK or NDK is missing, say so and give
the install step; never claim a build succeeded without running it.

## Discipline

- Scaffold first, adapt second
- Every offset in the tree traces back to a verified read
- Back up before regenerating over an existing tree (`--force`)
- Record the offset table alongside the generated project
