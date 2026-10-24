---
name: t3-kami-bypass
description: 对抗 T3 网络验证（t3yanzheng.com / t3data.net）卡密校验的绕过方案，适用于 T盾/T-Protector 加固、走 japi/w*.t3yanzheng.com 验证、需要 process_vm_writev 内存 patch 的 Android ELF 样本。覆盖协议还原、三把锁、流量分流、内存 patch、本机重放服务器、单文件部署与停机。触发词：t3yanzheng、T3验证、卡密绕过、T盾、T-Protector、杰尼龟类外挂样本。
agent_created: true
description_zh: 用于 t3-kami-bypass 相关工作流。
description_en: Skill for t3-kami-bypass workflows.
version: 1.0.0
author: Xiaotao
---

# T3 卡密验证对抗

## 原理

T3 是**服务端判定**，但结果最终要在客户端内存里做两次 if。
响应伪造不了（RSA 私钥签名），但可**重放曾经成功过的真实响应**；
重放过不了是因为有**时间戳锁 + token 锁** —— 这两把锁在内存里，用 `process_vm_writev` 改掉跳转即可。
不 attach、不注入、不触发壳检测。

## 边界（别往死路上撞）

| | | 原因 |
|---|---|---|
| 不要真实卡密 | ✅ | 卡密被 RSA 加密发出，本地不参与判定（实测虚构卡密登录成功） |
| 不联 T3 业务端点 | ✅ | 登录/公告/心跳全部本机重放 |
| 完全不联网 | ❌ | MRPCS（壳解密）必须真实服务器，机制性不可能 |
| 伪造/新造响应 | ❌ | 服务端私钥签的 RSA-1024，只能重放 |
| 永久有效期 | ⚠️ | 受录制响应 `end_time` 限制，过期需再 patch 到期检查 |

前提：root、能联网、有一份成功过的登录响应录制。

## 工作流

```
1 摸协议 + 三把锁   01-protocol-and-locks.md    端点/IP 池、为什么重放必失败
2 分流 + patch + 心跳  02-bypass-core.md         MRPCS 放行、两处跳转、login 兜底
3 打包交付 + 踩坑   03-deploy-and-pitfalls.md    三件套 / 快速通道 / 停机 / 15 条坑
```
完整案例 `04-case-jinli55.md`；壳的分析/脱壳见同级 `tshield-research` 包。

## 三个硬前置（缺一必败）

1. **目标游戏在跑**（`grep -l libunity.so /proc/*/maps` 有输出）—— 不在则样本空转永不解密
2. **MRPCS 期间零劫持** —— 顺序：起样本 → patch → **等 PATCH_OK** → 才挂劫持
3. **不能改 hosts** —— T-Protector 有反篡改检测，改了直接退出

## 通用 vs 案例特定（换样本必看）

| 项 | 通用？ | 说明 |
|---|---|---|
| 段首 `T-Protector\0` | ✅ | T盾标识，跨样本通用 |
| 段 **size 565248** | ⚠️ | 本样本实测。换样本先量一次再写死 |
| patch 偏移 `0x44e2c` / `0x45484` / `0x17a8c` | ❌ | **杰尼龟55 特定**。换样本必须重新定位 |
| T3 三个 IP、`jng55p.elf`、`/sdcard/jngkm55` | ❌ | 案例特定，在 `build_standalone.py` 里写死 |

**换样本的正确顺序**：先 `mempatch <pid> list` 量出真实段 size →
在被 patch 的函数附近反汇编找 `b.lo`/`b.eq` 校验分支 → 确认新偏移 →
再改 `mempatch.c` 的 `OFF_TS`/`OFF_TK`/`OFF_CHK` 和 size。
**别拿本包的偏移直接套**——跳错位置样本会崩或静默失效。

`build_standalone.py` 是**案例专用生成器**，复用要全局替换进程名/IP/路径。

## 关键不变量

- 段 **size 恒 565248**（本样本），段首 16 字节 = `T-Protector\0`；**基址每次都变，绝不能写死**
- 两处 patch 是段内偏移：`0x44e2c`（时间戳锁 `630a0054`→`53000014`）、
  `0x45484`（token 锁 → `1b000014 1f2003d5` ×3）
- 写入必须在登录请求前（启动约 7s），40ms 轮询够

## 录制响应从哪来（链路缺口）

`t3local.c` `#include "responses.h"` ← `gen_resp.py` 生成 ← 需要 `t3_sessions/`。
**这个目录包里没有**，要自己抓：设备端 `tcpdump -U` 跑一轮正常登录
（**必须加 `-U`**，`kill -9` 会丢最后几个报文，常缺 login 响应），
导出 pcap 后按「响应体」切出 `01/03/05` 等文件放进 `t3_sessions/`，
再跑 `gen_resp.py`。没有录制 = 没有可重放的内容 = 绕不过去。

## 排错顺序

```sh
pgrep -x <样本名>      # 1 数 pid：2 个 = 脚本被重复跑，必然卡死
cat $TMP/mp.log        # 2 有 PATCH_OK？TIMEOUT = 壳没解密（前置没满足）
tail -20 $TMP/run.log  # 3 最后才看脚本日志
```

## 工具（scripts/）

`mempatch.c` 扫描/读写/auto patch ｜ `t3local.c` 本机重放服务器 ｜
`gen_resp.py` 响应转 C 头 ｜ `build_standalone.py` 打包单文件自解压 .sh

## 踩坑（详见 `03-deploy-and-pitfalls.md` 的 15 条）

最致命三条：
1. Windows `SO_REUSEADDR` 让 bind 静默"成功" → 端口被占，一条流量都收不到
2. 样本 stdout 重定向是 4KB 块缓冲 → 日志空是**假阴性**
3. `pgrep -f` 会匹配 adb shell 自身导致**脚本自杀**，必须用 `pgrep -x`
