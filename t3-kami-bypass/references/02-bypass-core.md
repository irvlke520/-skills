# 绕过核心：分流 + 内存 patch + 心跳

## 一、流量分流（最易翻车）

> **MRPCS（壳解密）直连真实；业务（公告/登录/心跳）劫到本机重放。**

翻车的唯一原因基本都是把 MRPCS 一起劫了。后果不是"登录失败"，而是
**壳根本不解密主程序** → 没有可 patch 的代码 → `TIMEOUT` → 样本 5~12 秒静默退出（日志空）。

**不能按 IP 区分**：业务登录的原始目标 IP 和 japi 是同一个 → 只能靠**时间差**：
```
MRPCS 只在启动后 3~7 秒做一次 → 等 PATCH_OK → 之后才挂劫持
```
绝对不要开局就挂；"延迟劫持"（delay 2~4s）也失败（patch 成了但 login 走真实 → 卡密不存在）。

| 劫持方式 | 结论 |
|---|---|
| `ip route add local <ip>/32 dev lo scope host` | ✅ 可用，但对所有 uid 生效 |
| `iptables -t nat REDIRECT` + `-m owner --uid-owner 0` | ✅ 推荐，只劫 root |
| `iptables -m string --string "Host: ..."` | ❌ nat 表匹配不到负载 |
| 改 hosts | ❌ 反篡改检测，直接退出 |
| LD_PRELOAD / frida | ❌ 被杀 / 被检测 |

**自劫持陷阱**：`ip route` 劫持后中转自己也出不去（`recv=0`）
→ 中转跑 `uid 2000`（`su 2000 -c "$TMP/t3local 18080 --no-mrpc"`），劫持规则只匹配 uid 0；
或劫持列表排除中转要转发的 IP。

转发真实时：**不要 `shutdown(SHUT_WR)`、不要改 `Connection:`**（半关闭会让服务端回 400）；
**不要 dechunk**（保留 chunked 头会让客户端解析失败卡死）。

验证：`iptables -t nat -S OUTPUT | grep -c 18080` —— MRPCS 阶段应为 0，PATCH_OK 后应为 1。

## 二、内存 patch（核心手段）

**为什么是 `process_vm_writev`**：T盾反的是"注入"不是"改内存"。
ptrace ATTACH 挂死、LD_PRELOAD 空值也杀、frida-gadget 被检测；
而 writev 不 attach、不设 TracerPid、不加载 so、maps 不留痕，**同 uid 即可写，样本无感知**。

**段定位**（基址每次都变，必须动态扫）：
```
扫 /proc/<pid>/maps 的 r-x 段
  → 段首 16 字节 == "T-Protector\0"
  → size == 565248
  → 校验 base + 0x17a8c 处是 "token" 的 UTF-8 开头
```
实测基址 8 个不同值（0x800000000 / 0x660000000 / 0x390000000 …）→ **绝不能写死地址**。
唯一不变量是 **size 565248**。

**两处 patch（段内偏移）**：

| 偏移 | 原 | 改 | 作用 |
|---|---|---|---|
| `0x44e2c` | `b.lo` = `630a0054` | `b` = `53000014` | 跳过时间戳校验失败 |
| `0x45484` | 失败分支 | `1b000014 1f2003d5 1f2003d5 1f2003d5` | 跳成功分支 `0x454f0` + nop×3 |

写入必须在登录请求前（启动约 7s），40ms 轮询够。

**工具** `scripts/mempatch.c`：
```
mempatch auto <进程名> <超时ms> <模式>      # 模式 ts / token / both
mempatch <pid> list | rd <va> <len> | wr <va> <hex...>
```
auto 流程：等进程 → 扫段 → 校验 → 写 → 打印 `PATCH_OK pid=<pid>`。

**编译**（本机只有 zig 能交叉编译 aarch64）：
```sh
ZIG_GLOBAL_CACHE_DIR=<工作区内目录> /c/zig/zig cc -target aarch64-linux-musl -static -O2 -s x.c -o x_arm64
```
必须复用同一缓存目录（否则重编 libc 撞 AccessDenied）；**push 后要 `chmod 755`**。

**`TIMEOUT` ≠ 工具坏了** = 壳没解密。按顺序查：游戏在不在跑 → MRPCS 有没有被劫 → 有没有改 hosts。

残留风险：有效期受响应 `end_time` 限制；每次启动都要重新 patch；壳 CRC 自校验未做长稳测试。

## 三、心跳

- 端点 `POST /91B439D4C57AED35`，**每 60 秒**，带 `kami=`；是**独立线程**
- 失败有计数（`[心跳] 验证失败 (%d/%d` / `连续失败 %d 次`）→ **连续失败会踢退出**

**调试技巧**：fifo 启动但**不喂数据** → 主线程阻塞在读 stdin，心跳线程照样跑
→ 不用装游戏/进对局也能观察心跳。（`sleep 600 | prog` 不行，EOF 会让样本走完退出）

**兜底**：历史抓包从没录到心跳响应（样本每次都在"获取基址失败"处退出）。
解决：**heart 无录制时复用 login 响应** —— 两者都是 512 字节加密体，客户端只认 `code==200`，实测接受。
实测 5 轮（每 60s）全程存活，后续累计 11 次仍存活。

**心跳转发真实必然 400**（三个节点全挡）→ **不是故障**，靠录制响应兜底即可。
真正必须联网的只有启动那几秒的 MRPCS。
