# 交付 + 踩坑

## 三件套

生成器 `scripts/build_standalone.py` 一次产出：

| 文件 | 推到设备哪 | 作用 |
|---|---|---|
| `JINLI55.sh`（61.7MB） | `/sdcard/` | 主脚本，自解压 + 全流程 |
| `JINLI55_reload.sh`（8KB） | `/data/local/tmp/.jng55/jng55_reload.sh` | 快速通道本体（被 exec） |
| `JINLI55_stop.sh`（1.3KB） | `/data/local/tmp/jng55_stop.sh` | 停机 |

`.jng55` 是 root 建的，**adb 不能直接写** → 先 push 到 `/data/local/tmp/` 再 `su -c mv`。
单文件结构：`[HEAD] [FAST] [base64×4] [RUN] [GEN]`。

## 快速通道

```sh
if [ "$FORCE" = "0" ] && [ -s $TMP/jng55_reload.sh ] && [ -s $TMP/jng55.master ] \
   && [ -s $TMP/mempatch ] && [ -s $TMP/t3local ]; then
  if [ "$(cat $TMP/.deploy_id 2>/dev/null)" = "$DEPLOY_ID" ]; then
    DRAW_PCT 100; printf '\n'
    exec sh $TMP/jng55_reload.sh --quiet "$@"
  fi
fi
```
**关键在 `exec`**：进程替换后 payload 一个字节都不会被读。用 `if` 跳过解压命令没用——
shell 照样要把整个 heredoc 读完。

实测：快速通道 **0.02s** / 全量解析 61MB 0.42s / base64 解码 47MB 3.03s（+写盘 3.23s）
→ 全量只慢约 3.2 秒，"47MB 解压很慢"是错觉。

- `DEPLOY_ID` = 四个组件 size 拼 md5 前 8 位，写进 `$TMP/.deploy_id`；组件一换自动失效
- `--full`/`-f` 强制全量
- **`--quiet`**：HEAD 是主脚本和 reload 共用的，exec 进 reload 会打两遍开场白 →
  exec 时传 `--quiet`，解析顺序必须在 `--full` **之前**
- **坑**：`HEAD_FAST` 是 HEAD 的派生，占位符 `__DEPLOY_ID__` 也要 replace，
  否则 reload 把字面字符串写进 `.deploy_id` → 快速通道永远不命中

## 停机（trap 不一定跑得到）

```sh
for p in $(pgrep -x jng55p.elf) $(pgrep -x t3local) $(pgrep -x t3fwd); do kill -9 $p 2>/dev/null; done
while iptables -t nat -D OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null; do :; done
for ip in 103.85.86.98 117.149.251.84 110.42.70.112; do ip route del local $ip/32 dev lo scope host 2>/dev/null; done
umount /system/etc/hosts 2>/dev/null
settings put system screen_off_timeout 60000 2>/dev/null   # 脚本设成了 2147483647
```
四项复查：`pgrep -x jng55p.elf` / `pgrep -x t3local` / `iptables ... grep -c 18080` /
`ip route show table local | grep -cE '103\.85|117\.149|110\.42'` —— 全空/0 才算干净。
彻底清：`rm -rf /data/local/tmp/.jng55 /sdcard/jngkm55`（后者是"上次卡密"，留着会直接自动登录）。

## 效果何时消失（常被问）

- 外挂是**外部进程方式**：样本每帧 `process_vm_readv/writev` 读写游戏内存；
  mempatch 打的是**样本自己**，**没往游戏进程注入任何东西**
- → **样本进程一死，效果立刻消失，不用重进游戏**
- 但"点停止脚本"只杀 shell，**样本可能变孤儿继续跑** → 判据只有 `pgrep -x jng55p.elf`
- **别在样本活着时重进游戏**：它持有的 `libunity.so` 基址失效，功能出错。先退干净再重进

## 排错顺序（固定）

```sh
pgrep -x jng55p.elf     # 1 数 pid（2 个 = 脚本被重复跑，必然卡死）
cat $TMP/mp.log         # 2 有没有 PATCH_OK
tail -20 $TMP/run.log   # 3 才看脚本日志（每次运行要先清空 + 打时间戳）
```

## 15 条核心踩坑

1. **Windows `SO_REUSEADDR` 让 bind 静默"成功"** → 端口被上个会话占着，一条流量都收不到。不设它 + 循环找空闲端口
2. **样本 stdout 重定向文件是 4KB 块缓冲** → 日志空 = **假阴性**。判据：`/proc/pid/task/*/syscall` 没有线程停在读上
3. **`pgrep -f` 匹配 adb shell 自身 → 脚本自杀**（EXIT=137）。必须用 `pgrep -x`
4. **`mempatch` 报 `TIMEOUT`** = 壳没解密，不是工具坏。查：游戏在跑？MRPCS 被劫？改过 hosts？
5. **只劫持 1 个 T3 IP 会漏网**（IP 池 ≥4 且会新增）→ 曾误判成功
6. **劫持列表含中转要转发的 IP → 自劫持**（`recv=0`）。中转跑 uid 2000 或排除那些 IP
7. **转发不要 `shutdown(SHUT_WR)`、不要改 `Connection:`** → 半关闭让服务端回 400
8. **转发响应不要 dechunk** → 保留 chunked 头让客户端解析失败卡死
9. **`tcpdump` 不加 `-U`**，`kill -9` 会丢最后几个报文（常缺 login 响应）
10. **后台驻留必须 `setsid nohup sh -c "exec ..." &`**，只用 `(setsid ... &)` 会被 adb 断开杀掉
11. **adb push 后权限丢失** → 每次 `chmod 755`；**root 建的目录 adb 不能直接写**，先 push 外层再 `su mv`
12. **Windows bash + adb 引号坑**：`"su -c '... $(...) ...'"` 里的 `$(...)` 被**本地 bash** 展开。
    简单命令用 `pgrep -x X | xargs kill -9`；复杂逻辑写成 .sh push 上去跑
13. **adb 吞反斜杠**：`printf "X\n" > f` 变成字面 `n` → 按行读的程序永不返回，一律用 `echo`
14. **喂输入**：样本放后台会被 `SIGTTIN` 停掉（"敲了没反应"）→ 必须前台；
    `cat > fifo` 转发是块缓冲会卡死 → 让样本以 fifo 为 stdin 或独占终端；
    `/sdcard` 是 FUSE **不支持 mkfifo**（放 `/data/local/tmp`）；
    自动登录已成功时**别补喂卡密**（会被"选择服务器"当编号吃掉）；
    驱动菜单选完**别多喂 `0`**（= 全部关闭 → "未开启任何功能，程序退出"）
15. **残留进程**：壳异常路径会**死循环占满一核**（曾残留 103% CPU 跑 12 小时，用户以为全设备崩了）；
    **中文进程名 `pgrep` 匹配不到** → 清理用 `ps -A -o pid,pcpu,comm | grep 杰尼龟`；
    样本单实例开满功能吃 185% CPU → 两个实例叠加必然把游戏饿死

其余（次要但会卡住，简记）：

- `adb reverse tcp:80 tcp:80` **无权限**（adbd 不能绑低端口）→ 用 8080 等高位；
  且 reverse "返回成功"不代表通，必须从设备侧 `nc` 实测
- 喂菜单编号**间隔要 ≥8 秒**（块缓冲让日志滞后于真实提示）
- 取 `libunity.so` 基址前要 `am start` 把游戏拉回前台，否则报"获取基址失败"
- 清理循环里 `grep -E '...|dbg'` 会把 dbg 脚本自己杀掉

## 性能（不然会误判成"卡死"）

- 功能全开后样本每帧扫游戏内存，实测 **185% CPU**，把游戏（nice -10）饿死 → 看着像卡死
- 修：PATCH_OK 后 `renice -n 19 -p <样本pid>`；别一次全开功能；关掉加速器类应用
- 急救：`pkill -9 <样本>; pkill -9 t3local` → idle 立刻从 271% 回到 644%

## 设备环境补充

- 联发科硬解器 `c2.mtk.avc.decoder` 会让游戏播开场视频时 SIGBUS 崩溃
  → `setprop debug.stagefright.force-swcodec 1`（+ `media.stagefright.force-swcodec`，重启失效要每次设）
- `exec >> $RUNLOG` 改 fd 后前台程序继承的也是日志 fd → 让它看到终端要 `exec 1>&4 2>&4`（启动先 `exec 4>&1`）
- `run.log` 用追加模式会糊成一坨 → 每次运行先 `: > $RUNLOG` 清空 + 打时间戳
- 编译：本机无 NDK/clang，只有 zig 0.14（Windows 程序，输出路径不能用 `/tmp`）
