#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把绕过所需的一切打包成一个 .sh —— 设备端自解压自运行，不依赖 PC、不依赖外部服务器。

结构:
    [头部 shell]        -> 建目录
    [base64 heredoc x4] -> 解出 mempatch / t3local / busybox / 样本
    [运行逻辑]          -> 接管域名 + 起中转 + 起样本 + patch + 喂配置

核心思路（踩过坑之后的版本）:
    T3 的流量分成两拨，必须区别对待：
      * MRPCS(rules/crc)  走 japi.t3yanzheng.com —— 壳靠它解密主程序。
        这个响应绑 nonce、由服务端私钥签名，**不能伪造**；而且实测转发会被
        服务端挡（返回 400 / "域名未过白"）。所以 japi 必须让样本**直连真实服务器**。
      * 业务(beat/notice/login/heart) 走 w*.t3yanzheng.com —— 卡密验证在这里。
        把它用 hosts 指到 127.0.0.1，由本机 t3local 回放录制好的"登录成功"响应。

    为什么不用 ip route add local 或 iptables REDIRECT 全量劫持：
      全量劫持会把 MRPCS 也拦下来，只能转发，而转发必被挡 -> 壳解不出主程序 ->
      mempatch 找不到 565248 字节的 T-Protector 段 -> 报 TIMEOUT -> 样本约 12 秒退出。

用法(设备上, root 环境):
    sh JINLI55_standalone.sh             # 默认 港澳台服 / 驱动13 / 功能1234
    sh JINLI55_standalone.sh 1           # 1=国际服  2=港澳台服
    sh JINLI55_standalone.sh 2 13 1234   # 服务器 驱动 功能

前提: 设备已 root(KernelSU/Magisk 均可) + 能正常上网。
"""
import base64
import os
import stat

HERE = os.path.dirname(os.path.abspath(__file__))
A = os.path.abspath(os.path.join(HERE, '..'))
ROOT = os.path.abspath(os.path.join(A, '..'))
OUT = os.path.join(ROOT, 'JINLI55_standalone.sh')

SAMPLE = os.path.join(ROOT, '杰尼龟55功能_全球端_港澳台端.sh')
MEMPATCH = os.path.join(A, 'patch', 'mempatch_arm64')
T3LOCAL = os.path.join(A, 'patch', 't3local_arm64')
BUSYBOX = os.path.join(A, 'standalone', 'busybox')

for p in (SAMPLE, MEMPATCH, T3LOCAL):
    assert os.path.exists(p), '缺少组件: %s' % p
have_bb = os.path.exists(BUSYBOX)

HEAD = r'''#!/system/bin/sh
# JINLI55 卡密绕过 —— 设备端独立版（自解压，不依赖 PC / 外部服务器）
# 用法: sh JINLI55_standalone.sh [服务器]
#   sh JINLI55_standalone.sh --full [服务器]   # 强制重新解压（组件变了/想推倒重来时用）
#   服务器: 1=国际服 com.activision.callofduty.shooter  2=港澳台服 com.garena.game.codm（默认）
# 卡密 / 驱动 / 功能 全部由你自己看菜单手动输入 —— 脚本不代填、不自动喂。
# 前提: 已 root + 能上网（MRPCS 必须直连 T3 真实服务器）
DEPLOY_ID=__DEPLOY_ID__
# --quiet：被主脚本 exec 过来时带的标记，表示开场三行已经打过了，别重复打
QUIET=0
if [ "$1" = "--quiet" ]; then QUIET=1; shift; fi
FORCE=0
if [ "$1" = "--full" ] || [ "$1" = "-f" ]; then FORCE=1; shift; fi
SRV=${1:-2}
case "$SRV" in
  1) PKG=com.activision.callofduty.shooter ;;
  *) SRV=2; PKG=com.garena.game.codm ;;
esac

TMP=/data/local/tmp/.jng55

if [ "$(id -u 2>/dev/null)" != "0" ]; then
  echo "[!] 必须以 root 运行（su -c 'sh ...'）"; exit 1
fi

# 解压时画进度条用：覆盖当前行更新，30 格宽
DRAW_PCT() {
  PCT=$1
  BARS=$((PCT * 30 / 100))
  BAR=""
  i=0
  while [ $i -lt 30 ]; do
    if [ $i -lt $BARS ]; then BAR="${BAR}█"; else BAR="${BAR} "; fi
    i=$((i+1))
  done
  printf '\r加载中：[%s] %3d%%' "$BAR" "$PCT"
}

if [ "$QUIET" = "0" ]; then
  echo "破解由丛雨丸完成，祝您游戏愉快！"
  echo "正在绕过卡密喵------"
fi
'''

# 快速通道：已部署过就跳过 47MB 自解压。
# 关键在 exec —— 进程被替换后，后面那几十 MB base64 一个字节都不会被读到，
# 所以第二次起是秒开（不用解析、不用解码、不用写盘）。
FAST = r'''
# ---- 快速通道：已部署过就跳过 47MB 自解压 ----
if [ "$FORCE" = "0" ] && [ -s $TMP/jng55_reload.sh ] && [ -s $TMP/jng55.master ] \
   && [ -s $TMP/mempatch ] && [ -s $TMP/t3local ]; then
  if [ "$(cat $TMP/.deploy_id 2>/dev/null)" = "$DEPLOY_ID" ]; then
    # 不用解压，直接给一条满的进度条；--quiet 让 reload 别再打一次开场白
    DRAW_PCT 100
    printf '\n'
    exec sh $TMP/jng55_reload.sh --quiet "$@"
  fi
fi
'''

# 完整版才做的事：清空工作目录并解压 47MB 样本
EXTRACT_HEAD = r'''DRAW_PCT 0
rm -rf $TMP 2>/dev/null
mkdir -p $TMP 2>/dev/null || { echo "[!] 无法创建 $TMP"; exit 1; }
cd $TMP || exit 1
if ! command -v base64 >/dev/null 2>&1; then
  echo "[!] 设备没有 base64 命令，无法自解压"; exit 1
fi
'''

# 快速恢复版：复用 $TMP 里已解压好的组件，不重新解压
RELOAD_HEAD = r'''if [ "$QUIET" = "0" ]; then
  # 直接跑 reload 时（不是被主脚本 exec 过来的）也要有第三行进度条
  DRAW_PCT 100
  printf '\n'
fi
mkdir -p $TMP 2>/dev/null
cd $TMP || exit 1
for f in mempatch t3local jng55.master; do
  if [ ! -s $TMP/$f ]; then
    echo "[!] 缺少 $TMP/$f"
    echo "    请先完整运行一次 JINLI55_standalone.sh"
    exit 1
  fi
done
'''

RUN = r'''
chmod 755 $TMP/mempatch $TMP/t3local $TMP/jng55.master 2>/dev/null
[ -f $TMP/busybox ] && chmod 755 $TMP/busybox
# 记下本次部署的版本戳，下次脚本靠它判断能不能走快速通道
printf '%s\n' "$DEPLOY_ID" > $TMP/.deploy_id 2>/dev/null

# 联发科硬解器 c2.mtk.avc.decoder 会让游戏播开场视频时 SIGBUS 崩溃 -> 强制软解
setprop debug.stagefright.force-swcodec 1 2>/dev/null
setprop media.stagefright.force-swcodec 1 2>/dev/null
# 屏幕超时会让系统杀掉前台游戏
settings put system screen_off_timeout 2147483647 2>/dev/null
# 清残留（进程 / iptables / 路由 / hosts 挂载）
for p in $(pgrep -x t3local) $(pgrep -x t3fwd); do kill -9 $p 2>/dev/null; done
for n in $(ps -Ao pid,args 2>/dev/null | grep -E 'jng55p\.elf|jng_in' | grep -v grep | awk '{print $1}'); do
  kill -9 $n 2>/dev/null
done
while iptables -t nat -D OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null; do :; done
for h in w w1 w2 w3 w4 w5 w6 w7 w8 w9; do
  while iptables -t nat -D OUTPUT -p tcp --dport 80 -m owner --uid-owner 0 \
      -m string --string "Host: $h.t3yanzheng.com" --algo bm -j REDIRECT --to-ports 18080 2>/dev/null; do :; done
done
for ip in 103.85.86.98 117.149.251.84 110.42.70.112; do
  ip route del local $ip/32 dev lo scope host 2>/dev/null
done
umount /system/etc/hosts 2>/dev/null
sleep 1

# MRPCS(壳解密) 一旦被拦就只能转发，而转发必被服务端挡（实测所有节点全 400），
# 壳解不出主程序 -> 样本约 12 秒退出。所以这里先只起服务、不加任何劫持，
# 让样本直连真实服务器把主程序解出来；等 mempatch 报 PATCH_OK 之后再挂劫持。
T3LOG=$TMP/t3local.log
rm -f $T3LOG
# 以 uid 2000 监听 18080：后面加的劫持规则只匹配 uid 0，
# 这样中转自己转发心跳时不会被自己劫持（ip route 劫持对所有 uid 生效，会把自己玩死）
setsid nohup su 2000 -c "$TMP/t3local 18080 --no-mrpc" > $T3LOG 2>&1 &
sleep 2
TPID=$(pgrep -x t3local | head -1)
if [ -z "$TPID" ]; then
  echo "  [!] uid 2000 启动失败，退回 root:"; head -6 $T3LOG 2>/dev/null
  setsid nohup $TMP/t3local 18080 --no-mrpc > $T3LOG 2>&1 &
  sleep 2
  TPID=$(pgrep -x t3local | head -1)
fi

if ! grep -l libunity.so /proc/*/maps >/dev/null 2>&1; then
  monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep 2
  am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER $PKG >/dev/null 2>&1
  i=0
  while [ $i -lt 90 ]; do
    grep -l libunity.so /proc/*/maps >/dev/null 2>&1 && break
    i=$((i+1)); sleep 2
  done
fi
grep -l libunity.so /proc/*/maps >/dev/null 2>&1 || :  # 静默检查，不再提示

# 样本启动时会读 /sdcard/jngkm55 里的"上次卡密"直接自动登录，
# 留着它就不会再问你卡密了 —— 手动模式下先挪走，让它弹出卡密输入框
if [ -f /sdcard/jngkm55 ]; then
  cp /sdcard/jngkm55 $TMP/bak_jngkm55 2>/dev/null
  rm -f /sdcard/jngkm55 2>/dev/null
fi

# ============================================================
# 从这一步起脚本自己不再往终端写字，全部进 $TMP/run.log，
# 终端只留给样本 —— 之前脚本的提示块和样本菜单同时往终端写，
# 糊成一坨，驱动菜单直接被盖掉了。
# 样本的输出显式指回终端(fd 4)。
# ============================================================
sleep 2

RUNLOG=$TMP/run.log
exec 4>&1
# 每次运行先清空：之前是追加模式，跑几次日志就糊成一坨，根本看不出是哪次出问题
: > $RUNLOG 2>/dev/null
exec >> $RUNLOG 2>&1
echo "=== 本次运行 $(date '+%m-%d %H:%M:%S') 脚本pid=$$ 服务器=$SRV ==="

# 收尾清理：样本退出后必须把中转和劫持一起撤掉。
# 不然 iptables 规则会一直把 uid 0 的 80 端口劫到 18080，
# 影响设备上其他 root 应用的正常出网。
cleanup() {
  for p in $(pgrep -x t3local); do kill -9 $p 2>/dev/null; done
  while iptables -t nat -D OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null; do :; done
}
# EXIT/INT/TERM 都挂上：你 Ctrl-C 中断、样本自己退出、脚本正常结束都会清
trap cleanup EXIT INT TERM

echo "[7/8] 启动样本（patch 后台注入，失败自动重来）"
cp $TMP/jng55.master $TMP/jng55p.elf
chmod 755 $TMP/jng55p.elf

TRY=1
while [ $TRY -le 3 ]; do
  rm -f $TMP/mp.log 2>/dev/null
  # 后台 1：注入内存 patch（内部轮询等壳解密）
  $TMP/mempatch auto jng55p.elf 40000 both > $TMP/mp.log 2>&1 &
  MPPID=$!

  # 后台 2：等 PATCH_OK 才挂劫持 + 降样本优先级。
  # 必须等 PATCH_OK —— MRPCS 和业务共 IP，提前劫持壳就解不出主程序。
  (
    i=0
    while [ $i -lt 45 ]; do
      grep -q PATCH_OK $TMP/mp.log 2>/dev/null && break
      i=$((i+1)); sleep 1
    done
    grep -q PATCH_OK $TMP/mp.log 2>/dev/null || exit 0
    # 实测功能开多后样本能吃到 185% CPU，把游戏(本身 nice -10)饿死 -> 卡死
    for q in $(pgrep -x jng55p.elf); do renice -n 19 -p $q >/dev/null 2>&1; done
    iptables -t nat -C OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null \
      || iptables -t nat -I OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null
  ) >> $RUNLOG 2>&1 &

  # 临时把 fd 1/2 还原回终端(fd 4 是启动时备份的原始 stdout/stderr)：
  # 前面 exec >> $RUNLOG 把脚本的 stdout 切到日志去了，
  # 不还原的话样本继承的也是日志 fd —— 菜单全进 run.log，终端看不见。
  exec 1>&4 2>&4

  # 前台跑样本：独占终端，你就像正常跑程序一样一条条输入。
  #  - 不能放后台：后台进程读 tty 会被 SIGTTIN 停掉，表现就是"敲了没反应"
  #  - 不能走 fifo 转发：cat / 管道写非 tty 是 4KB 块缓冲，
  #    敲的回车攒不够 4KB 就送不进去，样本会一直卡在"卡密:"
  #  - 壳没解密(MrpcS 偶发失败)时样本自己约 12 秒就退出，
  #    于是下面的循环能自动重来一次，不用你手动重跑
  $TMP/jng55p.elf

  grep -q PATCH_OK $TMP/mp.log 2>/dev/null && break
  echo "[!] 第 $TRY 次壳没解密成功（MRPCS 偶发失败），自动重来" >&4
  kill -9 $MPPID 2>/dev/null
  TRY=$((TRY+1))
  sleep 3
done

if ! grep -q PATCH_OK $TMP/mp.log 2>/dev/null; then
  echo "[!] patch 三次都没成，看 $TMP/mp.log，退出后重跑脚本" >&4
fi
'''

# 快速版（不含 payload）的头部注释要跟主脚本区分开
HEAD_FAST = HEAD.replace(
    '# 用法: sh JINLI55_standalone.sh [服务器]',
    '# 用法: sh jng55_reload.sh [服务器]   ← 快速通道版：复用已解压组件，不重新解压'
).replace(
    '#   sh JINLI55_standalone.sh --full [服务器]   # 强制重新解压（组件变了/想推倒重来时用）',
    '#   组件缺失 / 想推倒重来时：跑完整版 sh JINLI55_standalone.sh [--full]')

# 主脚本跑完时，把「不含 47MB 样本」的快速恢复脚本落到 $TMP，
# 这样游戏重启后不用再解压一遍
GEN = r'''
# 产出快速恢复脚本（重启游戏后跑它即可，跳过解压）
cat > $TMP/jng55_reload.sh <<'JNG_RELOAD_EOF'
__RELOAD_BODY__
JNG_RELOAD_EOF
chmod 755 $TMP/jng55_reload.sh 2>/dev/null
echo "重启游戏后快速恢复: su -c 'sh $TMP/jng55_reload.sh'"
'''

# 停机脚本：关掉外挂本体（杀样本 + 中转 + 撤劫持），不碰游戏、不删部署。
# 单独产出一个小文件，方便 adb push 到设备常驻，也避免设备清了就没得用。
STOP = r'''#!/system/bin/sh
# 关掉外挂本体：杀样本 + 中转，撤掉 iptables / 路由劫持。游戏不动、部署不删。
# 用法（PC）  : adb shell "su -c 'sh /data/local/tmp/jng55_stop.sh'"
# 用法（终端）: su -c 'sh /data/local/tmp/jng55_stop.sh'
for p in $(pgrep -x jng55p.elf) $(pgrep -x t3local) $(pgrep -x t3fwd); do
  kill -9 $p 2>/dev/null
done
while iptables -t nat -D OUTPUT -p tcp -m tcp --dport 80 -m owner --uid-owner 0 -j REDIRECT --to-ports 18080 2>/dev/null; do :; done
for ip in 103.85.86.98 117.149.251.84 110.42.70.112; do
  ip route del local $ip/32 dev lo scope host 2>/dev/null
done
umount /system/etc/hosts 2>/dev/null
settings put system screen_off_timeout 60000 2>/dev/null

echo "=== 复查（样本/中转空 = 已关，两个劫持数 0 = 已撤）==="
echo "样本   : $(pgrep -x jng55p.elf | tr '\n' ' ')"
echo "中转   : $(pgrep -x t3local | tr '\n' ' ')"
echo "劫持规则: $(iptables -t nat -S OUTPUT 2>/dev/null | grep -c 18080)"
echo "路由劫持: $(ip route show table local 2>/dev/null | grep -cE '103\.85|117\.149|110\.42')"
echo "游戏pid : $(pgrep -f 'com.garena.game.codm|com.activision.callofduty.shooter' | head -1)"
echo "-- 想连登录状态一起清: rm -f /sdcard/jngkm55"
echo "-- 想连部署一起删    : rm -rf /data/local/tmp/.jng55（会把本脚本一起删掉）"
'''

# 版本戳：由四个组件的大小决定，组件一换就自动失效，强制重新解压
import hashlib
_sig = []
for _p in (MEMPATCH, T3LOCAL, BUSYBOX, SAMPLE):
    _sig.append(str(os.path.getsize(_p)) if os.path.exists(_p) else '-')
DEPLOY_ID = hashlib.md5(','.join(_sig).encode()).hexdigest()[:8]
HEAD = HEAD.replace('__DEPLOY_ID__', DEPLOY_ID)
HEAD_FAST = HEAD_FAST.replace('__DEPLOY_ID__', DEPLOY_ID)   # 快速版头部也要替换，否则 reload 把字面 "__DEPLOY_ID__" 写进 .deploy_id，快速通道永远失效

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write(HEAD)
    f.write(FAST)
    f.write(EXTRACT_HEAD)

    def emit(path, name, pct_next):
        f.write("base64 -d > $TMP/%s <<'JNG_EOF'\n" % name)
        with open(path, 'rb') as src:
            while True:
                chunk = src.read(3 * 1024 * 1024)
                if not chunk:
                    break
                f.write(base64.b64encode(chunk).decode())
                f.write('\n')
        f.write('JNG_EOF\nDRAW_PCT %d\n' % pct_next)

    emit(MEMPATCH, 'mempatch', 10)
    emit(T3LOCAL, 't3local', 20)
    if have_bb:
        emit(BUSYBOX, 'busybox', 30)
    emit(SAMPLE, 'jng55.master', 100)

    f.write(RUN)
    f.write(GEN.replace('__RELOAD_BODY__', HEAD_FAST + RELOAD_HEAD + RUN))

os.chmod(OUT, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
print('生成: %s  (%.1f MB)  DEPLOY_ID=%s' % (
    OUT, os.path.getsize(OUT) / 1024 / 1024.0, DEPLOY_ID))

# 同时单独产出一份「不含 47MB」的快速版，方便直接 adb push 到 $TMP/jng55_reload.sh
RELOAD_OUT = os.path.join(ROOT, 'JINLI55_reload.sh')
with open(RELOAD_OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write(HEAD_FAST + RELOAD_HEAD + RUN)
os.chmod(RELOAD_OUT, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
print('生成: %s  (%.1f KB) —— 推到设备 /data/local/tmp/.jng55/jng55_reload.sh 即可跳过解压' % (
    RELOAD_OUT, os.path.getsize(RELOAD_OUT) / 1024.0))

STOP_OUT = os.path.join(ROOT, 'JINLI55_stop.sh')
with open(STOP_OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write(STOP)
os.chmod(STOP_OUT, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
print('生成: %s  (%.1f KB) —— 推到设备 /data/local/tmp/jng55_stop.sh，一条命令关掉外挂' % (
    STOP_OUT, os.path.getsize(STOP_OUT) / 1024.0))
