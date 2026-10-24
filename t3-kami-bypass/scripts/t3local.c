/* t3local - 设备端本地 T3 重放服务器，监听 :80，不依赖 PC 与 T3 服务器。
 *
 * 配合 ip route add local <T3 IP>/32 dev lo scope host 使用：
 * 样本的 DNS 照常解析，但 TCP 连到本机，由本程序直接回放录制好的响应。
 *
 * 用法: t3local [port]   (默认 80，需要 root 才能绑 1024 以下)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "responses.h"

#define BUFSZ 65536

static int g_no_mrpc = 0;   /* 1 = 对 MRPCS(rules/crc) 直接返回 502，用于测试 */
/* 1 = MRPCS 也走本地重放（用录制的 rules/crc），完全不连真实服务器。
 * 用来验证"壳是否只校验签名、不校验时间戳/nonce"——若成立即可做纯离线版。 */
static int g_replay_mrpc = 0;
/* MRPCS 不能重放（壳拿不到有效 MRPCS 就不解密主程序，进程约 5s 退出），
 * 必须转发到真实服务器。选一个"没有域名解析到它"的 T3 IP 当出口，
 * 这样它不会被 ip route local 劫持回本机。实测：103.85.86.98 可作出口。 */
static char g_real_ip[64] = "103.85.86.98";
static int  g_real_port = 80;

/* 本次连接"原本要连"的目标 IP。
 * 关键：T3 是多节点 + 域名过白，硬编码连 103.85.86.98 会被挡（返回 400 / 域名未过白），
 * 而样本自己解析出来的那个节点才是能用的。所以转发必须回到"原始目标 IP"：
 *   - iptables REDIRECT 模式：用 SO_ORIGINAL_DST 取
 *   - ip route add local 模式：用 getsockname 取（本地地址就是被劫持的那个 IP）
 * 取到了就优先用它，取不到才退回命令行给的 IP。 */
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
static char g_orig_ip[64] = "";
static char g_target[64] = "";

/* MRPCS 是多节点 DNS 轮询，而且只有其中一部分节点当前可用
 * （实测：劫持到 117.149.251.84 时转发回它，服务端一律 400；
 *   而样本不劫持时是先试 117 失败、再试 103.85.86.98 成功的）。
 * 我们劫持后样本没有重试机会，所以转发必须自己把候选节点挨个试过去，
 * 拿到非 4xx/5xx 的响应才算成功。 */
static const char *MRPCS_NODES[] = {
    "117.149.251.84", "103.85.86.98", "110.42.70.112", NULL
};

/* 把整个 Connection 行替换成 "Connection: close"（与 PC 版 MITM 的正则替换等价）。
 * 之前用等长替换补了 5 个空格，服务端拿到的值带尾随空格，很可能就是它导致
 * 转发的 MRPCS 响应被样本拒绝。这里改成整行替换，长度可变。 */
static size_t force_close(unsigned char *req, size_t n)
{
    const char *NEW = "Connection: close";
    size_t newlen = strlen(NEW);
    for (size_t i = 0; i + 12 < n; i++) {
        int line_start = (i == 0) || (i >= 2 && req[i - 2] == '\r' && req[i - 1] == '\n');
        if (!line_start) continue;
        if (strncasecmp((const char *)req + i, "Connection:", 11) != 0) continue;
        size_t j = i;
        while (j + 1 < n && !(req[j] == '\r' && req[j + 1] == '\n')) j++;
        size_t oldlen = j - i;
        if (newlen != oldlen)
            memmove(req + i + newlen, req + j, n - j);
        memcpy(req + i, NEW, newlen);
        return n - oldlen + newlen;
    }
    return n;
}

/* send 一次不一定发完，必须循环到发满为止，否则大响应会被截断 */
static int sendall(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(fd, p + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += (size_t)r;
    }
    return 0;
}

static int relay_real(int c, const unsigned char *req, size_t n)
{
    /* 原样转发，一个字节都不改：
     * 之前这里做了两件事，结果服务端一律回 400 Bad Request：
     *   1) 把 "Connection: Keep-Alive" 改成 "Connection: close"
     *   2) 发完就 shutdown(s, SHUT_WR) 半关闭
     * 服务端/WAF 看到半关闭会认为请求不完整 -> 400。样本自己直连时是
     * Keep-Alive 且不半关闭，所以能拿到 200。改成完全照抄客户端行为。 */
    struct timespec t0, t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* 候选节点：原始目标优先，然后是其余已知节点，最后才是命令行给的 IP */
    const char *cand[8];
    int ncand = 0;
    if (g_orig_ip[0]) cand[ncand++] = g_orig_ip;
    for (int i = 0; MRPCS_NODES[i]; i++) {
        int dup = 0;
        for (int j = 0; j < ncand; j++) if (!strcmp(cand[j], MRPCS_NODES[i])) dup = 1;
        if (!dup && ncand < 7) cand[ncand++] = MRPCS_NODES[i];
    }
    if (g_real_ip[0]) {
        int dup = 0;
        for (int j = 0; j < ncand; j++) if (!strcmp(cand[j], g_real_ip)) dup = 1;
        if (!dup && ncand < 8) cand[ncand++] = g_real_ip;
    }

    char b[BUFSZ];
    for (int ci = 0; ci < ncand; ci++) {
        const char *tip = cand[ci];
        struct timeval tv;
        tv.tv_sec = 5; tv.tv_usec = 0;               /* 连接/收包都设 5s 上限 */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(g_real_port);
        if (inet_pton(AF_INET, tip, &a.sin_addr) != 1) { close(s); continue; }
        if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
            fprintf(stderr, "[t3local] relay: connect %s FAILED %s\n", tip, strerror(errno));
            close(s); continue;
        }
        if (sendall(s, req, n) < 0) { close(s); continue; }
        /* 不要 shutdown(SHUT_WR)：半关闭会让服务端回 400 */

        ssize_t r = recv(s, b, sizeof b, 0);
        if (r <= 0) { fprintf(stderr, "[t3local] relay %s: no response\n", tip); close(s); continue; }
        /* 看状态行：4xx/5xx 说明这个节点当前不服务，换下一个 */
        int bad = 0;
        if (r >= 12 && !memcmp(b, "HTTP/", 5)) {
            char code = b[9];
            if (code == '4' || code == '5') bad = 1;
        }
        fprintf(stderr, "[t3local] relay %s -> %c%c%c%s\n", tip, b[9], b[10], b[11],
                bad ? "  (换下一个节点)" : "  OK");
        fflush(stderr);
        if (bad) { close(s); continue; }

        snprintf(g_target, sizeof g_target, "%s", tip);
        if (sendall(c, b, (size_t)r) < 0) { close(s); return 0; }
        size_t total = (size_t)r;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while ((r = recv(s, b, sizeof b, 0)) > 0) {
            total += (size_t)r;
            if (sendall(c, b, (size_t)r) < 0) break;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double c_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
        double r_ms = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
        fprintf(stderr, "[t3local] relay: sent=%zu recv=%zu -> %s connect=%.0fms recv=%.0fms\n",
                n, total, tip, c_ms, r_ms);
        close(s);
        return 1;
    }
    fprintf(stderr, "[t3local] relay: 所有节点都失败\n");
    return 0;
}

static const unsigned char *pick(const char *path, const char *body, int *len)
{
    if (g_no_mrpc && (strstr(path, "/rules/") || strstr(path, "/crc/"))) {
        *len = 0;
        return NULL;
    }
    if (strstr(path, "/rules/")) { *len = resp_rules_len;  return resp_rules;  }
    if (strstr(path, "/crc/"))   { *len = resp_crc_len;    return resp_crc;    }
    if (!strcmp(path, "/BBA82463358ECC72")) { *len = resp_beat_len;   return resp_beat;   }
    if (!strcmp(path, "/FAD7AD854E8FBBB8")) { *len = resp_notice_len; return resp_notice; }
    if (!strcmp(path, "/7865199B50FC57D5")) { *len = resp_login_len;  return resp_login;  }
    /* 心跳：当时没录到，先让调用方转发真实服务器，失败再回退用登录响应
     * （两者都是 512 字节的同类加密体，结构一致） */
    if (!strcmp(path, "/91B439D4C57AED35")) { *len = resp_login_len;  return resp_login;  }
    if (!strcmp(path, "/91B439D4C57AED35")) { *len = resp_heart_len;  return resp_heart;  }
    if (body && strstr(body, "kami="))      { *len = resp_login_len;  return resp_login;  }
    *len = 0;
    return NULL;
}

static void handle(int c)
{
    char buf[BUFSZ];
    size_t n = 0;
    /* 读到 \r\n\r\n */
    while (n < sizeof buf - 1) {
        ssize_t r = recv(c, buf + n, sizeof buf - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
        buf[n] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (!strstr(buf, "\r\n\r\n")) { close(c); return; }

    char *hend = strstr(buf, "\r\n\r\n");
    *hend = 0;
    char *body = hend + 4;

    /* Content-Length 的话把 body 收全（其实我们不 care 内容，但要读干净） */
    char *clp = strstr(buf, "Content-Length:");
    if (!clp) clp = strstr(buf, "content-length:");
    if (clp) {
        long cl = atol(clp + 15);
        long have = (long)strlen(body);
        while (have < cl && n < (size_t)cl + 4096) {
            ssize_t r = recv(c, buf + n, 1, 0);
            if (r <= 0) break;
            n += (size_t)r;
            have++;
        }
    }

    char method[16] = {0}, path[256] = {0};
    if (sscanf(buf, "%15s %255s", method, path) < 2) { close(c); return; }

    int len = 0;
    const unsigned char *resp = pick(path, body, &len);

    /* 心跳没有录制，先试着转发真实服务器；转发失败再回退到登录响应 */
    if (!strcmp(path, "/91B439D4C57AED35")) {
        if (relay_real(c, (const unsigned char *)buf, n)) {
            shutdown(c, SHUT_WR); close(c); return;
        }
        fprintf(stderr, "[t3local] heartbeat: 转发失败，回退登录响应\n");
        fflush(stderr);
    }

    /* MRPCS 必须走真实服务器：壳解密主程序的前置条件 */
    if (!g_no_mrpc && !g_replay_mrpc && (strstr(path, "/rules/") || strstr(path, "/crc/"))) {
        relay_real(c, (const unsigned char *)buf, n);
        fprintf(stderr, "[t3local] %-6s %-40s -> REAL %s\n", method, path,
                g_target[0] ? g_target : g_real_ip);
        fflush(stderr);
        shutdown(c, SHUT_WR);
        close(c);
        return;
    }

    if (resp && len > 0) {
        send(c, resp, len, 0);
        fprintf(stderr, "[t3local] %-6s %-40s -> %d bytes (orig=%s)\n", method, path, len,
                g_orig_ip[0] ? g_orig_ip : "?");
    } else {
        const char *e = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                        "Connection: close\r\n\r\n";
        send(c, e, strlen(e), 0);
        fprintf(stderr, "[t3local] %-6s %-40s -> 502 (no recording, orig=%s)\n", method, path,
                g_orig_ip[0] ? g_orig_ip : "?");
    }
    fflush(stderr);
    shutdown(c, SHUT_WR);
    close(c);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 80;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--no-mrpc")) { g_no_mrpc = 1; continue; }
        if (!strcmp(argv[i], "--replay-mrpc")) { g_replay_mrpc = 1; continue; }
        if (strchr(argv[i], '.'))
            snprintf(g_real_ip, sizeof g_real_ip, "%s", argv[i]);   /* 真实出口 IP */
    }
    signal(SIGCHLD, SIG_IGN);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
        perror("bind");
        fprintf(stderr, "[!] 端口 %d 绑定失败（<1024 需要 root）\n", port);
        return 1;
    }
    listen(s, 32);
    fprintf(stderr, "[t3local] 监听 0.0.0.0:%d，本地重放 T3 响应\n", port);
    fflush(stderr);

    while (1) {
        int c = accept(s, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            close(s);
            /* 取"原本要连"的 IP：REDIRECT 用 SO_ORIGINAL_DST，路由劫持用 getsockname */
            struct sockaddr_in od;
            socklen_t olen = sizeof od;
            memset(&od, 0, sizeof od);
            if (getsockopt(c, IPPROTO_IP, SO_ORIGINAL_DST, &od, &olen) == 0 &&
                od.sin_family == AF_INET) {
                char b[64];
                if (inet_ntop(AF_INET, &od.sin_addr, b, sizeof b)) {
                    unsigned int h = ntohl(od.sin_addr.s_addr);
                    /* 排除 loopback / 0.0.0.0 —— 那说明没取到真目标 */
                    if ((h >> 24) != 127 && h != 0)
                        snprintf(g_orig_ip, sizeof g_orig_ip, "%s", b);
                }
            }
            if (!g_orig_ip[0]) {
                struct sockaddr_in ln;
                socklen_t ll = sizeof ln;
                memset(&ln, 0, sizeof ln);
                if (getsockname(c, (struct sockaddr *)&ln, &ll) == 0) {
                    char b[64];
                    if (inet_ntop(AF_INET, &ln.sin_addr, b, sizeof b)) {
                        unsigned int h = ntohl(ln.sin_addr.s_addr);
                        if ((h >> 24) != 127 && h != 0)
                            snprintf(g_orig_ip, sizeof g_orig_ip, "%s", b);
                    }
                }
            }
            handle(c);
            _exit(0);
        }
        close(c);
    }
    return 0;
}
