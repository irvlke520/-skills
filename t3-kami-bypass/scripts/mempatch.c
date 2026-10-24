/* mempatch - 读写目标进程内存，不 attach、不 ptrace、不注入 so。
 * 主路径 process_vm_writev/readv（内核 ptrace 权限，但不设 TracerPid）；
 * 失败时回退 /proc/<pid>/mem。
 *
 * 用法:
 *   mempatch <pid> list
 *   mempatch <pid> rd <hexva> <len>
 *   mempatch <pid> wr <hexva> <hexbytes...>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/uio.h>

/* ---- 按 comm 找 pid ---- */
static int find_pid(const char *name)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char p[64];
        snprintf(p, sizeof p, "/proc/%s/comm", e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        char c[256];
        if (fgets(c, sizeof c, f)) {
            c[strcspn(c, "\n")] = 0;
            if (!strcmp(c, name)) { found = atoi(e->d_name); fclose(f); break; }
        }
        fclose(f);
    }
    closedir(d);
    return found;
}

/* ---- 扫 maps 找开头是 T-Protector\0 的可执行段 ---- */
static unsigned long long find_base(pid_t pid, unsigned long long *osize)
{
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    char line[512];
    unsigned long long s = 0, e = 0;
    char perm[8];
    while (fgets(line, sizeof line, f)) {
        unsigned long long a, b;
        char pm[8], rest[256];
        if (sscanf(line, "%llx-%llx %7s %255[^\n]", &a, &b, pm, rest) != 4) continue;
        if (pm[0] != 'r' || pm[1] != '-' || pm[2] != 'x') continue;
        unsigned long long sz = b - a;
        if (sz < 65536 || sz > 4194304) continue;
        unsigned char hdr[16];
        struct iovec li = { hdr, 16 };
        struct iovec ri = { (void *)(uintptr_t)a, 16 };
        ssize_t n = process_vm_readv(pid, &li, 1, &ri, 1, 0);
        if (n == 16 && !memcmp(hdr, "T-Protector\0", 12)) {
            s = a; e = b;
            if (osize) *osize = sz;
            break;
        }
    }
    fclose(f);
    (void)e;
    return s;
}

/* ---- patch 定义 ---- */
#define OFF_TS    0x44e2cULL   /* b.lo (时间戳) -> b */
#define OFF_TK    0x45484ULL   /* 失败分支 -> b 成功 + nop*3 */
#define OFF_CHK   0x17a8cULL   /* "token" UTF-8 前 8 字节, 用于校验基址正确 */

static const unsigned char PATCH_TS[4]  = { 0x53, 0x00, 0x00, 0x14 };
static const unsigned char PATCH_TK[16] = { 0x1b, 0x00, 0x00, 0x14,
                                            0x1f, 0x20, 0x03, 0xd5,
                                            0x1f, 0x20, 0x03, 0xd5,
                                            0x1f, 0x20, 0x03, 0xd5 };
static const unsigned char EXPECT_CHK[8] = { 0x74,0x6f,0x6b,0x65,0x6e,0xe6,0xa0,0xa1 };

static int rd(pid_t pid, unsigned long long va, void *buf, size_t len)
{
    struct iovec li = { buf, len };
    struct iovec ri = { (void *)(uintptr_t)va, len };
    ssize_t n = process_vm_readv(pid, &li, 1, &ri, 1, 0);
    if (n < 0) {
        char p[64];
        snprintf(p, sizeof p, "/proc/%d/mem", pid);
        int fd = open(p, O_RDONLY);
        if (fd < 0) return -1;
        n = pread(fd, buf, len, (off_t)va);
        close(fd);
    }
    return (int)n;
}

static int wr(pid_t pid, unsigned long long va, const void *buf, size_t len)
{
    struct iovec li = { (void *)buf, len };
    struct iovec ri = { (void *)(uintptr_t)va, len };
    ssize_t n = process_vm_writev(pid, &li, 1, &ri, 1, 0);
    if (n < 0) {
        char p[64];
        snprintf(p, sizeof p, "/proc/%d/mem", pid);
        int fd = open(p, O_WRONLY);
        if (fd < 0) return -1;
        n = pwrite(fd, buf, len, (off_t)va);
        close(fd);
    }
    return (int)n;
}

/* auto <comm> <timeout_ms> [mode] : 等进程 -> 定位 -> 校验 -> patch
 * mode: both(默认,ts+tk) | ts(仅时间戳) | tk(仅token) | none(只定位) */
static int cmd_auto(const char *name, int timeout_ms, const char *mode)
{
    int do_ts = !mode || !strcmp(mode, "both") || !strcmp(mode, "ts");
    int do_tk = !mode || !strcmp(mode, "both") || !strcmp(mode, "tk");
    int waited = 0;
    while (waited < timeout_ms) {
        int pid = find_pid(name);
        if (pid > 0) {
            unsigned long long sz = 0;
            unsigned long long base = find_base(pid, &sz);
            if (base && sz == 565248) {
                unsigned char chk[8];
                if (rd(pid, base + OFF_CHK, chk, 8) == 8 &&
                    !memcmp(chk, EXPECT_CHK, 8)) {
                    unsigned char old[16];
                    rd(pid, base + OFF_TS, old, 4);
                    printf("# base=0x%llx size=%llu chk=ok ts_old=", base, sz);
                    for (int i = 0; i < 4; i++) printf("%02x", old[i]);
                    printf("\n");
                    printf(" mode=%s\n", mode ? mode : "both");
                    if (do_ts) {
                        if (wr(pid, base + OFF_TS, PATCH_TS, 4) != 4) { printf("# ts write FAIL %s\n", strerror(errno)); return 3; }
                        rd(pid, base + OFF_TS, old, 4);
                        printf("# ts_new=");
                        for (int i = 0; i < 4; i++) printf("%02x", old[i]);
                    }
                    if (do_tk) {
                        if (wr(pid, base + OFF_TK, PATCH_TK, 16) != 16) { printf("# tk write FAIL %s\n", strerror(errno)); return 3; }
                        rd(pid, base + OFF_TK, old, 16);
                        printf(" tk_new=");
                        for (int i = 0; i < 16; i++) printf("%02x", old[i]);
                    }
                    printf("\n# PATCH_OK pid=%d\n", pid);
                    return 0;
                } else {
                    printf("# base found 0x%llx but chk mismatch, retry\n", base);
                }
            }
        }
        usleep(40000);
        waited += 40;
    }
    printf("# TIMEOUT name=%s\n", name);
    return 4;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *s, unsigned char *out, size_t max)
{
    size_t n = 0;
    while (*s && n < max) {
        if (*s == ' ' || *s == ':' || *s == '\n') { s++; continue; }
        int hi = hexval(s[0]);
        if (hi < 0) break;
        if (!s[1]) break;
        int lo = hexval(s[1]);
        if (lo < 0) break;
        out[n++] = (unsigned char)((hi << 4) | lo);
        s += 2;
    }
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: mempatch auto <comm> <timeout_ms>\n"
                        "       mempatch <pid> list|rd|wr [va] [arg]\n");
        return 2;
    }
    if (!strcmp(argv[1], "auto")) {
        if (argc < 4) { fprintf(stderr, "need comm\n"); return 2; }
        int to = argc > 3 ? atoi(argv[3]) : 30000;
        return cmd_auto(argv[2], to, argc > 4 ? argv[4] : "both");
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    const char *cmd = argv[2];

    if (!strcmp(cmd, "list")) {
        char p[64];
        snprintf(p, sizeof p, "/proc/%d/maps", pid);
        FILE *f = fopen(p, "r");
        if (!f) { perror("maps"); return 1; }
        char line[512];
        while (fgets(line, sizeof line, f)) fputs(line, stdout);
        fclose(f);
        return 0;
    }
    if (argc < 5) { fprintf(stderr, "need va\n"); return 2; }
    unsigned long long va = strtoull(argv[3], NULL, 16);

    if (!strcmp(cmd, "rd")) {
        size_t len = (size_t)strtoull(argv[4], NULL, 0);
        if (len == 0) len = 16;
        if (len > 4096) len = 4096;
        unsigned char *buf = malloc(len);
        struct iovec liov = { buf, len };
        struct iovec riov = { (void *)(uintptr_t)va, len };
        ssize_t n = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
        const char *how = "vm_readv";
        if (n < 0) {
            char p[64];
            snprintf(p, sizeof p, "/proc/%d/mem", pid);
            int fd = open(p, O_RDONLY);
            if (fd < 0) { perror("open mem"); return 1; }
            n = pread(fd, buf, len, (off_t)va);
            how = "procmem";
            close(fd);
        }
        if (n < 0) { perror("read"); return 1; }
        for (ssize_t i = 0; i < n; i++) printf("%02x", buf[i]);
        printf("\n# %s n=%zd\n", how, n);
        return 0;
    }

    if (!strcmp(cmd, "wr")) {
        unsigned char buf[512];
        size_t n = 0;
        for (int i = 4; i < argc; i++)
            n += parse_hex(argv[i], buf + n, sizeof buf - n);
        if (n == 0) { fprintf(stderr, "no bytes\n"); return 2; }
        struct iovec liov = { buf, n };
        struct iovec riov = { (void *)(uintptr_t)va, n };
        ssize_t w = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
        const char *how = "vm_writev";
        if (w < 0) {
            char p[64];
            snprintf(p, sizeof p, "/proc/%d/mem", pid);
            int fd = open(p, O_WRONLY);
            if (fd >= 0) {
                w = pwrite(fd, buf, n, (off_t)va);
                how = "procmem";
                close(fd);
            }
        }
        if (w < 0) { perror("write"); return 1; }
        printf("# %s ok va=0x%llx n=%zu\n", how, va, w);
        return 0;
    }
    fprintf(stderr, "bad cmd\n");
    return 2;
}
