/*
 * kernel_bridge.c
 *
 * Reads target-process structures through a kernel character device, projects
 * them to screen space, and publishes the result on a localhost TCP port for
 * the Java render layer.
 *
 * Data flow:
 *   kernel module (/dev/...) --ioctl--> this library --tcp--> OverlayService
 *
 * The module owns all memory access. This layer only issues ioctls and does
 * arithmetic, so nothing here needs to attach to or inject into the target.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#include "driver.h"

#define TAG "KernelBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

typedef struct {
    uint64_t module_base;
    uint64_t matrix_off;
    uint64_t entity_base;
    int32_t stride;
    int32_t count;
    int32_t pos_off;
    int32_t health_off;
    int32_t team_off;
    int32_t screen_w;
    int32_t screen_h;
    float box_ratio;
    float height;
} config_t;

static config_t g_cfg;
static int g_fd = -1;
static volatile int g_running = 0;
static pthread_t g_thread;
static int g_pid = 0;
static int g_port = 0;

static int read_mem(uint64_t addr, void *buf, size_t size) {
    if (g_fd < 0) {
        return 0;
    }
    struct kmem_req req;
    memset(&req, 0, sizeof(req));
    req.pid = g_pid;
    req.addr = addr;
    req.size = size;
    req.buf = (uint64_t)(uintptr_t) buf;
    if (ioctl(g_fd, KMEM_READ, &req) < 0) {
        return 0;
    }
    return 1;
}

/* Column-major friendly form: identical expression for row-vector * row-major
 * and column-major * column-vector. See tools/game_geometry.py. */
static int project(const float *m, float x, float y, float z,
                   float W, float H, float *sx, float *sy, float *dist) {
    float cw = m[3] * x + m[7] * y + m[11] * z + m[15];
    if (cw <= 0.0001f) {
        return 0;
    }
    float cx = m[0] * x + m[4] * y + m[8] * z + m[12];
    float cy = m[1] * x + m[5] * y + m[9] * z + m[13];
    float ndc_x = cx / cw;
    float ndc_y = cy / cw;
    *sx = (ndc_x * 0.5f + 0.5f) * W;
    *sy = (0.5f - ndc_y * 0.5f) * H;
    *dist = cw;
    return 1;
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t) n;
    }
    return 0;
}

static void *worker(void *arg) {
    (void) arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        LOGE("socket: %s", strerror(errno));
        return NULL;
    }

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t) g_port);

    if (bind(srv, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        LOGE("bind: %s", strerror(errno));
        close(srv);
        return NULL;
    }
    listen(srv, 1);
    LOGI("listening on 127.0.0.1:%d", g_port);

    char line[192];
    float matrix[16];

    while (g_running) {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int client = accept(srv, NULL, NULL);
        if (client < 0) {
            continue;
        }
        LOGI("renderer connected");

        while (g_running) {
            if (!read_mem(g_cfg.module_base + g_cfg.matrix_off, matrix, sizeof(matrix))) {
                usleep(50000);
                continue;
            }

            if (send_all(client, "CLEAR\n", 6) < 0) {
                break;
            }

            for (int i = 0; i < g_cfg.count; i++) {
                uint64_t base = g_cfg.entity_base + (uint64_t) i * (uint64_t) g_cfg.stride;

                float pos[3];
                float hp = 0.0f;
                int32_t team = 0;

                if (!read_mem(base + g_cfg.pos_off, pos, sizeof(pos))) {
                    continue;
                }
                read_mem(base + g_cfg.health_off, &hp, sizeof(hp));
                read_mem(base + g_cfg.team_off, &team, sizeof(team));

                if (hp <= 0.0f) {
                    continue;
                }

                float feet_x, feet_y, dist;
                float head_x, head_y, head_dist;

                if (!project(matrix, pos[0], pos[1], pos[2],
                              (float) g_cfg.screen_w, (float) g_cfg.screen_h,
                              &feet_x, &feet_y, &dist)) {
                    continue;
                }
                if (!project(matrix, pos[0], pos[1], pos[2] + g_cfg.height,
                              (float) g_cfg.screen_w, (float) g_cfg.screen_h,
                              &head_x, &head_y, &head_dist)) {
                    continue;
                }

                float box_h = feet_y - head_y;
                if (box_h <= 1.0f) {
                    continue;
                }
                float box_w = box_h * g_cfg.box_ratio;

                int n = snprintf(line, sizeof(line), "%.1f,%.1f,%.1f,%.1f,%.1f,%d\n",
                                 feet_x - box_w * 0.5f, head_y, box_w, box_h, dist, team);
                if (send_all(client, line, (size_t) n) < 0) {
                    break;
                }
            }
            usleep(8000);
        }

        close(client);
        LOGI("renderer disconnected");
    }

    close(srv);
    return NULL;
}

JNIEXPORT jint JNICALL
Java_lab_overlay_KernelBridge_nativeOpen(JNIEnv *env, jclass cls, jstring device) {
    (void) cls;
    const char *path = (*env)->GetStringUTFChars(env, device, NULL);
    if (!path) {
        return -1;
    }
    g_fd = open(path, O_RDWR);
    int saved = errno;
    (*env)->ReleaseStringUTFChars(env, device, path);
    if (g_fd < 0) {
        return -saved;
    }
    LOGI("opened %s fd=%d", path ? path : "", g_fd);
    return 0;
}

JNIEXPORT void JNICALL
Java_lab_overlay_KernelBridge_nativeClose(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

JNIEXPORT void JNICALL
Java_lab_overlay_KernelBridge_nativeSetConfig(JNIEnv *env, jclass cls,
                                              jlongArray icfg, jfloatArray fcfg) {
    (void) cls;
    jsize ilen = (*env)->GetArrayLength(env, icfg);
    jsize flen = (*env)->GetArrayLength(env, fcfg);
    if (ilen < 10 || flen < 2) {
        return;
    }

    jlong *i = (*env)->GetLongArrayElements(env, icfg, NULL);
    jfloat *f = (*env)->GetFloatArrayElements(env, fcfg, NULL);
    if (!i || !f) {
        if (i) (*env)->ReleaseLongArrayElements(env, icfg, i, JNI_ABORT);
        if (f) (*env)->ReleaseFloatArrayElements(env, fcfg, f, JNI_ABORT);
        return;
    }

    g_cfg.module_base = (uint64_t) i[0];
    g_cfg.matrix_off = (uint64_t) i[1];
    g_cfg.entity_base = (uint64_t) i[2];
    g_cfg.stride = (int32_t) i[3];
    g_cfg.count = (int32_t) i[4];
    g_cfg.pos_off = (int32_t) i[5];
    g_cfg.health_off = (int32_t) i[6];
    g_cfg.team_off = (int32_t) i[7];
    g_cfg.screen_w = (int32_t) i[8];
    g_cfg.screen_h = (int32_t) i[9];
    g_cfg.box_ratio = f[0];
    g_cfg.height = f[1];

    (*env)->ReleaseLongArrayElements(env, icfg, i, JNI_ABORT);
    (*env)->ReleaseFloatArrayElements(env, fcfg, f, JNI_ABORT);
}

JNIEXPORT jint JNICALL
Java_lab_overlay_KernelBridge_nativeStart(JNIEnv *env, jclass cls, jint pid, jint port) {
    (void) env;
    (void) cls;
    if (g_running) {
        return -1;
    }
    g_pid = pid;
    g_port = port;
    g_running = 1;
    if (pthread_create(&g_thread, NULL, worker, NULL) != 0) {
        g_running = 0;
        return -2;
    }
    LOGI("started pid=%d port=%d", pid, port);
    return 0;
}

JNIEXPORT void JNICALL
Java_lab_overlay_KernelBridge_nativeStop(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    if (!g_running) {
        return;
    }
    g_running = 0;
    pthread_join(g_thread, NULL);
    LOGI("stopped");
}

JNIEXPORT jint JNICALL
Java_lab_overlay_KernelBridge_nativeReadTest(JNIEnv *env, jclass cls, jlong addr) {
    (void) env;
    (void) cls;
    int32_t value = 0;
    if (!read_mem((uint64_t) addr, &value, sizeof(value))) {
        return -1;
    }
    return value;
}
