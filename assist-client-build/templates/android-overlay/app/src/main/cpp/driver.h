#ifndef LAB_OVERLAY_DRIVER_H
#define LAB_OVERLAY_DRIVER_H

/*
 * ioctl protocol shared with the kernel module.
 *
 * The module is expected to register a character device and handle:
 *   KMEM_READ  - copy `size` bytes from target pid at `addr` into userspace `buf`
 *   KMEM_WRITE - copy `size` bytes from userspace `buf` into target pid at `addr`
 *   KMEM_PID   - resolve a process name (passed in buf) to a pid
 *
 * Adjust the magic number, device path, and command codes to match your module.
 */

#include <linux/ioctl.h>
#include <stdint.h>

#define KMEM_DEVICE_DEFAULT "/dev/kmem_hub"

#define KMEM_MAGIC 'k'

struct kmem_req {
    int32_t pid;
    uint32_t flags;
    uint64_t addr;
    uint64_t size;
    uint64_t buf;
};

#define KMEM_READ  _IOWR(KMEM_MAGIC, 1, struct kmem_req)
#define KMEM_WRITE _IOWR(KMEM_MAGIC, 2, struct kmem_req)
#define KMEM_PID   _IOWR(KMEM_MAGIC, 3, struct kmem_req)

#endif
