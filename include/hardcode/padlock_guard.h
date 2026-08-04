#ifndef HARDCODE_PADLOCK_GUARD_H
#define HARDCODE_PADLOCK_GUARD_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u32 padlock_guard_u32;
typedef __u64 padlock_guard_u64;
#else
#include <stdint.h>
typedef uint32_t padlock_guard_u32;
typedef uint64_t padlock_guard_u64;
#endif

#define PADLOCK_GUARD_PATH_MAX 4096u
#define PADLOCK_GUARD_DEVICE_NAME "hardcode_padlock_guard"
#define PADLOCK_GUARD_IOCTL_MAGIC 'P'

struct padlock_guard_request {
    char path[PADLOCK_GUARD_PATH_MAX];
    padlock_guard_u64 start;
    padlock_guard_u64 length;
    padlock_guard_u64 token;
    padlock_guard_u32 flags;
    padlock_guard_u32 reserved;
};

#define PADLOCK_GUARD_FLAG_LOCKED 0x00000001u
#define PADLOCK_GUARD_FLAG_SESSION 0x00000002u

#define PADLOCK_GUARD_IOCTL_REGISTER \
    _IOW(PADLOCK_GUARD_IOCTL_MAGIC, 0x01, struct padlock_guard_request)
#define PADLOCK_GUARD_IOCTL_UNREGISTER \
    _IOW(PADLOCK_GUARD_IOCTL_MAGIC, 0x02, struct padlock_guard_request)
#define PADLOCK_GUARD_IOCTL_BEGIN_WRITE \
    _IOWR(PADLOCK_GUARD_IOCTL_MAGIC, 0x03, struct padlock_guard_request)
#define PADLOCK_GUARD_IOCTL_END_WRITE \
    _IOW(PADLOCK_GUARD_IOCTL_MAGIC, 0x04, struct padlock_guard_request)
#define PADLOCK_GUARD_IOCTL_QUERY \
    _IOWR(PADLOCK_GUARD_IOCTL_MAGIC, 0x05, struct padlock_guard_request)

#endif
