#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>

#include <hardcode/padlock_guard.h>

MODULE_AUTHOR("Hardcode");
MODULE_DESCRIPTION("Padlock guard module for protected store writes");
MODULE_LICENSE("GPL");

#define PADLOCK_GUARD_HASH_BITS 8

struct padlock_guard_entry {
    struct hlist_node node;
    dev_t dev;
    unsigned long ino;
    char path[PADLOCK_GUARD_PATH_MAX];
    padlock_guard_u64 start;
    padlock_guard_u64 length;
    padlock_guard_u64 token;
    pid_t writer_tgid;
    bool locked;
    bool session_active;
    bool session_dirty;
};

static DEFINE_MUTEX(padlock_guard_lock);
static DEFINE_HASHTABLE(padlock_guard_table, PADLOCK_GUARD_HASH_BITS);
static struct kprobe padlock_guard_probe_file_permission;
static struct kprobe padlock_guard_probe_file_truncate;
#ifdef CONFIG_SECURITY_PATH
static struct kprobe padlock_guard_probe_path_unlink;
static struct kprobe padlock_guard_probe_path_rename;
static struct kprobe padlock_guard_probe_path_truncate;
#endif

static struct miscdevice padlock_guard_device;
static bool padlock_guard_pinned;

static u64 padlock_guard_key(dev_t dev, unsigned long ino)
{
    return (((u64) dev) << 32u) ^ (u64) ino;
}

static struct padlock_guard_entry *padlock_guard_find_locked(dev_t dev, unsigned long ino)
{
    struct padlock_guard_entry *entry;
    u64 key = padlock_guard_key(dev, ino);

    hash_for_each_possible(padlock_guard_table, entry, node, key) {
        if (entry->dev == dev && entry->ino == ino) {
            return entry;
        }
    }

    return NULL;
}

static struct padlock_guard_entry *padlock_guard_find_path_locked(const char *path)
{
    struct path resolved;
    struct inode *inode;
    struct padlock_guard_entry *entry = NULL;

    if (!path || kern_path(path, LOOKUP_FOLLOW, &resolved) != 0) {
        return NULL;
    }

    inode = d_inode(resolved.dentry);
    if (inode) {
        entry = padlock_guard_find_locked(inode->i_sb->s_dev, inode->i_ino);
    }

    path_put(&resolved);
    return entry;
}

static struct padlock_guard_entry *padlock_guard_find_inode_locked(struct inode *inode)
{
    if (!inode) {
        return NULL;
    }

    return padlock_guard_find_locked(inode->i_sb->s_dev, inode->i_ino);
}

static bool padlock_guard_is_authorized(struct padlock_guard_entry *entry)
{
    return entry->session_active && entry->writer_tgid == task_tgid_nr(current);
}

static bool padlock_guard_deny_file(struct file *file)
{
    struct inode *inode;
    struct padlock_guard_entry *entry;

    if (!file) {
        return false;
    }

    inode = file_inode(file);
    if (!inode) {
        return false;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_inode_locked(inode);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        return false;
    }

    if (!entry->locked || padlock_guard_is_authorized(entry)) {
        mutex_unlock(&padlock_guard_lock);
        return false;
    }

    mutex_unlock(&padlock_guard_lock);
    return true;
}

static bool padlock_guard_deny_dentry(struct dentry *dentry)
{
    struct inode *inode;
    struct padlock_guard_entry *entry;

    if (!dentry) {
        return false;
    }

    inode = d_inode(dentry);
    if (!inode) {
        return false;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_inode_locked(inode);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        return false;
    }

    if (!entry->locked || padlock_guard_is_authorized(entry)) {
        mutex_unlock(&padlock_guard_lock);
        return false;
    }

    mutex_unlock(&padlock_guard_lock);
    return true;
}

static unsigned long padlock_guard_kprobe_return_address(struct pt_regs *regs)
{
    return regs_get_kernel_stack_nth(regs, 0);
}

static int padlock_guard_kprobe_deny(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long return_address = padlock_guard_kprobe_return_address(regs);

    if (!return_address) {
        return 0;
    }

    regs_set_return_value(regs, -EPERM);
    instruction_pointer_set(regs, return_address);
    return 1;
}

static int padlock_guard_kprobe_file_permission(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *) regs_get_kernel_argument(regs, 0);
    int mask = (int) regs_get_kernel_argument(regs, 1);

    if ((mask & MAY_WRITE) == 0) {
        return 0;
    }

    if (!padlock_guard_deny_file(file)) {
        return 0;
    }

    return padlock_guard_kprobe_deny(p, regs);
}

static int padlock_guard_kprobe_file_truncate(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *) regs_get_kernel_argument(regs, 0);

    if (!padlock_guard_deny_file(file)) {
        return 0;
    }

    return padlock_guard_kprobe_deny(p, regs);
}

#ifdef CONFIG_SECURITY_PATH
static int padlock_guard_kprobe_path_unlink(struct kprobe *p, struct pt_regs *regs)
{
    struct dentry *dentry = (struct dentry *) regs_get_kernel_argument(regs, 1);

    if (!padlock_guard_deny_dentry(dentry)) {
        return 0;
    }

    return padlock_guard_kprobe_deny(p, regs);
}

static int padlock_guard_kprobe_path_rename(struct kprobe *p, struct pt_regs *regs)
{
    struct dentry *dentry = (struct dentry *) regs_get_kernel_argument(regs, 1);

    if (!padlock_guard_deny_dentry(dentry)) {
        return 0;
    }

    return padlock_guard_kprobe_deny(p, regs);
}

static int padlock_guard_kprobe_path_truncate(struct kprobe *p, struct pt_regs *regs)
{
    const struct path *path = (const struct path *) regs_get_kernel_argument(regs, 0);
    struct dentry *dentry = path ? path->dentry : NULL;

    if (!padlock_guard_deny_dentry(dentry)) {
        return 0;
    }

    return padlock_guard_kprobe_deny(p, regs);
}
#endif

static int padlock_guard_register_entry(const char *path, padlock_guard_u64 start, padlock_guard_u64 length)
{
    struct path resolved;
    struct inode *inode;
    struct padlock_guard_entry *entry;

    if (!path || kern_path(path, LOOKUP_FOLLOW, &resolved) != 0) {
        return -ENOENT;
    }

    inode = d_inode(resolved.dentry);
    if (!inode) {
        path_put(&resolved);
        return -ENOENT;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_inode_locked(inode);
    if (!entry) {
        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            mutex_unlock(&padlock_guard_lock);
            path_put(&resolved);
            return -ENOMEM;
        }
        entry->dev = inode->i_sb->s_dev;
        entry->ino = inode->i_ino;
        hash_add(padlock_guard_table, &entry->node, padlock_guard_key(entry->dev, entry->ino));
    }

    strscpy(entry->path, path, sizeof(entry->path));
    entry->start = start;
    entry->length = length;
    entry->locked = true;
    entry->session_active = false;
    entry->session_dirty = false;
    entry->writer_tgid = 0;
    entry->token = 0;
    mutex_unlock(&padlock_guard_lock);
    path_put(&resolved);
    return 0;
}

static void padlock_guard_unregister_entry(const char *path)
{
    struct path resolved;
    struct inode *inode;
    struct padlock_guard_entry *entry;

    if (!path || kern_path(path, LOOKUP_FOLLOW, &resolved) != 0) {
        return;
    }

    inode = d_inode(resolved.dentry);
    if (!inode) {
        path_put(&resolved);
        return;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_inode_locked(inode);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        path_put(&resolved);
        return;
    }
    hash_del(&entry->node);
    mutex_unlock(&padlock_guard_lock);
    path_put(&resolved);
    kfree(entry);
}

static int padlock_guard_begin_session(struct padlock_guard_request *request)
{
    struct padlock_guard_entry *entry;
    u64 token;

    if (!request || request->path[0] == '\0') {
        return -EINVAL;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_path_locked(request->path);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        return -ENOENT;
    }

    if (entry->session_active && entry->writer_tgid != task_tgid_nr(current)) {
        mutex_unlock(&padlock_guard_lock);
        return -EBUSY;
    }

    do {
        get_random_bytes(&token, sizeof(token));
    } while (token == 0);

    entry->session_active = true;
    entry->writer_tgid = task_tgid_nr(current);
    entry->session_dirty = true;
    entry->token = token;
    request->token = token;
    request->flags = PADLOCK_GUARD_FLAG_LOCKED | PADLOCK_GUARD_FLAG_SESSION;
    mutex_unlock(&padlock_guard_lock);
    return 0;
}

static int padlock_guard_end_session(struct padlock_guard_request *request)
{
    struct padlock_guard_entry *entry;

    if (!request || request->path[0] == '\0') {
        return -EINVAL;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_path_locked(request->path);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        return -ENOENT;
    }

    if (!entry->session_active || entry->writer_tgid != task_tgid_nr(current) || entry->token != request->token) {
        mutex_unlock(&padlock_guard_lock);
        return -EPERM;
    }

    entry->session_active = false;
    entry->writer_tgid = 0;
    entry->session_dirty = false;
    entry->token = 0;
    request->flags = PADLOCK_GUARD_FLAG_LOCKED;
    mutex_unlock(&padlock_guard_lock);
    return 0;
}

static int padlock_guard_query(struct padlock_guard_request *request)
{
    struct padlock_guard_entry *entry;

    if (!request || request->path[0] == '\0') {
        return -EINVAL;
    }

    mutex_lock(&padlock_guard_lock);
    entry = padlock_guard_find_path_locked(request->path);
    if (!entry) {
        mutex_unlock(&padlock_guard_lock);
        return -ENOENT;
    }

    request->start = entry->start;
    request->length = entry->length;
    request->token = entry->token;
    request->flags = 0;
    if (entry->locked) {
        request->flags |= PADLOCK_GUARD_FLAG_LOCKED;
    }
    if (entry->session_active) {
        request->flags |= PADLOCK_GUARD_FLAG_SESSION;
    }
    mutex_unlock(&padlock_guard_lock);
    return 0;
}

static long padlock_guard_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct padlock_guard_request *request;
    int result;

    (void) file;

    if (_IOC_TYPE(cmd) != PADLOCK_GUARD_IOCTL_MAGIC) {
        return -ENOTTY;
    }

    request = kzalloc(sizeof(*request), GFP_KERNEL);
    if (!request) {
        return -ENOMEM;
    }

    if (copy_from_user(request, (void __user *) arg, sizeof(*request)) != 0) {
        kfree(request);
        return -EFAULT;
    }

    switch (cmd) {
        case PADLOCK_GUARD_IOCTL_REGISTER:
            if (request->path[PADLOCK_GUARD_PATH_MAX - 1u] != '\0') {
                kfree(request);
                return -ENAMETOOLONG;
            }
            result = padlock_guard_register_entry(request->path, request->start, request->length);
            request->flags = result == 0 ? PADLOCK_GUARD_FLAG_LOCKED : 0;
            break;
        case PADLOCK_GUARD_IOCTL_UNREGISTER:
            padlock_guard_unregister_entry(request->path);
            result = 0;
            break;
        case PADLOCK_GUARD_IOCTL_BEGIN_WRITE:
            result = padlock_guard_begin_session(request);
            break;
        case PADLOCK_GUARD_IOCTL_END_WRITE:
            result = padlock_guard_end_session(request);
            break;
        case PADLOCK_GUARD_IOCTL_QUERY:
            result = padlock_guard_query(request);
            break;
        default:
            kfree(request);
            return -ENOTTY;
    }

    if (result != 0) {
        kfree(request);
        return result;
    }

    if (_IOC_DIR(cmd) & _IOC_READ) {
        if (copy_to_user((void __user *) arg, request, sizeof(*request)) != 0) {
            kfree(request);
            return -EFAULT;
        }
    }

    kfree(request);
    return 0;
}

static const struct file_operations padlock_guard_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = padlock_guard_ioctl,
    .compat_ioctl = padlock_guard_ioctl,
    .llseek = noop_llseek,
};

static void padlock_guard_kprobe_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    (void) p;
    (void) regs;
    (void) flags;
}

static int padlock_guard_register_probe(struct kprobe *probe, const char *symbol, kprobe_pre_handler_t handler)
{
    memset(probe, 0, sizeof(*probe));
    probe->symbol_name = symbol;
    probe->pre_handler = handler;
    probe->post_handler = padlock_guard_kprobe_post;
    return register_kprobe(probe);
}

static void padlock_guard_unregister_all_probes(void)
{
    unregister_kprobe(&padlock_guard_probe_file_permission);
    unregister_kprobe(&padlock_guard_probe_file_truncate);
#ifdef CONFIG_SECURITY_PATH
    unregister_kprobe(&padlock_guard_probe_path_unlink);
    unregister_kprobe(&padlock_guard_probe_path_rename);
    unregister_kprobe(&padlock_guard_probe_path_truncate);
#endif
}

static int __init padlock_guard_init(void)
{
    int result;

    mutex_init(&padlock_guard_lock);
    hash_init(padlock_guard_table);

    padlock_guard_device.minor = MISC_DYNAMIC_MINOR;
    padlock_guard_device.name = PADLOCK_GUARD_DEVICE_NAME;
    padlock_guard_device.fops = &padlock_guard_fops;

    result = misc_register(&padlock_guard_device);
    if (result != 0) {
        pr_err("failed to register misc device: %d\n", result);
        return result;
    }

    result = padlock_guard_register_probe(
        &padlock_guard_probe_file_permission,
        "security_file_permission",
        padlock_guard_kprobe_file_permission
    );
    if (result != 0) {
        pr_err("failed to register security_file_permission probe: %d\n", result);
        goto fail_misc;
    }

    result = padlock_guard_register_probe(
        &padlock_guard_probe_file_truncate,
        "security_file_truncate",
        padlock_guard_kprobe_file_truncate
    );
    if (result != 0) {
        pr_err("failed to register security_file_truncate probe: %d\n", result);
        goto fail_probes;
    }

#ifdef CONFIG_SECURITY_PATH
    result = padlock_guard_register_probe(
        &padlock_guard_probe_path_unlink,
        "security_path_unlink",
        padlock_guard_kprobe_path_unlink
    );
    if (result != 0) {
        pr_err("failed to register security_path_unlink probe: %d\n", result);
        goto fail_probes;
    }

    result = padlock_guard_register_probe(
        &padlock_guard_probe_path_rename,
        "security_path_rename",
        padlock_guard_kprobe_path_rename
    );
    if (result != 0) {
        pr_err("failed to register security_path_rename probe: %d\n", result);
        goto fail_probes;
    }

    result = padlock_guard_register_probe(
        &padlock_guard_probe_path_truncate,
        "security_path_truncate",
        padlock_guard_kprobe_path_truncate
    );
    if (result != 0) {
        pr_err("failed to register security_path_truncate probe: %d\n", result);
        goto fail_probes;
    }
#endif

    padlock_guard_pinned = try_module_get(THIS_MODULE);
    pr_info("loaded\n");
    return 0;

fail_probes:
    padlock_guard_unregister_all_probes();
fail_misc:
    misc_deregister(&padlock_guard_device);
    return result;
}

static void __exit padlock_guard_exit(void)
{
    if (padlock_guard_pinned) {
        module_put(THIS_MODULE);
    }
    padlock_guard_unregister_all_probes();
    misc_deregister(&padlock_guard_device);
    pr_info("unloaded\n");
}

module_init(padlock_guard_init);
module_exit(padlock_guard_exit);
