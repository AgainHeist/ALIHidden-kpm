// ============================================================
//  DARKxKERNEL KPM  (nvsvc)  v2
//  Userspace protocol: /dev/nvsvc  ->  DarkXKernal KernelTools.cpp
//  Strict hiding, default ON. Kernel 5.4 - 6.1 (arm64 / x86_64)
// ============================================================
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <common.h>
#include <kpmodule.h>
#include <kputils.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

#ifndef KPM
#define KPM 1
#endif

KPM_NAME("nvsvc");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("DarkXKernel");
KPM_DESCRIPTION("system service");

#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ESRCH
#define ESRCH 3
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EIO
#define EIO 5
#endif
#ifndef E2BIG
#define E2BIG 7
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef IS_ERR
#define IS_ERR(x) ((unsigned long)(x) >= (unsigned long)-4095UL)
#endif
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0
#endif
#ifndef FOLL_WRITE
#define FOLL_WRITE 0x01
#endif
#ifndef FOLL_FORCE
#define FOLL_FORCE 0x08
#endif
#ifndef LOOKUP_FOLLOW
#define LOOKUP_FOLLOW 0x0001
#endif
#ifndef LOOKUP_DIRECTORY
#define LOOKUP_DIRECTORY 0x0004
#endif
#ifndef PIDTYPE_PID
#define PIDTYPE_PID 0
#endif
#ifndef MISC_DYNAMIC_MINOR
#define MISC_DYNAMIC_MINOR 255
#endif

#if defined(__aarch64__)
# define P_ARG0(r) ((r)->regs[0])
# define P_ARG1(r) ((r)->regs[1])
# define P_ARG2(r) ((r)->regs[2])
# define P_RET(r)  ((r)->regs[0])
#elif defined(__x86_64__)
# define P_ARG0(r) ((r)->di)
# define P_ARG1(r) ((r)->si)
# define P_ARG2(r) ((r)->dx)
# define P_RET(r)  ((r)->ax)
#else
# error "arm64 / x86_64 only"
#endif

/* ============================================================
 *  KERNEL STRUCT SHIMS  (5.4 - 6.1 layouts, corrected)
 * ============================================================ */
struct module;
struct inode;
struct vfsmount;
struct pid;
struct task_struct;
struct anon_vma;
struct vm_operations_struct;

struct qstr { unsigned int hash; unsigned int len; const unsigned char *name; };
struct hlist_bl_node { struct hlist_bl_node *next, **pprev; };

struct dentry {
	unsigned int d_flags;
	unsigned int d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
};

struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct file { struct path f_path; };

struct dir_context {
	bool (*actor)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
	loff_t pos;
};

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter)(void *, void *);
	ssize_t (*write_iter)(void *, void *);
	int (*iopoll)(void *, void *);
	int (*iterate)(struct file *, struct dir_context *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	unsigned int (*poll)(struct file *, void *);
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
};

/* FIX #1: nodename wapas, warna misc_register 0x1B6 deref karke panic karta hai */
struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	void *parent;
	void *this_device;
	const void *groups;
	const char *nodename;
	umode_t mode;
};

struct seq_file { char *buf; size_t size; size_t from; size_t count; };

struct kstatfs { long f_type; long f_bsize; };

/* FIX #4: poora 5.4-6.1 vm_area_struct, vm_file ab sahi offset par */
struct vm_area_struct {
	unsigned long vm_start;
	unsigned long vm_end;
	struct vm_area_struct *vm_next;
	struct vm_area_struct *vm_prev;
	void *vm_rb[3];
	unsigned long rb_subtree_gap;
	struct mm_struct *vm_mm;
	unsigned long vm_page_prot;
	unsigned long vm_flags;
	void *vm_shared[4];
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	unsigned long vm_pgoff;
	struct file *vm_file;
};

struct mm_struct { struct vm_area_struct *mmap; };

/* FIX #3: uts_namespace ke shuru mein struct kref (4 byte) hota hai */
#define __NEW_UTS_LEN 64
struct kp_utsname {
	char sysname[__NEW_UTS_LEN + 1];
	char nodename[__NEW_UTS_LEN + 1];
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	char machine[__NEW_UTS_LEN + 1];
	char domainname[__NEW_UTS_LEN + 1];
};
struct kp_utsns { unsigned int kref; struct kp_utsname name; };

/* ============================================================
 *  RUNTIME SYMBOLS
 * ============================================================ */
static int  (*k_misc_register)(struct miscdevice *);
static void (*k_misc_deregister)(struct miscdevice *);
static int  (*k_kern_path)(const char *, unsigned int, struct path *);
static void (*k_path_put)(const struct path *);
static struct pid *(*k_find_vpid)(int);
static struct task_struct *(*k_pid_task)(struct pid *, int);
static struct mm_struct *(*k_get_task_mm)(struct task_struct *);
static void (*k_mmput)(struct mm_struct *);
static void (*k_get_task_struct)(struct task_struct *);
static void (*k_put_task_struct)(struct task_struct *);
static void *(*k_kvmalloc)(unsigned long, int);
static void (*k_kvfree)(void *);
static int  (*k_access_process_vm)(struct task_struct *, unsigned long, void *, int, int);
static loff_t (*k_no_llseek)(struct file *, loff_t, int);
static int  (*k_copy_from_user)(void *, const void __user *, unsigned long);
static int  *k_kptr_restrict;
static char **k_saved_cmdline;
static struct kp_utsns *k_uts;

#define copy_from_user(to, from, n) \
	(k_copy_from_user ? k_copy_from_user((to), (from), (unsigned long)(n)) : -EFAULT)
#define copy_to_user(to, from, n)   (compat_copy_to_user((to), (from), (int)(n)))
#define strncpy_from_user(d, s, n)  (compat_strncpy_from_user((d), (s), (n)))
#define kp_get_user_byte(dst, src)  copy_from_user((dst), (src), 1)

/* ============================================================
 *  kprobe / kretprobe over KP inline hooks
 * ============================================================ */
struct kprobe;
typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, unsigned long);
struct kprobe {
	const char *symbol_name;
	kprobe_pre_handler_t pre_handler;
	kprobe_post_handler_t post_handler;
	void *addr;
	int hooked;
};
struct kretprobe_instance { void *data; };
typedef int (*kretprobe_entry_handler_t)(struct kretprobe_instance *, struct pt_regs *);
typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);
struct kretprobe {
	struct kprobe kp;
	kretprobe_entry_handler_t entry_handler;
	kretprobe_handler_t handler;
	int data_size;
	int maxactive;
	int hooked;
};

#ifndef regs_return_value
#define regs_return_value(r) P_RET(r)
#endif

#if defined(__aarch64__)
static void regs_in(struct pt_regs *r, hook_fargs4_t *f)
{
	memset(r, 0, sizeof(*r));
	r->regs[0] = f->arg0; r->regs[1] = f->arg1;
	r->regs[2] = f->arg2; r->regs[3] = f->arg3;
}
static void regs_out(hook_fargs4_t *f, struct pt_regs *r)
{
	f->arg0 = r->regs[0]; f->arg1 = r->regs[1];
	f->arg2 = r->regs[2]; f->arg3 = r->regs[3];
}
#else
static void regs_in(struct pt_regs *r, hook_fargs4_t *f)
{
	memset(r, 0, sizeof(*r));
	r->di = f->arg0; r->si = f->arg1; r->dx = f->arg2; r->cx = f->arg3;
}
static void regs_out(hook_fargs4_t *f, struct pt_regs *r)
{
	f->arg0 = r->di; f->arg1 = r->si; f->arg2 = r->dx; f->arg3 = r->cx;
}
#endif

static void kprobe_before(hook_fargs4_t *f, void *ud)
{
	struct kprobe *p = (struct kprobe *)ud;
	struct pt_regs r;
	if (!p->pre_handler) return;
	regs_in(&r, f);
	p->pre_handler(p, &r);
	regs_out(f, &r);
}

static void kprobe_after(hook_fargs4_t *f, void *ud)
{
	struct kprobe *p = (struct kprobe *)ud;
	struct pt_regs r;
	if (!p->post_handler) return;
	regs_in(&r, f);
	P_RET(&r) = f->ret;
	p->post_handler(p, &r, 0);
	f->ret = P_RET(&r);
	regs_out(f, &r);
}

static void kret_before(hook_fargs4_t *f, void *ud)
{
	struct kretprobe *kr = (struct kretprobe *)ud;
	struct kretprobe_instance ri;
	struct pt_regs r;
	f->local.data[7] = 0;
	if (!kr->entry_handler) return;
	ri.data = f->local.data;
	regs_in(&r, f);
	f->local.data[7] = kr->entry_handler(&ri, &r) ? 1 : 0;
	regs_out(f, &r);
}

static void kret_after(hook_fargs4_t *f, void *ud)
{
	struct kretprobe *kr = (struct kretprobe *)ud;
	struct kretprobe_instance ri;
	struct pt_regs r;
	if (!f->local.data[7] || !kr->handler) return;
	ri.data = f->local.data;
	regs_in(&r, f);
	P_RET(&r) = f->ret;
	kr->handler(&ri, &r);
	f->ret = P_RET(&r);
	regs_out(f, &r);
}

static int register_kprobe(struct kprobe *p)
{
	unsigned long addr;
	if (!p->symbol_name || !kallsyms_lookup_name) return -EINVAL;
	addr = kallsyms_lookup_name(p->symbol_name);
	if (!addr) { pr_info("nvsvc: no sym %s\n", p->symbol_name); return -ESRCH; }
	p->addr = (void *)addr;
	if (hook_wrap4(p->addr, kprobe_before, kprobe_after, p)) { p->addr = 0; return -EIO; }
	p->hooked = 1;
	return 0;
}

static void unregister_kprobe(struct kprobe *p)
{
	if (!p->hooked) return;
	hook_unwrap(p->addr, kprobe_before, kprobe_after);
	p->hooked = 0;
}

static int register_kretprobe(struct kretprobe *kr)
{
	unsigned long addr;
	if (!kr->kp.symbol_name || !kallsyms_lookup_name) return -EINVAL;
	if (kr->data_size > 48) return -E2BIG;
	addr = kallsyms_lookup_name(kr->kp.symbol_name);
	if (!addr) { pr_info("nvsvc: no sym %s\n", kr->kp.symbol_name); return -ESRCH; }
	kr->kp.addr = (void *)addr;
	if (hook_wrap4(kr->kp.addr, kret_before, kret_after, kr)) { kr->kp.addr = 0; return -EIO; }
	kr->hooked = 1;
	return 0;
}

static void unregister_kretprobe(struct kretprobe *kr)
{
	if (!kr->hooked) return;
	hook_unwrap(kr->kp.addr, kret_before, kret_after);
	kr->hooked = 0;
}

/* ---------- helpers ---------- */
static long kp_strscpy(char *d, const char *s, long c)
{
	long i;
	if (c <= 0) return -E2BIG;
	for (i = 0; i + 1 < c && s[i]; i++) d[i] = s[i];
	d[i] = '\0';
	return i;
}

static void *kp_memmem(const void *h, long hl, const void *n, long nl)
{
	const char *p = h, *end = p + hl, *nd = n;
	if (nl <= 0 || nl > hl) return 0;
	while (p + nl <= end) {
		p = memchr(p, nd[0], end - p - nl + 1);
		if (!p) return 0;
		if (!memcmp(p, nd, nl)) return (void *)p;
		p++;
	}
	return 0;
}

#define DEV_NAME   "nvsvc"
#define OP_INIT    0x800
#define OP_READ    0x801
#define OP_WRITE   0x802
#define OP_BASE    0x803
#define OP_HIDE    0x804
#define OP_STRICT  0x805
#define OP_VER     0x806
#define API_VER    2
#define MAX_IO     0x2000000
#define SMALL_IO   512
#define PATH_S     48
#define FAKE_DIR   "/data/misc/.__np"
#define FAKE_FALL  "/data/misc"

#define OVERLAY_MAGIC 0x794c7630U
#define EXT4_MAGIC    0xef53U

struct copy_mem { int pid; unsigned int pad; unsigned long long addr, buffer, size; };
struct mod_base { int pid; unsigned int pad; unsigned long long name, base; };
#ifdef CONFIG_COMPAT
struct copy_mem32 { int pid; unsigned int addr, buffer, size; };
struct mod_base32 { int pid; unsigned int name, base; };
#endif

static char saved_release[__NEW_UTS_LEN + 1];
static char saved_version[__NEW_UTS_LEN + 1];
static int  saved_kptr;
static int  inited;
static int  strict = 1;
static int  hide_pid;
static unsigned int hooks_ok;
static const char *fake_path = FAKE_FALL;

static int bypass(void) { return current_uid() == 0 && !strict; }

static const char *const hidden[] = {
	"/data/adb", "/sbin/su", "/system/bin/su", "/system/xbin/su",
	"/vendor/bin/su", "/system/bin/.ext", "/debug_ramdisk",
	"/sbin/.magisk", "/system/bin/magisk", "/system/bin/ksud",
	"/system/bin/apd", "/system/etc/init/magisk",
	"/system/etc/init/init.magisk.rc", "/system/app/Magisk",
	"/cache/magisk.log", "/data/magisk",
	"/data/data/com.topjohnwu.magisk",
	"/data/user/0/com.topjohnwu.magisk",
	"/data/user_de/0/com.topjohnwu.magisk",
	"/data/data/me.weishu.kernelsu",
	"/data/user/0/me.weishu.kernelsu",
	"/data/user_de/0/me.weishu.kernelsu",
	"/data/data/me.bmax.apatch",
	"/data/user/0/me.bmax.apatch",
	"/data/user_de/0/me.bmax.apatch",
	"/data/local/tmp", "/proc/config.gz", "/sys/module/nvsvc",
	"/data/misc/.__np",
};
#define HIDDEN_N ARRAY_SIZE(hidden)

static const char *const blk_name[] = {
	"su", "magisk", "Magisk", "ksud", "apd", "adb", "kpatch",
	"nvsvc", ".__np", ".magisk", ".ext", "debug_ramdisk",
	"libnvsvc.so", "init.magisk.rc", "config.gz",
};
#define BLK_N ARRAY_SIZE(blk_name)

static const char *const blk_pfx[] = {
	"com.topjohnwu.magisk", "me.weishu.kernelsu",
	"me.bmax.apatch", "com.dergoogler.mmrl",
};
#define BLK_PF ARRAY_SIZE(blk_pfx)

static const char *const blk_text[] = {
	"kpatch", "APatch", "KernelSU", "magisk", "Magisk", "ksud", "apd",
	"overlay", "nvsvc", ".__np", "debug_ramdisk", "libnvsvc",
	"/data/adb", "/data/local/tmp",
	"com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
};
#define BLK_T ARRAY_SIZE(blk_text)

static int is_hidden(const char *p)
{
	unsigned int i;
	long n;
	if (!p || p[0] != '/') return 0;
	for (i = 0; i < HIDDEN_N; i++) {
		n = (long)strlen(hidden[i]);
		if (!strncmp(p, hidden[i], n) && (p[n] == '\0' || p[n] == '/'))
			return 1;
	}
	return 0;
}

static int name_blocked(const char *n, int len)
{
	unsigned int i;
	long l;
	if (len <= 0 || len > 64) return 0;
	for (i = 0; i < BLK_N; i++)
		if ((int)strlen(blk_name[i]) == len && !memcmp(n, blk_name[i], len))
			return 1;
	for (i = 0; i < BLK_PF; i++) {
		l = (long)strlen(blk_pfx[i]);
		if ((long)len > l && !memcmp(n, blk_pfx[i], l)) return 1;
	}
	return 0;
}

static int text_blocked(const char *s, long len)
{
	unsigned int i;
	long n;
	if (!len) return 0;
	for (i = 0; i < BLK_T; i++) {
		n = (long)strlen(blk_text[i]);
		if (n > len) continue;
		if (kp_memmem(s, len, blk_text[i], n)) return 1;
	}
	return 0;
}

static void blank_word(char *b, const char *w)
{
	long n = (long)strlen(w);
	char *p = b;
	while ((p = strstr(p, w))) { memset(p, ' ', n); p += n; }
}

/* ---------- uts ---------- */
static void uts_scrub(void)
{
	char *r = k_uts->name.release, *v = k_uts->name.version, *c;
	memcpy(saved_release, r, sizeof(saved_release));
	memcpy(saved_version, v, sizeof(saved_version));
	c = strpbrk(r, "-+");
	if (c) *c = '\0';
	blank_word(v, "APatch");
	blank_word(v, "KernelSU");
	blank_word(v, "kpatch");
	blank_word(v, "KPM");
	blank_word(v, "Magisk");
	c = v + strlen(v);
	while (c > v && c[-1] == ' ') *--c = '\0';
}

static void uts_restore(void)
{
	memcpy(k_uts->name.release, saved_release, sizeof(saved_release));
	memcpy(k_uts->name.version, saved_version, sizeof(saved_version));
}

/* ---------- bootloader / props ---------- */
static void set_bootstate(char *c)
{
	char *p = strstr(c, "verifiedbootstate="), *v;
	if (!p) return;
	v = p + 18;
	if (!strncmp(v, "orange", 6) || !strncmp(v, "yellow", 6)) { memcpy(v, "green ", 6); return; }
	if (!strncmp(v, "red", 3)) {
		long tail = (long)strlen(v + 3);
		memmove(v + 5, v + 3, tail + 1);
		memcpy(v, "green", 5);
	}
}

static void set_locked(char *c)
{
	char *p = strstr(c, "flash.locked=");
	if (!p) return;
	p += 13;
	if (*p == '0') *p = '1';
}

static void set_vbmeta(char *c)
{
	char *p = strstr(c, "vbmeta.device_state=");
	if (!p) return;
	p += 20;
	if (!strncmp(p, "unlocked", 8)) memcpy(p, "locked  ", 8);
}

static void set_verity(char *c)
{
	char *p = strstr(c, "veritymode=");
	if (!p) return;
	p += 11;
	if (!strncmp(p, "disabled", 8) || !strncmp(p, "logging", 7)) {
		long tail = (long)strlen(p + 8);
		memmove(p + 9, p + 8, tail + 1);
		memcpy(p, "enforcing", 9);
	}
}

static void set_selinux(char *c)
{
	char *p = strstr(c, "androidboot.selinux=");
	if (!p || strncmp(p + 21, "permissive", 10)) return;
	memcpy(p + 21, "enforcing", 9);
	memmove(p + 30, p + 31, strlen(p + 31) + 1);
}

static void scrub_boot_args(char *c)
{
	set_bootstate(c); set_locked(c); set_vbmeta(c); set_verity(c); set_selinux(c);
}

static void cmdline_scrub(void)
{
	char *c;
	if (!k_saved_cmdline) return;
	c = *k_saved_cmdline;
	if (c) scrub_boot_args(c);
}

static void scrub_buildprop(char *c)
{
	char *p;
	if ((p = strstr(c, "ro.debuggable=1"))) p[14] = '0';
	if ((p = strstr(c, "ro.secure=0"))) p[10] = '1';
	if ((p = strstr(c, "ro.build.type=userdebug"))) memcpy(p + 14, "user     ", 9);
	if ((p = strstr(c, "ro.build.tags=test-keys"))) memcpy(p + 14, "release  ", 9);
}

static void scrub_ctx(char *c)
{
	char *p;
	if ((p = strstr(c, "kernelsu"))) memcpy(p, "init    ", 8);
	if ((p = strstr(c, "magisk"))) memcpy(p, "init  ", 6);
	if ((p = strstr(c, "ksu"))) memcpy(p, "init", 4);
}

/* ---------- getname ---------- */
struct gp_data { char path[PATH_S]; int hide; };

static struct kretprobe kr_name = {
	.kp.symbol_name = "getname_flags",
	.maxactive      = 128,
	.data_size      = sizeof(struct gp_data),
};

static int name_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gp_data *d = (struct gp_data *)ri->data;
	const char __user *u = (const char __user *)P_ARG0(regs);
	char c;
	d->hide = 0;
	if (bypass() || !u) return 1;
	if (kp_get_user_byte(&c, u) || c != '/') return 1;
	if (strncpy_from_user(d->path, u, sizeof(d->path) - 1) < 0) return 1;
	d->path[sizeof(d->path) - 1] = '\0';
	d->hide = is_hidden(d->path);
	return 1;
}

static int name_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gp_data *d = (struct gp_data *)ri->data;
	struct filename *fn = (struct filename *)P_RET(regs);
	if (d->hide && fn && !IS_ERR(fn) && fn->name)
		kp_strscpy((char *)fn->name, fake_path, PATH_MAX);
	return 0;
}

static struct kprobe kp_path;

static int pre_path(struct kprobe *p, struct pt_regs *regs)
{
	struct filename *fn;
	(void)p;
	if (bypass()) return 0;
	fn = (struct filename *)P_ARG1(regs);
	if (fn && fn->name && is_hidden(fn->name))
		kp_strscpy((char *)fn->name, fake_path, PATH_MAX);
	return 0;
}

/* ---------- dir filter (per-call shadow, race-free) ---------- */
struct shadow { struct dir_context dc; struct dir_context *orig; int pidonly; };

static bool filter_actor(struct dir_context *c, const char *name, int namlen,
			 loff_t off, u64 ino, unsigned type)
{
	struct dir_context *o = ((struct shadow *)c)->orig;
	c->pos = off;
	if (name_blocked(name, namlen)) { o->pos = off; return false; }
	return o->actor(o, name, namlen, off, ino, type);
}

static bool filter_actor_pid(struct dir_context *c, const char *name, int namlen,
			     loff_t off, u64 ino, unsigned type)
{
	struct dir_context *o = ((struct shadow *)c)->orig;
	int v = 0, i;
	c->pos = off;
	for (i = 0; i < namlen && name[i] >= '0' && name[i] <= '9'; i++)
		v = v * 10 + (name[i] - '0');
	if (i && i == namlen && v == hide_pid) { o->pos = off; return false; }
	if (name_blocked(name, namlen)) { o->pos = off; return false; }
	return o->actor(o, name, namlen, off, ino, type);
}

static void dir_before(hook_fargs4_t *f, void *ud)
{
	struct shadow *s = (struct shadow *)f->local.data;
	struct dir_context *ctx = (struct dir_context *)f->arg1;
	int pidonly = (int)(unsigned long)ud;

	f->local.data[7] = 0;
	if (bypass() || !ctx || !ctx->actor) return;
	if ((void *)ctx->actor == (void *)filter_actor) return;
	if (pidonly && !hide_pid) return;

	s->orig = ctx;
	memcpy(&s->dc, ctx, sizeof(*ctx));
	s->dc.actor = pidonly ? filter_actor_pid : filter_actor;
	s->pidonly = pidonly;
	f->arg1 = (unsigned long)&s->dc;
	f->local.data[7] = 1;
}

static void dir_after(hook_fargs4_t *f, void *ud)
{
	struct shadow *s = (struct shadow *)f->local.data;
	(void)ud;
	if (!f->local.data[7]) return;
	s->orig->pos = s->dc.pos;
}

static struct kprobe kp_iter, kp_piddir;

/* ---------- read scrub ---------- */
static struct kretprobe kr_pread, kr_bprop;

static int pre_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *f = (struct file *)P_ARG0(regs);
	int *mode = (int *)ri->data;
	const char *n;
	*mode = 0;
	if (bypass() || !f || !f->f_path.dentry) return 0;
	n = f->f_path.dentry->d_name.name;
	if (!n) return 0;
	if (!strncmp(n, "bootargs", 8)) { *mode = 1; return 1; }
	if (!strcmp(n, "build.prop")) { *mode = 2; return 1; }
	if (!strcmp(n, "current")) {
		const char *pn = f->f_path.dentry->d_parent ?
			f->f_path.dentry->d_parent->d_name.name : NULL;
		if (pn && !strcmp(pn, "attr")) { *mode = 3; return 1; }
		return 0;
	}
	if (!strcmp(n, "enforce")) { *mode = 4; return 1; }
	return 0;
}

static int post_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	int mode = *(int *)ri->data;
	char buf[1024];
	long n;
	if (!mode || ret <= 0) return 0;
	n = ret > (long)sizeof(buf) - 1 ? (long)sizeof(buf) - 1 : ret;
	if (copy_from_user(buf, ub, n)) return 0;
	buf[n] = '\0';
	switch (mode) {
	case 1: scrub_boot_args(buf); break;
	case 2: scrub_buildprop(buf); break;
	case 3: scrub_ctx(buf); break;
	case 4: if (buf[0] == '0') buf[0] = '1'; break;
	default: return 0;
	}
	copy_to_user(ub, buf, n);
	return 0;
}

/* ---------- statfs ---------- */
static struct kretprobe kr_statfs;

static int entry_statfs(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	(void)ri; (void)regs;
	return 1;
}

static int post_statfs(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kstatfs *st = (struct kstatfs *)P_ARG1(regs);
	(void)ri;
	if (bypass() || !st) return 0;
	if (st->f_type == OVERLAY_MAGIC) st->f_type = EXT4_MAGIC;
	return 0;
}

/* ---------- readlink ---------- */
static struct kretprobe kr_rl;

static int pre_rl(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *on = (int *)ri->data;
	(void)regs;
	*on = bypass() ? 0 : 1;
	return *on;
}

static int post_rl(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	static const char repl[] = "/dev/ashmem";
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	char buf[64];
	long n;
	if (!*(int *)ri->data || ret <= 0) return 0;
	n = ret > (long)sizeof(buf) - 1 ? (long)sizeof(buf) - 1 : ret;
	if (copy_from_user(buf, ub, n)) return 0;
	buf[n] = '\0';
	if (!strstr(buf, DEV_NAME)) return 0;
	if (copy_to_user(ub, repl, sizeof(repl) - 1)) return 0;
	P_RET(regs) = (unsigned long)(sizeof(repl) - 1);
	return 0;
}

/* ---------- seq compaction ---------- */
struct tr_data { struct seq_file *m; long saved; int maps; };
static struct kretprobe kr_mounts, kr_mountinfo, kr_modules, kr_misc;
static struct kretprobe kr_fs, kr_vm, kr_status, kr_smaps, kr_maps, kr_roll;

static int tr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct seq_file *m = (struct seq_file *)P_ARG0(regs);
	d->m = m; d->saved = 0; d->maps = 0;
	if (bypass() || !m || !m->buf || m->size < m->count || m->size > 0x100000) return 0;
	d->saved = (long)m->count;
	return 1;
}

static int tr_entry_maps(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int r = tr_entry(ri, regs);
	((struct tr_data *)ri->data)->maps = 1;
	return r;
}

static void zero_tracer(char *buf, long start, long end)
{
	char *p = kp_memmem(buf + start, end - start, "TracerPid:", 10);
	if (!p) return;
	p += 10;
	while (p < buf + end && (*p == '\t' || *p == ' ')) p++;
	if (p >= buf + end || *p < '0' || *p > '9') return;
	*p++ = '0';
	while (p < buf + end && *p >= '0' && *p <= '9') *p++ = ' ';
}

static void defang_perms(char *buf, long start, long end)
{
	long i = start;
	while (i < end) {
		char *nl = memchr(buf + i, '\n', end - i);
		long ll = nl ? (long)(nl - (buf + i)) + 1 : end - i;
		char *sp = memchr(buf + i, ' ', ll);
		if (sp && (sp - buf) + 4 < i + ll && sp[1] == 'r' && sp[2] == 'w' && sp[3] == 'x')
			sp[2] = '-';
		i += ll;
	}
}

static int tr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct seq_file *m = d->m;
	long i, o, end;
	(void)regs;
	if (!d->saved || !m || (long)m->count <= d->saved) return 0;
	zero_tracer(m->buf, d->saved, (long)m->count);
	if (d->maps) defang_perms(m->buf, d->saved, (long)m->count);
	i = d->saved; end = (long)m->count; o = d->saved;
	while (i < end) {
		char *nl = memchr(m->buf + i, '\n', end - i);
		long ll = nl ? (long)(nl - (m->buf + i)) + 1 : end - i;
		if (text_blocked(m->buf + i, ll)) { i += ll; continue; }
		if (o != i) memmove(m->buf + o, m->buf + i, ll);
		o += ll; i += ll;
	}
	m->count = (unsigned long)o;
	return 0;
}

static void hook_tr(struct kretprobe *kr, const char *sym, int maps)
{
	kr->kp.symbol_name = sym;
	kr->entry_handler = maps ? tr_entry_maps : tr_entry;
	kr->handler = tr_ret;
	kr->data_size = sizeof(struct tr_data);
	kr->maxactive = 64;
	if (!register_kretprobe(kr)) { hooks_ok++; return; }
	memset(kr, 0, sizeof(*kr));
}

static void hooks_install(void)
{
	kr_name.entry_handler = name_entry;
	kr_name.handler = name_ret;
	if (!register_kretprobe(&kr_name)) hooks_ok++;
	else {
		memset(&kr_name, 0, sizeof(kr_name));
		kp_path.symbol_name = "filename_lookup";
		kp_path.pre_handler = pre_path;
		if (!register_kprobe(&kp_path)) hooks_ok++;
	}
	kp_iter.symbol_name = "iterate_dir";
	kp_iter.pre_handler = NULL;
	if (!hook_wrap4((void *)kallsyms_lookup_name("iterate_dir"), dir_before, dir_after, (void *)0)) {
		kp_iter.hooked = 1; hooks_ok++;
	}
	if (kallsyms_lookup_name("proc_pid_readdir") &&
	    !hook_wrap4((void *)kallsyms_lookup_name("proc_pid_readdir"), dir_before, dir_after, (void *)1)) {
		kp_piddir.hooked = 1; hooks_ok++;
	}

	kr_pread.data_size = sizeof(int);
	kr_bprop.data_size = sizeof(int);
	kr_pread.entry_handler = pre_read;
	kr_bprop.entry_handler = pre_read;
	kr_pread.handler = post_read;
	kr_bprop.handler = post_read;
	hook_tr(&kr_pread, "proc_reg_read", 0);
	hook_tr(&kr_bprop, "vfs_read", 0);

	/* FIX #2: symbol_name ab set hota hai */
	kr_statfs.kp.symbol_name = "vfs_statfs";
	kr_statfs.data_size = 0;
	kr_statfs.entry_handler = entry_statfs;
	kr_statfs.handler = post_statfs;
	kr_statfs.maxactive = 64;
	if (!register_kretprobe(&kr_statfs)) hooks_ok++; else memset(&kr_statfs, 0, sizeof(kr_statfs));

	kr_rl.kp.symbol_name = "vfs_readlink";
	kr_rl.data_size = sizeof(int);
	kr_rl.entry_handler = pre_rl;
	kr_rl.handler = post_rl;
	kr_rl.maxactive = 64;
	if (!register_kretprobe(&kr_rl)) hooks_ok++; else memset(&kr_rl, 0, sizeof(kr_rl));

	hook_tr(&kr_mounts, "show_vfsmnt", 0);
	hook_tr(&kr_mountinfo, "show_mountinfo", 0);
	hook_tr(&kr_modules, "m_show", 0);
	hook_tr(&kr_misc, "misc_show", 0);
	hook_tr(&kr_fs, "filesystems_proc_show", 0);
	hook_tr(&kr_vm, "s_show", 0);
	hook_tr(&kr_status, "proc_pid_status", 0);
	hook_tr(&kr_maps, "show_map_vma", 1);
	hook_tr(&kr_smaps, "show_smap", 1);
	hook_tr(&kr_roll, "smaps_rollup_show", 1);
}

static void hooks_remove(void)
{
	if (kr_name.hooked) unregister_kretprobe(&kr_name);
	if (kp_path.hooked) unregister_kprobe(&kp_path);
	if (kp_iter.hooked) hook_unwrap((void *)kallsyms_lookup_name("iterate_dir"), dir_before, dir_after);
	if (kp_piddir.hooked) hook_unwrap((void *)kallsyms_lookup_name("proc_pid_readdir"), dir_before, dir_after);
	if (kr_pread.hooked) unregister_kretprobe(&kr_pread);
	if (kr_bprop.hooked) unregister_kretprobe(&kr_bprop);
	if (kr_statfs.hooked) unregister_kretprobe(&kr_statfs);
	if (kr_rl.hooked) unregister_kretprobe(&kr_rl);
	if (kr_mounts.hooked) unregister_kretprobe(&kr_mounts);
	if (kr_mountinfo.hooked) unregister_kretprobe(&kr_mountinfo);
	if (kr_modules.hooked) unregister_kretprobe(&kr_modules);
	if (kr_misc.hooked) unregister_kretprobe(&kr_misc);
	if (kr_fs.hooked) unregister_kretprobe(&kr_fs);
	if (kr_vm.hooked) unregister_kretprobe(&kr_vm);
	if (kr_status.hooked) unregister_kretprobe(&kr_status);
	if (kr_maps.hooked) unregister_kretprobe(&kr_maps);
	if (kr_smaps.hooked) unregister_kretprobe(&kr_smaps);
	if (kr_roll.hooked) unregister_kretprobe(&kr_roll);
}

static void pick_fake_path(void)
{
	struct path p;
	if (!k_kern_path || !k_path_put) return;
	if (!k_kern_path(FAKE_DIR, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &p)) {
		k_path_put(&p);
		fake_path = FAKE_DIR;
		return;
	}
	pr_info("nvsvc: %s missing, using %s\n", FAKE_DIR, FAKE_FALL);
}

/* ---------- symbols ---------- */
#define RS(name, slot) do { *(void **)&(slot) = (void *)kallsyms_lookup_name(name); \
	if (!(slot)) pr_info("nvsvc: missing %s\n", name); } while (0)

static int resolve_syms(void)
{
	if (!kallsyms_lookup_name) return -ESRCH;
	RS("_copy_from_user", k_copy_from_user);
	if (!k_copy_from_user) RS("__arch_copy_from_user", k_copy_from_user);
	RS("kptr_restrict", k_kptr_restrict);
	RS("saved_command_line", k_saved_cmdline);
	RS("init_uts_ns", k_uts);
	RS("misc_register", k_misc_register);
	RS("misc_deregister", k_misc_deregister);
	RS("kern_path", k_kern_path);
	RS("path_put", k_path_put);
	RS("find_vpid", k_find_vpid);
	RS("pid_task", k_pid_task);
	RS("get_task_mm", k_get_task_mm);
	RS("mmput", k_mmput);
	RS("get_task_struct", k_get_task_struct);
	RS("put_task_struct", k_put_task_struct);
	RS("kvmalloc", k_kvmalloc);
	RS("kvfree", k_kvfree);
	RS("access_process_vm", k_access_process_vm);
	RS("no_llseek", k_no_llseek);
	if (!k_misc_register || !k_misc_deregister || !k_copy_from_user) return -ESRCH;
	return 0;
}

/* ---------- ioctl ---------- */
static struct task_struct *task_get(int pid)
{
	struct task_struct *t;
	if (!k_find_vpid || !k_pid_task) return NULL;
	t = k_pid_task(k_find_vpid(pid), PIDTYPE_PID);
	if (t && k_get_task_struct) k_get_task_struct(t);
	return t;
}

static void task_put(struct task_struct *t) { if (t && k_put_task_struct) k_put_task_struct(t); }

static void wb_size(unsigned long arg, int c32, unsigned long long sz)
{
#ifdef CONFIG_COMPAT
	if (c32) {
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return;
		x.size = (unsigned int)sz;
		copy_to_user((void __user *)arg, &x, sizeof(x));
		return;
	}
#endif
	{
		struct copy_mem x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return;
		x.size = sz;
		copy_to_user((void __user *)arg, &x, sizeof(x));
	}
}

static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct copy_mem cm;
	struct task_struct *tsk;
	void *kbuf;
	char small[SMALL_IO];
	int ret, c32 = 0;
	(void)f;
#ifdef CONFIG_COMPAT
	c32 = in_compat_syscall();
#endif
	memset(&cm, 0, sizeof(cm));

	if (cmd == OP_INIT) return 0;
	if (cmd == OP_VER) {
		int v = (API_VER << 16) | (int)hooks_ok;
		return copy_to_user((void __user *)arg, &v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_STRICT) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		strict = !!v;
		return 0;
	}
	if (cmd == OP_HIDE) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		hide_pid = v;
		return 0;
	}

	if (c32) {
#ifdef CONFIG_COMPAT
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return -EFAULT;
		cm.pid = x.pid; cm.addr = x.addr; cm.buffer = x.buffer; cm.size = x.size;
#endif
	} else if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;

	if (cmd == OP_BASE) {
		struct mod_base mb;
		struct mm_struct *mm;
		struct vm_area_struct *vma;
		char pname[256];
		unsigned long long found = 0;
		int guard = 0;

		memset(&mb, 0, sizeof(mb));
		if (c32) {
#ifdef CONFIG_COMPAT
			struct mod_base32 y;
			if (copy_from_user(&y, (void __user *)arg, sizeof(y))) return -EFAULT;
			mb.pid = y.pid; mb.name = y.name;
#endif
		} else if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) return -EFAULT;

		if (!mb.pid || !mb.name) return -EINVAL;
		if (strncpy_from_user(pname, (const char __user *)(unsigned long)mb.name,
				      sizeof(pname) - 1) < 0) return -EFAULT;
		pname[sizeof(pname) - 1] = '\0';
		if (!pname[0] || !k_get_task_mm) return -EINVAL;

		tsk = task_get(mb.pid);
		if (!tsk) return -ESRCH;
		mm = k_get_task_mm(tsk);
		task_put(tsk);
		if (!mm) return -ESRCH;

		vma = mm->mmap;
		while (vma && guard++ < 8192) {
			const char *dn;
			if (vma->vm_file && vma->vm_file->f_path.dentry) {
				dn = vma->vm_file->f_path.dentry->d_name.name;
				if (dn && strstr(dn, pname)) { found = vma->vm_start; break; }
			}
			if (vma->vm_next && vma->vm_next <= vma) break;
			vma = vma->vm_next;
		}
		if (k_mmput) k_mmput(mm);
		mb.base = found;

		if (c32) {
#ifdef CONFIG_COMPAT
			struct mod_base32 y = { mb.pid, (unsigned int)mb.name, (unsigned int)found };
			copy_to_user((void __user *)arg, &y, sizeof(y));
#endif
		} else copy_to_user((void __user *)arg, &mb, sizeof(mb));
		return 0;
	}

	if (!cm.pid || !cm.size || cm.size > MAX_IO || !cm.addr || !cm.buffer) return -EINVAL;
	tsk = task_get(cm.pid);
	if (!tsk) return -ESRCH;
	if (!k_access_process_vm) { task_put(tsk); return -EIO; }

	if (cm.size <= SMALL_IO) kbuf = small;
	else {
		if (!k_kvmalloc) { task_put(tsk); return -ENOMEM; }
		kbuf = k_kvmalloc((unsigned long)cm.size, GFP_KERNEL);
		if (!kbuf) { task_put(tsk); return -ENOMEM; }
	}

	if (cmd == OP_READ) {
		ret = k_access_process_vm(tsk, (unsigned long)cm.addr, kbuf, (int)cm.size, 0);
		if (ret > 0 && copy_to_user((void __user *)(unsigned long)cm.buffer, kbuf, ret))
			ret = -EFAULT;
	} else if (cmd == OP_WRITE) {
		if (copy_from_user(kbuf, (void __user *)(unsigned long)cm.buffer,
				   (unsigned long)cm.size)) ret = -EFAULT;
		else ret = k_access_process_vm(tsk, (unsigned long)cm.addr, kbuf,
					       (int)cm.size, FOLL_WRITE | FOLL_FORCE);
	} else ret = -EINVAL;

	if (kbuf != (void *)small && k_kvfree) k_kvfree(kbuf);
	task_put(tsk);
	if (ret > 0) { wb_size(arg, c32, (unsigned long long)ret); return 0; }
	return ret < 0 ? ret : -EIO;
}

static struct file_operations dev_fops;
static struct miscdevice dev;

static long nvsvc_start(const char *args, const char *event, void *__user reserved)
{
	int r;
	(void)args; (void)event; (void)reserved;

	r = resolve_syms();
	if (r) { pr_info("nvsvc: resolve %d\n", r); return r; }

	memset(&dev_fops, 0, sizeof(dev_fops));
	dev_fops.unlocked_ioctl = dev_ioctl;
#ifdef CONFIG_COMPAT
	dev_fops.compat_ioctl = dev_ioctl;
#endif
	dev_fops.llseek = k_no_llseek;

	memset(&dev, 0, sizeof(dev));
	dev.minor = MISC_DYNAMIC_MINOR;
	dev.name = DEV_NAME;
	dev.fops = &dev_fops;
	dev.mode = 0666;         /* ab sahi offset par -> node 0666 banta hai */

	pick_fake_path();
	r = k_misc_register(&dev);
	if (r) { pr_info("nvsvc: misc_register %d\n", r); return r; }

	if (k_uts) uts_scrub();
	cmdline_scrub();
	if (k_kptr_restrict) { saved_kptr = *k_kptr_restrict; *k_kptr_restrict = 2; }
	hooks_install();
	inited = 1;
	pr_info("nvsvc: loaded, %u hooks\n", hooks_ok);
	return 0;
}

static long nvsvc_stop(void *__user reserved)
{
	(void)reserved;
	if (!inited) return 0;
	hooks_remove();
	if (k_kptr_restrict) *k_kptr_restrict = saved_kptr;
	if (k_uts) uts_restore();
	if (k_misc_deregister) k_misc_deregister(&dev);
	inited = 0;
	return 0;
}

KPM_INIT(nvsvc_start);
KPM_EXIT(nvsvc_stop);
