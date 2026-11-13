// ============================================================
//  DARKxKERNEL KPM  (nvsvc)  v8  FINAL
//  Owner tag: XOR-encoded + checksum-locked
//  Kernel 3.18 - 7.x (arm64 / x86_64)  |  layout-aware
//  Sab shim local, koi kernel type dependency nahi
// ============================================================
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <common.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

#if defined(__has_include)
#  if __has_include(<kputils.h>)
#    include <kputils.h>
#    define KP_HAVE_UTILS 1
#  endif
#  if __has_include(<linux/compat.h>)
#    include <linux/compat.h>
#    define KP_HAVE_COMPAT_H 1
#  endif
#endif

#ifndef KP_HAVE_UTILS
extern unsigned long kallsyms_lookup_name(const char *name);
extern unsigned int current_uid(void);
#endif
#ifdef CONFIG_COMPAT
#  ifndef KP_HAVE_COMPAT_H
extern int in_compat_syscall(void);
#  endif
#endif

#ifndef STAGE
#define STAGE 6
#endif

/* ============================================================
 *  OWNER TAG
 * ============================================================ */
#define NAME_KEY 0x5A
#define NAME_SUM 0x1B25
static const unsigned char name_enc[] = {
	0x15, 0x2D, 0x34, 0x3F, 0x28, 0x7A, 0x18, 0x23, 0x7A, 0x3B, 0x36, 0x33, 0x5A
};
static char owner_name[24];

static int name_decode(void)
{
	unsigned int i, s = 0;
	for (i = 0; i < sizeof(name_enc); i++)
		owner_name[i] = (char)(name_enc[i] ^ NAME_KEY);
	for (i = 0; owner_name[i]; i++)
		s += (unsigned int)owner_name[i] * (i + 1);
	return s == NAME_SUM;
}

KPM_NAME("Owner By ali");
KPM_VERSION("8.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("ali");
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
 *  KERNEL STRUCT SHIMS (3.18 - 7.x)
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

/* f_u (llist/rcu_head union) = 16 byte, f_path uske BAAD */
struct file {
	void *f_u[2];
	struct path f_path;
};

/* kernel ka struct filename -> pehla field hi name hai */
struct kp_filename { const char *name; };

struct dir_context {
	bool (*actor)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
	loff_t pos;
};

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	void *read_iter;
	void *write_iter;
	void *iopoll;
	void *iterate;
	void *iterate_shared;
	void *poll;
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
};

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

static int kptr_ok(const void *p)
{
	unsigned long a = (unsigned long)p;
	return a >= 0xffff000000000000UL && a != ~0UL;
}

/* ============================================================
 *  file_operations offset  ->  layout-agnostic
 *  primary: def_chr_fops probe (usme sirf .open set hota hai)
 *  fallback: version table
 * ============================================================ */
#define FOPS_MAX 384
static unsigned char fops_buf[FOPS_MAX] __attribute__((aligned(16)));
static unsigned int uio_off, cio_off;

static void fops_put(unsigned int off, const void *fn)
{
	if (off && off + sizeof(void *) <= FOPS_MAX)
		*(const void **)(fops_buf + off) = fn;
}

static int fops_offsets(unsigned int maj, unsigned int min)
{
	const unsigned long *p;
	unsigned int i, idx, delta;

	/* unlocked_ioctl ke baad: compat_ioctl, mmap,
	 * [mmap_supported_flags 4.20+], open  ->  delta 3 ya 4 */
	delta = (maj > 4 || (maj == 4 && min >= 20)) ? 4 : 3;

	p = (const unsigned long *)kallsyms_lookup_name("def_chr_fops");
	if (p) {
		for (i = 8; i < 18; i++) {
			if (!kptr_ok((const void *)p[i])) continue;
			if (i < delta + 6) return -EINVAL;
			idx = i - delta;
			if (idx < 6 || idx > 12) return -EINVAL;
			uio_off = idx * (unsigned int)sizeof(void *);
			cio_off = uio_off + (unsigned int)sizeof(void *);
			pr_info("nvsvc: fops probe uio=%u\n", uio_off);
			return 0;
		}
	}

	/* table fallback */
	if (maj >= 7) idx = 9;
	else if (maj == 6) idx = (min >= 6) ? 9 : 10;
	else if (maj == 5) idx = (min == 0) ? 9 : 10;
	else if (maj == 4) idx = (min >= 7) ? 9 : 8;
	else idx = 8;

	uio_off = idx * (unsigned int)sizeof(void *);
	cio_off = uio_off + (unsigned int)sizeof(void *);
	pr_info("nvsvc: fops table uio=%u\n", uio_off);
	return (uio_off >= 48 && uio_off <= 104) ? 0 : -EINVAL;
}

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
	if (!p->symbol_name) return -EINVAL;
	addr = kallsyms_lookup_name(p->symbol_name);
	if (!addr) { pr_info("nvsvc: no sym %s\n", p->symbol_name); return -ESRCH; }
	p->addr = (void *)addr;
	if (hook_wrap4(p->addr, kprobe_before, kprobe_after, p)) { p->addr = 0; return -EIO; }
	p->hooked = 1;
	return 0;
}

static void unregister_kprobe(struct kprobe *p)
{
	if (!p->hooked || !p->addr) return;
	hook_unwrap(p->addr, kprobe_before, kprobe_after);
	p->hooked = 0;
}

static int register_kretprobe(struct kretprobe *kr)
{
	unsigned long addr;
	if (!kr->kp.symbol_name) return -EINVAL;
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
	if (!kr->hooked || !kr->kp.addr) return;
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
#define API_VER    4
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
static int  uts_ok;
static int  strict = 1;
static int  hide_pid;
static unsigned int hooks_ok;
static const char *fake_path = FAKE_FALL;
static unsigned long iterate_addr, piddir_addr;
static char *cmd_end;

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
	"/sys/class/misc/nvsvc", "/data/misc/.__np",
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

/* ---------- kernel version ---------- */
static int kver_mm(unsigned int *maj, unsigned int *min)
{
	const char *p;
	unsigned int a = 0, b = 0;
	if (!kptr_ok(k_uts)) return -1;
	p = k_uts->name.release;
	while (*p >= '0' && *p <= '9') a = a * 10 + (unsigned int)(*p++ - '0');
	if (*p != '.') return -1;
	p++;
	while (*p >= '0' && *p <= '9') b = b * 10 + (unsigned int)(*p++ - '0');
	if (!a) return -1;
	*maj = a; *min = b;
	return 0;
}

/* ---------- uts ---------- */
static const char *const uts_mark[] = {
	"APatch", "KernelSU", "kpatch", "KPM", "Magisk", "SukiSU", "ReSukiSU",
};

static int uts_marked(const char *s)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(uts_mark); i++)
		if (strstr(s, uts_mark[i])) return 1;
	return 0;
}

static void uts_scrub(void)
{
	char *r, *v, *c;

	if (!kptr_ok(k_uts)) return;
	if (strncmp(k_uts->name.sysname, "Linux", 5)) {
		pr_info("nvsvc: uts shim mismatch, skip\n");
		return;
	}
	r = k_uts->name.release;
	v = k_uts->name.version;
	memcpy(saved_release, r, sizeof(saved_release));
	memcpy(saved_version, v, sizeof(saved_version));
	uts_ok = 1;

	if (uts_marked(r)) {
		c = strpbrk(r, "-+");
		if (c) *c = '\0';
	}
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
	if (!uts_ok || !kptr_ok(k_uts)) return;
	memcpy(k_uts->name.release, saved_release, sizeof(saved_release));
	memcpy(k_uts->name.version, saved_version, sizeof(saved_version));
}

/* ---------- bootloader / props ---------- */
static int room(char *p, long n)
{
	return cmd_end && p + n <= cmd_end;
}

static void set_bootstate(char *c)
{
	char *p = strstr(c, "verifiedbootstate="), *v;
	long tail;
	if (!p) return;
	v = p + 18;
	if (!strncmp(v, "orange", 6) || !strncmp(v, "yellow", 6)) {
		if (room(v, 6)) memcpy(v, "green ", 6);
		return;
	}
	if (!strncmp(v, "red", 3)) {
		tail = (long)strlen(v + 3);
		if (!room(v, tail + 6)) return;
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
	char *p = strstr(c, "veritymode="), *v;
	long tail;
	if (!p) return;
	v = p + 11;
	if (!strncmp(v, "disabled", 8) || !strncmp(v, "logging", 7)) {
		tail = (long)strlen(v + 8);
		if (!room(v, tail + 10)) return;
		memmove(v + 9, v + 8, tail + 1);
		memcpy(v, "enforcing", 9);
	}
}

static void set_selinux(char *c)
{
	char *p = strstr(c, "androidboot.selinux="), *v;
	long tail;
	if (!p) return;
	v = p + 21;
	if (strncmp(v, "permissive", 10)) return;
	tail = (long)strlen(v + 10);
	if (!room(v, tail + 11)) return;
	memcpy(v, "enforcing", 9);
	memmove(v + 9, v + 10, tail + 1);
}

static void scrub_boot_args(char *c)
{
	set_bootstate(c); set_locked(c); set_vbmeta(c); set_verity(c); set_selinux(c);
}

static void cmdline_scrub(void)
{
	char *c;
	if (!k_saved_cmdline || !kptr_ok(k_saved_cmdline)) return;
	c = *k_saved_cmdline;
	if (!c || !kptr_ok(c)) return;
	cmd_end = c + strlen(c);
	scrub_boot_args(c);
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
	struct kp_filename *fn = (struct kp_filename *)P_RET(regs);
	if (!d->hide || !kptr_ok(fn) || IS_ERR(fn) || !kptr_ok(fn->name)) return 0;
	kp_strscpy((char *)fn->name, fake_path, PATH_MAX);
	return 0;
}

static struct kprobe kp_path;

static int pre_path(struct kprobe *p, struct pt_regs *regs)
{
	struct kp_filename *fn;
	(void)p;
	if (bypass()) return 0;
	fn = (struct kp_filename *)P_ARG1(regs);
	if (!kptr_ok(fn) || !kptr_ok(fn->name)) return 0;
	if (is_hidden(fn->name))
		kp_strscpy((char *)fn->name, fake_path, PATH_MAX);
	return 0;
}

/* ---------- dir filter ---------- */
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
	if (bypass() || !kptr_ok(ctx) || !kptr_ok(ctx->actor)) return;
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

/* ---------- read scrub ---------- */
static struct kretprobe kr_pread, kr_bprop;

static int pre_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *f = (struct file *)P_ARG0(regs);
	int *mode = (int *)ri->data;
	const char *n;
	*mode = 0;
	if (bypass() || !kptr_ok(f) || !kptr_ok(f->f_path.dentry)) return 0;
	n = f->f_path.dentry->d_name.name;
	if (!kptr_ok(n)) return 0;
	if (!strncmp(n, "bootargs", 8)) { *mode = 1; return 1; }
	if (!strcmp(n, "build.prop")) { *mode = 2; return 1; }
	if (!strcmp(n, "current")) {
		const char *pn = kptr_ok(f->f_path.dentry->d_parent) ?
			f->f_path.dentry->d_parent->d_name.name : NULL;
		if (kptr_ok(pn) && !strcmp(pn, "attr")) { *mode = 3; return 1; }
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
	char buf[768];
	long n;
	if (!mode || ret <= 0 || !ub) return 0;
	n = ret > (long)sizeof(buf) - 1 ? (long)sizeof(buf) - 1 : ret;
	if (copy_from_user(buf, ub, n)) return 0;
	buf[n] = '\0';
	switch (mode) {
	case 1: cmd_end = buf + n; scrub_boot_args(buf); break;
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
	if (bypass() || !kptr_ok(st)) return 0;
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
	if (!*(int *)ri->data || ret <= 0 || !ub) return 0;
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
	if (bypass() || !kptr_ok(m) || !kptr_ok(m->buf)) return 0;
	if (m->size < m->count || m->size > 0x100000) return 0;
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
	if (!d->saved || !kptr_ok(m) || (long)m->count <= d->saved) return 0;
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
#if STAGE >= 3
	kr_name.entry_handler = name_entry;
	kr_name.handler = name_ret;
	if (!register_kretprobe(&kr_name)) hooks_ok++;
	else {
		memset(&kr_name, 0, sizeof(kr_name));
		kp_path.symbol_name = "filename_lookup";
		kp_path.pre_handler = pre_path;
		if (!register_kprobe(&kp_path)) hooks_ok++;
	}
	pr_info("nvsvc: stage3 %u\n", hooks_ok);
#endif

#if STAGE >= 4
	kr_pread.data_size = sizeof(int);
	kr_bprop.data_size = sizeof(int);
	kr_pread.entry_handler = pre_read;
	kr_bprop.entry_handler = pre_read;
	kr_pread.handler = post_read;
	kr_bprop.handler = post_read;
	hook_tr(&kr_pread, "proc_reg_read", 0);
	hook_tr(&kr_bprop, "vfs_read", 0);

	kr_statfs.kp.symbol_name = "vfs_statfs";
	kr_statfs.data_size = 0;
	kr_statfs.entry_handler = entry_statfs;
	kr_statfs.handler = post_statfs;
	kr_statfs.maxactive = 64;
	if (!register_kretprobe(&kr_statfs)) hooks_ok++;
	else memset(&kr_statfs, 0, sizeof(kr_statfs));

	kr_rl.kp.symbol_name = "vfs_readlink";
	kr_rl.data_size = sizeof(int);
	kr_rl.entry_handler = pre_rl;
	kr_rl.handler = post_rl;
	kr_rl.maxactive = 64;
	if (!register_kretprobe(&kr_rl)) hooks_ok++;
	else memset(&kr_rl, 0, sizeof(kr_rl));
	pr_info("nvsvc: stage4 %u\n", hooks_ok);
#endif

#if STAGE >= 5
	iterate_addr = kallsyms_lookup_name("iterate_dir");
	if (iterate_addr &&
	    !hook_wrap4((void *)iterate_addr, dir_before, dir_after, (void *)0))
		hooks_ok++;
	else
		iterate_addr = 0;

	piddir_addr = kallsyms_lookup_name("proc_pid_readdir");
	if (piddir_addr &&
	    !hook_wrap4((void *)piddir_addr, dir_before, dir_after, (void *)1))
		hooks_ok++;
	else
		piddir_addr = 0;
	pr_info("nvsvc: stage5 %u\n", hooks_ok);
#endif

#if STAGE >= 6
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
	pr_info("nvsvc: stage6 %u\n", hooks_ok);
#endif
}

static void hooks_remove(void)
{
#if STAGE >= 5
	if (iterate_addr) hook_unwrap((void *)iterate_addr, dir_before, dir_after);
	if (piddir_addr) hook_unwrap((void *)piddir_addr, dir_before, dir_after);
#endif
	if (kr_name.hooked) unregister_kretprobe(&kr_name);
	if (kp_path.hooked) unregister_kprobe(&kp_path);
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
	RS("_copy_from_user", k_copy_from_user);
	if (!k_copy_from_user) RS("__arch_copy_from_user", k_copy_from_user);
	if (!k_copy_from_user) RS("__copy_from_user", k_copy_from_user);
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
		while (kptr_ok(vma) && guard++ < 8192) {
			const char *dn;
			if (vma->vm_mm != mm) break;
			if (kptr_ok(vma->vm_file) && kptr_ok(vma->vm_file->f_path.dentry)) {
				dn = vma->vm_file->f_path.dentry->d_name.name;
				if (kptr_ok(dn) && strstr(dn, pname)) { found = vma->vm_start; break; }
			}
			if (!kptr_ok(vma->vm_next) || vma->vm_next <= vma) break;
			vma = vma->vm_next;
		}
		if (k_mmput) k_mmput(mm);
		mb.base = found;

		if (c32) {
#ifdef CONFIG_COMPAT
			struct mod_base32 y;
			y.pid = mb.pid; y.name = (unsigned int)mb.name; y.base = (unsigned int)found;
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

static struct miscdevice dev;

static long owner_ctl(const char *ctl_args, char __user *out_msg, int outlen)
{
	int n = 0;
	(void)ctl_args;
	if (!out_msg || outlen <= 0) return 0;
	while (owner_name[n]) n++;
	if (n > outlen) n = outlen;
	return copy_to_user(out_msg, owner_name, n) ? -EFAULT : n;
}

KPM_CTL0(owner_ctl);

static long nvsvc_start(const char *args, const char *event, void *__user reserved)
{
	unsigned int maj = 0, min = 0;
	int r;
	(void)args; (void)event; (void)reserved;

	if (!name_decode()) {
		pr_info("nvsvc: owner tag tampered\n");
		return -EIO;
	}
	pr_info("nvsvc: %s (stage %d)\n", owner_name, STAGE);

	r = resolve_syms();
	if (r) { pr_info("nvsvc: resolve %d\n", r); return r; }

	/* ---- hard guard: galat kernel par bootloop nahi ---- */
	if (kver_mm(&maj, &min)) {
		pr_info("nvsvc: kernel version nahi padhi ja saki\n");
		return -EINVAL;
	}
	if (maj < 3 || (maj == 3 && min < 18)) {
		pr_info("nvsvc: kernel %u.%u bahut purana (3.18+ chahiye)\n", maj, min);
		return -EINVAL;
	}

	r = fops_offsets(maj, min);
	if (r) { pr_info("nvsvc: fops offset resolve fail\n"); return r; }

	memset(fops_buf, 0, sizeof(fops_buf));
	fops_put((unsigned int)sizeof(void *), (const void *)k_no_llseek);
	fops_put(uio_off, (const void *)dev_ioctl);
#ifdef CONFIG_COMPAT
	fops_put(cio_off, (const void *)dev_ioctl);
#endif
	pr_info("nvsvc: kernel %u.%u uio=%u cio=%u\n", maj, min, uio_off, cio_off);

	memset(&dev, 0, sizeof(dev));
	dev.minor = MISC_DYNAMIC_MINOR;
	dev.name = DEV_NAME;
	dev.fops = (const struct file_operations *)fops_buf;
	dev.mode = 0666;

	pick_fake_path();

	r = k_misc_register(&dev);
	if (r) { pr_info("nvsvc: misc_register %d\n", r); return r; }
	pr_info("nvsvc: registered\n");

#if STAGE >= 2
	if (k_uts) uts_scrub();
	cmdline_scrub();
	if (kptr_ok(k_kptr_restrict) && *k_kptr_restrict < 2) {
		saved_kptr = *k_kptr_restrict;
		*k_kptr_restrict = 2;
	}
#endif

#if STAGE >= 3
	hooks_install();
	if (!hooks_ok) {
		if (kptr_ok(k_kptr_restrict)) *k_kptr_restrict = saved_kptr;
		uts_restore();
		k_misc_deregister(&dev);
		pr_info("nvsvc: koi hook nahi, abort\n");
		return -EIO;
	}
#endif

	inited = 1;
	pr_info("nvsvc: loaded, %u hooks\n", hooks_ok);
	return 0;
}

static long nvsvc_stop(void *__user reserved)
{
	(void)reserved;
	if (!inited) return 0;
	inited = 0;
	hooks_remove();
	if (kptr_ok(k_kptr_restrict)) *k_kptr_restrict = saved_kptr;
	uts_restore();
	if (k_misc_deregister) k_misc_deregister(&dev);
	return 0;
}

KPM_INIT(nvsvc_start);
KPM_EXIT(nvsvc_stop);
