// ============================================================
//  DARKxKERNEL KPM  (wanbai)  v33.0  — FINAL
//
//  v33 — load par sirf EK hook. Baaki OP_INIT par.
//   1. Load: sirf getname hook (path hiding) + learner. Halka.
//   2. App ka pehla OP_INIT aane par baaki hooks (read scrub,
//      statfs, readlink, dir) install hote hain, live_probe ke
//      saath. Fail = wapas hata do.
//   3. OP_SAFE(1) = wapas sirf-minimal, OP_SAFE(0) = poora.
//   4. fargs use ab bhi 12 byte / 48 (naam hook), dir hooks 0.
//
//  v32: KRET_BODY_MAX header se derive + static assert.
//  v31: post_read stack reserve, bootstate red, verity.
//  v30: koi uid detect nahi.
//  v29: dmesg default off, fops 7..12, duplicate d_off fix.
//
//  BTF offsets sirf "/" selftest pass hone par. Fail = defaults.
// ============================================================
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <common.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

#if defined(__has_include)
#  if __has_include(<kputils.h>)
#    include <kputils.h>
#    define KP_HAVE_UTILS 1
#  endif
#endif

#ifndef KP_HAVE_UTILS
extern unsigned int current_uid(void);
#endif

#ifndef STAGE
#define STAGE 5
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
KPM_VERSION("33.0.0");
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
#ifndef ENODEV
#define ENODEV 19
#endif
#ifndef EBUSY
#define EBUSY 16
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

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define KP_STATIC_ASSERT(c, m) _Static_assert(c, m)
#else
#  define KP_STATIC_ASSERT(c, m) typedef char __kpsa_##__LINE__[(c) ? 1 : -1]
#endif

#define USER_TOP 0x0001000000000000UL

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
 *  KERNEL STRUCT SHIMS
 * ============================================================ */
struct module;
struct inode;
struct vfsmount;
struct pid;
struct task_struct;
struct anon_vma;
struct vm_operations_struct;
struct input_dev;

struct kp_qstr { unsigned int hash; unsigned int len; const unsigned char *name; };
struct kp_list_head { struct kp_list_head *next, *prev; };

struct kp_path { void *mnt; void *dentry; };
struct kp_file { char f_u[16]; };
struct kp_filename { const char *name; };

struct kp_dir_context;
typedef bool (*kp_filldir_t)(struct kp_dir_context *, const char *, int, loff_t, u64, unsigned);
struct kp_dir_context { kp_filldir_t actor; loff_t pos; };

struct kp_fops {
	struct module *owner;
	loff_t (*llseek)(struct kp_file *, loff_t, int);
	ssize_t (*read)(struct kp_file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct kp_file *, const char __user *, size_t, loff_t *);
	void *read_iter;
	void *write_iter;
	void *iopoll;
	void *iterate;
	void *iterate_shared;
	void *poll;
	long (*unlocked_ioctl)(struct kp_file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct kp_file *, unsigned int, unsigned long);
};

struct kp_miscdevice {
	int minor;
	const char *name;
	const struct kp_fops *fops;
	struct list_head list;
	void *parent;
	void *this_device;
	const void *groups;
	const char *nodename;
	umode_t mode;
};

struct kp_seq_file { char *buf; size_t size; size_t from; size_t count; };
struct kp_statfs { long f_type; long f_bsize; };

struct kp_mm { void *head; };

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
static int  (*k_misc_register)(struct kp_miscdevice *);
static void (*k_misc_deregister)(struct kp_miscdevice *);
static int  (*k_kern_path)(const char *, unsigned int, struct kp_path *);
static void (*k_path_put)(const struct kp_path *);
static void *(*k_filp_open)(const char *, int, int);
static int  (*k_filp_close)(void *, void *);
static struct pid *(*k_find_vpid)(int);
static struct task_struct *(*k_pid_task)(struct pid *, int);
static struct kp_mm *(*k_get_task_mm)(struct task_struct *);
static void (*k_mmput)(struct kp_mm *);
static void (*k_get_task_struct)(struct task_struct *);
static void (*k_put_task_struct)(struct task_struct *);
static void *(*k_kvmalloc)(unsigned long, int);
static void (*k_kvfree)(void *);
static int  (*k_access_process_vm)(struct task_struct *, unsigned long, void *, int, int);
static loff_t (*k_no_llseek)(struct kp_file *, loff_t, int);
static void (*k_flush_icache)(unsigned long, unsigned long);
static int  (*k_copy_from_user)(void *, const void __user *, unsigned long);
static int  (*k_in_compat)(void);
static int  *k_kptr_restrict;
static char **k_saved_cmdline;
static char *k_banner;
static struct kp_utsns *k_uts;
static void *(*k_find_vma)(void *, unsigned long);
static void *(*k_find_vma_prev)(void *, unsigned long, void **);

static int  (*k_input_event)(struct input_dev *, unsigned int, unsigned int, int);
static int  (*k_input_mt_slot)(struct input_dev *, int);
static void (*k_input_mt_report_slot_state)(struct input_dev *, unsigned int, bool);
static int  (*k_input_mt_get_slot_by_key)(struct input_dev *, int);
static void (*k_input_sync)(struct input_dev *);

#define copy_from_user(to, from, n) \
	(k_copy_from_user ? k_copy_from_user((to), (from), (unsigned long)(n)) : -EFAULT)
#define copy_to_user(to, from, n)   (compat_copy_to_user((to), (from), (int)(n)))
#define strncpy_from_user(d, s, n)  (compat_strncpy_from_user((d), (s), (n)))

static int kptr_ok(const void *p)
{
	unsigned long a = (unsigned long)p;
	return a >= 0xffff000000000000UL && a != ~0UL;
}

static int user_ok(unsigned long a)
{
	return a && a < USER_TOP;
}

static unsigned long sym_addr(const char *n)
{
	if (!kallsyms_lookup_name || !n) return 0;
	return (unsigned long)kallsyms_lookup_name(n);
}

#define HAVE(s) sym_addr(s)

/* ============================================================
 *  BTF CORE
 * ============================================================ */
#define BTF_MAGIC 0xeb9fU

struct btf_header {
	unsigned short magic;
	unsigned char  version;
	unsigned char  flags;
	unsigned int   hdr_len;
	unsigned int   type_off;
	unsigned int   type_len;
	unsigned int   str_off;
	unsigned int   str_len;
};

struct btf_type {
	unsigned int name_off;
	unsigned int info;
	unsigned int size_or_type;
};

struct btf_member {
	unsigned int name_off;
	unsigned int type;
	unsigned int offset;
};

static const unsigned char *btf_base;
static const char *btf_strs;
static unsigned int btf_type_len, btf_str_len;
static int btf_parsed;
static int btf_ok;

static unsigned int btf_rec_size(const struct btf_type *t)
{
	unsigned int k = (t->info >> 24) & 0x1f;
	unsigned int v = t->info & 0xffff;

	switch (k) {
	case 1:  return 12 + 4;
	case 3:  return 12 + 12;
	case 4:
	case 5:  return 12 + v * 12;
	case 6:  return 12 + v * 8;
	case 13: return 12 + v * 8;
	case 14: return 12 + 4;
	case 15: return 12 + v * 12;
	case 17: return 12 + 8;
	case 19: return 12 + v * 12;
	default: return 12;
	}
}

static int btf_name_eq(unsigned int off, const char *name)
{
	const char *p;
	unsigned int i;

	if (off >= btf_str_len) return 0;
	p = btf_strs + off;
	for (i = 0; i + off < btf_str_len; i++) {
		if (p[i] != name[i]) return 0;
		if (!p[i]) return 1;
	}
	return 0;
}

static int btf_scan(unsigned int want_id, const char *want_name, unsigned int want_kind,
		    const struct btf_type **out, unsigned int *out_id)
{
	const unsigned char *p = btf_base;
	unsigned int id = 1, left = btf_type_len, sz;

	while (left >= 12) {
		const struct btf_type *t = (const struct btf_type *)p;

		sz = btf_rec_size(t);
		if (sz < 12 || sz > left) return -1;

		if (want_id) {
			if (id == want_id) { *out = t; return 0; }
		} else if (((t->info >> 24) & 0x1f) == want_kind &&
			   btf_name_eq(t->name_off, want_name)) {
			*out = t;
			if (out_id) *out_id = id;
			return 0;
		}
		p += sz; left -= sz; id++;
		if (id > 500000) break;
	}
	return -1;
}

static unsigned int btf_struct_id(const char *name)
{
	const struct btf_type *t;
	unsigned int id = 0;

	if (!btf_parsed) return 0;
	if (!btf_scan(0, name, 4, &t, &id)) return id;
	if (!btf_scan(0, name, 5, &t, &id)) return id;
	return 0;
}

static int btf_member_off(unsigned int type_id, const char *name, int need_ptr)
{
	const struct btf_type *t;
	const struct btf_member *m;
	unsigned int i, v, sz;
	int off, need;

	if (!btf_parsed || !type_id) return -1;
	if (btf_scan(type_id, 0, 0, &t, 0)) return -1;
	if (((t->info >> 24) & 0x1f) != 4 && ((t->info >> 24) & 0x1f) != 5) return -1;

	sz = t->size_or_type;
	if (!sz || sz > 0x4000) return -1;
	need = need_ptr ? 8 : 1;

	v = t->info & 0xffff;
	m = (const struct btf_member *)((const char *)t + 12);
	for (i = 0; i < v; i++) {
		if (!btf_name_eq(m[i].name_off, name)) continue;
		off = (int)((m[i].offset & 0xffffff) / 8);
		if (off + need > (int)sz) return -1;
		return off;
	}
	return -1;
}

static int btf_parse(void)
{
	unsigned long s = sym_addr("__start_BTF");
	unsigned long e = sym_addr("__stop_BTF");
	const struct btf_header *h;
	unsigned int total;

	if (!s || !e || e <= s) return -1;
	total = (unsigned int)(e - s);
	if (total < 24 || total > 0x2000000U) return -1;

	h = (const struct btf_header *)s;
	if (h->magic != BTF_MAGIC || h->version != 1) return -1;
	if (h->hdr_len < 24 || h->hdr_len > total) return -1;
	if (h->type_off > total - h->hdr_len) return -1;
	if (h->type_len > total - h->hdr_len - h->type_off) return -1;
	if (h->str_off > total - h->hdr_len) return -1;
	if (h->str_len < 1 || h->str_len > total - h->hdr_len - h->str_off) return -1;

	btf_base = (const unsigned char *)h + h->hdr_len + h->type_off;
	btf_type_len = h->type_len;
	btf_strs = (const char *)h + h->hdr_len + h->str_off;
	btf_str_len = h->str_len;
	if (btf_strs[0] != '\0') return -1;
	if (btf_type_len < 12) return -1;
	btf_parsed = 1;
	return 0;
}

/* ============================================================
 *  OFFSET TABLE
 * ============================================================ */
struct koffs {
	int vma_start, vma_end, vma_file, vma_mm;
	int file_fpath, path_dentry;
	int dentry_name, dentry_parent, dentry_inode;
	int inode_uid, inode_mode;
	int idev_absbit, idev_absinfo, idev_node;
};

static const struct koffs OFF_DEF = {
	.vma_start     = 0,
	.vma_end       = 8,
	.vma_file      = 0xa8,
	.vma_mm        = 0x40,
	.file_fpath    = 0x10,
	.path_dentry   = 8,
	.dentry_name   = 0x20,
	.dentry_parent = 0x18,
	.dentry_inode  = 0x30,
	.inode_uid     = 4,
	.inode_mode    = 0,
	.idev_absbit   = 0x338,
	.idev_absinfo  = -1,
	.idev_node     = -1,
};

static struct koffs OFF;

static struct kp_qstr *d_name_of(void *d)
{ return (struct kp_qstr *)((char *)d + OFF.dentry_name); }

static void *d_parent_of(void *d)
{ return *(void **)((char *)d + OFF.dentry_parent); }

static void *d_inode_of(void *d)
{ return *(void **)((char *)d + OFF.dentry_inode); }

static struct kp_path *f_path_of(void *f)
{ return (struct kp_path *)((char *)f + OFF.file_fpath); }

static void *f_dentry_of(void *f)
{
	struct kp_path *p;

	if (!kptr_ok(f)) return 0;
	p = f_path_of(f);
	if (!kptr_ok(p)) return 0;
	return *(void **)((char *)p + OFF.path_dentry);
}

static int offs_selftest(void)
{
	struct kp_path p;
	void *d, *i, *file, *fd2;
	struct kp_qstr *q;
	unsigned int mode;
	int ok = 1;

	if (!k_kern_path || !k_path_put) return 0;

	memset(&p, 0, sizeof(p));
	if (k_kern_path("/", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &p)) return 0;

	d = *(void **)((char *)&p + OFF.path_dentry);
	if (!kptr_ok(d)) { k_path_put(&p); return 0; }

	q = d_name_of(d);
	if (!kptr_ok(q) || q->len != 1 || !kptr_ok(q->name) || q->name[0] != '/') ok = 0;

	if (ok) {
		i = d_inode_of(d);
		if (!kptr_ok(i)) {
			ok = 0;
		} else {
			mode = *(unsigned int *)((char *)i + OFF.inode_mode);
			if ((mode & 0xF000) != 0x4000) ok = 0;
		}
	}

	if (ok && k_filp_open && k_filp_close) {
		file = k_filp_open("/", 0, 0);
		if (!file || IS_ERR(file) || !kptr_ok(file)) {
			ok = 0;
		} else {
			fd2 = f_dentry_of(file);
			if (fd2 != d) ok = 0;
			k_filp_close(file, 0);
		}
	}

	k_path_put(&p);
	return ok;
}

static void offs_resolve(void)
{
	unsigned int t;
	int v;

	OFF = OFF_DEF;
	btf_ok = 0;

	if (btf_parse()) {
		pr_info("wanbai: BTF nahi mila, defaults\n");
		return;
	}

	t = btf_struct_id("vm_area_struct");
	if (t) {
		if ((v = btf_member_off(t, "vm_start", 0)) >= 0) OFF.vma_start = v;
		if ((v = btf_member_off(t, "vm_end", 0))   >= 0) OFF.vma_end   = v;
		if ((v = btf_member_off(t, "vm_file", 1))  >= 0) OFF.vma_file  = v;
		if ((v = btf_member_off(t, "vm_mm", 1))    >= 0) OFF.vma_mm    = v;
	}

	if (k_filp_open && k_filp_close) {
		t = btf_struct_id("file");
		if (t && (v = btf_member_off(t, "f_path", 1)) >= 0) OFF.file_fpath = v;
	}

	OFF.path_dentry = 8;

	t = btf_struct_id("dentry");
	if (t) {
		if ((v = btf_member_off(t, "d_name", 1))   >= 0) OFF.dentry_name   = v;
		if ((v = btf_member_off(t, "d_parent", 1)) >= 0) OFF.dentry_parent = v;
		if ((v = btf_member_off(t, "d_inode", 1))  >= 0) OFF.dentry_inode  = v;
	}
	t = btf_struct_id("inode");
	if (t) {
		if ((v = btf_member_off(t, "i_uid", 0))  >= 0) OFF.inode_uid  = v;
		if ((v = btf_member_off(t, "i_mode", 0)) >= 0) OFF.inode_mode = v;
	}

	if (!offs_selftest()) {
		OFF = OFF_DEF;
		pr_info("wanbai: btf selftest fail -> defaults\n");
		return;
	}
	btf_ok = 1;

	t = btf_struct_id("input_dev");
	if (t) {
		v = btf_member_off(t, "absbit", 1);
		if (v >= 0x80 && v <= 0x800) OFF.idev_absbit = v;
		v = btf_member_off(t, "absinfo", 1);
		if (v >= 0x80 && v <= 0x800) OFF.idev_absinfo = v;
		v = btf_member_off(t, "node", 1);
		if (v > 0 && v <= 0x800) OFF.idev_node = v;
	}

	pr_info("wanbai: btf ok vma=%d/%d f=%d dn=%d ino=%d idev=%d/%d/%d\n",
		OFF.vma_start, OFF.vma_end, OFF.file_fpath, OFF.dentry_name,
		OFF.inode_uid, OFF.idev_absbit, OFF.idev_absinfo, OFF.idev_node);
}

/* ============================================================
 *  fops buffer
 * ============================================================ */
#define FOPS_MAX 384
static unsigned char fops_buf[FOPS_MAX] __attribute__((aligned(16)));

static void fops_put(unsigned int off, const void *fn)
{
	if (off + sizeof(void *) <= FOPS_MAX)
		*(const void **)(fops_buf + off) = fn;
}

static long dev_dispatch(struct kp_file *f, unsigned long a, unsigned long b);

/* ============================================================
 *  kprobe / kretprobe
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

#define HOOK_LOCAL_BYTES ((unsigned int)sizeof(((hook_fargs4_t *)0)->local.data))
#define KRET_BODY_MAX    (HOOK_LOCAL_BYTES - (unsigned int)sizeof(unsigned long))
KP_STATIC_ASSERT(HOOK_LOCAL_BYTES > sizeof(unsigned long) * 2, "hook local data too small");

#define F_FLAG f->local.data[0]
#define F_BODY ((void *)(f->local.data + 1))

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
	F_FLAG = 0;
	if (!kr->entry_handler) return;
	ri.data = F_BODY;
	regs_in(&r, f);
	F_FLAG = kr->entry_handler(&ri, &r) ? 1 : 0;
	regs_out(f, &r);
}

static void kret_after(hook_fargs4_t *f, void *ud)
{
	struct kretprobe *kr = (struct kretprobe *)ud;
	struct kretprobe_instance ri;
	struct pt_regs r;
	if (!F_FLAG || !kr->handler) return;
	ri.data = F_BODY;
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
	addr = sym_addr(p->symbol_name);
	if (!addr) return -ESRCH;
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
	if (!kr->data_size) kr->data_size = sizeof(int);
	if ((unsigned int)kr->data_size > KRET_BODY_MAX) return -E2BIG;
	addr = sym_addr(kr->kp.symbol_name);
	if (!addr) return -ESRCH;
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

#define DEV_NAME   "wanbai"
#define DEV_LEN    ((int)sizeof(DEV_NAME) - 1)
#define MAGIC      0x4E56
#define OP_INIT    0x800
#define OP_READ    0x801
#define OP_WRITE   0x802
#define OP_BASE    0x803
#define OP_HIDE    0x804
#define OP_STRICT  0x805
#define OP_VER     0x806
#define OP_ABI     0x807
#define OP_UTS     0x808
#define OP_MUID    0x809
#define OP_GUID    0x80A
#define OP_GBYP    0x80B
#define OP_OFF     0x80C
#define OP_FLUSH   0x80D
#define OP_VFS     0x80E
#define OP_PING    0x80F
#define OP_STATE   0x810
#define OP_TOUCH   0x811
#define OP_TRANGE  0x812
#define OP_HIDEN   0x813
#define OP_DMESG   0x814
#define OP_TOUCHQ  0x816
#define OP_TREL    0x819
#define OP_KPTR    0x81A
#define OP_IHIDE   0x81B
#define OP_ISTAT   0x81C
#define OP_SAFE    0x81D
#define API_VER    17
#define SMALL_IO   512
#define KMEM_CHUNK 1024
#define KMEM_MAX   0x1000000
#define PATH_S     32
#define FAKE_DIR   "/data/misc/.__np"
#define FAKE_FALL  "/data/misc"

#define OVERLAY_MAGIC 0x794c7630U
#define EXT4_MAGIC    0xef53U

struct copy_mem { int pid; unsigned int pad; unsigned long long addr, buffer, size; };
struct mod_base { int pid; unsigned int pad; unsigned long long name, base; };
struct copy_mem32 { int pid; unsigned int addr, buffer, size; };
struct mod_base32 { int pid; unsigned int name, base; };

static char saved_release[__NEW_UTS_LEN + 1];
static char saved_version[__NEW_UTS_LEN + 1];
static int  saved_kptr;
static int  kptr_saved;
static int  dev_ok;
static int  inited;
static int  uts_ok;
static int  strict;
static int  hide_pid;
static int  mgr_uid = -1;
static int  game_uid = -1;
static int  game_byp;
static int  hooks_off;
static int  hooks_full;
static int  vfs_on;
static int  abi_force = -1;
static unsigned int hooks_ok;
static unsigned int miss_syms;
static const char *fake_path = FAKE_FALL;
static unsigned long iterate_addr, piddir_addr;
static char *cmd_end;

static int g_name, g_read, g_seq;

static struct kp_dir_context *g_dctx;
static void *g_dorig;
static char g_ddevdir, g_demitted;

static int bypass(void)
{
	unsigned int u;

	if (strict == 2) return 1;
	if (mgr_uid < 0 && game_uid < 0) return 0;

	u = current_uid();
	if (u == 0) return 0;
	if (game_byp && game_uid > 0 && (int)u == game_uid) return 1;
	return mgr_uid > 0 && (int)u == mgr_uid;
}

/* ============================================================
 *  REWRITE LIST
 * ============================================================ */
static const char *const hidden[] = {
	"/sbin/su", "/system/bin/su", "/system/xbin/su",
	"/vendor/bin/su", "/vendor/bin/kp", "/system/xbin/kp",
	"/system/bin/kp", "/system/bin/magisk", "/system/bin/ksud",
	"/system/bin/apd", "/system/bin/.ext", "/sbin/.magisk",
	"/debug_ramdisk", "/system/app/Magisk", "/cache/magisk.log",
	"/data/magisk", "/system/etc/init/magisk",
	"/system/etc/init/init.magisk.rc", "/system/etc/init/init.kpatch.rc",
	"/proc/config.gz", "/sys/module/wanbai", "/sys/class/misc/wanbai",
	"/sys/module/kpatch", "/sys/module/kernelpatch",
};
#define HIDDEN_N ARRAY_SIZE(hidden)

static const char *const blk_name[] = {
	"su", "magisk", "Magisk", "magiskd", "ksud",
	"apd", "adb", "kpatch", "kpatchd", "kp", "wanbai",
	".__np", ".magisk", ".ext", "debug_ramdisk",
	"libnvsvc.so", "init.magisk.rc", "init.kpatch.rc", "config.gz",
	"zygisk", "zygiskd", "libzygisk.so", "libzygiskd.so", "tmp",
	"android.system.svc", "system_log_svc", "STEMMERX.sh",
};
#define BLK_N ARRAY_SIZE(blk_name)

static const char *const blk_pfx[] = {
	"com.topjohnwu.magisk", "me.weishu.kernelsu",
	"me.bmax.apatch", "com.dergoogler.mmrl",
	".system_",
};
#define BLK_PF ARRAY_SIZE(blk_pfx)

static const char *const blk_text[] = {
	"kpatch", "APatch", "KernelSU", "magisk", "Magisk", "ksud", "apd",
	"overlay", "wanbai", ".__np", "debug_ramdisk", "libnvsvc",
	"/data/adb", "/data/local/tmp", "zygisk", "Zygisk",
	"com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
	"android.system.svc", "STEMMERX",
};
#define BLK_T ARRAY_SIZE(blk_text)

static const char *const blk_maps[] = {
	"overlay", "/data/adb", "wanbai", "libnvsvc", "debug_ramdisk",
	"/data/local/tmp", "zygisk", ".__np", "android.system.svc",
};
#define BLK_M ARRAY_SIZE(blk_maps)

#define HIDE_MAX 8
static int hide_set[HIDE_MAX];
static int hide_set_n;

static int pid_in_set(int v)
{
	int i;
	if (v <= 0) return 0;
	for (i = 0; i < hide_set_n; i++)
		if (hide_set[i] == v) return 1;
	return 0;
}

static int proc_pid_hidden(const char *p)
{
	const char *q;
	int v = 0, i = 0;

	if (!p || p[0] != '/' || p[1] != 'p') return 0;
	if (strncmp(p, "/proc/", 6)) return 0;
	q = p + 6;
	while (q[i] >= '0' && q[i] <= '9') {
		v = v * 10 + (q[i] - '0');
		if (++i > 7) return 0;
	}
	if (!i || (q[i] && q[i] != '/')) return 0;
	return pid_in_set(v);
}

static void scrub_tracer(char *b, long n)
{
	char *p = kp_memmem(b, n, "TracerPid:", 10);
	if (!p) return;
	p += 10;
	while (p < b + n && (*p == '\t' || *p == ' ')) p++;
	if (p >= b + n || *p < '0' || *p > '9') return;
	*p++ = '0';
	while (p < b + n && *p >= '0' && *p <= '9') *p++ = ' ';
}

static int is_hidden(const char *p)
{
	const char *h;
	unsigned int i;
	long n;

	if (!p || p[0] != '/') return 0;
	if (proc_pid_hidden(p)) return 1;
	switch (p[1]) {
	case 'd': case 's': case 'v': case 'c': case 'p':
		break;
	default:
		return 0;
	}
	for (i = 0; i < HIDDEN_N; i++) {
		h = hidden[i];
		if (h[2] != p[2]) continue;
		n = (long)strlen(h);
		if (!strncmp(p, h, n) && (p[n] == '\0' || p[n] == '/'))
			return 1;
	}
	return 0;
}

static int name_blocked(const char *n, int len)
{
	unsigned int i;
	long l;

	if (len <= 0 || len > 64) return 0;
	switch (n[0]) {
	case 's': case 'm': case 'M': case 'k': case 'a': case 'n': case 'w':
	case '.': case 'd': case 'l': case 'i': case 'c': case 'z': case 't':
		break;
	default:
		return 0;
	}
	for (i = 0; i < BLK_N; i++) {
		if ((int)strlen(blk_name[i]) != len) continue;
		if (!memcmp(n, blk_name[i], len)) return 1;
	}
	for (i = 0; i < BLK_PF; i++) {
		l = (long)strlen(blk_pfx[i]);
		if ((long)len > l && !memcmp(n, blk_pfx[i], l)) return 1;
	}
	return 0;
}

static int text_blocked_set(const char *s, long len, const char *const *set, int cnt)
{
	int i;
	long n;

	if (len <= 0) return 0;
	for (i = 0; i < cnt; i++) {
		n = (long)strlen(set[i]);
		if (n > len) continue;
		if (kp_memmem(s, len, set[i], n)) return 1;
	}
	return 0;
}

static void blank_word(char *b, const char *w)
{
	long n = (long)strlen(w);
	char *p = b;
	while ((p = strstr(p, w))) { memset(p, ' ', n); p += n; }
}

/* ============================================================
 *  dmesg filter
 * ============================================================ */
#define KM_MAX 1024
static struct kretprobe kr_kmsg;
static int dmesg_hide = 0;

static int kmsg_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *on = (int *)ri->data;
	(void)regs;
	*on = (dmesg_hide && !bypass()) ? 1 : 0;
	return *on;
}

static int kmsg_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	char buf[KM_MAX], out[KM_MAX];
	long n, i, o = 0, line;

	if (!*(int *)ri->data || ret <= 0 || !user_ok((unsigned long)ub)) return 0;
	n = ret > (long)sizeof(buf) - 1 ? (long)sizeof(buf) - 1 : ret;
	if (copy_from_user(buf, ub, n)) return 0;
	buf[n] = '\0';

	for (i = 0; i < n; i = line) {
		char *nl = memchr(buf + i, '\n', n - i);
		line = nl ? (long)(nl - buf) + 1 : n;
		if (kp_memmem(buf + i, line - i, "wanbai", 6)) continue;
		if (o + (line - i) > (long)sizeof(out)) break;
		memcpy(out + o, buf + i, line - i);
		o += line - i;
	}
	if (!o) { P_RET(regs) = 0; return 0; }
	if (copy_to_user(ub, out, o)) return 0;
	P_RET(regs) = o;
	return 0;
}

/* ============================================================
 *  touch inject
 * ============================================================ */
#define INJ_KEY 0x4B504D31u
#define ABS_MT_POSITION_X 0x35
#define ABS_MT_POSITION_Y 0x36
#define ABS_X 0x00
#define ABS_Y 0x01
#define BTN_TOUCH 0x14a
#define EV_KEY 0x01
#define EV_ABS 0x03
#define MT_TOOL_FINGER 0
#define ABSINFO_SZ 24
#define ABSINFO_MAX_OFF 8

static void *inj_dev;
static int inj_ok;
static int inj_on = 1;
static int inj_down;
static int inj_hidden;
static unsigned int inj_mx, inj_my;
static void *inj_addr;

static int bit_test(const unsigned long *bm, int nr)
{
	return (int)((bm[nr / 64] >> (nr % 64)) & 1UL);
}

static int inj_alive(void)
{
	const char *n;
	if (!inj_ok || !kptr_ok(inj_dev)) return 0;
	n = *(const char **)((char *)inj_dev + 0);
	if (!kptr_ok(n)) return 0;
	return n[0] >= 0x20 && n[0] <= 0x7e;
}

static void *pick_input_dev(void)
{
	struct kp_list_head *h, *p;
	int guard = 0;

	if (OFF.idev_node <= 0 || OFF.idev_absbit <= 0) return 0;
	h = (struct kp_list_head *)sym_addr("input_dev_list");
	if (!h || !kptr_ok(h) || !kptr_ok(h->next)) return 0;

	for (p = h->next; kptr_ok(p) && p != h && guard++ < 256; p = p->next) {
		void *d = (char *)p - OFF.idev_node;
		unsigned long *ab;

		if (!kptr_ok(d)) break;
		if (!kptr_ok(p->next) || !kptr_ok(p->prev)) continue;
		if (p->next == p) continue;

		ab = (unsigned long *)((char *)d + OFF.idev_absbit);
		if (!kptr_ok(ab)) continue;
		if (!bit_test(ab, ABS_MT_POSITION_X)) continue;
		if (!bit_test(ab, ABS_MT_POSITION_Y)) continue;
		return d;
	}
	return 0;
}

static void inj_range_probe(void)
{
	int *ai, mx, my;

	if (!inj_alive()) return;
	if (OFF.idev_absinfo < 0x80 || OFF.idev_absinfo > 0x800) return;

	ai = *(int **)((char *)inj_dev + OFF.idev_absinfo);
	if (!kptr_ok(ai)) return;
	mx = *(int *)((char *)ai + ABS_MT_POSITION_X * ABSINFO_SZ + ABSINFO_MAX_OFF);
	my = *(int *)((char *)ai + ABS_MT_POSITION_Y * ABSINFO_SZ + ABSINFO_MAX_OFF);
	if (mx > 0 && mx < 100000 && my > 0 && my < 100000) {
		inj_mx = (unsigned int)mx;
		inj_my = (unsigned int)my;
	}
}

static void idev_hide(int on)
{
	struct kp_list_head *n, *h;

	if (!inj_alive() || OFF.idev_node <= 0) return;
	n = (struct kp_list_head *)((char *)inj_dev + OFF.idev_node);

	if (on) {
		if (inj_hidden || !kptr_ok(n->next) || !kptr_ok(n->prev)) return;
		if (n->next == n) return;
		n->prev->next = n->next;
		n->next->prev = n->prev;
		n->next = n;
		n->prev = n;
		inj_hidden = 1;
		return;
	}
	h = (struct kp_list_head *)sym_addr("input_dev_list");
	if (!inj_hidden || !h || !kptr_ok(h) || !kptr_ok(h->prev)) return;
	n->next = h;
	n->prev = h->prev;
	h->prev->next = n;
	h->prev = n;
	inj_hidden = 0;
}

static int idev_selftest(void)
{
	void *d = pick_input_dev();
	struct kp_list_head *n;
	const char *nm;
	int i;

	if (!d) return 0;

	nm = *(const char **)d;
	if (!kptr_ok(nm)) return 0;
	for (i = 0; i < 3; i++)
		if (nm[i] < 0x20 || nm[i] > 0x7e) return 0;

	n = (struct kp_list_head *)((char *)d + OFF.idev_node);
	if (!kptr_ok(n->next) || !kptr_ok(n->prev)) return 0;

	inj_dev = d;
	inj_ok = 1;
	inj_range_probe();
	if (!inj_alive()) { inj_dev = 0; inj_ok = 0; return 0; }
	return 1;
}

static void learn_before(hook_fargs4_t *f, void *ud)
{
	struct input_dev *d = (struct input_dev *)f->arg0;
	(void)ud;
	if (inj_ok || !kptr_ok(d)) return;
	if ((int)f->arg1 != EV_ABS) return;
	inj_dev = d;
	inj_ok = 1;
}

static void learn_after(hook_fargs4_t *f, void *ud) { (void)f; (void)ud; }

static int learner_install(void)
{
	unsigned long a;
	if (inj_addr) return 0;
	a = sym_addr("input_event");
	if (!a) return -ESRCH;
	if (hook_wrap4((void *)a, learn_before, learn_after, 0)) return -EIO;
	inj_addr = (void *)a;
	hooks_ok++;
	return 0;
}

static void learner_remove(void)
{
	if (!inj_addr) return;
	hook_unwrap(inj_addr, learn_before, learn_after);
	inj_addr = 0;
	if (hooks_ok) hooks_ok--;
}

static void inject_touch(unsigned int x, unsigned int y, int down)
{
	struct input_dev *d = inj_dev;
	int slot;

	if (!inj_alive() || !inj_on || !k_input_event) return;
	if (!inj_mx || !inj_my) inj_range_probe();
	if (inj_mx && x > inj_mx) x = inj_mx;
	if (inj_my && y > inj_my) y = inj_my;

	if (k_input_mt_slot && k_input_mt_report_slot_state && k_input_mt_get_slot_by_key) {
		slot = k_input_mt_get_slot_by_key(d, (int)INJ_KEY);
		if (slot < 0) slot = 0;
		k_input_mt_slot(d, slot);
		k_input_mt_report_slot_state(d, MT_TOOL_FINGER, down ? true : false);
		if (down) {
			k_input_event(d, EV_ABS, ABS_MT_POSITION_X, (int)x);
			k_input_event(d, EV_ABS, ABS_MT_POSITION_Y, (int)y);
		}
	} else {
		k_input_event(d, EV_ABS, ABS_X, (int)x);
		k_input_event(d, EV_ABS, ABS_Y, (int)y);
		k_input_event(d, EV_KEY, BTN_TOUCH, down);
	}
	if (k_input_sync) k_input_sync(d);
	inj_down = down;
}

/* ============================================================
 *  kernel version
 * ============================================================ */
static int kver_mm(unsigned int *maj, unsigned int *min)
{
	const char *p;
	unsigned int a = 0, b = 0;

	if (k_banner && kptr_ok(k_banner) && !strncmp(k_banner, "Linux version ", 14)) {
		p = k_banner + 14;
	} else if (kptr_ok(k_uts)) {
		p = k_uts->name.release;
	} else {
		return -1;
	}

	while (*p >= '0' && *p <= '9') a = a * 10 + (unsigned int)(*p++ - '0');
	if (*p != '.') return -1;
	p++;
	while (*p >= '0' && *p <= '9') b = b * 10 + (unsigned int)(*p++ - '0');
	if (!a) return -1;
	*maj = a; *min = b;
	return 0;
}

/* ---------- uts ---------- */
static const char *const uts_cut[] = {
	"APatch", "KernelSU", "KPM", "Magisk", "SukiSU", "ReSukiSU",
};

static int uts_cut_marked(const char *s)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(uts_cut); i++)
		if (strstr(s, uts_cut[i])) return 1;
	return 0;
}

static int uts_layout_ok(void)
{
	const char *r, *v;
	unsigned int i, digits = 0;

	if (!kptr_ok(k_uts)) return 0;
	if (strncmp(k_uts->name.sysname, "Linux", 5)) return 0;

	r = k_uts->name.release;
	v = k_uts->name.version;

	for (i = 0; i < __NEW_UTS_LEN && r[i]; i++)
		if (r[i] >= '0' && r[i] <= '9') digits++;
	if (!digits || !strchr(r, '.')) return 0;
	if (!v[0]) return 0;
	for (i = 0; i < __NEW_UTS_LEN && v[i]; i++)
		if ((unsigned char)v[i] < 0x20 || (unsigned char)v[i] > 0x7e) return 0;

	return 1;
}

static void uts_scrub(void)
{
	char *r, *v, *c;
	long l;

	if (uts_ok) return;
	if (!uts_layout_ok()) {
		pr_info("wanbai: uts layout mismatch, skip\n");
		return;
	}
	r = k_uts->name.release;
	v = k_uts->name.version;
	memcpy(saved_release, r, sizeof(saved_release));
	memcpy(saved_version, v, sizeof(saved_version));
	uts_ok = 1;

	if (uts_cut_marked(r)) {
		c = strpbrk(r, "-+");
		if (c) *c = '\0';
	}

	blank_word(v, "APatch");
	blank_word(v, "KernelSU");
	blank_word(v, "KPM");
	blank_word(v, "Magisk");
	c = v + strlen(v);
	while (c > v && c[-1] == ' ') *--c = '\0';

	if (!strstr(v, "kpatch")) {
		l = (long)strlen(v);
		if (l + 8 < (long)sizeof(k_uts->name.version))
			memcpy(v + l, " kpatch", 8);
	}
}

static void uts_restore(void)
{
	if (!uts_ok || !kptr_ok(k_uts)) return;
	memcpy(k_uts->name.release, saved_release, sizeof(saved_release));
	memcpy(k_uts->name.version, saved_version, sizeof(saved_version));
	uts_ok = 0;
}

/* ---------- uid ---------- */
static unsigned int inode_uid(const char *path)
{
	struct kp_path p;
	void *d, *i;
	unsigned int uid = 0, mode;

	if (!k_kern_path || !k_path_put) return 0;
	memset(&p, 0, sizeof(p));
	if (k_kern_path(path, LOOKUP_FOLLOW, &p)) return 0;

	d = *(void **)((char *)&p + OFF.path_dentry);
	if (!kptr_ok(d)) { k_path_put(&p); return 0; }
	i = d_inode_of(d);
	if (!kptr_ok(i)) { k_path_put(&p); return 0; }

	mode = *(unsigned int *)((char *)i + OFF.inode_mode);
	if ((mode & 0xF000) != 0x4000 && (mode & 0xF000) != 0x8000) { k_path_put(&p); return 0; }
	uid = *(unsigned int *)((char *)i + OFF.inode_uid);
	k_path_put(&p);
	return (uid > 0 && uid < 20000) ? uid : 0;
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
		if (!room(v, tail + 5)) return;
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
	long vlen, tail;

	if (!p) return;
	v = p + 11;
	if (!strncmp(v, "disabled", 8)) vlen = 8;
	else if (!strncmp(v, "logging", 7)) vlen = 7;
	else return;

	tail = (long)strlen(v + vlen);
	if (!room(v, tail + 9)) return;
	memmove(v + 9, v + vlen, tail + 1);
	memcpy(v, "enforcing", 9);
}

static void set_selinux(char *c)
{
	char *p = strstr(c, "androidboot.selinux="), *v;
	long tail;
	if (!p) return;
	v = p + 21;
	if (strncmp(v, "permissive", 10)) return;
	tail = (long)strlen(v + 10);
	if (!room(v, tail + 10)) return;
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

	cmd_end = NULL;
	if (!k_saved_cmdline || !kptr_ok(k_saved_cmdline)) return;
	c = *k_saved_cmdline;
	if (!c || !kptr_ok(c)) return;
	if (!strstr(c, "androidboot")) return;
	cmd_end = c + strlen(c) + 2;
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
	long tail;

	if ((p = strstr(c, "kernelsu"))) {
		tail = (long)strlen(p + 8);
		memcpy(p, "init", 4);
		memmove(p + 4, p + 8, tail + 1);
		return;
	}
	if ((p = strstr(c, "magisk"))) {
		tail = (long)strlen(p + 6);
		memcpy(p, "init", 4);
		memmove(p + 4, p + 6, tail + 1);
		return;
	}
	if ((p = strstr(c, "ksu"))) {
		tail = (long)strlen(p + 3);
		memmove(p + 4, p + 3, tail + 1);
		memcpy(p, "init", 4);
	}
}

/* ---------- getname ---------- */
struct gp_data { int hide; int guard; };
KP_STATIC_ASSERT(sizeof(struct gp_data) <= KRET_BODY_MAX, "gp_data too big for hook local");

static struct kretprobe kr_name = {
	.kp.symbol_name = "getname_flags",
	.maxactive      = 128,
	.data_size      = sizeof(struct gp_data),
};

static int name_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gp_data *d = (struct gp_data *)ri->data;
	const char __user *u = (const char __user *)P_ARG0(regs);
	char path[PATH_S];

	d->hide = 0;
	d->guard = 0;
	if (g_name) return 1;
	if (bypass() || !u) return 1;
	g_name = 1;
	d->guard = 1;
	if (strncpy_from_user(path, u, sizeof(path) - 1) < 0) return 1;
	path[sizeof(path) - 1] = '\0';
	if (path[0] == '/') d->hide = is_hidden(path);
	return 1;
}

static int name_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gp_data *d = (struct gp_data *)ri->data;
	struct kp_filename *fn = (struct kp_filename *)P_RET(regs);
	if (d->guard) g_name = 0;
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
static int is_dev_dir(unsigned long filep)
{
	void *d, *par;
	struct kp_qstr *q;

	if (!kptr_ok((void *)filep)) return 0;
	d = f_dentry_of((void *)filep);
	if (!kptr_ok(d)) return 0;
	q = d_name_of(d);
	if (!kptr_ok(q) || q->len != 3 || !kptr_ok(q->name)) return 0;
	if (memcmp(q->name, "dev", 3)) return 0;
	par = d_parent_of(d);
	if (!kptr_ok(par)) return 0;
	q = d_name_of(par);
	return kptr_ok(q) && q->len == 1;
}

static bool filter_actor(struct kp_dir_context *c, const char *name, int namlen,
			 loff_t off, u64 ino, unsigned type)
{
	kp_filldir_t o = (kp_filldir_t)g_dorig;

	if (!o) return false;
	c->pos = off;

	if (g_ddevdir) {
		if (namlen == DEV_LEN && !memcmp(name, DEV_NAME, DEV_LEN)) {
			g_demitted = 1;
			return o(c, name, namlen, off, ino, type);
		}
		if (!g_demitted) {
			g_demitted = 1;
			o(c, DEV_NAME, DEV_LEN, off, 0, 2);
			off = c->pos;
		}
		return o(c, name, namlen, off, ino, type);
	}

	if (name_blocked(name, namlen)) return false;
	return o(c, name, namlen, off, ino, type);
}

static bool filter_actor_pid(struct kp_dir_context *c, const char *name, int namlen,
			     loff_t off, u64 ino, unsigned type)
{
	kp_filldir_t o = (kp_filldir_t)g_dorig;
	int v = 0, i;

	if (!o) return false;
	c->pos = off;

	for (i = 0; i < namlen && name[i] >= '0' && name[i] <= '9'; i++)
		v = v * 10 + (name[i] - '0');
	if (i && i == namlen && (v == hide_pid || pid_in_set(v))) return false;
	if (name_blocked(name, namlen)) return false;
	return o(c, name, namlen, off, ino, type);
}

static void dir_before(hook_fargs4_t *f, void *ud)
{
	struct kp_dir_context *ctx = (struct kp_dir_context *)f->arg1;
	int pidonly = (int)(unsigned long)ud;
	int dev = 0;

	if (g_dctx) return;
	if (!kptr_ok(ctx)) return;
	if (!kptr_ok((const void *)ctx->actor)) return;
	if ((void *)ctx->actor == (void *)filter_actor) return;
	if ((void *)ctx->actor == (void *)filter_actor_pid) return;

	if (bypass()) {
		dev = is_dev_dir(f->arg0);
		if (!dev) return;
	} else if (pidonly && !hide_pid && !hide_set_n) {
		return;
	}

	g_dctx = ctx;
	g_dorig = (void *)ctx->actor;
	g_ddevdir = (char)dev;
	g_demitted = 0;
	ctx->actor = (pidonly && !dev) ? filter_actor_pid : filter_actor;
}

static void dir_after(hook_fargs4_t *f, void *ud)
{
	struct kp_dir_context *ctx = g_dctx;
	(void)f; (void)ud;
	if (!ctx) return;
	ctx->actor = (kp_filldir_t)g_dorig;
	g_dctx = 0;
	g_dorig = 0;
}

/* ---------- read scrub ---------- */
static struct kretprobe kr_pread, kr_bprop;

static int pid_parent(struct kp_file *f)
{
	struct kp_qstr *q;
	void *d, *par;
	const char *pn;

	d = f_dentry_of(f);
	if (!kptr_ok(d)) return 0;
	par = d_parent_of(d);
	if (!kptr_ok(par)) return 0;
	q = d_name_of(par);
	if (!kptr_ok(q) || !kptr_ok(q->name)) return 0;
	pn = (const char *)q->name;
	return pn[0] >= '0' && pn[0] <= '9';
}

static int pre_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kp_file *f = (struct kp_file *)P_ARG0(regs);
	int *mode = (int *)ri->data;
	struct kp_qstr *q;
	void *d;
	const char *n;
	unsigned int len;

	*mode = 0;
	if (g_read) return 0;
	if (bypass()) return 0;

	d = f_dentry_of(f);
	if (!kptr_ok(d)) return 0;
	q = d_name_of(d);
	if (!kptr_ok(q)) return 0;

	len = q->len;
	if (len != 7 && len != 8 && len != 10 && len != 6) return 0;

	n = (const char *)q->name;
	if (!kptr_ok(n)) return 0;
	if (len == 7 && !strcmp(n, "cmdline") && pid_parent(f)) { *mode = 1; return 1; }
	if (len == 8 && !strncmp(n, "bootargs", 8)) { *mode = 1; return 1; }
	if (len == 10 && !strcmp(n, "build.prop")) { *mode = 2; return 1; }
	if (len == 7 && !strcmp(n, "enforce")) { *mode = 4; return 1; }
	if (len == 6 && !strcmp(n, "status") && pid_parent(f)) { *mode = 5; return 1; }
	if (len == 7 && !strcmp(n, "current") && pid_parent(f)) { *mode = 3; return 1; }
	return 0;
}

static int post_read(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	int mode = *(int *)ri->data;
	char buf[320];
	long n;

	if (!mode || ret <= 0 || !user_ok((unsigned long)ub)) return 0;
	g_read = 1;
	n = ret > (long)sizeof(buf) - 8 ? (long)sizeof(buf) - 8 : ret;
	if (copy_from_user(buf, ub, n)) { g_read = 0; return 0; }
	buf[n] = '\0';
	cmd_end = buf + sizeof(buf);
	switch (mode) {
	case 1: scrub_boot_args(buf); break;
	case 2: scrub_buildprop(buf); break;
	case 3: scrub_ctx(buf); break;
	case 4: if (buf[0] == '0') buf[0] = '1'; break;
	case 5: scrub_tracer(buf, n); break;
	default: break;
	}
	cmd_end = NULL;
	copy_to_user(ub, buf, n);
	g_read = 0;
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
	struct kp_statfs *st = (struct kp_statfs *)P_ARG1(regs);
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
	if (!*(int *)ri->data || ret <= 0 || !user_ok((unsigned long)ub)) return 0;
	n = ret > (long)sizeof(buf) - 1 ? (long)sizeof(buf) - 1 : ret;
	if (copy_from_user(buf, ub, n)) return 0;
	buf[n] = '\0';
	if (!strstr(buf, DEV_NAME)) return 0;
	if (copy_to_user(ub, repl, sizeof(repl) - 1)) return 0;
	P_RET(regs) = (unsigned long)(sizeof(repl) - 1);
	return 0;
}

/* ---------- seq compaction ---------- */
#define TR_TEXT 0
#define TR_MAPS 1
#define TR_STATUS 2

struct tr_data { struct kp_seq_file *m; long saved; int kind; int ok; };
KP_STATIC_ASSERT(sizeof(struct tr_data) <= KRET_BODY_MAX, "tr_data too big");

static struct kretprobe kr_mounts, kr_mountinfo, kr_modules, kr_misc;
static struct kretprobe kr_fs, kr_vm, kr_status, kr_smaps, kr_maps, kr_roll;

static int tr_entry_kind(struct kretprobe_instance *ri, struct pt_regs *regs, int kind)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct kp_seq_file *m = (struct kp_seq_file *)P_ARG0(regs);

	d->m = m; d->saved = 0; d->kind = kind; d->ok = 0;
	if (g_seq) return 0;
	if (bypass() || !kptr_ok(m) || !kptr_ok(m->buf)) return 0;
	if (m->size < 64 || m->size > 0x100000) return 0;
	if (m->count > m->size || m->from) return 0;
	g_seq = 1;
	d->saved = (long)m->count;
	d->ok = 1;
	return 1;
}

static int tr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{ return tr_entry_kind(ri, regs, TR_TEXT); }

static int tr_entry_maps(struct kretprobe_instance *ri, struct pt_regs *regs)
{ return tr_entry_kind(ri, regs, TR_MAPS); }

static int tr_entry_status(struct kretprobe_instance *ri, struct pt_regs *regs)
{ return tr_entry_kind(ri, regs, TR_STATUS); }

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
		char *sp = memchr(buf + i, ' ', ll < 64 ? ll : 64);
		if (sp && (sp - buf) + 4 < i + ll && sp[1] == 'r' && sp[2] == 'w' && sp[3] == 'x')
			sp[2] = '-';
		i += ll;
	}
}

static int tr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct kp_seq_file *m = d->m;
	long i, o, end;
	(void)regs;

	if (!d->ok) return 0;
	g_seq = 0;
	if (!kptr_ok(m) || (long)m->count <= d->saved) return 0;
	if ((unsigned long)m->count > m->size) return 0;

	if (d->kind == TR_STATUS) zero_tracer(m->buf, d->saved, (long)m->count);
	if (d->kind == TR_MAPS) defang_perms(m->buf, d->saved, (long)m->count);

	i = d->saved; end = (long)m->count; o = d->saved;
	while (i < end) {
		char *nl = memchr(m->buf + i, '\n', end - i);
		long ll = nl ? (long)(nl - (m->buf + i)) + 1 : end - i;
		int hit = (d->kind == TR_MAPS)
			? text_blocked_set(m->buf + i, ll, blk_maps, BLK_M)
			: text_blocked_set(m->buf + i, ll, blk_text, BLK_T);
		if (hit) { i += ll; continue; }
		if (o != i) memmove(m->buf + o, m->buf + i, ll);
		o += ll; i += ll;
	}
	m->count = (unsigned long)o;
	return 0;
}

static void hook_tr(struct kretprobe *kr, const char *sym, int kind)
{
	kr->kp.symbol_name = sym;
	if (!kr->entry_handler) {
		if (kind == TR_MAPS) kr->entry_handler = tr_entry_maps;
		else if (kind == TR_STATUS) kr->entry_handler = tr_entry_status;
		else kr->entry_handler = tr_entry;
	}
	if (!kr->handler) kr->handler = tr_ret;
	if (!kr->data_size) kr->data_size = sizeof(struct tr_data);
	kr->maxactive = 64;
	if (!register_kretprobe(kr)) { hooks_ok++; return; }
	memset(kr, 0, sizeof(*kr));
}

static void hook_bprop(int on)
{
	if (on) {
		if (kr_bprop.hooked) return;
		kr_bprop.data_size = sizeof(int);
		kr_bprop.entry_handler = pre_read;
		kr_bprop.handler = post_read;
		hook_tr(&kr_bprop, "vfs_read", TR_TEXT);
	} else if (kr_bprop.hooked) {
		unregister_kretprobe(&kr_bprop);
	}
}

/* ============================================================
 *  live probe
 * ============================================================ */
static int live_probe(void)
{
	struct kp_path p;
	void *d, *file, *fd2;
	int ok = 1;

	if (!k_kern_path || !k_path_put) return 1;

	memset(&p, 0, sizeof(p));
	if (k_kern_path("/", LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &p)) return 0;
	d = *(void **)((char *)&p + OFF.path_dentry);
	if (!kptr_ok(d)) ok = 0;

	if (ok && k_filp_open && k_filp_close) {
		file = k_filp_open("/", 0, 0);
		if (!file || IS_ERR(file) || !kptr_ok(file)) {
			ok = 0;
		} else {
			fd2 = f_dentry_of(file);
			if (fd2 != d) ok = 0;
			k_filp_close(file, 0);
		}
	}
	k_path_put(&p);
	return ok;
}

/* ---- minimal: sirf path hook ---- */
static void hooks_install_min(void)
{
#if STAGE >= 3
	if (HAVE("getname_flags")) {
		kr_name.entry_handler = name_entry;
		kr_name.handler = name_ret;
		if (!register_kretprobe(&kr_name)) hooks_ok++;
		else memset(&kr_name, 0, sizeof(kr_name));
	} else if (HAVE("filename_lookup")) {
		kp_path.symbol_name = "filename_lookup";
		kp_path.pre_handler = pre_path;
		if (!register_kprobe(&kp_path)) hooks_ok++;
	}
#endif
}

/* ---- full: read scrub + statfs + readlink + dir ---- */
static void hooks_install_rest(void)
{
	if (HAVE("proc_reg_read")) {
		kr_pread.data_size = sizeof(int);
		kr_pread.entry_handler = pre_read;
		kr_pread.handler = post_read;
		hook_tr(&kr_pread, "proc_reg_read", TR_TEXT);
	}
	hook_bprop(vfs_on);

	if (HAVE("vfs_statfs")) {
		kr_statfs.kp.symbol_name = "vfs_statfs";
		kr_statfs.data_size = 0;
		kr_statfs.entry_handler = entry_statfs;
		kr_statfs.handler = post_statfs;
		kr_statfs.maxactive = 64;
		if (!register_kretprobe(&kr_statfs)) hooks_ok++;
		else memset(&kr_statfs, 0, sizeof(kr_statfs));
	}

	if (HAVE("vfs_readlink")) {
		kr_rl.kp.symbol_name = "vfs_readlink";
		kr_rl.data_size = sizeof(int);
		kr_rl.entry_handler = pre_rl;
		kr_rl.handler = post_rl;
		kr_rl.maxactive = 64;
		if (!register_kretprobe(&kr_rl)) hooks_ok++;
		else memset(&kr_rl, 0, sizeof(kr_rl));
	}

	if (!iterate_addr) {
		iterate_addr = sym_addr("iterate_dir");
		if (iterate_addr &&
		    !hook_wrap4((void *)iterate_addr, dir_before, dir_after, (void *)0))
			hooks_ok++;
		else
			iterate_addr = 0;
	}
	if (!piddir_addr) {
		piddir_addr = sym_addr("proc_pid_readdir");
		if (piddir_addr &&
		    !hook_wrap4((void *)piddir_addr, dir_before, dir_after, (void *)1))
			hooks_ok++;
		else
			piddir_addr = 0;
	}

#if STAGE >= 6
	if (HAVE("show_vfsmnt"))           hook_tr(&kr_mounts, "show_vfsmnt", TR_TEXT);
	if (HAVE("show_mountinfo"))        hook_tr(&kr_mountinfo, "show_mountinfo", TR_TEXT);
	if (HAVE("m_show"))                hook_tr(&kr_modules, "m_show", TR_TEXT);
	if (HAVE("misc_show"))             hook_tr(&kr_misc, "misc_show", TR_TEXT);
	if (HAVE("filesystems_proc_show")) hook_tr(&kr_fs, "filesystems_proc_show", TR_TEXT);
	if (HAVE("s_show"))                hook_tr(&kr_vm, "s_show", TR_TEXT);
	if (HAVE("proc_pid_status"))       hook_tr(&kr_status, "proc_pid_status", TR_STATUS);
	if (HAVE("show_map_vma"))          hook_tr(&kr_maps, "show_map_vma", TR_MAPS);
	if (HAVE("show_smap"))             hook_tr(&kr_smaps, "show_smap", TR_MAPS);
	if (HAVE("smaps_rollup_show"))     hook_tr(&kr_roll, "smaps_rollup_show", TR_MAPS);
#endif
}

static void dir_hooks_remove(void)
{
	if (iterate_addr) {
		hook_unwrap((void *)iterate_addr, dir_before, dir_after);
		iterate_addr = 0;
		if (hooks_ok) hooks_ok--;
	}
	if (piddir_addr) {
		hook_unwrap((void *)piddir_addr, dir_before, dir_after);
		piddir_addr = 0;
		if (hooks_ok) hooks_ok--;
	}
}

static void hooks_remove(void)
{
	dir_hooks_remove();
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
	hooks_full = 0;
}

static void pick_fake_path(void)
{
	struct kp_path p;
	if (!k_kern_path || !k_path_put) return;
	memset(&p, 0, sizeof(p));
	if (!k_kern_path(FAKE_DIR, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &p)) {
		k_path_put(&p);
		fake_path = FAKE_DIR;
	}
}

/* ---------- symbols ---------- */
#define RS(name, slot) do { *(void **)&(slot) = (void *)sym_addr(name); \
	if (!(slot)) miss_syms++; } while (0)

static int resolve_syms(void)
{
	if (!kallsyms_lookup_name) return -ESRCH;

	RS("_copy_from_user", k_copy_from_user);
	if (!k_copy_from_user) { miss_syms--; RS("__arch_copy_from_user", k_copy_from_user); }
	if (!k_copy_from_user) { miss_syms--; RS("__copy_from_user", k_copy_from_user); }
	if (!k_copy_from_user) { miss_syms--; RS("copy_from_user", k_copy_from_user); }

	RS("linux_banner", k_banner);
	RS("kptr_restrict", k_kptr_restrict);
	RS("saved_command_line", k_saved_cmdline);
	RS("init_uts_ns", k_uts);
	RS("in_compat_syscall", k_in_compat);
	RS("misc_register", k_misc_register);
	RS("misc_deregister", k_misc_deregister);
	RS("kern_path", k_kern_path);
	RS("path_put", k_path_put);
	RS("filp_open", k_filp_open);
	RS("filp_close", k_filp_close);
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
	RS("flush_icache_range", k_flush_icache);
	RS("find_vma", k_find_vma);
	if (!k_find_vma) { miss_syms--; RS("find_vma_prev", k_find_vma_prev); }
	RS("input_event", k_input_event);
	RS("input_mt_slot", k_input_mt_slot);
	RS("input_mt_report_slot_state", k_input_mt_report_slot_state);
	RS("input_mt_get_slot_by_key", k_input_mt_get_slot_by_key);
	RS("input_sync", k_input_sync);

	if (!k_copy_from_user) pr_info("wanbai: copy_from_user missing, ioctl degraded\n");
	return 0;
}

static struct task_struct *task_get(int pid)
{
	struct task_struct *t;
	if (!k_find_vpid || !k_pid_task) return NULL;
	t = k_pid_task(k_find_vpid(pid), PIDTYPE_PID);
	if (t && k_get_task_struct) k_get_task_struct(t);
	return t;
}

static void task_put(struct task_struct *t) { if (t && k_put_task_struct) k_put_task_struct(t); }

/* ============================================================
 *  chunked r/w
 * ============================================================ */
static char *kmem_buf;
static volatile int kmem_busy;

static long kmem_rw(int pid, unsigned long addr, unsigned long ua,
		    unsigned long len, int wr)
{
	struct task_struct *t;
	long done = 0, r = 0;

	if (!kmem_buf || !len || len > KMEM_MAX) return -EINVAL;
	if (!user_ok(addr) || !user_ok(ua)) return -EINVAL;
	if (!k_access_process_vm) return -EIO;
	if (kmem_busy) return -EBUSY;
	kmem_busy = 1;

	t = task_get(pid);
	if (!t) { kmem_busy = 0; return -ESRCH; }

	while (done < (long)len) {
		unsigned long n = len - done;
		if (n > KMEM_CHUNK) n = KMEM_CHUNK;

		if (wr) {
			if (copy_from_user(kmem_buf, (void __user *)(ua + done), n)) { r = -EFAULT; break; }
			r = k_access_process_vm(t, addr + done, kmem_buf, (int)n, FOLL_WRITE | FOLL_FORCE);
		} else {
			r = k_access_process_vm(t, addr + done, kmem_buf, (int)n, 0);
			if (r > 0 && copy_to_user((void __user *)(ua + done), kmem_buf, r)) { r = -EFAULT; break; }
		}
		if (r <= 0) break;
		done += r;
		if (r < (long)n) break;
	}
	task_put(t);
	kmem_busy = 0;

	if (wr && done > 0 && k_flush_icache)
		k_flush_icache(addr, addr + (unsigned long)done);
	return done > 0 ? done : (r < 0 ? r : -EIO);
}

/* ---------- ioctl ---------- */
static void wb_size(unsigned long arg, int c32, unsigned long long sz)
{
	if (c32) {
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return;
		x.size = (unsigned int)sz;
		copy_to_user((void __user *)arg, &x, sizeof(x));
		return;
	}
	{
		struct copy_mem x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return;
		x.size = sz;
		copy_to_user((void __user *)arg, &x, sizeof(x));
	}
}

static const int vm_file_off[] = { 0xa8, 0xb0, 0xa0, 0xb8, 0x98 };

static struct kp_file *vma_file(void *v)
{
	unsigned int i;
	struct kp_file *f;

	if (!kptr_ok(v)) return 0;
	if (OFF.vma_file > 0) {
		f = *(struct kp_file **)((char *)v + OFF.vma_file);
		if (kptr_ok(f) && kptr_ok(f_dentry_of(f))) return f;
	}
	for (i = 0; i < ARRAY_SIZE(vm_file_off); i++) {
		if (vm_file_off[i] == OFF.vma_file) continue;
		f = *(struct kp_file **)((char *)v + vm_file_off[i]);
		if (!kptr_ok(f)) continue;
		if (!kptr_ok(f_dentry_of(f))) continue;
		return f;
	}
	return 0;
}

static long dev_ioctl(struct kp_file *f, unsigned int cmd, unsigned long arg)
{
	struct copy_mem cm;
	struct task_struct *tsk;
	char small[SMALL_IO];
	int ret, c32 = 0;
	(void)f;

	c32 = abi_force >= 0 ? abi_force : (k_in_compat ? (k_in_compat() ? 1 : 0) : 0);
	memset(&cm, 0, sizeof(cm));

	if (cmd == OP_INIT) {
		/* pehla init par poore hooks laga do */
		if (inited && !hooks_full && !hooks_off) {
			hooks_full = 1;
			hooks_install_rest();
			if (!live_probe()) {
				pr_info("wanbai: probe B fail -> rest wapas\n");
				dir_hooks_remove();
				if (kr_pread.hooked) unregister_kretprobe(&kr_pread);
				if (kr_statfs.hooked) unregister_kretprobe(&kr_statfs);
				if (kr_rl.hooked) unregister_kretprobe(&kr_rl);
			}
			pr_info("wanbai: full on, hooks %u\n", hooks_ok);
		}
		return 0;
	}
	if (!user_ok(arg)) return 0;

	if (cmd == OP_VER) {
		int v = (int)(((unsigned)MAGIC << 16) | (API_VER & 0xFFFF));
		return copy_to_user((void __user *)arg, &v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_PING) {
		int v = (int)(((unsigned)MAGIC << 16) | ((hooks_ok & 0xFF) << 8) | 0x01);
		return copy_to_user((void __user *)arg, &v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_STATE) {
		int v[4];
		v[0] = mgr_uid;
		v[1] = game_uid;
		v[2] = (int)hooks_ok;
		v[3] = (strict & 0xFF) | ((game_byp & 0xF) << 8) | ((vfs_on & 1) << 12)
			| ((dev_ok & 1) << 13) | ((kptr_saved & 1) << 14)
			| ((miss_syms & 0xFF) << 16) | ((btf_ok & 1) << 24)
			| ((hooks_full & 1) << 25);
		return copy_to_user((void __user *)arg, v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_STRICT) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		strict = v;
		return 0;
	}
	if (cmd == OP_HIDE) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		hide_pid = v;
		return 0;
	}
	if (cmd == OP_HIDEN) {
		int v[HIDE_MAX + 1];
		int i;
		if (copy_from_user(v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (v[HIDE_MAX] < 0 || v[HIDE_MAX] > HIDE_MAX) return -EINVAL;
		hide_set_n = 0;
		for (i = 0; i < v[HIDE_MAX]; i++)
			if (v[i] > 0 && hide_set_n < HIDE_MAX) hide_set[hide_set_n++] = v[i];
		return 0;
	}
	if (cmd == OP_KPTR) {
		unsigned int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (v && !kptr_saved && kptr_ok(k_kptr_restrict)) {
			saved_kptr = *k_kptr_restrict;
			kptr_saved = 1;
			*k_kptr_restrict = 1;
		} else if (!v && kptr_saved && kptr_ok(k_kptr_restrict)) {
			*k_kptr_restrict = saved_kptr;
			kptr_saved = 0;
		}
		return 0;
	}
	if (cmd == OP_TOUCH) {
		unsigned int v[3];
		if (!inj_alive()) return -ENODEV;
		if (copy_from_user(v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (v[2] == 1) inject_touch(v[0], v[1], 1);
		else if (v[2] == 0) inject_touch(v[0], v[1], 0);
		else if (inj_down) inject_touch(v[0], v[1], 1);
		return 0;
	}
	if (cmd == OP_TRANGE) {
		unsigned int v[2];
		if (copy_from_user(v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (!v[0] || !v[1]) return -EINVAL;
		inj_mx = v[0]; inj_my = v[1];
		return 0;
	}
	if (cmd == OP_TOUCHQ) {
		unsigned int v[3];
		if (!inj_alive() && !inj_dev) {
			inj_dev = pick_input_dev();
			inj_ok = inj_dev ? 1 : 0;
		}
		if (!inj_mx || !inj_my) inj_range_probe();
		v[0] = inj_alive() ? 1u : 0u;
		v[1] = inj_mx; v[2] = inj_my;
		return copy_to_user((void __user *)arg, v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_IHIDE) {
		unsigned int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (!inj_alive()) {
			inj_dev = pick_input_dev();
			inj_ok = inj_dev ? 1 : 0;
		}
		idev_hide(v ? 1 : 0);
		return 0;
	}
	if (cmd == OP_ISTAT) {
		int v[3];
		v[0] = inj_alive() ? 1 : 0;
		v[1] = inj_hidden;
		v[2] = btf_ok;
		return copy_to_user((void __user *)arg, v, sizeof(v)) ? -EFAULT : 0;
	}
	if (cmd == OP_TREL) {
		if (inj_hidden) idev_hide(0);
		inj_ok = 0; inj_dev = 0; inj_mx = 0; inj_my = 0;
		learner_remove();
		inj_dev = pick_input_dev();
		if (inj_dev) { inj_ok = 1; inj_range_probe(); }
		if (!inj_dev) return learner_install();
		return 0;
	}
	if (cmd == OP_DMESG) {
		unsigned int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		dmesg_hide = !!v;
		return 0;
	}
	if (cmd == OP_MUID) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		mgr_uid = v;
		return 0;
	}
	if (cmd == OP_GUID) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		game_uid = v;
		return 0;
	}
	if (cmd == OP_GBYP) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		game_byp = v;
		return 0;
	}
	if (cmd == OP_VFS) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		vfs_on = !!v;
		hook_bprop(vfs_on);
		return 0;
	}
	if (cmd == OP_SAFE) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (v) {
			hooks_remove();
			hooks_install_min();
			pr_info("wanbai: minimal, hooks %u\n", hooks_ok);
		} else {
			hooks_full = 1;
			hooks_install_rest();
			if (!live_probe()) { dir_hooks_remove(); }
			pr_info("wanbai: full on, hooks %u\n", hooks_ok);
		}
		return 0;
	}
	if (cmd == OP_OFF) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (v && !hooks_off) {
			hooks_remove();
			learner_remove();
			hooks_ok = 0;
			hooks_off = 1;
		} else if (!v && hooks_off) {
			hooks_off = 0;
			hooks_install_min();
			learner_install();
		}
		return 0;
	}
	if (cmd == OP_ABI) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		abi_force = v;
		return 0;
	}
	if (cmd == OP_UTS) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		if (!k_uts) return 0;
		if (v) uts_scrub(); else uts_restore();
		return 0;
	}
	if (cmd == OP_FLUSH) {
		unsigned long long r[2];
		if (copy_from_user(&r, (void __user *)arg, sizeof(r))) return -EFAULT;
		if (k_flush_icache && r[1] > r[0])
			k_flush_icache((unsigned long)r[0], (unsigned long)r[1]);
		return 0;
	}

	if (c32) {
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return -EFAULT;
		cm.pid = x.pid; cm.addr = x.addr; cm.buffer = x.buffer; cm.size = x.size;
	} else if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;

	if (cmd == OP_BASE) {
		struct mod_base mb;
		struct kp_mm *mm;
		void *vma, *prev;
		char pname[256];
		unsigned long long found = 0;
		int guard = 0;

		memset(&mb, 0, sizeof(mb));
		if (c32) {
			struct mod_base32 y;
			if (copy_from_user(&y, (void __user *)arg, sizeof(y))) return -EFAULT;
			mb.pid = y.pid; mb.name = y.name;
		} else if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) return -EFAULT;

		if (!mb.pid || !mb.name || !user_ok((unsigned long)mb.name)) return -EINVAL;
		if (strncpy_from_user(pname, (const char __user *)(unsigned long)mb.name,
				      sizeof(pname) - 1) < 0) return -EFAULT;
		pname[sizeof(pname) - 1] = '\0';
		if (!pname[0] || !k_get_task_mm) return -EINVAL;

		tsk = task_get(mb.pid);
		if (!tsk) return -ESRCH;
		mm = k_get_task_mm(tsk);
		task_put(tsk);
		if (!mm) return -ESRCH;

		prev = NULL;
		if (k_find_vma) vma = k_find_vma(mm, 0);
		else if (k_find_vma_prev) vma = k_find_vma_prev(mm, 0, &prev);
		else vma = *(void **)mm;

		while (kptr_ok(vma) && guard++ < 8192) {
			struct kp_file *vf;
			unsigned long vstart = *(unsigned long *)((char *)vma + OFF.vma_start);
			unsigned long vend = *(unsigned long *)((char *)vma + OFF.vma_end);

			if (!vend || vend <= vstart) break;

			vf = vma_file(vma);
			if (vf) {
				struct kp_qstr *q = d_name_of(f_dentry_of(vf));
				if (kptr_ok(q) && kptr_ok(q->name) &&
				    strstr((const char *)q->name, pname)) {
					found = vstart;
					break;
				}
			}
			if (k_find_vma) vma = k_find_vma(mm, vend);
			else if (k_find_vma_prev) { prev = NULL; vma = k_find_vma_prev(mm, vend, &prev); }
			else vma = *(void **)((char *)vma + 0x10);
		}
		if (k_mmput) k_mmput(mm);
		mb.base = found;

		if (c32) {
			struct mod_base32 y;
			y.pid = mb.pid; y.name = (unsigned int)mb.name; y.base = (unsigned int)found;
			copy_to_user((void __user *)arg, &y, sizeof(y));
		} else copy_to_user((void __user *)arg, &mb, sizeof(mb));
		return 0;
	}

	if (!cm.pid || !cm.size) return -EINVAL;
	if (cm.size > KMEM_MAX) return -EINVAL;
	if (!user_ok((unsigned long)cm.addr) || !user_ok((unsigned long)cm.buffer)) return -EINVAL;

	if (cmd == OP_READ || cmd == OP_WRITE) {
		if (cm.size > SMALL_IO) {
			ret = (int)kmem_rw(cm.pid, (unsigned long)cm.addr, (unsigned long)cm.buffer,
					   (unsigned long)cm.size, cmd == OP_WRITE);
			if (ret > 0) { wb_size(arg, c32, (unsigned long long)ret); return 0; }
			return ret;
		}
		tsk = task_get(cm.pid);
		if (!tsk) return -ESRCH;
		if (!k_access_process_vm) { task_put(tsk); return -EIO; }
		if (cmd == OP_READ) {
			ret = k_access_process_vm(tsk, (unsigned long)cm.addr, small, (int)cm.size, 0);
			if (ret > 0 && copy_to_user((void __user *)(unsigned long)cm.buffer, small, ret))
				ret = -EFAULT;
		} else {
			if (copy_from_user(small, (void __user *)(unsigned long)cm.buffer,
					   (unsigned long)cm.size)) ret = -EFAULT;
			else {
				ret = k_access_process_vm(tsk, (unsigned long)cm.addr, small,
							  (int)cm.size, FOLL_WRITE | FOLL_FORCE);
				if (ret > 0 && k_flush_icache)
					k_flush_icache((unsigned long)cm.addr,
						       (unsigned long)cm.addr + (unsigned long)ret);
			}
		}
		task_put(tsk);
		if (ret > 0) { wb_size(arg, c32, (unsigned long long)ret); return 0; }
		return ret < 0 ? ret : -EIO;
	}

	return -EINVAL;
}

static long dev_dispatch(struct kp_file *f, unsigned long a, unsigned long b)
{
	if (a >= 0xffff000000000000UL) return 1;
	return dev_ioctl(f, (unsigned int)a, b);
}

static loff_t dev_noop_llseek(struct kp_file *f, loff_t o, int w)
{ (void)f; (void)w; return o; }

static ssize_t dev_read(struct kp_file *f, char __user *b, size_t n, loff_t *p)
{ (void)f; (void)b; (void)n; (void)p; return 0; }

static ssize_t dev_write(struct kp_file *f, const char __user *b, size_t n, loff_t *p)
{ (void)f; (void)b; (void)n; (void)p; return 0; }

static struct kp_miscdevice dev;

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
	unsigned int maj = 0, min = 0, i;
	int r;

	(void)args; (void)event; (void)reserved;

	if (!name_decode()) {
		pr_info("wanbai: owner tag tampered\n");
		return -EIO;
	}

	pr_info("wanbai: abi local=%u body=%u\n", HOOK_LOCAL_BYTES, KRET_BODY_MAX);

	if (HAVE("devkmsg_read")) {
		kr_kmsg.kp.symbol_name = "devkmsg_read";
		kr_kmsg.data_size = sizeof(int);
		kr_kmsg.entry_handler = kmsg_entry;
		kr_kmsg.handler = kmsg_ret;
		kr_kmsg.maxactive = 32;
		if (!register_kretprobe(&kr_kmsg)) hooks_ok++;
		else memset(&kr_kmsg, 0, sizeof(kr_kmsg));
	}

	r = resolve_syms();
	if (r) { pr_info("wanbai: kallsyms missing\n"); goto err; }

	offs_resolve();

	if (kver_mm(&maj, &min)) { maj = 0; min = 0; pr_info("wanbai: kver unknown\n"); }
	else if (maj < 3 || (maj == 3 && min < 18)) {
		pr_info("wanbai: kernel %u.%u bahut purana\n", maj, min);
		r = -EINVAL;
		goto err;
	}

	if (k_kvmalloc) kmem_buf = k_kvmalloc(KMEM_CHUNK, GFP_KERNEL);

	memset(fops_buf, 0, sizeof(fops_buf));
	fops_put(1 * sizeof(void *),
		 (const void *)(k_no_llseek ? k_no_llseek : dev_noop_llseek));
	fops_put(2 * sizeof(void *), (const void *)dev_read);
	fops_put(3 * sizeof(void *), (const void *)dev_write);
	for (i = 7; i <= 12; i++) fops_put(i * sizeof(void *), (const void *)dev_dispatch);

	memset(&dev, 0, sizeof(dev));
	dev.minor = MISC_DYNAMIC_MINOR;
	dev.name = DEV_NAME;
	dev.fops = (const struct kp_fops *)fops_buf;
	dev.mode = 0600;

	pick_fake_path();

	if (btf_ok) idev_selftest();

	if (k_misc_register && k_misc_deregister) {
		r = k_misc_register(&dev);
		if (r) { pr_info("wanbai: misc_register %d\n", r); r = 0; }
		else dev_ok = 1;
	}

#if STAGE >= 2
	if (k_uts) uts_scrub();
	cmdline_scrub();
#endif

	/* sirf minimal hooks — baaki OP_INIT par */
	hooks_install_min();
	if (hooks_ok && !live_probe()) {
		pr_info("wanbai: probe A fail -> hooks wapas\n");
		hooks_remove();
		hooks_ok = 0;
	}
	if (!inj_dev) learner_install();

	inited = 1;
	pr_info("wanbai: loaded minimal, hooks %u, miss %u, kver %u.%u, dev %d, btf %d, idev %d\n",
		hooks_ok, miss_syms, maj, min, dev_ok, btf_ok, inj_ok);
	return 0;

err:
	hooks_remove();
	learner_remove();
	if (dev_ok && k_misc_deregister) { k_misc_deregister(&dev); dev_ok = 0; }
	uts_restore();
	if (kmem_buf && k_kvfree) { k_kvfree(kmem_buf); kmem_buf = NULL; }
	if (kr_kmsg.hooked) unregister_kretprobe(&kr_kmsg);
	hooks_ok = 0;
	return r;
}

static long nvsvc_stop(void *__user reserved)
{
	(void)reserved;
	if (!inited) return 0;
	inited = 0;
	hooks_off = 0;
	g_name = g_read = g_seq = 0;
	g_dctx = 0; g_dorig = 0;
	if (inj_hidden) idev_hide(0);
	hooks_remove();
	learner_remove();
	hooks_ok = 0;
	if (kptr_saved && kptr_ok(k_kptr_restrict)) { *k_kptr_restrict = saved_kptr; kptr_saved = 0; }
	uts_restore();
	inj_ok = 0; inj_dev = 0; inj_down = 0; inj_mx = 0; inj_my = 0; inj_hidden = 0;
	hide_set_n = 0;
	if (kmem_buf && k_kvfree) { k_kvfree(kmem_buf); kmem_buf = NULL; }
	if (dev_ok && k_misc_deregister) { k_misc_deregister(&dev); dev_ok = 0; }
	return 0;
}

KPM_INIT(nvsvc_start);
KPM_EXIT(nvsvc_stop);
