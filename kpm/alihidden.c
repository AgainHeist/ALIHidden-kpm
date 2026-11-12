// ============================================================
//  ALiHidden — stealth memory KPM / LKM   v12
//  Owner By ALi
//  Target : DarkXKernal (com.dts.freefiremax)
//  Build  : KPM default  [LKM ke liye -DALIHIDDEN_LKM]
//  Strict : default ON — root bhi kuch nahi dekhta
// ============================================================
#ifndef ALIHIDDEN_LKM
#define KPM 1
#endif

#include <compiler.h>
#include <common.h>
#include <kpmodule.h>
#include <kputils.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/fsuid.h>
#include <linux/cred.h>
#include <linux/err.h>
#ifndef KPM
#include <linux/module.h>
#endif
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#ifdef KPM
KPM_NAME("ALiHidden");
KPM_VERSION("12.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("ALi");
KPM_DESCRIPTION("system memory service");
#endif

extern int kptr_restrict;
extern char *saved_command_line;

/* ---------- portable helpers ---------- */
static ssize_t kp_strscpy(char *d, const char *s, size_t c)
{
	size_t i;

	if (!c) return -E2BIG;
	for (i = 0; i + 1 < c && s[i]; i++) d[i] = s[i];
	d[i] = '\0';
	return (ssize_t)i;
}

static void *kp_memmem(const void *h, size_t hl, const void *n, size_t nl)
{
	const char *p = h, *end = p + hl;
	const char *nd = n;

	if (!nl || nl > hl) return NULL;
	while (p + nl <= end) {
		p = memchr(p, nd[0], end - p - nl + 1);
		if (!p) return NULL;
		if (!memcmp(p, nd, nl)) return (void *)p;
		p++;
	}
	return NULL;
}

#define WANT_READDIR     1
#define WANT_MAPS        1
#define WANT_DTARGS      1
#define WANT_TRACER      1
#define WANT_PERMS       1
#define WANT_READLINK    1
#define WANT_STATFS      1
#define WANT_BUILDPROP   1
#define WANT_ATTR        1
#define WANT_ENFORCE     1

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

#define DEV_NAME   "nvsvc"
#define OP_INIT    0x800
#define OP_READ    0x801
#define OP_WRITE   0x802
#define OP_BASE    0x803
#define OP_STRICT  0x804
#define OP_VER     0x805
#define API_VER    11
#define MAX_IO     0x2000000
#define SMALL_IO   512
#define PATH_S     96
#define FAKE_DIR   "/data/misc/.__np"
#define FAKE_FALL  "/data/misc"

#define OVERLAY_MAGIC 0x794c7630U
#define EXT4_MAGIC    0xef53U

struct copy_mem { __s32 pid; __u32 pad; __u64 addr; __u64 buffer; __u64 size; };
struct mod_base { __s32 pid; __u32 pad; __u64 name; __u64 base; };
#ifdef CONFIG_COMPAT
struct copy_mem32 { __s32 pid; __u32 addr; __u32 buffer; __u32 size; };
struct mod_base32 { __s32 pid; __u32 name; __u32 base; };
#endif

static char saved_release[__NEW_UTS_LEN + 1];
static char saved_version[__NEW_UTS_LEN + 1];
static int  saved_kptr;
static bool inited;
static bool strict = true;
static const char *fake_path = FAKE_FALL;

static bool bypass(void)
{
	return current_fsuid().val == 0 && !strict;
}

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
	"/data/local/tmp", "/proc/config.gz", "/sys/module/alihidden",
};
#define HIDDEN_N ARRAY_SIZE(hidden)

static const char *const blk_name[] = {
	"su", "magisk", "Magisk", "ksud", "apd", "adb", "kpatch",
	"nvsvc", ".__np", ".magisk", ".ext", "debug_ramdisk",
	"libnvsvc.so", "init.magisk.rc", "alihidden",
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
	"alihidden", "/data/adb", "/data/local/tmp",
	"com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
};
#define BLK_T ARRAY_SIZE(blk_text)

static bool is_hidden(const char *p)
{
	unsigned int i;
	size_t n;

	if (!p || p[0] != '/') return false;
	for (i = 0; i < HIDDEN_N; i++) {
		n = strlen(hidden[i]);
		if (!strncmp(p, hidden[i], n) && (p[n] == '\0' || p[n] == '/'))
			return true;
	}
	return false;
}

static bool name_blocked(const char *n, int len)
{
	unsigned int i;

	if (len <= 0 || len > 64) return false;
	for (i = 0; i < BLK_N; i++)
		if ((int)strlen(blk_name[i]) == len && !memcmp(n, blk_name[i], len))
			return true;
	for (i = 0; i < BLK_PF; i++) {
		size_t l = strlen(blk_pfx[i]);
		if ((size_t)len > l && !memcmp(n, blk_pfx[i], l))
			return true;
	}
	return false;
}

static bool text_blocked(const char *s, size_t len)
{
	unsigned int i;

	if (!len) return false;
	for (i = 0; i < BLK_T; i++) {
		size_t n = strlen(blk_text[i]);
		if (n > len) continue;
		if (kp_memmem(s, len, blk_text[i], n)) return true;
	}
	return false;
}

static void blank_word(char *b, const char *w)
{
	size_t n = strlen(w);
	char *p = b;

	while ((p = strstr(p, w))) { memset(p, ' ', n); p += n; }
}

/* ---------- uts ---------- */
static void uts_scrub(void)
{
	char *r = init_uts_ns.name.release;
	char *v = init_uts_ns.name.version;
	char *c;

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
	memcpy(init_uts_ns.name.release, saved_release, sizeof(saved_release));
	memcpy(init_uts_ns.name.version, saved_version, sizeof(saved_version));
}

/* ---------- bootloader ---------- */
static void set_bootstate(char *c)
{
	char *p = strstr(c, "verifiedbootstate=");
	char *v;

	if (!p) return;
	v = p + 18;
	if (!strncmp(v, "orange", 6) || !strncmp(v, "yellow", 6)) {
		memcpy(v, "green ", 6);
		return;
	}
	if (!strncmp(v, "red", 3)) {
		size_t tail = strlen(v + 3);
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
		size_t tail = strlen(p + 8);
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
	set_bootstate(c);
	set_locked(c);
	set_vbmeta(c);
	set_verity(c);
	set_selinux(c);
}

static void cmdline_scrub(void)
{
	char *c = saved_command_line;

	if (!c) return;
	scrub_boot_args(c);
}

/* ---------- build.prop ---------- */
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
struct gp_data { char path[PATH_S]; bool hide; };

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

	d->hide = false;
	if (bypass()) return 1;
	if (!u) return 1;
	if (get_user(c, u) || c != '/') return 1;
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

	if (bypass()) return 0;
	fn = (struct filename *)P_ARG1(regs);
	if (!fn || !fn->name) return 0;
	if (is_hidden(fn->name))
		kp_strscpy((char *)fn->name, fake_path, PATH_MAX);
	return 0;
}

/* ---------- readdir ---------- */
#if WANT_READDIR
struct shadow { struct dir_context dc; struct dir_context *orig; };
static DEFINE_PER_CPU(struct shadow, g_sh);

static int filter_actor(struct dir_context *c, const char *name, int namlen,
			loff_t off, u64 ino, unsigned type)
{
	struct shadow *s = container_of(c, struct shadow, dc);

	s->dc.pos = off;
	if (name_blocked(name, namlen)) { s->orig->pos = off; return 0; }
	return s->orig->actor(s->orig, name, namlen, off, ino, type);
}

static int pre_iterate(struct kprobe *p, struct pt_regs *regs)
{
	struct dir_context *ctx = (struct dir_context *)P_ARG1(regs);
	struct shadow *s;

	if (bypass()) return 0;
	if (!ctx || !ctx->actor || ctx->actor == filter_actor) return 0;

	s = this_cpu_ptr(&g_sh);
	s->orig = ctx;
	memcpy(&s->dc, ctx, sizeof(*ctx));
	s->dc.actor = filter_actor;
	P_ARG1(regs) = (unsigned long)&s->dc;
	return 0;
}

static void post_iterate(struct kprobe *p, struct pt_regs *regs, unsigned long fl)
{
	struct dir_context *ctx = (struct dir_context *)P_ARG1(regs);
	struct shadow *s = this_cpu_ptr(&g_sh);

	if (!ctx || ctx != s->orig) return;
	ctx->pos = s->dc.pos;
	s->orig = NULL;
}

static struct kprobe kp_iter;
#endif

/* ---------- read scrub ---------- */
static DEFINE_PER_CPU(int, g_pread);
static struct kprobe kp_pread, kp_bprop;

static void pre_read(struct kprobe *p, struct pt_regs *regs)
{
	struct file *f = (struct file *)P_ARG0(regs);
	const char *n;

	this_cpu_write(g_pread, 0);
	if (bypass()) return;
	if (!f || !f->f_path.dentry) return;
	n = f->f_path.dentry->d_name.name;
	if (!n) return;

	if (!strncmp(n, "bootargs", 8)) { this_cpu_write(g_pread, 1); return; }
	if (!strcmp(n, "build.prop")) { this_cpu_write(g_pread, 2); return; }
	if (!strcmp(n, "current")) {
		const char *pn = f->f_path.dentry->d_parent ?
			f->f_path.dentry->d_parent->d_name.name : NULL;
		if (pn && !strcmp(pn, "attr")) this_cpu_write(g_pread, 3);
		return;
	}
	if (!strcmp(n, "enforce")) this_cpu_write(g_pread, 4);
}

static void post_read(struct kprobe *p, struct pt_regs *regs, unsigned long fl)
{
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	int mode = this_cpu_read(g_pread);
	char buf[1024];
	size_t n;

	if (!mode || ret <= 0) return;
	n = ret > (long)sizeof(buf) - 1 ? sizeof(buf) - 1 : (size_t)ret;
	if (copy_from_user(buf, ub, n)) return;
	buf[n] = '\0';

	switch (mode) {
	case 1: scrub_boot_args(buf); break;
	case 2: scrub_buildprop(buf); break;
	case 3: scrub_ctx(buf); break;
	case 4: if (buf[0] == '0') buf[0] = '1'; break;
	default: return;
	}
	copy_to_user(ub, buf, n);
}

/* ---------- statfs ---------- */
#if WANT_STATFS
static struct kprobe kp_statfs;

static void post_statfs(struct kprobe *p, struct pt_regs *regs, unsigned long fl)
{
	struct kstatfs *st = (struct kstatfs *)P_ARG1(regs);

	if (bypass() || !st) return;
	if (st->f_type == OVERLAY_MAGIC) st->f_type = EXT4_MAGIC;
}
#endif

/* ---------- readlink ---------- */
#if WANT_READLINK
static DEFINE_PER_CPU(int, g_rl);
static struct kprobe kp_rl;

static int pre_rl(struct kprobe *p, struct pt_regs *regs)
{
	this_cpu_write(g_rl, bypass() ? 0 : 1);
	return 0;
}

static void post_rl(struct kprobe *p, struct pt_regs *regs, unsigned long fl)
{
	static const char repl[] = "/dev/ashmem";
	char __user *ub = (char __user *)P_ARG1(regs);
	long ret = (long)regs_return_value(regs);
	char buf[64];
	size_t n;

	if (!this_cpu_read(g_rl) || ret <= 0) return;
	n = ret > (long)sizeof(buf) - 1 ? sizeof(buf) - 1 : (size_t)ret;
	if (copy_from_user(buf, ub, n)) return;
	buf[n] = '\0';
	if (!strstr(buf, DEV_NAME)) return;
	if (copy_to_user(ub, repl, sizeof(repl) - 1)) return;
	P_RET(regs) = (unsigned long)(sizeof(repl) - 1);
}
#endif

/* ---------- seq compaction ---------- */
struct tr_data { struct seq_file *m; size_t saved; bool maps; };

static struct kretprobe kr_mounts, kr_mountinfo, kr_modules, kr_misc;
static struct kretprobe kr_fs, kr_vm, kr_status;
#if WANT_MAPS
static struct kretprobe kr_smaps, kr_maps, kr_roll;
#endif

static int tr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct seq_file *m = (struct seq_file *)P_ARG0(regs);

	d->m = m;
	d->saved = 0;
	d->maps = false;
	if (bypass()) return 0;
	if (!m || !m->buf || m->size < m->count || m->size > 0x100000) return 0;
	d->saved = m->count;
	return 0;
}

static int tr_entry_maps(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	tr_entry(ri, regs);
	((struct tr_data *)ri->data)->maps = true;
	return 0;
}

#if WANT_TRACER
static void zero_tracer(char *buf, size_t start, size_t end)
{
	char *p = kp_memmem(buf + start, end - start, "TracerPid:", 10);

	if (!p) return;
	p += 10;
	while (p < buf + end && (*p == '\t' || *p == ' ')) p++;
	if (p >= buf + end || *p < '0' || *p > '9') return;
	*p++ = '0';
	while (p < buf + end && *p >= '0' && *p <= '9') *p++ = ' ';
}
#endif

#if WANT_PERMS
static void defang_perms(char *buf, size_t start, size_t end)
{
	size_t i = start;

	while (i < end) {
		char *nl = memchr(buf + i, '\n', end - i);
		size_t ll = nl ? (size_t)(nl - (buf + i)) + 1 : end - i;
		char *sp = memchr(buf + i, ' ', ll);

		if (sp && (size_t)(sp - buf) + 4 < i + ll &&
		    sp[1] == 'r' && sp[2] == 'w' && sp[3] == 'x')
			sp[2] = '-';
		i += ll;
	}
}
#endif

static int tr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tr_data *d = (struct tr_data *)ri->data;
	struct seq_file *m = d->m;
	size_t i, o, end;

	if (!d->saved || !m || m->count <= d->saved) return 0;

#if WANT_TRACER
	zero_tracer(m->buf, d->saved, m->count);
#endif
#if WANT_PERMS
	if (d->maps) defang_perms(m->buf, d->saved, m->count);
#endif

	i = d->saved;
	end = m->count;
	o = d->saved;

	while (i < end) {
		char *nl = memchr(m->buf + i, '\n', end - i);
		size_t ll = nl ? (size_t)(nl - (m->buf + i)) + 1 : end - i;

		if (text_blocked(m->buf + i, ll)) { i += ll; continue; }
		if (o != i) memmove(m->buf + o, m->buf + i, ll);
		o += ll;
		i += ll;
	}
	m->count = o;
	return 0;
}

static void hook_kp(struct kprobe *kp, const char *sym,
		    kprobe_pre_handler_t pre, kprobe_post_handler_t post)
{
	kp->symbol_name = sym;
	kp->pre_handler = pre;
	kp->post_handler = post;
	if (register_kprobe(kp)) memset(kp, 0, sizeof(*kp));
}

static void hook_tr(struct kretprobe *kr, const char *sym, bool maps)
{
	kr->kp.symbol_name = sym;
	kr->entry_handler = maps ? tr_entry_maps : tr_entry;
	kr->handler = tr_ret;
	kr->data_size = sizeof(struct tr_data);
	kr->maxactive = 64;
	if (register_kretprobe(kr)) memset(kr, 0, sizeof(*kr));
}

static void hooks_install(void)
{
	kr_name.entry_handler = name_entry;
	kr_name.handler = name_ret;
	if (register_kretprobe(&kr_name)) {
		memset(&kr_name, 0, sizeof(kr_name));
		hook_kp(&kp_path, "filename_lookup", pre_path, NULL);
	}
#if WANT_READDIR
	hook_kp(&kp_iter, "iterate_dir", pre_iterate, post_iterate);
#endif
	hook_kp(&kp_pread, "proc_reg_read", pre_read, post_read);
	hook_kp(&kp_bprop, "vfs_read", pre_read, post_read);
#if WANT_STATFS
	hook_kp(&kp_statfs, "vfs_statfs", NULL, post_statfs);
#endif
#if WANT_READLINK
	hook_kp(&kp_rl, "vfs_readlink", pre_rl, post_rl);
#endif

	hook_tr(&kr_mounts, "show_vfsmnt", false);
	hook_tr(&kr_mountinfo, "show_mountinfo", false);
	hook_tr(&kr_modules, "m_show", false);
	hook_tr(&kr_misc, "misc_show", false);
	hook_tr(&kr_fs, "filesystems_proc_show", false);
	hook_tr(&kr_vm, "s_show", false);
	hook_tr(&kr_status, "proc_pid_status", false);
#if WANT_MAPS
	hook_tr(&kr_maps, "show_map_vma", true);
	hook_tr(&kr_smaps, "show_smap", true);
	hook_tr(&kr_roll, "smaps_rollup_show", true);
#endif
}

static void hooks_remove(void)
{
	if (kr_name.handler) unregister_kretprobe(&kr_name);
	if (kp_path.pre_handler) unregister_kprobe(&kp_path);
#if WANT_READDIR
	if (kp_iter.pre_handler) unregister_kprobe(&kp_iter);
#endif
	if (kp_pread.pre_handler) unregister_kprobe(&kp_pread);
	if (kp_bprop.pre_handler) unregister_kprobe(&kp_bprop);
#if WANT_STATFS
	if (kp_statfs.post_handler) unregister_kprobe(&kp_statfs);
#endif
#if WANT_READLINK
	if (kp_rl.pre_handler) unregister_kprobe(&kp_rl);
#endif
	if (kr_mounts.handler) unregister_kretprobe(&kr_mounts);
	if (kr_mountinfo.handler) unregister_kretprobe(&kr_mountinfo);
	if (kr_modules.handler) unregister_kretprobe(&kr_modules);
	if (kr_misc.handler) unregister_kretprobe(&kr_misc);
	if (kr_fs.handler) unregister_kretprobe(&kr_fs);
	if (kr_vm.handler) unregister_kretprobe(&kr_vm);
	if (kr_status.handler) unregister_kretprobe(&kr_status);
#if WANT_MAPS
	if (kr_maps.handler) unregister_kretprobe(&kr_maps);
	if (kr_smaps.handler) unregister_kretprobe(&kr_smaps);
	if (kr_roll.handler) unregister_kretprobe(&kr_roll);
#endif
}

static void pick_fake_path(void)
{
	struct path p;

	if (!kern_path(FAKE_DIR, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &p)) {
		path_put(&p);
		fake_path = FAKE_DIR;
		return;
	}
	pr_info("ALiHidden: %s missing, falling back to %s\n", FAKE_DIR, FAKE_FALL);
}

/* ---------- ioctl ---------- */
static struct task_struct *task_get(pid_t pid)
{
	struct task_struct *t;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (t) get_task_struct(t);
	rcu_read_unlock();
	return t;
}

static void wb_size(unsigned long arg, bool c32, __u64 sz)
{
#ifdef CONFIG_COMPAT
	if (c32) {
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return;
		x.size = (__u32)sz;
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
	int ret;
	bool c32 = false;

#ifdef CONFIG_COMPAT
	c32 = in_compat_syscall();
#endif
	memset(&cm, 0, sizeof(cm));

	if (cmd == OP_INIT) return 0;

	if (cmd == OP_VER) {
		int v = API_VER;
		return copy_to_user((void __user *)arg, &v, sizeof(v)) ? -EFAULT : 0;
	}

	if (cmd == OP_STRICT) {
		int v;
		if (copy_from_user(&v, (void __user *)arg, sizeof(v))) return -EFAULT;
		strict = !!v;
		return 0;
	}

	if (c32) {
#ifdef CONFIG_COMPAT
		struct copy_mem32 x;
		if (copy_from_user(&x, (void __user *)arg, sizeof(x))) return -EFAULT;
		cm.pid = x.pid; cm.addr = x.addr;
		cm.buffer = x.buffer; cm.size = x.size;
#endif
	} else if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) {
		return -EFAULT;
	}

	if (cmd == OP_BASE) {
		struct mod_base mb;
		struct mm_struct *mm;
		struct vm_area_struct *vma;
		char pname[256];
		__u64 found = 0;

		memset(&mb, 0, sizeof(mb));
		if (c32) {
#ifdef CONFIG_COMPAT
			struct mod_base32 y;
			if (copy_from_user(&y, (void __user *)arg, sizeof(y)))
				return -EFAULT;
			mb.pid = y.pid; mb.name = y.name;
#endif
		} else if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) {
			return -EFAULT;
		}
		if (!mb.pid || !mb.name) return -EINVAL;
		if (strncpy_from_user(pname, (const char __user *)(uintptr_t)mb.name,
				      sizeof(pname) - 1) < 0)
			return -EFAULT;
		pname[sizeof(pname) - 1] = '\0';
		if (!pname[0]) return -EINVAL;

		tsk = task_get((pid_t)mb.pid);
		if (!tsk) return -ESRCH;
		mm = get_task_mm(tsk);
		put_task_struct(tsk);
		if (!mm) return -ESRCH;

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			const char *dn;
			if (!vma->vm_file || !vma->vm_file->f_path.dentry) continue;
			dn = vma->vm_file->f_path.dentry->d_name.name;
			if (dn && strstr(dn, pname)) { found = vma->vm_start; break; }
		}
		mmput(mm);

		mb.base = found;
		if (c32) {
#ifdef CONFIG_COMPAT
			struct mod_base32 y = {
				.pid = (__s32)mb.pid,
				.name = (__u32)mb.name,
				.base = (__u32)found,
			};
			copy_to_user((void __user *)arg, &y, sizeof(y));
#endif
		} else {
			copy_to_user((void __user *)arg, &mb, sizeof(mb));
		}
		return 0;
	}

	if (!cm.pid || !cm.size || cm.size > MAX_IO || !cm.addr || !cm.buffer)
		return -EINVAL;

	tsk = task_get((pid_t)cm.pid);
	if (!tsk) return -ESRCH;

	kbuf = cm.size <= SMALL_IO ? (void *)small : kvmalloc(cm.size, GFP_KERNEL);
	if (!kbuf) { put_task_struct(tsk); return -ENOMEM; }

	if (cmd == OP_READ) {
		ret = access_process_vm(tsk, cm.addr, kbuf, (int)cm.size, 0);
		if (ret > 0 && copy_to_user((void __user *)(uintptr_t)cm.buffer, kbuf, ret))
			ret = -EFAULT;
	} else if (cmd == OP_WRITE) {
		if (copy_from_user(kbuf, (void __user *)(uintptr_t)cm.buffer, cm.size)) {
			ret = -EFAULT;
		} else {
			ret = access_process_vm(tsk, cm.addr, kbuf, (int)cm.size,
						FOLL_WRITE | FOLL_FORCE);
		}
	} else {
		ret = -EINVAL;
	}

	if (kbuf != (void *)small) kvfree(kbuf);
	put_task_struct(tsk);

	if (ret > 0) { wb_size(arg, c32, ret); return 0; }
	return ret < 0 ? ret : -EIO;
}

static const struct file_operations dev_fops = {
#ifdef KPM
	.owner          = NULL,
#else
	.owner          = THIS_MODULE,
#endif
	.unlocked_ioctl = dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = dev_ioctl,
#endif
	.llseek         = no_llseek,
};

static struct miscdevice dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = DEV_NAME,
	.fops  = &dev_fops,
	.mode  = 0666,
};

static long alihidden_start(const char *args, const char *event, void *__user reserved)
{
	int r;

	pick_fake_path();
	r = misc_register(&dev);
	if (r) return r;

	uts_scrub();
	cmdline_scrub();
	saved_kptr = kptr_restrict;
	kptr_restrict = 2;
	hooks_install();
	inited = true;
	return 0;
}

static long alihidden_stop(void *__user reserved)
{
	if (!inited) return 0;
	hooks_remove();
	kptr_restrict = saved_kptr;
	uts_restore();
	misc_deregister(&dev);
	inited = false;
	return 0;
}

#ifdef KPM
KPM_INIT(alihidden_start);
KPM_EXIT(alihidden_stop);
#else
static int __init alihidden_init(void) { return (int)alihidden_start(NULL, NULL, NULL); }
static void __exit alihidden_exit(void) { alihidden_stop(NULL); }
module_init(alihidden_init);
module_exit(alihidden_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ALi");
MODULE_DESCRIPTION("system memory service");
#endif
