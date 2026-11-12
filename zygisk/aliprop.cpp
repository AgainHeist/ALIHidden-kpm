
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <android/log.h>
#include "zygisk.hpp"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "ALiProp", __VA_ARGS__)
#define KACC_NATIVE 0x0100u

using zygisk::Api;
using zygisk::AppSpecializeArgs;

/* ---------------- properties ---------------- */
struct Fake { const char *k, *v; };
static const Fake fakes[] = {
	{"ro.boot.verifiedbootstate", "green"},
	{"ro.boot.flash.locked", "1"},
	{"ro.boot.vbmeta.device_state", "locked"},
	{"ro.boot.veritymode", "enforcing"},
	{"ro.boot.selinux", "enforcing"},
	{"ro.debuggable", "0"},
	{"ro.secure", "1"},
	{"ro.build.tags", "release-keys"},
	{"ro.build.type", "user"},
	{"ro.kernel.qemu", "0"},
	{"ro.boot.qemu", "0"},
};
#define NFAKE (sizeof(fakes) / sizeof(fakes[0]))

static const char *lookup(const char *name)
{
	if (!name) return nullptr;
	for (size_t i = 0; i < NFAKE; i++)
		if (!strcmp(name, fakes[i].k)) return fakes[i].v;
	return nullptr;
}

static int (*orig_get)(const char *, char *);
typedef void (*prop_cb)(void *, const char *, const char *, uint32_t);
static void (*orig_cb)(const void *, prop_cb, void *);

static int my_get(const char *name, char *value)
{
	const char *v = lookup(name);

	if (v) {
		if (value) strcpy(value, v);
		return (int)strlen(v);
	}
	return orig_get ? orig_get(name, value) : 0;
}

static void my_cb(const void *pi, prop_cb cb, void *cookie)
{
	char name[32];

	memcpy(name, pi, sizeof(name));
	name[sizeof(name) - 1] = '\0';

	const char *v = lookup(name);
	if (v) { cb(cookie, name, v, 0); return; }
	if (orig_cb) orig_cb(pi, cb, cookie);
}

/* ---------------- packages ---------------- */
static const char *bad_pkgs[] = {
	"com.topjohnwu.magisk",
	"me.weishu.kernelsu",
	"me.bmax.apatch",
	"com.dergoogler.mmrl",
	"io.github.vvb2060.mahoshojo",
};
#define NBAD (sizeof(bad_pkgs) / sizeof(bad_pkgs[0]))

static bool is_bad(const char *n)
{
	if (!n) return false;
	for (size_t i = 0; i < NBAD; i++)
		if (!strcmp(n, bad_pkgs[i])) return true;
	return false;
}

static void throw_nf(JNIEnv *env)
{
	jclass c = env->FindClass("android/content/pm/PackageManager$NameNotFoundException");
	if (c) env->ThrowNew(c, "hidden");
}

/* ---------------- art entry discovery ---------------- */
struct Range { uintptr_t lo, hi; };
static Range art_exec[16];
static int art_n;

static void load_art_ranges()
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	art_n = 0;

	if (!f) return;
	while (fgets(line, sizeof(line), f) && art_n < 16) {
		if (!strstr(line, "libart.so")) continue;
		uintptr_t lo, hi;
		if (sscanf(line, "%lx-%lx %*s", &lo, &hi) != 2) continue;
		art_exec[art_n].lo = lo;
		art_exec[art_n].hi = hi;
		art_n++;
	}
	fclose(f);
}

static bool in_art(uintptr_t v)
{
	for (int i = 0; i < art_n; i++)
		if (v >= art_exec[i].lo && v < art_exec[i].hi) return true;
	return false;
}

static void **find_slot(void *m)
{
	for (int off = 8; off <= 40; off += 4) {
		uintptr_t v = *(uintptr_t *)((char *)m + off);
		if (v && in_art(v)) return (void **)((char *)m + off);
	}
	return nullptr;
}

struct Hooked {
	jmethodID mid = nullptr;
	void **slot = nullptr;
	void *orig = nullptr;
	uint32_t *flags = nullptr;
};

static Hooked h_gpi, h_gai;

static void install(JNIEnv *env, jclass c, const char *name, const char *sig,
		    void *fn, Hooked *h)
{
	if (h->mid) return;
	h->mid = env->GetMethodID(c, name, sig);
	if (!h->mid) { env->ExceptionClear(); return; }
	h->slot = find_slot(h->mid);
	if (!h->slot) { h->mid = nullptr; return; }
	h->flags = (uint32_t *)((char *)h->mid + 4);
	h->orig = *h->slot;
	*h->flags |= KACC_NATIVE;
	*h->slot = fn;
}

static bool enter(Hooked *h)
{
	*h->flags &= ~KACC_NATIVE;
	*h->slot = h->orig;
	return true;
}

static void leave(Hooked *h, void *fn)
{
	*h->flags |= KACC_NATIVE;
	*h->slot = fn;
}

static jobject hk_gpi(JNIEnv *env, jobject thiz, jstring jname, jint flags)
{
	if (!jname) return env->CallObjectMethod(thiz, h_gpi.mid, jname, flags);
	const char *n = env->GetStringUTFChars(jname, nullptr);
	bool bad = is_bad(n);
	env->ReleaseStringUTFChars(jname, n);
	if (bad) { throw_nf(env); return nullptr; }

	enter(&h_gpi);
	jobject r = env->CallObjectMethod(thiz, h_gpi.mid, jname, flags);
	leave(&h_gpi, (void *)hk_gpi);
	return r;
}

static jobject hk_gai(JNIEnv *env, jobject thiz, jstring jname, jint flags)
{
	if (!jname) return env->CallObjectMethod(thiz, h_gai.mid, jname, flags);
	const char *n = env->GetStringUTFChars(jname, nullptr);
	bool bad = is_bad(n);
	env->ReleaseStringUTFChars(jname, n);
	if (bad) { throw_nf(env); return nullptr; }

	enter(&h_gai);
	jobject r = env->CallObjectMethod(thiz, h_gai.mid, jname, flags);
	leave(&h_gai, (void *)hk_gai);
	return r;
}

/* ---------------- lib discovery ---------------- */
static const char *libs[] = { "libil2cpp.so", "libunity.so", "libmain.so" };

static bool find_lib(const char *want, dev_t *dev, ino_t *ino)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	bool ok = false;

	if (!f) return false;
	while (fgets(line, sizeof(line), f)) {
		unsigned maj, min;
		unsigned long long i;
		if (!strstr(line, want)) continue;
		if (sscanf(line, "%*s %*s %*s %x:%x %llu", &maj, &min, &i) == 3) {
			*dev = makedev(maj, min);
			*ino = (ino_t)i;
			ok = true;
			break;
		}
	}
	fclose(f);
	return ok;
}

/* ---------------- module ---------------- */
class ALiProp : public zygisk::ModuleBase {
public:
	void onLoad(Api *api, JNIEnv *) override { this->api = api; }

	void postAppSpecialize(const AppSpecializeArgs *args) override
	{
		const char *n = args->nice_name ? *args->nice_name : nullptr;
		if (!n) return;
		if (!strstr(n, "freefire") && !strstr(n, "com.dts")) return;

		pthread_t t;
		if (pthread_create(&t, nullptr, thread, this) == 0)
			pthread_detach(t);
	}

private:
	Api *api = nullptr;

	static void *thread(void *arg)
	{
		auto *self = static_cast<ALiProp *>(arg);
		JNIEnv *env = nullptr;

		self->api->getEnv(&env);
		load_art_ranges();

		for (int i = 0; i < 4000; i++) {
			/* packages */
			if (!h_gpi.mid) {
				jclass at = env->FindClass("android/app/ActivityThread");
				if (at) {
					jmethodID cur = env->GetStaticMethodID(at, "currentApplication",
						"()Landroid/app/Application;");
					if (cur) {
						jobject app = env->CallStaticObjectMethod(at, cur);
						if (app) {
							jmethodID gpm = env->GetMethodID(
								env->GetObjectClass(app),
								"getPackageManager",
								"()Landroid/content/pm/PackageManager;");
							if (gpm) {
								jobject pm = env->CallObjectMethod(app, gpm);
								if (pm) {
									jclass pc = env->GetObjectClass(pm);
									install(env, pc, "getPackageInfo",
										"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
										(void *)hk_gpi, &h_gpi);
									install(env, pc, "getApplicationInfo",
										"(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",
										(void *)hk_gai, &h_gai);
									env->DeleteLocalRef(pm);
								}
							}
							env->DeleteLocalRef(app);
						}
					}
					env->ExceptionClear();
				}
			}

			/* libs */
			bool any = false;
			for (const char *lib : libs) {
				dev_t d;
				ino_t i2;
				if (!find_lib(lib, &d, &i2)) continue;
				self->api->pltHookRegister(d, i2, "__system_property_get",
					(void *)my_get, (void **)&orig_get);
				self->api->pltHookRegister(d, i2,
					"__system_property_read_callback",
					(void *)my_cb, (void **)&orig_cb);
				any = true;
			}
			if (any) self->api->pltHookCommit();

			if (any && h_gpi.mid) { LOGD("ready"); return nullptr; }
			usleep(5000);
		}
		LOGD("partial: lib=%d pkg=%d", orig_get != nullptr, h_gpi.mid != nullptr);
		return nullptr;
	}
};

REGISTER_ZYGISK_MODULE(ALiProp)
