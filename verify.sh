#!/system/bin/sh
# ============================================================
#  Owner By ali — KPM self test
#  hidden checks uid 2000 se chalte hain (root bypass hota hai)
# ============================================================

P=0; F=0
USE2000=0

if su 2000 -c true >/dev/null 2>&1; then
  USE2000=1
else
  echo "!! su 2000 fail — hidden checks root se chalenge, FAIL aayenge"
fi

run() {
  if [ "$USE2000" = "1" ]; then su 2000 -c "$1" 2>&1; else eval "$1" 2>&1; fi
}

ck() {
  r=$(run "$2")
  if [ "$r" = "$3" ]; then P=$((P+1)); echo "PASS  $1"
  else F=$((F+1)); echo "FAIL  $1  (got '$r' want '$3')"; fi
}

ckr() {
  r=$(eval "$2" 2>&1)
  if [ "$r" = "$3" ]; then P=$((P+1)); echo "PASS  $1"
  else F=$((F+1)); echo "FAIL  $1  (got '$r' want '$3')"; fi
}

echo "---- node ----"
ckr "dev node exists"  "[ -c /dev/wanbai ] && echo 0 || echo 1"            "0"
ckr "dev listed once"  "ls /dev | grep -c '^wanbai\$'"                     "1"
ck  "dev hidden(game)" "ls /dev | grep -c '^wanbai\$'"                     "0"
ck  "no wanbai misc"   "grep -c wanbai /proc/misc"                         "0"

echo "---- binaries ----"
ck  "su hidden"        "ls /system/bin | grep -c '^su\$'"                  "0"
ck  "magisk hidden"    "ls /system/bin | grep -c '^magisk\$'"              "0"
ck  "kp hidden"        "ls /system/bin | grep -c '^kp\$'"                  "0"
ck  "ksud hidden"      "ls /system/bin | grep -c '^ksud\$'"                "0"
ck  "apd hidden"       "ls /system/bin | grep -c '^apd\$'"                 "0"
ck  "adb dir hidden"   "ls /data | grep -c '^adb\$'"                       "0"
ck  "tmp hidden"       "ls /data/local 2>/dev/null | grep -c '^tmp\$'"     "0"
ck  "tmp openable"     "ls /data/local/tmp >/dev/null 2>&1; echo \$?"      "0"
ck  "kpatch moddir"    "ls /sys/module | grep -c '^kpatch\$'"              "0"
ck  "zygisk hidden"    "ls /data/adb/modules 2>/dev/null | grep -c zygisk" "0"
ck  "config.gz hidden" "ls /proc/config.gz 2>&1 | grep -c 'No such'"       "1"

echo "---- boot state ----"
ck  "bootstate"        "grep -o 'verifiedbootstate=[a-z]*' /proc/cmdline"  "verifiedbootstate=green"
ck  "flash locked"     "grep -o 'flash.locked=[01]' /proc/cmdline"         "flash.locked=1"
ck  "vbmeta locked"    "grep -o 'vbmeta.device_state=[a-z]*' /proc/cmdline" "vbmeta.device_state=locked"
ck  "verity enforcing" "grep -o 'veritymode=[a-z]*' /proc/cmdline"         "veritymode=enforcing"

echo "---- fs / proc ----"
ck  "no overlay mount" "grep -c overlay /proc/mounts"                      "0"
ck  "no overlay fs"    "grep -c overlay /proc/filesystems"                 "0"
ck  "statfs ext4"      "stat -f -c %t /system"                             "ef53"
ck  "tracerpid"        "grep -o 'TracerPid:[[:space:]]*[0-9]*' /proc/self/status | tr -d ' \t'" "TracerPid:0"
ck  "no rwxp"          "grep -c rwxp /proc/self/maps"                      "0"
ck  "ctx clean"        "cat /proc/self/attr/current | grep -c -E 'magisk|ksu'" "0"
ck  "enforce 1"        "cat /sys/fs/selinux/enforce"                       "1"

echo "---- props (rom dependent) ----"
ck  "debuggable"       "getprop ro.debuggable"                             "0"
ck  "tags"             "getprop ro.build.tags"                             "release-keys"

echo "---- module state ----"
ckr "kpatch token"     "grep -c kpatch /proc/version"                      "1"
ckr "owner tag"        "dmesg | grep -c 'wanbai: Owner By ali'"            "1"
ckr "mgr uid"          "dmesg | grep -c 'wanbai: mgr uid'"                 "1"
ckr "game uid"         "dmesg | grep -c 'wanbai: game uid'"                "1"
ckr "hooks live"       "dmesg | grep -c 'wanbai: loaded'"                  "1"

echo "---- $P pass / $F fail ----"
[ $F -eq 0 ] && echo "ALL GREEN" || echo "KUCH TOOTA HAI"
