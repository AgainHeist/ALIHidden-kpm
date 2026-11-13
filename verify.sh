#!/system/bin/sh
P=0; F=0
ck() {
  r=$(eval "$2" 2>&1)
  if [ "$r" = "$3" ]; then P=$((P+1)); echo "PASS  $1"
  else F=$((F+1)); echo "FAIL  $1  (got '$r' want '$3')"; fi
}

ck "su hidden"         "ls /system/bin | grep -c '^su$'"                   "0"
ck "magisk hidden"     "ls /system/bin | grep -c '^magisk$'"               "0"
ck "adb hidden"        "ls /data | grep -c '^adb$'"                        "0"
ck "tmp hidden"        "ls -d /data/local/tmp 2>/dev/null | wc -l"         "0"
ck "nvsvc /dev"        "ls /dev | grep -c '^nvsvc$'"                       "0"
ck "dev openable"      "ls -l /dev/nvsvc >/dev/null 2>&1; echo \$?"        "0"
ck "bootstate"         "grep -o 'verifiedbootstate=[a-z]*' /proc/cmdline"  "verifiedbootstate=green"
ck "flash locked"      "grep -o 'flash.locked=[01]' /proc/cmdline"         "flash.locked=1"
ck "vbmeta locked"     "grep -o 'vbmeta.device_state=[a-z]*' /proc/cmdline" "vbmeta.device_state=locked"
ck "no overlay"        "grep -c overlay /proc/mounts"                      "0"
ck "no overlay fs"     "grep -c overlay /proc/filesystems"                 "0"
ck "no nvsvc misc"     "grep -c nvsvc /proc/misc"                          "0"
ck "tracerpid"         "grep -o 'TracerPid:[[:space:]]*[0-9]*' /proc/self/status | tr -d ' \t'" "TracerPid:0"
ck "no rwxp"           "grep -c rwxp /proc/self/maps"                      "0"
ck "statfs ext4"       "stat -f -c %t /system"                             "ef53"
ck "enforce 1"         "cat /sys/fs/selinux/enforce"                       "1"
ck "ctx clean"         "cat /proc/self/attr/current | grep -c -E 'magisk|ksu'" "0"
ck "debuggable"        "getprop ro.debuggable"                             "0"
ck "tags"              "getprop ro.build.tags"                             "release-keys"
ck "config.gz hidden"  "ls /proc/config.gz 2>&1 | grep -c 'No such'"       "1"
ck "magisk pkg gone"   "pm list packages 2>/dev/null | grep -c topjohnwu"  "1"
ck "kpatch token"      "grep -c kpatch /proc/version"                      "1"
ck "owner tag"         "dmesg | grep -c 'nvsvc: Owner By ali'"             "1"
ck "hooks live"        "dmesg | grep -c 'nvsvc: loaded'"                   "1"

echo "---- $P pass / $F fail ----"
[ $F -eq 0 ] && echo "ALL GREEN" || echo "KUCH TOOTA HAI"
