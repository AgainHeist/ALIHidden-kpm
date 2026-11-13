#!/system/bin/sh
D=/data/misc/.__np
echo "kernel: $(uname -r)"
mkdir -p "$D" 2>/dev/null
mkdir -p "$D/ap" "$D/ksu" "$D/modules" 2>/dev/null
chown -R root:root "$D" 2>/dev/null
chmod 0700 "$D" 2>/dev/null
if [ -c /dev/wanbai ]; then
  chmod 0600 /dev/wanbai 2>/dev/null
  echo "wanbai: node OK"
else
  echo "wanbai: NODE MISSING -> dmesg"
fi
echo "kpatch token: $(grep -c kpatch /proc/version) (1 = APatch Full mode)"
echo "mgr uid: $(dmesg | grep -o 'wanbai: mgr uid [0-9]*' | tail -1)"
echo "game uid: $(dmesg | grep -o 'wanbai: game uid [0-9]*' | tail -1)"
