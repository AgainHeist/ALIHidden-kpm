#!/system/bin/sh
D=/data/misc/.__np
echo "kernel: $(uname -r)"
mkdir -p "$D" 2>/dev/null
chown root:root "$D" 2>/dev/null
chmod 0700 "$D" 2>/dev/null
if [ -c /dev/nvsvc ]; then echo "nvsvc: node OK"; else echo "nvsvc: NODE MISSING -> dmesg"; fi
echo "visible in /dev: $(ls /dev | grep -c '^nvsvc$') (0 = hidden)"
echo "visible in /sys/class/misc: $(ls /sys/class/misc 2>/dev/null | grep -c '^nvsvc$') (0 = hidden)"
