#!/system/bin/sh
D=/data/misc/.__np
echo "kernel: $(uname -r)"
echo "kp: $(dmesg | grep -o 'Kernel Patch Version: [0-9a-f]*' | tail -1)"

mkdir -p "$D" 2>/dev/null
chown root:root "$D" 2>/dev/null
chmod 0700 "$D" 2>/dev/null

if [ -c /dev/nvsvc ]; then echo "nvsvc: device node OK"; else echo "nvsvc: NODE MISSING -> dmesg dekho"; fi
echo "nvsvc: visible in /dev = $(ls /dev | grep -c '^nvsvc$') (0 = hidden, sahi hai)"
echo "nvsvc: fake dir = $D"
