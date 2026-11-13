#!/system/bin/sh
# DarkXKernel KPM post-load setup. KPM load ke BAAD chalao.
D=/data/misc/.__np

mkdir -p "$D" 2>/dev/null
chown root:root "$D" 2>/dev/null
chmod 0700 "$D" 2>/dev/null

if [ -c /dev/nvsvc ]; then
    echo "nvsvc: device node OK"
else
    echo "nvsvc: NODE MISSING -> kpm load fail hua hai, dmesg dekho"
fi

n=$(ls /dev | grep -c '^nvsvc$')
echo "nvsvc: visible in /dev = $n (0 = hidden, sahi hai)"
echo "nvsvc: fake dir = $D"
