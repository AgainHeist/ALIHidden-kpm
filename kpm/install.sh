#!/system/bin/sh
# mknod ki zaroorat nahi - devtmpfs khud /dev/nvsvc bana deta hai
mkdir -p /data/misc/.__np
chown root:root /data/misc/.__np
chmod 0700 /data/misc/.__np
