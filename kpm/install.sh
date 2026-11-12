
#!/system/bin/sh
mkdir -p /data/misc/.__np
chown root:root /data/misc/.__np
chmod 0700 /data/misc/.__np
mknod /dev/nvsvc c 10 $(awk '/nvsvc/{print $1}' /proc/misc)
chmod 0666 /dev/nvsvc
