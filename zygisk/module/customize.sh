
#!/system/bin/sh
[ "$ARCH" = "arm64" ] || abort "! arm64 only"
mkdir -p "$MODPATH/zygisk"
mv "$MODPATH/libaliprop.so" "$MODPATH/zygisk/arm64-v8a.so"
