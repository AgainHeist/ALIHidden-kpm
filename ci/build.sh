#!/bin/bash
set -e
STAGE="${STAGE:-5}"
BTI="${BTI:-0}"
OUT="dist"
mkdir -p "$OUT"

# pehle pinned refs, phir main fallback — ABI mismatch se bachne ke liye
try_build() {
    local ref="$1"
    rm -rf kp
    if [ "$ref" = "main" ]; then
        git clone --depth=1 https://github.com/bmax121/KernelPatch.git kp 2>/dev/null || return 1
    else
        git clone --depth=1 --branch "$ref" https://github.com/bmax121/KernelPatch.git kp 2>/dev/null || return 1
    fi
    test -f kp/kernel/include/kpmodule.h || return 1
    echo ">> KP ref: $ref  commit: $(git -C kp rev-parse --short HEAD)"
    make -C kpm clean >/dev/null 2>&1 || true
    make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu- STAGE="$STAGE" BTI="$BTI"
}

ok=0
for ref in ${KP_REF:-0.13.1} 0.12.3 0.12.0 0.11.3 main; do
    if try_build "$ref"; then ok=1; break; fi
    echo "!! ref $ref fail"
done
[ "$ok" = "1" ] || { echo "!! koi bhi KP ref build nahi hua"; exit 1; }

cp kpm/alihidden.kpm "$OUT/"
ls -la "$OUT"
