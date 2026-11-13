#!/bin/bash
set -e
KP_REF="${KP_REF:-0.13.1}"
STAGE="${STAGE:-5}"
BTI="${BTI:-0}"

git clone --depth=1 --branch "$KP_REF" https://github.com/bmax121/KernelPatch.git kp 2>/dev/null || {
    echo "!! KP_REF $KP_REF clone fail — main (ABI mismatch risk)"
    git clone --depth=1 https://github.com/bmax121/KernelPatch.git kp
}
test -f kp/kernel/include/kpmodule.h || { echo "!! kpmodule.h nahi mila"; exit 1; }
echo "KP commit: $(git -C kp rev-parse --short HEAD)"

make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu- STAGE="$STAGE" BTI="$BTI"
ls -la kpm/*.kpm
