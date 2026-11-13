#!/bin/bash
set -e
KP_REF="${KP_REF:-main}"
STAGE="${STAGE:-6}"

git clone --depth=1 https://github.com/bmax121/KernelPatch.git kp
cd kp
if [ "$KP_REF" != "main" ]; then
    git fetch --depth=1 origin "refs/tags/$KP_REF:refs/tags/$KP_REF" 2>/dev/null || true
    git checkout "$KP_REF" 2>/dev/null || { echo "KP_REF $KP_REF nahi mila, main par"; git checkout main; }
fi
test -f kernel/include/kpmodule.h
echo "KP commit: $(git rev-parse --short HEAD)"
cd ..

make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu- STAGE="$STAGE"
ls -la kpm/*.kpm
