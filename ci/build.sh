#!/bin/bash
set -e

# APatch app me jo KernelPatch version dikhta hai, wahi yahan daal
# (ya dmesg | grep 'Kernel Patch Version' ka tag). Default latest.
KP_REF="${KP_REF:-main}"

echo "::group::fetch KernelPatch ($KP_REF)"
git clone --quiet https://github.com/bmax121/KernelPatch.git kp
cd kp
git checkout --quiet "$KP_REF" || { echo "ref $KP_REF nahi mila"; exit 1; }
echo "KP commit: $(git rev-parse --short HEAD)"
ls -l kernel/include/kputils.h kernel/include/kpmodule.h
cd ..
echo "::endgroup::"

echo "::group::build"
make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu-
echo "::endgroup::"

ls -la kpm/*.kpm
