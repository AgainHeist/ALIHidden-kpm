#!/bin/bash
set -e

echo "::group::fetch KernelPatch"
git clone --quiet https://github.com/bmax121/KernelPatch.git kp
cd kp
DEL=$(git log --diff-filter=D --format=%H -- kernel/include/kputils.h | head -n 1)
echo "kputils.h delete commit: ${DEL:-none}"
if [ -n "$DEL" ]; then
    git checkout --quiet "${DEL}^"
else
    echo "kputils.h kabhi tha hi nahi, current HEAD par build"
fi
ls -l kernel/include/kputils.h kernel/include/kpmodule.h
cd ..
echo "::endgroup::"

echo "::group::build"
make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu-
echo "::endgroup::"

ls -la kpm/*.kpm
