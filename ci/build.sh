#!/bin/bash
set -e

echo "::group::fetch KernelPatch"
git clone --quiet https://github.com/bmax121/KernelPatch.git kp
cd kp

PICK=$(git log --all --format=%H -- '*kputils.h' | head -n 1)
if [ -z "$PICK" ]; then PICK=$(git tag --sort=v:refname | head -n 1); fi

if [ -n "$PICK" ]; then
    echo "checkout: $PICK"
    git checkout --quiet "$PICK"
else
    echo "koi purana ref nahi mila, HEAD par build"
fi

ls -l kernel/include/kputils.h kernel/include/kpmodule.h || true
echo "--- kputils.h location ---"
find . -name 'kputils.h' | head
cd ..
echo "::endgroup::"

echo "::group::build"
make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu-
echo "::endgroup::"

ls -la kpm/*.kpm
