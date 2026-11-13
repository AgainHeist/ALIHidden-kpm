
#!/bin/bash
set -e

git clone https://github.com/bmax121/KernelPatch.git kp
cd kp
git checkout "$(git log --before=2026-10-01 -1 --format=%H)"
cd ..

test -f kp/kernel/include/kputils.h
make -C kpm KP_DIR="$PWD/kp" TARGET_COMPILE=aarch64-linux-gnu-
ls -la kpm/*.kpm
