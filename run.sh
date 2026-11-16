#!/bin/sh
# Launcher: finds Python 3 and runs run.py (works with busybox sh on Termux / iSH).
d=$(cd "$(dirname "$0")" && pwd)
for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        exec "$py" "$d/run.py" "$@"
    fi
done
echo "Python 3 is required." >&2
echo "  Ubuntu: sudo apt install python3 build-essential" >&2
echo "  Termux: pkg install python clang make binutils" >&2
echo "  iSH:    apk add python3 build-base" >&2
exit 2
