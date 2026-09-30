#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
if [ -z "${DISPLAY:-}" ]; then
    exec xvfb-run -a -s '-screen 0 1280x900x24 -nolisten tcp' python run_web.py
fi
exec python run_web.py
