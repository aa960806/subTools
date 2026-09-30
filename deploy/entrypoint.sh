#!/bin/sh
set -eu
umask 077
mkdir -p /app/data
chown -R subtools:subtools /app/data
exec gosu subtools xvfb-run -a -s '-screen 0 1280x900x24 -nolisten tcp' "$@"
