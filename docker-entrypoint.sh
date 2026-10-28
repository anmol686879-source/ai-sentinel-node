#!/bin/sh
# Mounted volumes (Render, Fly, Docker) are often owned by root. Fix ownership, then drop to the unprivileged "node" user.
set -e
D="${DATA_DIR:-/app/data}"
mkdir -p "$D"
chown -R node:node "$D" 2>/dev/null || true
exec su-exec node "$@"
