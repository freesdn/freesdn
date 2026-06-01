#!/bin/sh
# FreeSDN Frontend - Development Entrypoint
# Ensures node_modules stays in sync with package.json
# even when using an anonymous Docker volume for node_modules.

set -e

# Fast check: if package.json is newer than node_modules/.package-lock.json,
# or if a key dependency is missing, run npm install.
if [ ! -f node_modules/.package-lock.json ] || \
   [ package.json -nt node_modules/.package-lock.json ] || \
   [ package-lock.json -nt node_modules/.package-lock.json ]; then
  echo "[entrypoint] package.json changed - running npm install..."
  # Match the Dockerfile flag (see Dockerfile.dev comment).
  npm install --legacy-peer-deps
else
  echo "[entrypoint] node_modules up to date."
fi

exec "$@"
