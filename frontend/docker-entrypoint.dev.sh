#!/bin/sh
# FreeSDN Frontend - Development Entrypoint
# Reinstall a dependency volume when its lock/config or native runtime changes.

set -e

npm_version=$(npm --version)
fingerprint=$(node - "$npm_version" <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const hash = crypto.createHash('sha256');
for (const file of ['package.json', 'package-lock.json', '.npmrc']) {
  hash.update(file + '\0');
  if (file !== '.npmrc' || fs.existsSync(file)) hash.update(fs.readFileSync(file));
  hash.update('\0');
}
hash.update(JSON.stringify({
  node: process.versions.node, abi: process.versions.modules,
  platform: process.platform, arch: process.arch,
  libc: process.report.getReport().header.glibcVersionRuntime || 'musl',
  npm: process.argv[2],
}));
process.stdout.write(hash.digest('hex'));
JS
)
stamp=node_modules/.freesdn-dev-dependencies
if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$fingerprint" ] || \
   [ ! -f node_modules/.package-lock.json ] || [ ! -x node_modules/.bin/vite ]; then
  echo "[entrypoint] dependency lock or runtime changed - running npm ci..."
  # npm ci fails on lock drift and replaces native bindings from another libc/ABI.
  # A failed installation must never leave an accepted fingerprint.
  rm -f "$stamp"
  npm ci --legacy-peer-deps --no-audit --no-fund
  printf '%s\n' "$fingerprint" > "$stamp"
else
  echo "[entrypoint] dependency lock and runtime match."
fi

exec "$@"
