// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// Post-build gate for the public demo (demo.freesdn.org). The demo must be a
// fully backend-isolated static build.
//
// Demo isolation is STRUCTURAL: `build:demo` runs `vite build --mode demo`,
// which sets import.meta.env.MODE='demo' and loads .env.demo (VITE_DEMO_MODE=
// true). src/demo/mode.ts gates demo mocking on either signal. This script
// verifies those source invariants still hold and that the built dist/ ships no
// source maps (which would leak original source and build paths).
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const fail = [];

// 1. .env.demo sets VITE_DEMO_MODE=true
const envDemo = join(root, '.env.demo');
if (!existsSync(envDemo) || !/^\s*VITE_DEMO_MODE\s*=\s*true\s*$/m.test(readFileSync(envDemo, 'utf8'))) {
  fail.push('.env.demo missing or does not set VITE_DEMO_MODE=true');
}
// 2. mode.ts keeps the MODE==='demo' belt-and-suspenders fallback
const modeTs = readFileSync(join(root, 'src/demo/mode.ts'), 'utf8');
if (!modeTs.includes("MODE === 'demo'")) {
  fail.push("src/demo/mode.ts lost the `import.meta.env.MODE === 'demo'` fallback");
}
// 3. build:demo still passes --mode demo
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
if (!/--mode\s+demo/.test(pkg.scripts['build:demo'] || '')) {
  fail.push('package.json build:demo no longer passes `--mode demo`');
}

// 4. No source maps in the built dist.
const dist = join(root, 'dist');
if (!existsSync(dist)) {
  fail.push('dist/ not found, run `npm run build:demo` first');
} else {
  const maps = [];
  const walk = (d) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith('.map')) maps.push(p);
    }
  };
  walk(dist);
  if (maps.length) {
    fail.push(`source maps present in dist/ (${maps.length}), .map files leak original source/paths`);
  }
}

if (fail.length) {
  console.error('verify-demo-build FAILED:');
  for (const f of fail) console.error('  - ' + f);
  process.exit(1);
}
console.log('verify-demo-build OK: demo isolation invariants hold; dist ships no source maps');
