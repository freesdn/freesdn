// SPDX-License-Identifier: AGPL-3.0-only
// Bound the production entry's static JS dependency graph, not just each chunk.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gzipSync } from 'node:zlib';

const dist = resolve(import.meta.dirname, '../dist');
const manifest = JSON.parse(readFileSync(resolve(dist, '.vite/manifest.json'), 'utf8'));
const entry = manifest['index.html'];
if (!entry?.isEntry) throw new Error('Missing index.html entry in build manifest');

const visited = new Set();
const initialFiles = new Set();
function visit(key) {
  if (visited.has(key)) return;
  visited.add(key);
  const chunk = manifest[key];
  if (!chunk) throw new Error(`Missing static import in build manifest: ${key}`);
  if (chunk.file.endsWith('.js')) initialFiles.add(chunk.file);
  for (const imported of chunk.imports ?? []) visit(imported);
}
visit('index.html');

const initialBytes = [...initialFiles].reduce(
  (sum, file) => sum + gzipSync(readFileSync(resolve(dist, file)), { level: 9 }).length, 0,
);
const maxInitialGzipBytes = 650_000;
const maxChunkBytes = 1_250_000;
const oversizedChunks = [...new Set(Object.values(manifest).map(chunk => chunk.file))]
  .filter(file => file.endsWith('.js'))
  .map(file => ({ file, bytes: readFileSync(resolve(dist, file)).length }))
  .filter(chunk => chunk.bytes > maxChunkBytes);

console.log(JSON.stringify({
  scope: 'Entry and its static JavaScript imports; dynamic route imports excluded',
  initialGzipBytes: initialBytes,
  maxInitialGzipBytes,
  initialFiles: [...initialFiles].sort(),
  maxChunkBytes,
  oversizedChunks,
}, null, 2));
if (initialBytes > maxInitialGzipBytes || oversizedChunks.length) {
  throw new Error('Frontend bundle budget exceeded; inspect eager imports before raising limits');
}
