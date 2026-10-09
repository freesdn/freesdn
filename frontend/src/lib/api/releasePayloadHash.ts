// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** One bounded worker per deliberate job. No upload, mutation or crypto fallback. */
const CHUNK = 1048576;
const MAXIMUM = 524288000;
let jobs = 0;
export class ReleaseHashError extends Error {
  constructor() { super('The release checksum could not be completed. No release request was issued.'); this.name = 'ReleaseHashError'; }
}
export function hashReleasePayload(blob: Blob, options: {
  signal?: AbortSignal; assertCurrent: () => void; onProgress?: (bytes: number, total: number) => void;
}): Promise<string> {
  // Copy callbacks and immutable slice synchronously at the initiating call.
  const { signal, assertCurrent, onProgress } = options;
  let snapshot: Blob;
  try {
    assertCurrent();
    if (!(blob instanceof Blob) || !Number.isSafeInteger(blob.size) || blob.size < 0 || blob.size > MAXIMUM
      || signal?.aborted || jobs >= 2) throw new ReleaseHashError();
    snapshot = blob.slice(0, blob.size, 'application/octet-stream');
    if (snapshot.size !== blob.size) throw new ReleaseHashError();
  } catch { return Promise.reject(new ReleaseHashError()); }
  jobs += 1;
  return new Promise((resolve, reject) => {
    let worker: Worker | undefined;
    let settled = false;
    let observed = 0;
    let idle: ReturnType<typeof setTimeout> | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const finish = (checksum?: string) => {
      if (settled) return;
      settled = true; jobs -= 1;
      if (idle !== undefined) clearTimeout(idle);
      if (deadline !== undefined) clearTimeout(deadline);
      signal?.removeEventListener('abort', abort);
      if (worker) { worker.onmessage = null; worker.onerror = null; worker.onmessageerror = null; worker.terminate(); }
      if (checksum === undefined) reject(new ReleaseHashError()); else resolve(checksum);
    };
    const abort = () => finish();
    const armIdle = () => { if (idle !== undefined) clearTimeout(idle); idle = setTimeout(abort, 10000); };
    try {
      worker = new Worker(new URL('./releasePayloadHash.worker.ts', import.meta.url), { type: 'module', name: 'freesdn-release-checksum' });
      worker.onerror = event => { event.preventDefault(); finish(); };
      worker.onmessageerror = () => finish();
      worker.onmessage = event => {
        if (settled) return;
        try {
          assertCurrent();
          if (signal?.aborted) throw new ReleaseHashError();
          const item: unknown = event.data;
          if (!item || typeof item !== 'object' || Array.isArray(item)) throw new ReleaseHashError();
          const value = item as Record<string, unknown>;
          const keys = Object.keys(value).sort().join(',');
          if (value.type === 'progress' && keys === 'bytes,type'
            && value.bytes === Math.min(snapshot.size, observed + CHUNK) && value.bytes !== observed) {
            observed = value.bytes as number; armIdle();
            // A UI observer cannot turn a valid checksum into a failed job.
            try { onProgress?.(observed, snapshot.size); } catch { /* display only */ }
            assertCurrent(); if (signal?.aborted) finish();
          } else if (value.type === 'complete' && keys === 'bytes,checksum,type' && value.bytes === snapshot.size
            && observed === snapshot.size && typeof value.checksum === 'string' && /^[0-9a-f]{64}$/.test(value.checksum)) {
            finish(value.checksum);
          } else { finish(); }
        } catch { finish(); }
      };
      signal?.addEventListener('abort', abort, { once: true });
      armIdle(); deadline = setTimeout(abort, 120000);
      assertCurrent();
      if (signal?.aborted) finish(); else worker.postMessage(snapshot);
    } catch { finish(); }
  });
}
