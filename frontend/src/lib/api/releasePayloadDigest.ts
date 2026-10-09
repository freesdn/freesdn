// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Runs only inside the disposable hash worker. Not a signature or authority. */
import { sha256 } from '@noble/hashes/sha2.js';

export const RELEASE_HASH_CHUNK_BYTES = 1048576;
export const RELEASE_HASH_MAX_BYTES = 524288000;
export async function digestReleaseBlob(blob: Blob, progress: (bytes: number) => void): Promise<string> {
  if (!(blob instanceof Blob) || !Number.isSafeInteger(blob.size) || blob.size < 0 || blob.size > RELEASE_HASH_MAX_BYTES) {
    throw new Error('Release payload cannot be hashed.');
  }
  const state = sha256.create();
  try {
    for (let offset = 0; offset < blob.size; offset += RELEASE_HASH_CHUNK_BYTES) {
      const end = Math.min(blob.size, offset + RELEASE_HASH_CHUNK_BYTES);
      // Only a bounded slice becomes an ArrayBuffer; never blob.arrayBuffer().
      const bytes = await blob.slice(offset, end).arrayBuffer();
      if (bytes.byteLength !== end - offset) throw new Error('Release payload read was incomplete.');
      state.update(new Uint8Array(bytes));
      progress(end);
    }
    return Array.from(state.digest(), byte => byte.toString(16).padStart(2, '0')).join('');
  } finally { state.destroy(); }
}
