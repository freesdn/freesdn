// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { Blob as NodeBlob } from 'node:buffer';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { digestReleaseBlob, RELEASE_HASH_CHUNK_BYTES } from '../releasePayloadDigest';

beforeEach(() => vi.stubGlobal('Blob', NodeBlob));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe('worker incremental SHA-256 byte processing', () => {
  it.each([0, 1, 55, 56, 63, 64, 65, 1048575, 1048576, 1048577, 2097169])(
    'matches native SHA-256 for %s bytes with only bounded reads', async size => {
      const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 37 + 11) & 255);
      const blob = new Blob([bytes]);
      const topRead = vi.spyOn(blob, 'arrayBuffer').mockRejectedValue(new Error('whole file read forbidden'));
      const slice = vi.spyOn(blob, 'slice');
      const seen: number[] = [];
      expect(await digestReleaseBlob(blob, amount => seen.push(amount))).toBe(createHash('sha256').update(bytes).digest('hex'));
      expect(topRead).not.toHaveBeenCalled();
      expect(slice.mock.calls.every(([a = 0, b = 0]) => b - a <= RELEASE_HASH_CHUNK_BYTES)).toBe(true);
      expect(slice).toHaveBeenCalledTimes(Math.ceil(size / RELEASE_HASH_CHUNK_BYTES));
      expect(seen).toEqual(Array.from({ length: Math.ceil(size / RELEASE_HASH_CHUNK_BYTES) }, (_, i) => Math.min(size, (i + 1) * RELEASE_HASH_CHUNK_BYTES)));
    });
  it('refuses a short read instead of hashing fewer bytes than declared', async () => {
    const blob = new Blob(['abc']); vi.spyOn(blob, 'slice').mockReturnValue(new Blob(['ab']));
    const progress = vi.fn(); await expect(digestReleaseBlob(blob, progress)).rejects.toThrow(); expect(progress).not.toHaveBeenCalled();
  });
  it('rejects an oversize declared blob before any read or hash loop', async () => {
    const blob = new Blob(['a']); Object.defineProperty(blob, 'size', { value: 524288001 });
    const slice = vi.spyOn(blob, 'slice'); await expect(digestReleaseBlob(blob, vi.fn())).rejects.toThrow(); expect(slice).not.toHaveBeenCalled();
  });
  it('does not convert a failed file read into an empty digest', async () => {
    const blob = new Blob(['abc']); const part = new Blob(['abc']);
    vi.spyOn(blob, 'slice').mockReturnValue(part); vi.spyOn(part, 'arrayBuffer').mockRejectedValue(new Error('private native cause'));
    await expect(digestReleaseBlob(blob, vi.fn())).rejects.toThrow();
  });
});
