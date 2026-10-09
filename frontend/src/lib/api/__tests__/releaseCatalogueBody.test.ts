// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CATALOGUE_BODY_BYTES, CATALOGUE_BODY_MILLISECONDS,
  readReleaseCatalogueBody, ReleaseCatalogueReadError,
} from '../releaseCatalogueBody';

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
const encoder = new TextEncoder();

function authority() {
  const controller = new AbortController();
  return { controller, signal: controller.signal, assertCurrent: vi.fn(), abortRequest: vi.fn() };
}

function stream(chunks: Uint8Array[]) {
  let index = 0;
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else controller.close();
    }, cancel,
  });
  return { body, cancel };
}

describe('private catalogue byte consumer', () => {
  it.each([1, 2, 3, 4, 7])('preserves split UTF8 with chunk width %i', async width => {
    const text = '{"notes":"é שלום 🙂"}';
    const bytes = encoder.encode(text);
    const chunks = Array.from({ length: Math.ceil(bytes.length / width) },
      (_, i) => bytes.slice(i * width, (i + 1) * width));
    const { body, cancel } = stream(chunks);
    const scope = authority();
    expect(await readReleaseCatalogueBody(body, scope)).toBe(text);
    expect(scope.abortRequest).not.toHaveBeenCalled();
    expect(cancel).not.toHaveBeenCalled();
    expect(body.locked).toBe(false);
  });

  it.each([65533, 65534, 65535, 65536])('preserves Unicode crossing internal slab at %i', async prefix => {
    const text = 'a'.repeat(prefix) + '🙂€';
    const { body } = stream([encoder.encode(text)]);
    expect(await readReleaseCatalogueBody(body, authority())).toBe(text);
    expect(body.locked).toBe(false);
  });

  it('permits the exact byte bound and releases its reader', async () => {
    const slab = new Uint8Array(65536).fill(97);
    const { body } = stream(Array.from({ length: CATALOGUE_BODY_BYTES / slab.length }, () => slab));
    const value = await readReleaseCatalogueBody(body, authority());
    expect(value.length).toBe(CATALOGUE_BODY_BYTES);
    expect(value[0]).toBe('a');
    expect(value[value.length - 1]).toBe('a');
    expect(body.locked).toBe(false);
  });

  it.each(['one-chunk', 'incremental'])('refuses actual bytes above cap: %s', async mode => {
    const slab = new Uint8Array(65536).fill(97);
    const chunks = mode === 'one-chunk' ? [new Uint8Array(CATALOGUE_BODY_BYTES + 1)]
      : [...Array.from({ length: CATALOGUE_BODY_BYTES / slab.length }, () => slab), new Uint8Array([97])];
    const { body, cancel } = stream(chunks);
    const scope = authority();
    await expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    // A source may have already closed after its queued last chunk; either way
    // this consumer releases its lock and requests network abort.
    expect(cancel.mock.calls.length).toBeLessThanOrEqual(1);
    expect(body.locked).toBe(false);
  });

  it.each([
    { bytes: [0xc0, 0xaf] }, { bytes: [0x80] }, { bytes: [0xed, 0xa0, 0x80] },
    { bytes: [0xf5, 0x80, 0x80, 0x80] }, { bytes: [0xe2, 0x82] }, { bytes: [0xff] },
  ])('refuses malformed/incomplete UTF8 $bytes', async ({ bytes }) => {
    const { body } = stream([new Uint8Array(bytes)]);
    const scope = authority();
    await expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('retains a BOM for the strict protocol decoder to reject', async () => {
    const { body } = stream([new Uint8Array([0xef, 0xbb, 0xbf, 123, 125])]);
    expect(await readReleaseCatalogueBody(body, authority())).toBe('\ufeff{}');
  });

  it('does not claim empty body is valid JSON', async () => {
    const { body } = stream([]);
    expect(await readReleaseCatalogueBody(body, authority())).toBe('');
  });

  it.each([undefined, null, '{}', new Uint8Array([123, 125]), { text: async () => '{}' }])(
    'refuses non-stream/materialized response %#', async body => {
      const scope = authority();
      await expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
      expect(scope.abortRequest).toHaveBeenCalledOnce();
    },
  );

  it('refuses a locked stream without releasing another reader', async () => {
    const { body } = stream([encoder.encode('{}')]);
    const owner = body.getReader();
    const scope = authority();
    await expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    expect(body.locked).toBe(true);
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    await owner.cancel();
    owner.releaseLock();
  });

  it('refuses a non-byte chunk without retaining its contents', async () => {
    const body = new ReadableStream({ start(controller) { controller.enqueue('private-wire-content'); } });
    const scope = authority();
    const error = await readReleaseCatalogueBody(body, scope).catch(value => value);
    expect(error).toBeInstanceOf(ReleaseCatalogueReadError);
    expect(String(error)).not.toContain('private-wire-content');
    expect(error).not.toHaveProperty('cause');
    expect(body.locked).toBe(false);
  });

  it('refuses an already-aborted owner and releases the acquired reader', async () => {
    const scope = authority();
    scope.controller.abort();
    const { body } = stream([encoder.encode('{}')]);
    await expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('interrupts a stalled read and removes deadline/listener resources', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const scope = authority();
    const failure = expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    await vi.advanceTimersByTimeAsync(CATALOGUE_BODY_MILLISECONDS);
    await failure;
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('aborts a pending read when the owning action is invalidated', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const scope = authority();
    const failure = expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    scope.controller.abort();
    await failure;
    expect(cancel).toHaveBeenCalledOnce();
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('checks authority again after awaited data before returning it', async () => {
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const body = new ReadableStream<Uint8Array>({ start(value) { controller = value; } });
    const scope = authority();
    const failure = expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    scope.assertCurrent.mockImplementation(() => { throw new Error('private-account-state'); });
    controller.enqueue(encoder.encode('private-catalogue-row'));
    await failure;
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('redacts an underlying stream error and requests abort', async () => {
    const body = new ReadableStream<Uint8Array>({ start(c) { c.error(new Error('private-wire-failure')); } });
    const scope = authority();
    const error = await readReleaseCatalogueBody(body, scope).catch(value => value);
    expect(error).toBeInstanceOf(ReleaseCatalogueReadError);
    expect(String(error)).not.toContain('private-wire-failure');
    expect(error).not.toHaveProperty('cause');
    expect(scope.abortRequest).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('does not await a maliciously hanging underlying cancel promise', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => undefined));
    const body = new ReadableStream<Uint8Array>({ cancel });
    const scope = authority();
    const failure = expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    scope.controller.abort();
    await failure;
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });

  it('yields to an abort task despite an endless immediately resolved empty producer', async () => {
    let pulls = 0;
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      pull(c) { pulls += 1; c.enqueue(new Uint8Array()); }, cancel,
    });
    const scope = authority();
    const failure = expect(readReleaseCatalogueBody(body, scope)).rejects.toBeInstanceOf(ReleaseCatalogueReadError);
    setTimeout(() => scope.controller.abort(), 0);
    await failure;
    expect(pulls).toBeGreaterThan(0);
    expect(pulls).toBeLessThan(1000);
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  });
});
