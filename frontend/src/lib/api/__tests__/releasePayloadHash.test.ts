// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { hashReleasePayload, ReleaseHashError } from '../releasePayloadHash';

// Controlled Worker transport only: these cases do not prove browser worker
// loading, CSP, actual OS cancellation, peak RSS or full500MiB performance.
class ControlledWorker {
  static all: ControlledWorker[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  postMessage = vi.fn(); terminate = vi.fn();
  constructor() { ControlledWorker.all.push(this); }
  emit(value: unknown) { this.onmessage?.({ data: value } as MessageEvent); }
}
const checksum = 'a'.repeat(64);
const controls: AbortController[] = [];
function job(blob = new Blob(['abc']), assertCurrent = () => undefined, onProgress = vi.fn()) {
  const controller = new AbortController(); controls.push(controller);
  const promise = hashReleasePayload(blob, { signal: controller.signal, assertCurrent, onProgress });
  // Observe rejection synchronously so deliberate aborts never leave an unhandled promise.
  void promise.catch(() => undefined);
  return { promise, controller, worker: ControlledWorker.all[ControlledWorker.all.length - 1], onProgress };
}
beforeEach(() => { ControlledWorker.all = []; vi.stubGlobal('Worker', ControlledWorker); });
afterEach(() => { controls.splice(0).forEach(c => c.abort()); vi.useRealTimers(); vi.unstubAllGlobals(); });
describe('owned worker hashing lifecycle', () => {
  it('requires exact ordered progress before accepting a bounded checksum', async () => {
    const value = job(); value.worker.emit({ type: 'progress', bytes: 3 }); value.worker.emit({ type: 'complete', bytes: 3, checksum });
    expect(await value.promise).toBe(checksum); expect(value.onProgress).toHaveBeenCalledWith(3, 3);
    expect(value.worker.terminate).toHaveBeenCalledOnce(); expect(value.worker.onmessage).toBeNull();
  });
  it.each(['missing-progress', 'too-many-bytes', 'wrong-size', 'bad-digest', 'extra-field', 'repeat-progress', 'wrong-order', 'native-error', 'failed', 'not-object'])(
    'refuses %s worker output and releases the worker', async which => {
      const value = job();
      if (which !== 'missing-progress') value.worker.emit({ type: 'progress', bytes: 3 });
      if (which === 'too-many-bytes') value.worker.emit({ type: 'progress', bytes: 4 });
      else if (which === 'repeat-progress') value.worker.emit({ type: 'progress', bytes: 3 });
      else if (which === 'wrong-order') value.worker.emit({ type: 'progress', bytes: 2 });
      else if (which === 'native-error') value.worker.onerror?.({ preventDefault: vi.fn() } as unknown as ErrorEvent);
      else if (which === 'failed') value.worker.emit({ type: 'failed', detail: 'synthetic private pathname' });
      else if (which === 'not-object') value.worker.emit('synthetic private body');
      else value.worker.emit({ type: 'complete', bytes: which === 'wrong-size' ? 4 : 3,
        checksum: which === 'bad-digest' ? 'g'.repeat(64) : checksum, ...(which === 'extra-field' ? { extra: true } : {}) });
      await expect(value.promise).rejects.toBeInstanceOf(ReleaseHashError); expect(value.worker.terminate).toHaveBeenCalledOnce();
    });
  it('allows the actual empty-file digest without fake progress', async () => {
    const value = job(new Blob([])); value.worker.emit({ type: 'complete', bytes: 0, checksum });
    expect(await value.promise).toBe(checksum);
  });
  it('terminates on cancellation and ignores late saved callbacks', async () => {
    const value = job(); const callback = value.worker.onmessage!; value.controller.abort();
    callback({ data: { type: 'complete', bytes: 3, checksum } } as MessageEvent);
    await expect(value.promise).rejects.toThrow(ReleaseHashError); expect(value.worker.terminate).toHaveBeenCalledOnce();
  });
  it('checks current authority at message receipt and conceals original exceptions', async () => {
    let current = true; const value = job(new Blob(['abc']), () => { if (!current) throw new Error('private account text'); });
    current = false; value.worker.emit({ type: 'progress', bytes: 3 });
    await expect(value.promise).rejects.toMatchObject({ name: 'ReleaseHashError', message: expect.not.stringContaining('private') });
  });
  it('caps concurrent workers at two and releases a slot after abort', async () => {
    const first = job(); const second = job(); const refused = job();
    await expect(refused.promise).rejects.toThrow(ReleaseHashError); expect(ControlledWorker.all).toHaveLength(2);
    first.controller.abort(); await expect(first.promise).rejects.toThrow();
    const third = job(); expect(ControlledWorker.all).toHaveLength(3); second.controller.abort(); third.controller.abort();
    await Promise.all([second.promise.catch(() => undefined), third.promise.catch(() => undefined)]);
  });
  it('stops an unresponsive worker at the unchanged idle deadline', async () => {
    vi.useFakeTimers(); const value = job(); await vi.advanceTimersByTimeAsync(10000);
    await expect(value.promise).rejects.toThrow(); expect(value.worker.terminate).toHaveBeenCalledOnce();
  });
  it('stops at total deadline even when chunk progress keeps arriving', async () => {
    vi.useFakeTimers(); const value = job(new Blob([new Uint8Array(16 * 1048576)]));
    for (let i = 1; i <= 13; i++) { await vi.advanceTimersByTimeAsync(9000); value.worker.emit({ type: 'progress', bytes: i * 1048576 }); }
    await vi.advanceTimersByTimeAsync(3000); await expect(value.promise).rejects.toThrow(); expect(value.worker.terminate).toHaveBeenCalledOnce();
  });
  it('does not propagate display callback failures into checksum failure', async () => {
    const value = job(new Blob(['abc']), () => undefined, vi.fn(() => { throw new Error('display failed'); }));
    value.worker.emit({ type: 'progress', bytes: 3 }); value.worker.emit({ type: 'complete', bytes: 3, checksum });
    expect(await value.promise).toBe(checksum);
  });
  it('refuses oversized and already-aborted jobs without creating a worker', async () => {
    const blob = new Blob(['a']); Object.defineProperty(blob, 'size', { value: 524288001 });
    const controller = new AbortController(); controller.abort();
    await expect(hashReleasePayload(blob, { assertCurrent: () => undefined })).rejects.toThrow();
    await expect(hashReleasePayload(new Blob(), { assertCurrent: () => undefined, signal: controller.signal })).rejects.toThrow();
    expect(ControlledWorker.all).toHaveLength(0);
  });
  it('cleans up constructor failure without retaining an admission slot', async () => {
    vi.stubGlobal('Worker', class { constructor() { throw new Error('private constructor error'); } });
    await expect(hashReleasePayload(new Blob(), { assertCurrent: () => undefined })).rejects.toThrow(ReleaseHashError);
    vi.stubGlobal('Worker', ControlledWorker); const value = job(); value.controller.abort(); await expect(value.promise).rejects.toThrow();
    expect(value.worker.terminate).toHaveBeenCalledOnce();
  });
});
