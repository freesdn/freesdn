// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE, unintegrated stream consumer. It does not authenticate a request,
 * validate HTTP headers/JSON, or prove browser/network resource cleanup.
 * The caller owns the request and must keep its authority/abort scope alive
 * until this consumer and the page decoder both finish.
 */
export const CATALOGUE_BODY_BYTES = 16 * 1024 * 1024;
export const CATALOGUE_BODY_MILLISECONDS = 10000;

export class ReleaseCatalogueReadError extends Error {
  constructor() {
    super('The catalogue response could not be read safely. Review the current account before loading again.');
    this.name = 'ReleaseCatalogueReadError';
  }
}

type ReadAuthority = {
  readonly signal: AbortSignal;
  readonly assertCurrent: () => void;
  readonly abortRequest: () => void;
};

/** Count actual decoded transport bytes, not a peer's content-length claim.
 * No materialized-body fallback. Limits cover bytes consumed here; they do
 * not cap buffers allocated internally by the browser or the remote peer.
 */
export async function readReleaseCatalogueBody(body: unknown, authority: ReadAuthority): Promise<string> {
  const { signal, assertCurrent, abortRequest } = authority;
  const started = performance.now();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let yieldTimer: ReturnType<typeof setTimeout> | undefined;
  let interrupted = false;
  let pendingRefusal: (() => void) | undefined;
  let failed = false;
  let output: string | undefined;
  let abortRequested = false;
  const requestAbort = () => {
    if (abortRequested) return;
    abortRequested = true;
    try { abortRequest(); } catch { /* Do not disclose request/error data. */ }
  };
  const interrupt = () => {
    interrupted = true;
    pendingRefusal?.();
  };
  // Keep only the current wait attached to cancellation. Repeatedly racing a
  // shared pending promise would retain one reaction per peer-chosen chunk.
  const waitFor = <T,>(operation: Promise<T>): Promise<T> => new Promise((resolve, reject) => {
    const refuse = () => {
      if (pendingRefusal === refuse) pendingRefusal = undefined;
      reject(new ReleaseCatalogueReadError());
    };
    pendingRefusal = refuse;
    void operation.then(value => {
      if (pendingRefusal === refuse) pendingRefusal = undefined;
      resolve(value);
    }, refuse);
    if (interrupted) refuse();
  });
  const check = () => {
    if (interrupted || signal.aborted || performance.now() - started >= CATALOGUE_BODY_MILLISECONDS) {
      throw new ReleaseCatalogueReadError();
    }
    assertCurrent();
  };
  try {
    if (typeof ReadableStream === 'undefined' || !(body instanceof ReadableStream) || body.locked) {
      throw new ReleaseCatalogueReadError();
    }
    reader = body.getReader();
    signal.addEventListener('abort', interrupt, { once: true });
    timer = setTimeout(interrupt, CATALOGUE_BODY_MILLISECONDS);
    check();
    // Preserve a BOM as data for the strict JSON decoder to reject. Invalid
    // UTF-8 is refused, including an incomplete sequence at end of stream.
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const parts: string[] = [];
    // Peer chunking cannot create millions of retained tiny string entries.
    // At most256 complete slabs plus one final fragment reach `parts`.
    const slab = new Uint8Array(64 * 1024);
    let used = 0;
    let bytes = 0;
    let chunks = 0;
    while (true) {
      check();
      const next = await waitFor(reader.read());
      check();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > CATALOGUE_BODY_BYTES - bytes) {
        throw new ReleaseCatalogueReadError();
      }
      bytes += next.value.byteLength;
      let offset = 0;
      while (offset < next.value.byteLength) {
        check();
        const count = Math.min(slab.byteLength - used, next.value.byteLength - offset);
        slab.set(next.value.subarray(offset, offset + count), used);
        offset += count;
        used += count;
        if (used === slab.byteLength) {
          const text = decoder.decode(slab, { stream: true });
          if (text) parts.push(text);
          used = 0;
        }
      }
      chunks += 1;
      if (chunks % 64 === 0) {
        // A producer of immediately resolved/empty chunks must not starve the
        // abort timer or account-change notifications in the browser task queue.
        await waitFor(new Promise<void>(resolve => {
          yieldTimer = setTimeout(() => { yieldTimer = undefined; resolve(); }, 0);
        }));
        check();
      }
    }
    const tail = decoder.decode(slab.subarray(0, used));
    if (tail) parts.push(tail);
    const result = parts.join('');
    check();
    output = result;
  } catch {
    // Request abort and stream cancellation are requested, not claimed to be
    // observed server shutdown. A malicious underlying cancel promise must not
    // hold this refusal open indefinitely; the real transport needs its own test.
    failed = true;
    requestAbort();
    if (reader) {
      try { void reader.cancel().catch(() => undefined); } catch { /* Already errored/released. */ }
    }
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (yieldTimer !== undefined) clearTimeout(yieldTimer);
    signal.removeEventListener('abort', interrupt);
    if (reader) {
      try { reader.releaseLock(); } catch {
        failed = true;
        requestAbort();
      }
    }
  }
  if (failed || output === undefined) throw new ReleaseCatalogueReadError();
  return output;
}
