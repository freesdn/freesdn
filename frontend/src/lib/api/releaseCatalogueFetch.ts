// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE integration. Browser/HTTP deployment has not yet been qualified.
 * Call only within an initiating action's captured authority and abort lifetime.
 * Paired context headers detect stale context; they never grant server authority.
 */
import axios, { AxiosHeaders, type AxiosRequestConfig } from 'axios';
import { api } from './client';
import { CATALOGUE_BODY_BYTES, CATALOGUE_BODY_MILLISECONDS, readReleaseCatalogueBody } from './releaseCatalogueBody';
import { captureReleaseCataloguePosition, decodeReleaseCatalogue, type ReleaseCataloguePage,
  type ReleaseCataloguePosition } from './releaseCatalogueCodec';

export class CatalogueTransportError extends Error {
  constructor(readonly issued: boolean, readonly status?: number) {
    super('The catalogue request could not be confirmed. Review the current account before loading again.');
    this.name = 'CatalogueTransportError';
  }
}
type PreparedCatalogue = Readonly<{ url: string; position: Readonly<ReleaseCataloguePosition> }>;
type CapturedCatalogueAuthority = Readonly<{
  actor: string; organization: string; signal: AbortSignal;
  assertCurrent: () => void; abortRequest: () => void;
}>;

export function prepareCatalogueRead(position: unknown, filters: unknown): PreparedCatalogue {
  const captured = captureReleaseCataloguePosition(position);
  if (!filters || typeof filters !== 'object' || Array.isArray(filters)
    || Object.keys(filters).some(key => !['platform', 'agent_type'].includes(key))) {
    throw new CatalogueTransportError(false);
  }
  const query = new URLSearchParams({ limit: String(captured.limit) });
  for (const key of ['platform', 'agent_type'] as const) {
    const value = (filters as Record<string, unknown>)[key];
    if (value === undefined) continue;
    if (typeof value !== 'string' || !/^[A-Za-z0-9._+-]{1,50}$/.test(value)) throw new CatalogueTransportError(false);
    query.set(key, value);
  }
  if (captured.before_id !== undefined) {
    query.set('before_id', captured.before_id);
    query.set('before_published_at', captured.before_published_at!);
  }
  return Object.freeze({ url: `/agents/release-catalogue?${query}`, position: captured });
}

function cancelUnused(body: unknown) {
  if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream && !body.locked) {
    try { void body.cancel().catch(() => undefined); } catch { /* Already closed/errored. */ }
  }
}

// Axios can wrap the response in an async iterator whose return() waits behind
// a pending read. Keep the original reader owned separately so refusal does not
// depend on that wrapper advancing. A stable fetch hook avoids one cached Axios
// adapter (and its captured request state) per request.
// An explicitly named private option fits Axios's declared fetchOptions API.
// It is removed before delegating to native Fetch.
const catalogueLifetime = '__freesdnCatalogueResponseLifetime' as const;
type CatalogueResponseLifetime = { before: () => void; receive: (response: Response) => Response; finish: () => void };
type CatalogueFetchOptions = RequestInit & { [catalogueLifetime]?: CatalogueResponseLifetime };

async function ownedCatalogueFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const lifetime = (init as CatalogueFetchOptions | undefined)?.[catalogueLifetime];
  if (!lifetime) throw new CatalogueTransportError(false);
  const nativeOptions: CatalogueFetchOptions = { ...init };
  delete nativeOptions[catalogueLifetime];
  lifetime.before();
  return lifetime.receive(await globalThis.fetch(input, nativeOptions));
}

function ownCatalogueResponse(check: () => void, before: () => void): CatalogueResponseLifetime {
  let closed = false;
  let cancelOriginal: (() => void) | undefined;
  return {
    before() {
      if (closed) throw new CatalogueTransportError(false);
      check(); before();
    },
    receive(response) {
      if (closed) { cancelUnused(response.body); throw new CatalogueTransportError(true); }
      try { check(); } catch { cancelUnused(response.body); throw new CatalogueTransportError(true); }
      const body = response.body;
      if (!(body instanceof ReadableStream) || body.locked) throw new CatalogueTransportError(true);
      const reader = body.getReader();
      let finished = false;
      let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
      const release = () => { try { reader.releaseLock(); } catch { /* A pending read is observed below. */ } };
      const cancel = () => {
        if (finished) return;
        finished = true;
        // Request cleanup without waiting forever for an underlying cancel.
        try { void reader.cancel().catch(() => undefined); } catch { /* Already closed/errored. */ }
        release();
        try { controller?.error(new CatalogueTransportError(true)); } catch { /* Already cancelled. */ }
      };
      cancelOriginal = cancel;
      const stream = new ReadableStream<Uint8Array>({
        start(value) { controller = value; },
        async pull(value) {
          if (finished) return;
          try {
            const next = await reader.read();
            if (finished) return;
            if (next.done) { finished = true; release(); value.close(); }
            else value.enqueue(next.value);
          } catch { cancel(); }
        },
        cancel() { cancel(); },
      }, { highWaterMark: 0 });
      try { return new Response(stream, { status: response.status, statusText: response.statusText, headers: response.headers }); }
      catch { cancel(); throw new CatalogueTransportError(true); }
    },
    finish() { closed = true; cancelOriginal?.(); },
  };
}

/** One finite read, including queued interceptors, headers, body and validation.
 * Actual consumed bytes are bounded separately from untrusted content-length.
 * Checks are cooperative: synchronous decoding is checked afterward, not preempted.
 * This is not a bound on browser-internal buffers or a server shutdown proof.
 */
export async function fetchReleaseCatalogue(prepared: PreparedCatalogue,
  authority: CapturedCatalogueAuthority): Promise<ReleaseCataloguePage> {
  const { actor, organization, signal, assertCurrent, abortRequest } = authority;
  const { url, position } = prepared;
  const started = performance.now();
  let dispatched = false;
  let responseBody: unknown;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let rejectInterrupted: () => void = () => undefined;
  const interrupted = new Promise<never>((_resolve, reject) => {
    rejectInterrupted = () => reject(new CatalogueTransportError(dispatched));
  });
  void interrupted.catch(() => undefined);
  const check = () => {
    if (signal.aborted || performance.now() - started >= CATALOGUE_BODY_MILLISECONDS) {
      throw new CatalogueTransportError(dispatched);
    }
    assertCurrent();
  };
  const abort = () => { try { abortRequest(); } catch { /* Never expose the owner's state. */ } };
  const responseLifetime = ownCatalogueResponse(check, () => {
    if (dispatched) throw new CatalogueTransportError(true);
    dispatched = true;
  });
  try {
    check();
    // Fail closed without fetch/streams. Never use XHR or a materialized fallback.
    if (typeof fetch !== 'function' || typeof Request !== 'function' || typeof Response !== 'function'
      || typeof ReadableStream !== 'function') throw new CatalogueTransportError(false);
    const probe = new Response('');
    if (!(probe.body instanceof ReadableStream)) throw new CatalogueTransportError(false);
    cancelUnused(probe.body);
    signal.addEventListener('abort', rejectInterrupted, { once: true });
    timer = setTimeout(() => { abort(); rejectInterrupted(); }, CATALOGUE_BODY_MILLISECONDS);
    check();
    const config: AxiosRequestConfig & { _freesdnReleaseNoReplay: true } = {
      url, method: 'GET', withCredentials: true, signal, timeout: CATALOGUE_BODY_MILLISECONDS,
      _freesdnReleaseNoReplay: true, responseType: 'stream', maxContentLength: CATALOGUE_BODY_BYTES,
      fetchOptions: { cache: 'no-store', redirect: 'error', [catalogueLifetime]: responseLifetime },
      headers: { Accept: 'application/json', 'X-FreeSDN-Release-Actor': actor,
        'X-FreeSDN-Release-Organization': organization },
      transformResponse: [body => body],
      adapter: 'fetch', env: { fetch: ownedCatalogueFetch },
    };
    const pending = api.request<unknown>(config).then(response => {
      // An interceptor/adapter can finish after our bounded wait has refused.
      // Observe its result and cancel an unused late body; never disclose it.
      try { check(); } catch { cancelUnused(response.data); throw new CatalogueTransportError(dispatched); }
      return response;
    }, error => {
      if (axios.isAxiosError(error)) cancelUnused(error.response?.data);
      throw error;
    });
    const response = await Promise.race([pending, interrupted]);
    responseBody = response.data;
    check();
    if (!(response.headers instanceof AxiosHeaders)) throw new CatalogueTransportError(dispatched, response.status);
    const headers = response.headers;
    const mime = headers.get('content-type');
    const cache = headers.get('cache-control');
    const length = headers.get('content-length');
    if (response.status !== 200 || typeof mime !== 'string' || mime.length > 100
      || !/^application\/json\s*(?:;\s*charset=utf-8\s*)?$/i.test(mime)
      || typeof cache !== 'string' || cache.length > 500 || !cache.split(',').some(v => v.trim().toLowerCase() === 'no-store')
      || (length !== undefined && length !== null && (typeof length !== 'string'
        || !/^(?:0|[1-9][0-9]{0,15})$/.test(length) || Number(length) > CATALOGUE_BODY_BYTES))) {
      throw new CatalogueTransportError(dispatched, response.status);
    }
    const raw = await Promise.race([readReleaseCatalogueBody(responseBody, { signal, assertCurrent: check,
      abortRequest: abort }), interrupted]);
    check();
    const result = decodeReleaseCatalogue(raw, position);
    check();
    return result;
  } catch (error: unknown) {
    const status = axios.isAxiosError(error) ? error.response?.status
      : error instanceof CatalogueTransportError ? error.status : undefined;
    throw new CatalogueTransportError(dispatched, status);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    signal.removeEventListener('abort', rejectInterrupted);
    cancelUnused(responseBody);
    responseLifetime.finish();
    abort();
  }
}
