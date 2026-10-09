// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PRIVATE, not imported by the public release page.
 *
 * Create at the initiating user interaction, before placing work in a queue.
 * One action object permits one mutation attempt; it never refreshes or retries.
 * Read-only inspection remains available after an uncertain mutation. Dispose
 * on UI teardown. Most returned bodies stay unknown until a qualified contract
 * decoder validates them; cataloguePage integrates its bounded page decoder.
 * Neither a catalogue nor a recorded signature is publication/cleanup authority.
 */
import axios, { type AxiosRequestConfig } from 'axios';
import { isDemoMode } from '@/demo/mode';
import { useAuthStore } from '@/stores/authStore';
import { api } from './client';
import { CatalogueTransportError, fetchReleaseCatalogue, prepareCatalogueRead } from './releaseCatalogueFetch';
import type { ReleaseCataloguePage, ReleaseCataloguePosition } from './releaseCatalogueCodec';

export type ReleaseCommandAction = 'reserve' | 'resume' | 'publish' | 'delete' | 'cancel' | 'cleanup';
export type ReleaseCatalogueFilters = { platform?: string; agent_type?: string };
export type ReleaseTransportOutcome = 'not-issued' | 'unconfirmed';
export class ReleaseTransportError extends Error {
  readonly outcome: ReleaseTransportOutcome;
  readonly status: number | undefined;
  constructor(outcome: ReleaseTransportOutcome, status?: number) {
    super(outcome === 'not-issued'
      ? 'Release request was not issued. Review the current account and original intent.'
      : 'Release outcome is unconfirmed. Retain the original intent and inspect the same operation before deciding what to do.');
    this.name = 'ReleaseTransportError';
    this.outcome = outcome;
    this.status = status;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ZERO = '00000000-0000-0000-0000-000000000000';
const COMMAND_BYTES = 307200;
const PAYLOAD_BYTES = 524288000;
const LIFETIME_MS = 600000;
let activeActions = 0;

function identity(value: string): string {
  if (typeof value !== 'string' || value === ZERO || !UUID.test(value)) throw new ReleaseTransportError('not-issued');
  return value;
}

function context() {
  const state = useAuthStore.getState();
  const user = state.user;
  if (!user || !state.isAuthenticated || !state._isHydrated || !state._isAuthInitialized
    || state.isLoading || state.mfaPending || user.is_active !== true || !state.hasPermission('agent:admin')) {
    throw new ReleaseTransportError('not-issued');
  }
  const actor = identity(user.id);
  const organization = user.organization_id === null ? 'none' : identity(user.organization_id);
  const fingerprint = JSON.stringify([actor, organization, user.role, user.is_active, user.is_superuser,
    user.is_org_admin, user.mfa_enabled, [...user.permissions].sort(), [...user.roles].sort()]);
  return { actor, organization, fingerprint };
}

function intent(raw: string, operationId?: string): Record<string, unknown> {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > COMMAND_BYTES) throw new ReleaseTransportError('not-issued');
  // Reject lone surrogates before TextEncoder could silently replace them.
  for (const character of raw) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) throw new ReleaseTransportError('not-issued');
  }
  // Browser multipart text serialization may normalize whitespace newlines.
  if (new TextEncoder().encode(raw.replace(/\r\n|\r|\n/g, '\r\n')).byteLength > COMMAND_BYTES) {
    throw new ReleaseTransportError('not-issued');
  }
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new ReleaseTransportError('not-issued'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ReleaseTransportError('not-issued');
  const object = value as Record<string, unknown>;
  if (typeof object.operation_id !== 'string' || (operationId !== undefined && object.operation_id !== operationId)) {
    throw new ReleaseTransportError('not-issued');
  }
  identity(object.operation_id);
  // This is a transport check, NOT a replacement for the server's exact codec.
  // In particular raw duplicate keys are sent unchanged and refused by server.
  return object;
}

type OnceConfig = AxiosRequestConfig & { _freesdnReleaseNoReplay: true };

/** One deliberately initiated action; no credentials or document persistence. */
export function beginReleaseOperationAction() {
  if (isDemoMode || activeActions >= 8) throw new ReleaseTransportError('not-issued');
  const initial = context();
  activeActions += 1;
  let closed = false;
  let busy = false;
  let mutationAttempted = false;
  let currentController: AbortController | undefined;
  let unsubscribe: () => void = () => undefined;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  const dispose = () => {
    if (closed) return;
    closed = true;
    activeActions -= 1;
    unsubscribe();
    if (expiry !== undefined) clearTimeout(expiry);
    currentController?.abort();
  };
  const assertCurrent = () => {
    if (closed) throw new ReleaseTransportError('not-issued');
    try {
      if (context().fingerprint !== initial.fingerprint) throw new ReleaseTransportError('not-issued');
    } catch {
      dispose();
      throw new ReleaseTransportError('not-issued');
    }
  };
  // A -> B -> A never revives an old action: the first transition closes it.
  try {
    unsubscribe = useAuthStore.subscribe(() => {
      try { assertCurrent(); } catch { dispose(); }
    });
    expiry = setTimeout(dispose, LIFETIME_MS);
    assertCurrent();
  } catch {
    dispose();
    throw new ReleaseTransportError('not-issued');
  }

  const send = async (url: string, method: 'GET' | 'POST' | 'PATCH', data: string | FormData | undefined,
    mutation: boolean, signal?: AbortSignal): Promise<unknown> => {
    assertCurrent();
    if (busy || signal?.aborted || (mutation && mutationAttempted)) throw new ReleaseTransportError('not-issued');
    busy = true;
    if (mutation) mutationAttempted = true;
    const controller = new AbortController();
    currentController = controller;
    let dispatched = false;
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const adapter = axios.getAdapter(api.defaults.adapter);
      const config: OnceConfig = {
        url, method, data, withCredentials: true, timeout: 130000, signal: controller.signal,
        _freesdnReleaseNoReplay: true,
        headers: {
          'X-FreeSDN-Release-Actor': initial.actor,
          'X-FreeSDN-Release-Organization': initial.organization,
          // FormData chooses its own boundary. No file-sized buffering or JSON
          // conversion, and the server ignores its fixed transport filename.
          'Content-Type': data instanceof FormData ? false : 'application/json',
        },
        transformRequest: [(body) => body],
        // Preserve JSON wire text for the bounded duplicate-key decoder.
        // Test adapters may still return objects; production XHR returns text.
        transformResponse: [(body) => body],
        adapter: (request) => {
          assertCurrent();
          if (controller.signal.aborted) throw new ReleaseTransportError('not-issued');
          dispatched = true;
          return adapter(request);
        },
      };
      const response = await api.request<unknown>(config);
      assertCurrent();
      return response.data;
    } catch (error: unknown) {
      // Do not retain an Axios error: it carries full intent, headers and body.
      const code = axios.isAxiosError(error) ? error.response?.status : undefined;
      throw new ReleaseTransportError(dispatched ? 'unconfirmed' : 'not-issued', code);
    } finally {
      signal?.removeEventListener('abort', onAbort);
      currentController = undefined;
      busy = false;
    }
  };
  return Object.freeze({
    assertCurrent, dispose,
    cataloguePage(position: ReleaseCataloguePosition = { limit: 50 },
      filters: ReleaseCatalogueFilters = {}, signal?: AbortSignal): Promise<ReleaseCataloguePage> {
      // Capture all navigation values synchronously before an interceptor can wait.
      let prepared: ReturnType<typeof prepareCatalogueRead>;
      try { prepared = prepareCatalogueRead(position, filters); } catch { throw new ReleaseTransportError('not-issued'); }
      assertCurrent();
      if (busy || signal?.aborted) throw new ReleaseTransportError('not-issued');
      busy = true;
      const controller = new AbortController();
      currentController = controller;
      const onAbort = () => controller.abort();
      signal?.addEventListener('abort', onAbort, { once: true });
      return fetchReleaseCatalogue(prepared, { actor: initial.actor, organization: initial.organization,
        signal: controller.signal, assertCurrent, abortRequest: onAbort }).catch((error: unknown) => {
        throw new ReleaseTransportError(error instanceof CatalogueTransportError && error.issued
          ? 'unconfirmed' : 'not-issued', error instanceof CatalogueTransportError ? error.status : undefined);
      }).finally(() => {
        signal?.removeEventListener('abort', onAbort);
        currentController = undefined;
        busy = false;
      });
    },
    catalogue(filters: ReleaseCatalogueFilters = {}, signal?: AbortSignal) {
      // Build the path synchronously. Later edits to a caller's filter object
      // cannot change this request after an interceptor or adapter wait.
      if (!filters || typeof filters !== 'object' || Array.isArray(filters)
        || Object.keys(filters).some(key => !['platform', 'agent_type'].includes(key))) {
        throw new ReleaseTransportError('not-issued');
      }
      const query = new URLSearchParams();
      for (const key of ['platform', 'agent_type'] as const) {
        const value = filters[key];
        if (value === undefined) continue;
        if (typeof value !== 'string' || !/^[A-Za-z0-9._+-]{1,50}$/.test(value)) {
          throw new ReleaseTransportError('not-issued');
        }
        query.set(key, value);
      }
      const suffix = query.toString();
      // This is raw catalogue transport, not bounded pagination, response
      // validation, signature verification or new mutation authority.
      return send(`/agents/releases${suffix ? `?${suffix}` : ''}`, 'GET', undefined, false, signal);
    },
    promote(releaseId: string, signal?: AbortSignal) {
      // A lost acknowledgment must not cause an implicit second promotion.
      // The server independently verifies signature, scope and current state.
      return send(`/agents/releases/${identity(releaseId)}/promote`, 'PATCH', undefined, true, signal);
    },
    inspect(operationId: string, signal?: AbortSignal) {
      return send(`/agents/release-operations/${identity(operationId)}`, 'GET', undefined, false, signal);
    },
    review(raw: string, signal?: AbortSignal) {
      intent(raw);
      return send('/agents/release-operation-intents/review', 'POST', raw, false, signal);
    },
    reviewDeletion(releaseId: string, operationId: string, signal?: AbortSignal) {
      return send(`/agents/releases/${identity(releaseId)}/deletion-intent/${identity(operationId)}`, 'GET', undefined, false, signal);
    },
    command(operationId: string, action: ReleaseCommandAction, raw: string, signal?: AbortSignal) {
      identity(operationId);
      if (!['reserve', 'resume', 'publish', 'delete', 'cancel', 'cleanup'].includes(action)) throw new ReleaseTransportError('not-issued');
      intent(raw, operationId);
      return send(`/agents/release-operations/${operationId}/${action}`, 'POST', raw, true, signal);
    },
    upload(operationId: string, raw: string, file: Blob, signal?: AbortSignal) {
      identity(operationId);
      const value = intent(raw, operationId);
      const metadata = value.metadata;
      if (value.kind !== 'publish' || value.storage_kind !== 'owned' || !(file instanceof Blob)
        || file.size > PAYLOAD_BYTES || !metadata || typeof metadata !== 'object' || Array.isArray(metadata)
        || (metadata as Record<string, unknown>).file_size !== file.size) throw new ReleaseTransportError('not-issued');
      const form = new FormData();
      // A STRING field deliberately has no filename. A JSON Blob would acquire
      // filename=blob and be rejected by the existing intent-first parser.
      form.append('intent', raw);
      // Construct a named File explicitly so DOM implementations preserve the
      // same fixed transport filename. Blob parts keep the immutable slice;
      // no application-level arrayBuffer or full-file read is introduced.
      const payload = new File([file.slice(0, file.size, 'application/octet-stream')],
        'payload.bin', { type: 'application/octet-stream' });
      form.append('file', payload, 'payload.bin');
      return send(`/agents/release-operations/${operationId}/upload`, 'POST', form, true, signal);
    },
  });
}
