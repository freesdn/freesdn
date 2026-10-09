// SPDX-License-Identifier: AGPL-3.0-only
/** One initiating account and one probe request; no automatic refresh/replay.
 * A failed, cancelled or expired reply cannot establish remote rollback.
 * The server still checks current credentials and location ownership. These
 * browser identity headers express equality only, never permission.
 */
import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import { useAuthStore } from '@/stores/authStore';
import { api } from './client';
import type { StorageLocationTestResult } from './types';

export class StorageProbeError extends Error {
  readonly outcome: 'not-issued' | 'unconfirmed';
  readonly status?: number;
  constructor(outcome: 'not-issued' | 'unconfirmed', status?: number) {
    super(outcome === 'not-issued'
      ? 'Storage test was not issued. Check the current account and location.'
      : 'Storage test outcome is unconfirmed. The operation may have run; check the destination before repeating it.');
    this.name = 'StorageProbeError'; this.outcome = outcome; this.status = status;
  }
}
const lifetime = 180000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const zero = '00000000-0000-0000-0000-000000000000';
let active = 0;
const refuse = (): never => { throw new StorageProbeError('not-issued'); };
function identity(value: unknown): string {
  return typeof value === 'string' && value !== zero && UUID.test(value) ? value : refuse();
}
function claims(values: unknown): string[] {
  if (!Array.isArray(values) || values.length > 256
    || values.some(v => typeof v !== 'string' || v.length > 256)) return refuse();
  return [...values].sort();
}
function context() {
  const state = useAuthStore.getState(); const user = state.user;
  if (!user || !state.isAuthenticated || !state._isHydrated || !state._isAuthInitialized
    || state.isLoading || state.mfaPending || user.is_active !== true || user.is_org_admin !== true
    || !['admin', 'org_admin', 'super_admin'].includes(user.role)) return refuse();
  const actor = identity(user.id), organization = identity(user.organization_id);
  const fingerprint = JSON.stringify([actor, organization, user.role, user.is_active,
    user.is_org_admin, user.is_superuser, user.mfa_enabled, claims(user.roles), claims(user.permissions)]);
  return { actor, organization, fingerprint };
}
type OnceConfig = AxiosRequestConfig & { _freesdnStorageProbeNoReplay: true };

/** Capture at the initiating click before any application/interceptor queue.
 * Call dispose on UI teardown. A -> B -> A does not revive an old request.
 * One action object cannot issue a second probe, including after a failure.
 */
export function beginStorageProbe(locationId: string) {
  const location = identity(locationId); const initial = context();
  if (active >= 8) return refuse();
  active += 1;
  const started = performance.now();
  let closed = false, attempted = false;
  let controller: AbortController | undefined;
  let unsubscribe: () => void = () => undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const dispose = () => {
    if (closed) return;
    closed = true; active -= 1; unsubscribe();
    if (timer !== undefined) clearTimeout(timer);
    controller?.abort();
  };
  const assertCurrent = () => {
    try {
      if (closed || performance.now() - started >= lifetime || context().fingerprint !== initial.fingerprint) return refuse();
    } catch { dispose(); return refuse(); }
  };
  try {
    unsubscribe = useAuthStore.subscribe(() => { try { assertCurrent(); } catch { dispose(); } });
    timer = setTimeout(dispose, lifetime); assertCurrent();
  } catch { dispose(); return refuse(); }

  const run = async (signal?: AbortSignal): Promise<AxiosResponse<StorageLocationTestResult>> => {
    assertCurrent();
    if (attempted || signal?.aborted) return refuse();
    attempted = true;
    const own = new AbortController(); controller = own;
    let issued = false;
    const abort = () => own.abort();
    signal?.addEventListener('abort', abort, { once: true });
    try {
      const adapter = axios.getAdapter(api.defaults.adapter);
      const config: OnceConfig = {
        method: 'POST', url: `/backups/storage-locations/${location}/test`,
        withCredentials: true, timeout: lifetime, signal: own.signal,
        _freesdnStorageProbeNoReplay: true,
        headers: { 'X-FreeSDN-Storage-Probe-Actor': initial.actor,
          'X-FreeSDN-Storage-Probe-Organization': initial.organization },
        adapter: request => {
          assertCurrent();
          if (issued || own.signal.aborted || signal?.aborted) return refuse();
          issued = true;
          return adapter(request);
        },
      };
      const response = await api.request<StorageLocationTestResult>(config);
      assertCurrent();
      if (own.signal.aborted || signal?.aborted) return refuse();
      return response;
    } catch (error: unknown) {
      // An Axios error may retain response details, headers or request data.
      // Preserve only the numeric status and whether dispatch could have run.
      const status = axios.isAxiosError(error) ? error.response?.status : undefined;
      throw new StorageProbeError(issued ? 'unconfirmed' : 'not-issued', status);
    } finally {
      signal?.removeEventListener('abort', abort);
      controller = undefined;
    }
  };
  return Object.freeze({ assertCurrent, dispose, run });
}

/** Compatibility entry point. UI retaining a result should own an action and
 * recheck it before displaying; this helper covers transport acceptance only.
 */
export async function testStorageLocation(id: string, signal?: AbortSignal) {
  const action = beginStorageProbe(id);
  try { return await action.run(signal); } finally { action.dispose(); }
}
