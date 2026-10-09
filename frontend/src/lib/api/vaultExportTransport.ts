// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private workflow transport. Not connected to BackupsPage yet.
 * All secrets are ephemeral; disposal drops references, not guaranteed JS
 * string erasure. A cancelled/lost response never proves server rollback.
 */
import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import { z } from 'zod';
import { isDemoMode } from '@/demo/mode';
import { useAuthStore } from '@/stores/authStore';
import { api } from './client';

export class VaultTransportError extends Error {
  readonly outcome: 'not-issued' | 'unconfirmed';
  readonly status?: number;
  constructor(outcome: 'not-issued' | 'unconfirmed', status?: number) {
    super(outcome === 'not-issued'
      ? 'Vault request was not issued. Start fresh confirmation in the current account.'
      : 'Vault outcome is unconfirmed. Inspect the backup catalogue before starting another operation.');
    this.name = 'VaultTransportError'; this.outcome = outcome; this.status = status;
  }
}
const refuse = (): never => { throw new VaultTransportError('not-issued'); };
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  .refine(v => v !== '00000000-0000-0000-0000-000000000000');
const scalar = (v: string) => [...v].every(c => { const n = c.codePointAt(0)!; return n < 0xd800 || n > 0xdfff; });
const text = (max: number, min = 0) => z.string().refine(v => v.length <= max * 2
  && [...v].length >= min && [...v].length <= max && scalar(v) && !v.includes('\0'));
const token = z.string().min(1).max(8192).regex(/^[A-Za-z0-9._~-]+$/);
const expiry = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const bytesLimit = 200 * 1024 * 1024;
const identity = z.object({ version: z.literal(1), bytes: z.number().int().min(1).max(bytesLimit),
  sha256: z.string().regex(/^[0-9a-f]{64}$/) }).strict();
const backup = z.object({ name: text(128), description: text(2000).nullable().optional(),
  backup_type: text(32).optional(), site_id: uuid.nullable().optional(),
  device_ids: z.array(uuid).max(1000).nullable().optional(),
  include_devices: z.boolean().optional(), include_vlans: z.boolean().optional(),
  include_ssids: z.boolean().optional(), include_users: z.boolean().optional(),
  include_automation: z.boolean().optional(), storage_type: text(32).optional(),
  storage_location_id: uuid.nullable().optional(), is_encrypted: z.literal(true).optional(),
  include_secrets: z.literal(true), passphrase: text(512, 12),
  retention_days: z.number().int().min(1).max(3650).optional() }).strict();
const intentSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('create'), backup }).strict(),
  z.object({ kind: z.literal('download_recorded'), backup_id: uuid }).strict(),
  z.object({ kind: z.literal('observe_legacy'), backup_id: uuid, legacy_acknowledged: z.literal(true) }).strict(),
]);
export type VaultBrowserIntent = z.infer<typeof intentSchema>;
export type VaultArtifactIdentity = z.infer<typeof identity>;
const requirementsResponse = z.object({ method: z.enum(['local', 'ldap', 'oidc']),
  mfa_required: z.boolean(), oidc_redirect_uri: text(2048, 1).nullable() }).strict();
export type VaultFactorRequirements = z.infer<typeof requirementsResponse>;
type Phase = 'new' | 'oidc' | 'identity' | 'authorized' | 'legacy-observed' | 'spent';
type OnceConfig = AxiosRequestConfig & { _freesdnVaultNoReplay: true };
const proofResponse = z.object({ proof: token }).strict();
const identityResponse = z.object({ identity_token: token, expires_at: expiry }).strict();
const oidcResponse = z.object({ authorize_url: text(16384, 1), state: token, expires_at: expiry }).strict();
const legacyResponse = z.object({ operation: z.literal('download_legacy'), proof: token,
  artifact_integrity: z.literal('legacy_unverified'), observed_identity: identity,
  authentication_expires_at: expiry }).strict();
const createdResponse = z.object({ id: uuid, include_secrets: z.literal(true), status: text(32, 1) });

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(value); } catch { return refuse(); }
}
function wire(value: unknown): string {
  try {
    const raw = JSON.stringify(value);
    if (!raw || !scalar(raw) || raw.length > 131072 || new TextEncoder().encode(raw).byteLength > 131072) return refuse();
    return raw;
  } catch { return refuse(); }
}
function context() {
  const s = useAuthStore.getState(); const u = s.user;
  if (!u || !s.isAuthenticated || !s._isHydrated || !s._isAuthInitialized || s.isLoading || s.mfaPending
    || u.is_active !== true || u.is_superuser !== true || u.role !== 'super_admin') return refuse();
  const actor = parse(uuid, u.id); const organization = parse(uuid, u.organization_id);
  return { actor, organization, fingerprint: wire([actor, organization, u.role, u.is_active,
    u.is_superuser, u.is_org_admin, u.mfa_enabled, [...u.permissions].sort(), [...u.roles].sort()]) };
}
let active = 0;

/** Capture exactly one user-initiated intent before any queue/interceptor wait.
 * Server authority/factors remain decisive. Browser context is an equality
 * assertion, not permission. The caller must dispose on unmount/dialog close.
 */
export function beginVaultExport(rawIntent: VaultBrowserIntent) {
  if (isDemoMode || active >= 8) return refuse();
  const initial = context();
  let document: VaultBrowserIntent | undefined = parse(intentSchema, rawIntent);
  let intentText: string | undefined = wire(document);
  let phase: Phase = 'new'; let busy = false; let closed = false; let hintRead = false;
  let proof: string | undefined; let external: string | undefined; let state: string | undefined;
  let externalExpiry = 0; let externalDeadline = 0; let observed: VaultArtifactIdentity | undefined;
  let controller: AbortController | undefined;
  const started = performance.now();
  active += 1;
  let unsubscribe = () => undefined as void;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const dispose = () => {
    if (closed) return;
    closed = true; active -= 1; unsubscribe(); if (timer !== undefined) clearTimeout(timer);
    controller?.abort(); proof = undefined; external = undefined; state = undefined;
    document = undefined; intentText = undefined; observed = undefined;
  };
  const assertCurrent = () => {
    try {
      if (closed || performance.now() - started >= 600000 || context().fingerprint !== initial.fingerprint) return refuse();
    } catch { dispose(); return refuse(); }
  };
  try {
    unsubscribe = useAuthStore.subscribe(() => { try { assertCurrent(); } catch { dispose(); } });
    timer = setTimeout(dispose, 600000); assertCurrent();
  } catch { dispose(); return refuse(); }

  const setExpiry = (value: number) => {
    const remaining = value * 1000 - Date.now();
    if (remaining <= 0 || remaining > 600000) return refuse();
    externalExpiry = value; externalDeadline = performance.now() + remaining;
  };
  const requireFresh = () => {
    if (Date.now() >= externalExpiry * 1000 || performance.now() >= externalDeadline) return refuse();
  };
  const requiresExpiry = (value: Phase) => ['oidc', 'identity', 'legacy-observed'].includes(value);

  const send = async <T>(allowed: Phase, url: string, method: 'GET' | 'POST', body: string | undefined,
    proofHeader: string | undefined, binary: boolean, decode: (response: AxiosResponse<unknown>) => T): Promise<T> => {
    assertCurrent();
    if (busy || phase !== allowed) return refuse();
    busy = true; let issued = false; const own = new AbortController(); controller = own;
    try {
      const adapter = axios.getAdapter(api.defaults.adapter);
      const config: OnceConfig = { url, method, data: body, withCredentials: true, timeout: 130000,
        signal: own.signal, _freesdnVaultNoReplay: true, responseType: binary ? 'blob' : 'json',
        headers: { 'Content-Type': 'application/json', 'X-FreeSDN-Vault-Actor': initial.actor,
          'X-FreeSDN-Vault-Organization': initial.organization,
          ...(proofHeader ? { 'X-FreeSDN-Vault-Proof': proofHeader } : {}) },
        transformRequest: [v => v],
        onDownloadProgress: event => { if (event.loaded > (binary ? bytesLimit : 131072)) own.abort(); },
        adapter: request => {
          assertCurrent(); if (own.signal.aborted) return refuse();
          if (requiresExpiry(allowed)) requireFresh();
          issued = true; return adapter(request);
        } };
      const response = await api.request<unknown>(config);
      assertCurrent(); if (own.signal.aborted) return refuse();
      if (requiresExpiry(allowed)) requireFresh();
      if (!binary) wire(response.data);
      return decode(response);
    } catch (error: unknown) {
      const status = axios.isAxiosError(error) && Number.isInteger(error.response?.status) ? error.response?.status : undefined;
      dispose();
      // Never attach the original error, body, headers, tokens or provider URL.
      throw new VaultTransportError(issued ? 'unconfirmed' : 'not-issued', status);
    } finally { busy = false; controller = undefined; }
  };
  const command = (fields: Record<string, unknown>) => wire({ intent: JSON.parse(intentText ?? ''), ...fields });
  const acceptProof = (response: AxiosResponse<unknown>) => { proof = parse(proofResponse, response.data).proof; phase = 'authorized'; };
  const acceptIdentity = (response: AxiosResponse<unknown>) => {
    const value = parse(identityResponse, response.data); setExpiry(value.expires_at);
    external = value.identity_token; phase = 'identity';
  };
  const before = (required: Phase) => { assertCurrent(); if (busy || phase !== required) return refuse(); };
  const safe = <T>(call: () => Promise<T>): Promise<T> => {
    try { return call(); } catch { return Promise.reject(new VaultTransportError('not-issued')); }
  };
  const blob = (response: AxiosResponse<unknown>, legacy: boolean) => {
    const value = response.data;
    const classification = response.headers['x-freesdn-artifact-integrity'];
    if (!(value instanceof Blob) || value.size < 1 || value.size > bytesLimit
      || classification !== (legacy ? 'legacy_unverified' : 'verified')
      || (legacy && value.size !== observed?.bytes)) return refuse();
    phase = 'spent'; proof = undefined;
    // Do not trust Content-Disposition as a pathname. The caller may supply a
    // safe display name and must recheck assertCurrent immediately before save.
    return { blob: value, artifact_integrity: legacy ? 'legacy_unverified' as const : 'verified' as const };
  };
  return Object.freeze({ assertCurrent, dispose,
    requirements() { return safe(() => {
      before('new'); if (hintRead) return refuse(); hintRead = true;
      const action = document?.kind === 'create' ? 'create' : 'download';
      return send('new', `/auth/vault-export/requirements?action=${action}`, 'GET', undefined, undefined, false, response => {
        const value = parse(requirementsResponse, response.data);
        if (value.method !== 'oidc' && value.oidc_redirect_uri !== null) return refuse();
        if (value.oidc_redirect_uri !== null) {
          const url = new URL(value.oidc_redirect_uri);
          if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return refuse();
        }
        // Observation is not a factor or a permission. The server rechecks
        // the account and provider independently for every subsequent call.
        return value;
      });
    }); },
    authorizeLocal(password: string, mfaCode?: string) { return safe(() => {
      before('new'); const fields = { password: parse(text(1024, 1), password),
        ...(mfaCode === undefined ? {} : { mfa_code: parse(text(10, 1), mfaCode) }) };
      return send('new', '/auth/vault-export/authorize/local', 'POST', command(fields), undefined, false, acceptProof);
    }); },
    confirmLdap(password: string) { return safe(() => {
      before('new'); return send('new', '/auth/vault-export/identity/ldap', 'POST',
        command({ password: parse(text(1024, 1), password) }), undefined, false, acceptIdentity);
    }); },
    beginOidc() { return safe(() => {
      before('new'); return send('new', '/auth/vault-export/identity/oidc/start', 'POST', command({}), undefined, false, response => {
        const value = parse(oidcResponse, response.data); const url = new URL(value.authorize_url);
        if (url.protocol !== 'https:' || url.username || url.password || url.hash
          || url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== value.state) return refuse();
        setExpiry(value.expires_at); state = value.state; phase = 'oidc';
        return { authorize_url: value.authorize_url, state: value.state, expires_at: value.expires_at };
      });
    }); },
    completeOidc(callbackState: string, code: string) { return safe(() => {
      before('oidc'); requireFresh(); if (callbackState !== state) return refuse();
      return send('oidc', '/auth/vault-export/identity/oidc/complete', 'POST',
        command({ state, code: parse(text(8192, 1), code) }), undefined, false, acceptIdentity);
    }); },
    authorizeExternal(mfaCode?: string) { return safe(() => {
      before('identity'); requireFresh();
      return send('identity', '/auth/vault-export/authorize/external', 'POST', command({ identity_token: external,
        ...(mfaCode === undefined ? {} : { mfa_code: parse(text(10, 1), mfaCode) }) }), undefined, false, response => {
        acceptProof(response); external = undefined; state = undefined;
      });
    }); },
    create() { return safe(() => {
      before('authorized'); if (document?.kind !== 'create') return refuse();
      return send('authorized', '/backups/', 'POST', wire(document.backup), proof, false, response => {
        const value = parse(createdResponse, response.data); phase = 'spent'; proof = undefined;
        // Keep no passphrase in a completed action and expose only catalogue identity.
        document = undefined; intentText = undefined;
        return { id: value.id, status: value.status };
      });
    }); },
    observeLegacy() { return safe(() => {
      before('authorized'); if (document?.kind !== 'observe_legacy') return refuse();
      return send('authorized', `/backups/${document.backup_id}/vault-observation`, 'POST',
        wire({ legacy_acknowledged: true }), proof, false, response => {
          const value = parse(legacyResponse, response.data); setExpiry(value.authentication_expires_at);
          observed = value.observed_identity; proof = value.proof; phase = 'legacy-observed';
          return { observed_identity: { ...observed }, artifact_integrity: 'legacy_unverified' as const,
            authentication_expires_at: externalExpiry };
        });
    }); },
    download() { return safe(() => {
      assertCurrent();
      if (document?.kind === 'download_recorded') {
        before('authorized'); return send('authorized', `/backups/${document.backup_id}/download`, 'GET', undefined,
          proof, true, response => blob(response, false));
      }
      before('legacy-observed'); requireFresh();
      if (document?.kind !== 'observe_legacy' || !observed) return refuse();
      return send('legacy-observed', `/backups/${document.backup_id}/vault-download`, 'POST',
        wire({ legacy_acknowledged: true, observed_identity: observed }), proof, true, response => blob(response, true));
    }); },
  });
}
