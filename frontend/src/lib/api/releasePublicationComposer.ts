// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE creator. Capture at the form gesture; no requests or mutations.
 * The caller must dispose on teardown and feed getIntent into retained-file
 * review. A calculated checksum never replaces server byte verification.
 */
import { useAuthStore } from '@/stores/authStore';
import { beginReleaseOperationAction } from './releaseOperationTransport';
import { decodeReleaseIntent, releaseIdentity } from './releaseOperationCodec';
import { hashReleasePayload, ReleaseHashError } from './releasePayloadHash';

type Fields = { organization_id: string | null; version: string; platform: 'linux' | 'windows' | 'macos';
  agent_type: 'daemon' | 'desktop'; release_notes: string; min_backend_version: string; is_prerelease: boolean; is_latest: boolean };
export type ReleasePublicationDraft = Fields & (
  { storage_kind: 'owned'; file: File } |
  { storage_kind: 'external'; download_url: string; checksum_sha256: string; file_size: number }
);
export function captureReleasePublication(input: ReleasePublicationDraft) {
  const scope = beginReleaseOperationAction();
  let unsubscribe = () => undefined as void;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  let closed = false;
  const controller = new AbortController();
  const dispose = () => { if (closed) return; closed = true; unsubscribe(); clearTimeout(expiry); controller.abort(); scope.dispose(); };
  const assertCurrent = () => { if (closed) throw new ReleaseHashError(); try { scope.assertCurrent(); } catch { dispose(); throw new ReleaseHashError(); } };
  let raw: string;
  let payload: Blob | undefined;
  let attempted = false;
  let completed: string | undefined;
  try {
    // Never trust the TypeScript type at a JS/form boundary. Select only the
    // supported fields; the strict codec validates all scalar values/bounds.
    const operationId = releaseIdentity(crypto.randomUUID());
    const releaseId = releaseIdentity(crypto.randomUUID());
    const base = { operation_id: operationId, release_id: releaseId, organization_id: input.organization_id,
      kind: 'publish', storage_kind: input.storage_kind,
      metadata: { version: input.version, platform: input.platform, agent_type: input.agent_type,
        release_notes: input.release_notes, min_backend_version: input.min_backend_version,
        is_prerelease: input.is_prerelease, is_latest: input.is_latest } };
    if (input.storage_kind === 'owned') {
      if (!(input.file instanceof File)) throw new ReleaseHashError();
      // This is display/download metadata; it is never a caller-supplied path.
      const filename = input.file.name;
      const size = input.file.size;
      payload = input.file.slice(0, size, 'application/octet-stream');
      if (payload.size !== size) throw new ReleaseHashError();
      raw = JSON.stringify({ ...base, metadata: { ...base.metadata, file_size: size, filename,
        checksum_sha256: '0'.repeat(64), download_url: `/api/v1/agents/releases/${releaseId}/binary` } });
    } else if (input.storage_kind === 'external') {
      raw = JSON.stringify({ ...base, metadata: { ...base.metadata, filename: null,
        file_size: input.file_size, checksum_sha256: input.checksum_sha256, download_url: input.download_url } });
    } else { throw new ReleaseHashError(); }
    decodeReleaseIntent(raw); // Invalid metadata is refused before any worker.
    unsubscribe = useAuthStore.subscribe(() => { try { assertCurrent(); } catch { dispose(); } });
    expiry = setTimeout(dispose, 600000);
    assertCurrent();
  } catch { dispose(); throw new ReleaseHashError(); }
  return Object.freeze({
    assertCurrent, dispose,
    async execute(signal?: AbortSignal, onProgress?: (bytes: number, total: number) => void): Promise<void> {
      assertCurrent(); if (attempted || signal?.aborted) throw new ReleaseHashError();
      attempted = true;
      const abort = () => dispose(); signal?.addEventListener('abort', abort, { once: true });
      try {
        assertCurrent(); if (signal?.aborted) throw new ReleaseHashError();
        let candidate = raw;
        if (payload) {
          const checksum = await hashReleasePayload(payload, { signal: controller.signal, assertCurrent, onProgress });
          assertCurrent();
          const document = decodeReleaseIntent(raw);
          candidate = JSON.stringify({ ...document, metadata: { ...document.metadata, checksum_sha256: checksum } });
        }
        assertCurrent(); if (signal?.aborted) throw new ReleaseHashError();
        decodeReleaseIntent(candidate); completed = candidate;
      } catch { dispose(); throw new ReleaseHashError(); }
      finally { signal?.removeEventListener('abort', abort); }
    },
    getIntent(): string {
      assertCurrent(); if (completed === undefined) throw new ReleaseHashError();
      return completed;
    },
    getPayload(): Blob | undefined { assertCurrent(); if (completed === undefined) throw new ReleaseHashError(); return payload; },
  });
}
