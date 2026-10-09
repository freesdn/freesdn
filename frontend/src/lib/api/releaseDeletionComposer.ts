// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Private deletion-intent preparation. One captured read, never a mutation.
 * The caller must dispose on teardown and feed getIntent into retained-file
 * verification/review. A matched historical row grants no deletion authority.
 */
import { captureReleaseRequest } from './releaseOperationClient';
import { decodeReleaseIntent, releaseIdentity } from './releaseOperationCodec';
import { ReleaseTransportError } from './releaseOperationTransport';

export function captureReleaseDeletion(selectedReleaseId: string) {
  const releaseId = releaseIdentity(selectedReleaseId);
  const operationId = releaseIdentity(crypto.randomUUID());
  const request = captureReleaseRequest({ kind: 'deletion-review', releaseId, operationId });
  const controller = new AbortController();
  let closed = false;
  let attempted = false;
  let completed: string | undefined;
  const dispose = () => {
    if (closed) return;
    closed = true; completed = undefined; controller.abort(); request.dispose();
  };
  const assertCurrent = () => {
    if (closed) throw new ReleaseTransportError('not-issued');
    try { request.assertCurrent(); }
    catch { dispose(); throw new ReleaseTransportError('not-issued'); }
  };
  return Object.freeze({
    snapshot: Object.freeze({ releaseId, operationId }), assertCurrent, dispose,
    async execute(signal?: AbortSignal): Promise<void> {
      assertCurrent();
      if (attempted || signal?.aborted) throw new ReleaseTransportError('not-issued');
      attempted = true;
      const abort = () => dispose();
      signal?.addEventListener('abort', abort, { once: true });
      try {
        assertCurrent();
        if (signal?.aborted) throw new ReleaseTransportError('not-issued');
        const observation = await request.execute(controller.signal);
        assertCurrent();
        if (signal?.aborted || !('intent' in observation) || observation.intent.kind !== 'delete'
          || observation.deletion_target_matches !== true || observation.release_row_present !== true
          || observation.operation !== null) throw new ReleaseTransportError('unconfirmed');
        // The existing decoder already checked exact identity, full commitment
        // and safety flags. Preserve original metadata spelling, including case
        // and timestamps; do not reconstruct it from stale catalogue columns.
        const raw = JSON.stringify(observation.intent);
        const document = decodeReleaseIntent(raw);
        if (document.kind !== 'delete' || document.release_id !== releaseId
          || document.operation_id !== operationId) throw new ReleaseTransportError('unconfirmed');
        assertCurrent(); completed = raw;
      } catch (error) {
        dispose();
        if (error instanceof ReleaseTransportError) throw new ReleaseTransportError(error.outcome, error.status);
        throw new ReleaseTransportError('unconfirmed');
      } finally { signal?.removeEventListener('abort', abort); }
    },
    getIntent(): string {
      assertCurrent();
      if (completed === undefined) throw new ReleaseTransportError('not-issued');
      return completed;
    },
  });
}
