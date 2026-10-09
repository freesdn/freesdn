// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Deliberate one-attempt promotion. No automatic retry or signature claim. */
import { decodeReleasePromotion } from './releaseCatalogueCodec';
import { releaseIdentity } from './releaseOperationCodec';
import { beginReleaseOperationAction, ReleaseTransportError } from './releaseOperationTransport';

export function captureReleasePromotion(value: string) {
  const releaseId = releaseIdentity(value);
  const transport = beginReleaseOperationAction();
  let attempted = false;
  return Object.freeze({
    releaseId, assertCurrent: transport.assertCurrent, dispose: transport.dispose,
    async execute(signal?: AbortSignal) {
      transport.assertCurrent();
      if (attempted || signal?.aborted) throw new ReleaseTransportError('not-issued');
      attempted = true;
      const raw = await transport.promote(releaseId, signal);
      try {
        const observation = decodeReleasePromotion(raw, releaseId);
        transport.assertCurrent();
        return observation;
      } catch { throw new ReleaseTransportError('unconfirmed'); }
    },
  });
}
