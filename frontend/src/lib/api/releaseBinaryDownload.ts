// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Native download dispatch only. No buffered binary, token URL, saved-file
 * guarantee or cancellation of browser-owned work after dispatch. */
import { API_URL } from './client';
import { useAuthStore } from '@/stores/authStore';
import { beginReleaseOperationAction, ReleaseTransportError } from './releaseOperationTransport';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ZERO = '00000000-0000-0000-0000-000000000000';

/** Invoke synchronously at the explicit gesture after the caller validates its
 * displayed observation's generation. Account capture is not server authority. */
export function requestReleaseBinaryDownload(releaseId: string): void {
  const action = beginReleaseOperationAction();
  let anchor: HTMLAnchorElement | undefined;
  let referrerMeta: HTMLMetaElement | undefined;
  let dispatchAttempted = false;
  try {
    if (typeof releaseId !== 'string' || !UUID.test(releaseId) || releaseId === ZERO) throw new Error('identity');
    const user = useAuthStore.getState().user;
    if (!user || typeof API_URL !== 'string' || [...API_URL].some(character => character.charCodeAt(0) <= 0x20 || character.charCodeAt(0) === 0x7f)) throw new Error('configuration');
    const url = new URL(API_URL || window.location.origin, window.location.origin);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash
      || (window.location.protocol === 'https:' && url.protocol !== 'https:')) throw new Error('configuration');
    url.pathname = `${url.pathname.replace(/\/$/, '')}/api/v1/agents/releases/${releaseId}/binary`;
    url.searchParams.set('release_actor', user.id);
    url.searchParams.set('release_organization', user.organization_id ?? 'none');
    anchor = document.createElement('a');
    anchor.href = url.href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
    // Keep cross-origin navigation compatible with browser cookie policy.
    // Same-origin downloads use the document policy below: Chromium does not
    // apply the anchor policy on its native download-attribute path.
    anchor.referrerPolicy = 'no-referrer';
    document.body.append(anchor);
    if (url.origin === window.location.origin) {
      // Explicit insertion establishes the effective document policy; inspecting
      // meta tree order cannot prove it after prior metadata changes/removals.
      referrerMeta = document.createElement('meta');
      referrerMeta.name = 'referrer'; referrerMeta.content = 'no-referrer';
      document.head.append(referrerMeta);
      anchor.download = '';
    }
    action.assertCurrent();
    dispatchAttempted = true;
    anchor.click();
  } catch {
    throw new ReleaseTransportError(dispatchAttempted ? 'unconfirmed' : 'not-issued');
  } finally {
    // HTML preserves the stricter document policy after this element is removed.
    anchor?.remove(); referrerMeta?.remove(); action.dispose();
  }
}
