// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Browser WebPush helpers, request permission, subscribe via the service
 * worker's PushManager using the server's VAPID key, and register/deregister
 * the subscription with the backend.
 *
 * Push requires a registered service worker, which FreeSDN only registers in
 * production builds (see lib/pwa.ts), so in dev these helpers report
 * "unavailable" rather than hanging on `serviceWorker.ready`.
 */
import { pushApi } from '@/lib/api/cameras';

export type PushStatus =
  | 'unsupported' // browser lacks SW/PushManager/Notification, or no SW registered (dev)
  | 'unconfigured' // server has no VAPID keys
  | 'denied' // user blocked notifications
  | 'subscribed'
  | 'unsubscribed';

function browserSupportsPush(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'serviceWorker' in navigator &&
    typeof window !== 'undefined' &&
    'PushManager' in window &&
    'Notification' in window
  );
}

/** VAPID base64url key → the Uint8Array `applicationServerKey` wants. */
function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function getRegistration(): Promise<ServiceWorkerRegistration | undefined> {
  if (!browserSupportsPush()) return undefined;
  try {
    return await navigator.serviceWorker.getRegistration();
  } catch {
    return undefined;
  }
}

/** Current push state for this browser (cheap; safe to poll on mount). */
export async function getPushStatus(): Promise<PushStatus> {
  if (!browserSupportsPush()) return 'unsupported';
  if (Notification.permission === 'denied') return 'denied';
  const reg = await getRegistration();
  if (!reg) return 'unsupported'; // no SW (dev / not yet installed)
  const existing = await reg.pushManager.getSubscription();
  return existing ? 'subscribed' : 'unsubscribed';
}

/**
 * Turn push ON: request permission, subscribe through the SW's PushManager
 * with the server VAPID key, and register the subscription with the backend.
 * Throws a human-readable Error on any blocking condition.
 */
export async function enablePush(): Promise<void> {
  if (!browserSupportsPush()) throw new Error('Push notifications are not supported in this browser.');

  const { data } = await pushApi.getVapidKey();
  if (!data?.enabled || !data.public_key) {
    throw new Error('Push notifications are not configured on this server.');
  }

  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    throw new Error('Notification permission was not granted.');
  }

  const reg = await getRegistration();
  if (!reg) throw new Error('The app must be installed/loaded over HTTPS for push to work.');

  const existing = await reg.pushManager.getSubscription();
  const subscription =
    existing ??
    (await reg.pushManager.subscribe({
      userVisibleOnly: true,
      // Cast: the bytes are a valid BufferSource at runtime; TS 5.7's
      // Uint8Array<ArrayBufferLike> vs BufferSource narrowing is the only gap.
      applicationServerKey: urlBase64ToUint8Array(data.public_key) as BufferSource,
    }));

  await pushApi.subscribe(subscription.toJSON() as PushSubscriptionJSON);
}

/** Turn push OFF: deregister with the backend, then unsubscribe locally. */
export async function disablePush(): Promise<void> {
  const reg = await getRegistration();
  if (!reg) return;
  const existing = await reg.pushManager.getSubscription();
  if (!existing) return;
  // Tell the backend first so it stops sending even if the local unsubscribe
  // fails; ignore backend errors (the local unsubscribe is what the user sees).
  try {
    await pushApi.unsubscribe(existing.endpoint);
  } catch {
    /* best-effort */
  }
  await existing.unsubscribe();
}
