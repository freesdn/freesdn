// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PWA service-worker registration.
 *
 * Registered only in production builds, the dev server's HMR and the SW's
 * asset caching fight each other, and a stale SW in dev is a debugging trap.
 * Registration failures are non-fatal: the SPA works fine without a SW, it
 * just isn't installable/offline-capable until the next successful register.
 */
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD) return;
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return;

  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err) => {
      // eslint-disable-next-line no-console
      console.warn('[pwa] service worker registration failed:', err);
    });
  });
}
