// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Global Vitest setup file.
 *
 * Runs once per test file (Vitest re-runs setup per worker, not per test).
 * Responsibilities:
 *   - Register jest-dom custom matchers (`toBeInTheDocument`, etc.).
 *   - Auto-cleanup the DOM between tests so a stray component from the
 *     previous test can't bleed into the next.
 *   - Polyfill browser APIs that happy-dom doesn't ship (matchMedia,
 *     ResizeObserver, IntersectionObserver, Element.scrollIntoView).
 */
import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

// Initialize the GLOBAL i18n instance with the real English bundles so that
// components using useTranslation() rendered via a bare @testing-library
// `render()` (no I18nextProvider) still resolve real English copy. This
// mirrors production, where src/lib/i18n.ts initializes i18n globally on
// import. Tests using renderWithProviders get their own instance; both
// carry the same en data. Without this, t() returns raw keys and every
// text/aria assertion on a now-localized component fails.
if (!i18n.isInitialized) {
  const enResources: Record<string, Record<string, unknown>> = {};
  try {
    const dir = resolve(process.cwd(), 'public/locales/en');
    for (const file of readdirSync(dir)) {
      if (file.endsWith('.json')) {
        enResources[file.replace(/\.json$/, '')] = JSON.parse(
          readFileSync(resolve(dir, file), 'utf8'),
        );
      }
    }
  } catch {
    /* leave empty, components fall back to keys */
  }
  void i18n.use(initReactI18next).init({
    lng: 'en',
    fallbackLng: 'en',
    defaultNS: 'common',
    ns: Object.keys(enResources),
    resources: { en: enResources },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
}

afterEach(() => {
  cleanup();
});

// ---------------------------------------------------------------------------
// Web Storage.
//
// Node 26 ships its own EXPERIMENTAL `localStorage` / `sessionStorage` globals,
// and they are `undefined` unless the process was started with
// `--localstorage-file`. Node 24 had no such globals at all, so a bare
// `localStorage` reference resolved to happy-dom's. On Node 26 it resolves to
// Node's own undefined global instead, which shadows happy-dom entirely for
// any code that does not go through `window`.
//
// Zustand's `persist` middleware does exactly that -- its default
// `createJSONStorage` returns bare `localStorage` -- so every store using
// persist() threw
//
//     TypeError: Cannot read properties of undefined (reading 'setItem')
//
// and 66 tests across 9 files failed on Node 26 while passing on Node 24. The
// production image builds on node:26.7.0, so CI was green on a runtime the
// shipped image does not use.
//
// Bind the globals to a working implementation: happy-dom's if it exists,
// otherwise an in-memory one. No-op on Node 24, where the globals already
// resolve correctly.
// ---------------------------------------------------------------------------
function createMemoryStorage(): Storage {
  let store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    getItem: (key: string) => (store.has(key) ? (store.get(key) as string) : null),
    setItem: (key: string, value: string) => {
      store.set(key, String(value));
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
    clear: () => {
      store = new Map<string, string>();
    },
  } as Storage;
}

for (const name of ['localStorage', 'sessionStorage'] as const) {
  const current = (globalThis as Record<string, unknown>)[name] as Storage | undefined;
  if (current && typeof current.setItem === 'function') continue;

  const fromWindow =
    typeof window !== 'undefined'
      ? ((window as unknown as Record<string, unknown>)[name] as Storage | undefined)
      : undefined;

  Object.defineProperty(globalThis, name, {
    value: fromWindow && typeof fromWindow.setItem === 'function' ? fromWindow : createMemoryStorage(),
    configurable: true,
    writable: true,
  });
}

if (typeof window !== 'undefined') {
  if (!window.matchMedia) {
    window.matchMedia = (query: string) =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList;
  }

  if (!window.ResizeObserver) {
    window.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    } as unknown as typeof ResizeObserver;
  }

  if (!window.IntersectionObserver) {
    window.IntersectionObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
      takeRecords() {
        return [];
      }
      readonly root = null;
      readonly rootMargin = '';
      readonly thresholds = [];
    } as unknown as typeof IntersectionObserver;
  }

  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = vi.fn();
  }
}
