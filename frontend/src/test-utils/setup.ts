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
