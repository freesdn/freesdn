// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * `renderWithProviders`, wraps a UI under test in the same set of
 * providers the app uses at runtime so components don't blow up when
 * they call `useNavigate()`, `useQuery()`, or `useTranslation()`.
 *
 * Returns the standard testing-library `render` result plus the
 * QueryClient (so tests can drive cache state) and a small helper for
 * advancing routing.
 *
 * We deliberately don't import `src/lib/i18n.ts`, that module wires up
 * the HttpApi backend which tries to fetch translations from
 * `/locales/{{lng}}/...` over network. In tests we register a minimal
 * in-memory i18n instance with just the resource bundles we need.
 */
import { type ReactElement, type ReactNode } from 'react';
import { render, type RenderOptions, type RenderResult } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import i18n, { type i18n as I18nInstance } from 'i18next';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { ToastProvider } from '@/components/ui/toast';
import { TooltipProvider } from '@/components/ui/tooltip';

export function makeTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

let _testI18n: I18nInstance | null = null;

/**
 * Load the REAL English locale bundles (public/locales/en/*.json) so tests
 * render actual English copy, text/label queries (getByText('Save'),
 * getByLabelText(/organization name/i)) keep working now that ~all
 * components route strings through t(). Previously this used empty bundles
 * (t() returned the key), which broke once the i18n sweep wired up every
 * component. Read once via fs (vitest runs in Node; cwd = frontend).
 */
function loadEnResources(): Record<string, Record<string, unknown>> {
  const dir = resolve(process.cwd(), 'public/locales/en');
  const out: Record<string, Record<string, unknown>> = {};
  try {
    for (const file of readdirSync(dir)) {
      if (!file.endsWith('.json')) continue;
      const ns = file.replace(/\.json$/, '');
      out[ns] = JSON.parse(readFileSync(resolve(dir, file), 'utf8'));
    }
  } catch {
    // Fall back to empty common bundle if the locales dir can't be read.
    out.common = {};
  }
  return out;
}

function getTestI18n(): I18nInstance {
  if (_testI18n) return _testI18n;
  const enResources = loadEnResources();
  const instance = i18n.createInstance();
  instance.use(initReactI18next).init({
    lng: 'en',
    fallbackLng: 'en',
    defaultNS: 'common',
    ns: Object.keys(enResources),
    resources: { en: enResources },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
  _testI18n = instance;
  return instance;
}

export interface RenderWithProvidersOptions extends Omit<RenderOptions, 'wrapper'> {
  /** Initial URL the MemoryRouter should start at. */
  initialPath?: string;
  /**
   * If supplied, the UI under test is mounted at this route path
   * (useful for components that read URL params via `useParams`).
   */
  routePath?: string;
  /** Pre-seeded QueryClient. If omitted, a fresh one is created. */
  queryClient?: QueryClient;
}

export interface RenderWithProvidersResult extends RenderResult {
  queryClient: QueryClient;
}

export function renderWithProviders(
  ui: ReactElement,
  options: RenderWithProvidersOptions = {},
): RenderWithProvidersResult {
  const {
    initialPath = '/',
    routePath,
    queryClient = makeTestQueryClient(),
    ...renderOptions
  } = options;

  const testI18n = getTestI18n();

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <I18nextProvider i18n={testI18n}>
          <MemoryRouter initialEntries={[initialPath]}>
            <ToastProvider>
              <TooltipProvider>
                {routePath ? (
                  <Routes>
                    <Route path={routePath} element={children} />
                  </Routes>
                ) : (
                  children
                )}
              </TooltipProvider>
            </ToastProvider>
          </MemoryRouter>
        </I18nextProvider>
      </QueryClientProvider>
    );
  }

  const result = render(ui, { wrapper: Wrapper, ...renderOptions });
  return { ...result, queryClient };
}

export { makeTestQueryClient as createTestQueryClient };
