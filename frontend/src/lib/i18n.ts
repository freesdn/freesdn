// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import i18n from 'i18next';
import HttpApi from 'i18next-http-backend';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

// GA language scope: English + the two highest-reach additions (Spanish,
// Chinese). de/fr/pt-BR/he were dropped, partial stubs that would show a
// half-translated UI. The RTL plumbing below is retained so Hebrew can be
// re-added later without re-architecting.
export type SupportedLocale = 'en' | 'es' | 'zh';
export type TranslationNamespace =
  | 'common'
  | 'auth'
  | 'dashboard'
  | 'devices'
  | 'errors'
  | 'settings'
  | 'cameras'
  | 'network'
  | 'backup'
  | 'sites'
  | 'vpn'
  | 'analytics'
  | 'agents'
  | 'alerts'
  | 'accessPoints'
  | 'firmware'
  | 'roles'
  | 'logs'
  | 'integrations'
  | 'poe'
  | 'credentials'
  | 'discovery'
  | 'users'
  | 'automation'
  | 'webhooks'
  | 'drivers'
  | 'ai'
  | 'access'
  | 'pendingChanges'
  | 'collector'
  | 'security'
  | 'controllers'
  | 'organizations'
  | 'marketplace'
  | 'setup'
  | 'switches'
  | 'gateway'
  | 'hypervisor'
  | 'enterprise'
  | 'voip'
  | 'firewall'
  | 'about';

const FALLBACK_LANGUAGE: SupportedLocale = 'en';
const RTL_LANGUAGES = new Set<SupportedLocale>([]);

export const SUPPORTED_LOCALES: Array<{
  code: SupportedLocale;
  name: string;
  nativeName: string;
}> = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'es', name: 'Spanish', nativeName: 'Español' },
  { code: 'zh', name: 'Chinese', nativeName: '中文' },
];

const supportedLocaleCodes = SUPPORTED_LOCALES.map((locale) => locale.code);

function normalizeLocale(value: string | undefined | null): SupportedLocale {
  if (!value) {
    return FALLBACK_LANGUAGE;
  }
  const lower = value.toLowerCase();
  if (lower.startsWith('es')) return 'es';
  if (lower.startsWith('zh')) return 'zh';
  return FALLBACK_LANGUAGE;
}

function applyDocumentDirection(language: SupportedLocale): void {
  if (typeof document === 'undefined') {
    return;
  }
  document.documentElement.lang = language;
  document.documentElement.dir = RTL_LANGUAGES.has(language) ? 'rtl' : 'ltr';
}

if (!i18n.isInitialized) {
  i18n
    .use(HttpApi)
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      fallbackLng: FALLBACK_LANGUAGE,
      supportedLngs: supportedLocaleCodes,
      defaultNS: 'common',
      // Preload ONLY the namespaces used by always-mounted chrome (sidebar,
      // top bar, error boundaries, toasts). The ~40 feature namespaces
      // lazy-load on demand when their page mounts, react-i18next requests
      // the JSON and suspends under the route-level <Suspense> (App.tsx) /
      // app-level <Suspense> (main.tsx). Cuts startup from ~41 JSON fetches
      // to 2. Runtime-verified: pages render in en/es/zh via lazy ns load.
      ns: ['common', 'errors'],
      interpolation: { escapeValue: false },
      detection: {
        order: ['localStorage', 'navigator', 'htmlTag'],
        caches: ['localStorage'],
        lookupLocalStorage: 'freesdn_locale',
      },
      backend: {
        loadPath: '/locales/{{lng}}/{{ns}}.json',
      },
      react: {
        useSuspense: true,
      },
    });
}

const initialLanguage = normalizeLocale(i18n.resolvedLanguage || i18n.language);
applyDocumentDirection(initialLanguage);

i18n.on('languageChanged', (language: string) => {
  applyDocumentDirection(normalizeLocale(language));
});

export function getCurrentLanguage(): SupportedLocale {
  return normalizeLocale(i18n.resolvedLanguage || i18n.language);
}

export async function changeLanguage(locale: SupportedLocale): Promise<void> {
  if (locale === getCurrentLanguage()) {
    return;
  }
  await i18n.changeLanguage(locale);
  applyDocumentDirection(locale);
}

export function isRTL(locale: SupportedLocale): boolean {
  return RTL_LANGUAGES.has(locale);
}

export default i18n;
