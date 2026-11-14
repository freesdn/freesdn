// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Every translation namespace: one per JSON file in public/locales/<lang>/.
 *
 * Kept as a runtime list (not only a type) so a test can check it against the
 * files on disk; a namespace missing here made ``useI18n('storage')`` a type
 * error although the Storage pages ship ``storage.json``.
 */
export const TRANSLATION_NAMESPACES = [
  'common',
  'auth',
  'dashboard',
  'devices',
  'errors',
  'settings',
  'cameras',
  'network',
  'backup',
  'sites',
  'vpn',
  'analytics',
  'agents',
  'alerts',
  'accessPoints',
  'firmware',
  'roles',
  'logs',
  'integrations',
  'poe',
  'credentials',
  'discovery',
  'users',
  'automation',
  'webhooks',
  'drivers',
  'ai',
  'access',
  'pendingChanges',
  'collector',
  'security',
  'controllers',
  'organizations',
  'marketplace',
  'setup',
  'storage',
  'switches',
  'gateway',
  'hypervisor',
  'enterprise',
  'voip',
  'firewall',
  'about',
] as const;

export type TranslationNamespace = (typeof TRANSLATION_NAMESPACES)[number];
