// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shipped copy carries no em dashes (house style; a past commit stripped
 * them all). This covers the strings the shared components and layout render
 * on every page, in every language, plus the whole errors namespace.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SHARED_SECTIONS = [
  'BatchProgressDialog', 'Breadcrumb', 'BulkActionsBar', 'CapabilityMaturityBadge', 'ConfirmDialog',
  'CopyButton', 'DataTable', 'MaturityBadge',
  'DestructiveConfirmDialog', 'DetailSheet', 'DeviceTypeIcon', 'Dialog', 'EmptyState',
  'FormFieldArray', 'FormatValue', 'MainLayout', 'PageHeader', 'SearchBar', 'ShortcutsCheatsheet',
  'Sheet', 'Sidebar', 'SiteRequiredGate', 'SiteSelector', 'Tabs', 'ThemeToggle',
  'TimeRangeSelector', 'Toast', 'TopBar', 'TypeBadge', 'WizardDialog', 'nav', 'pagination',
  'relative', 'time',
];

function load(lang: string, ns: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(process.cwd(), `public/locales/${lang}/${ns}.json`), 'utf8'));
}

function leaves(value: unknown, path: string, out: Array<[string, string]>) {
  if (typeof value === 'string') out.push([path, value]);
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) leaves(v, path ? `${path}.${k}` : k, out);
  }
  return out;
}

describe('shared component copy', () => {
  for (const lang of ['en', 'es', 'zh']) {
    it(`has no em dashes (${lang})`, () => {
      const common = load(lang, 'common');
      const strings: Array<[string, string]> = [];
      for (const section of SHARED_SECTIONS) leaves(common[section], `common:${section}`, strings);
      leaves(load(lang, 'errors'), 'errors:', strings);
      expect(strings.length).toBeGreaterThan(100);
      expect(strings.filter(([, s]) => s.includes('—')).map(([k]) => k)).toEqual([]);
    });
  }
});
