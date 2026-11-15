// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Every literal translation key a page uses exists in EN, ES and ZH.
 *
 * `npm run i18n:verify` checks that the three locale files agree with each
 * other, not that the code's keys exist in them. The SLA page's measurement
 * note was a key no locale had, so every language showed the English
 * `defaultValue`, and its Reports tab was a hard-coded English label. This
 * reads the pages translated in this pass and resolves each `t('...')`
 * literal against all three locales (a plural key counts when its `_one` and
 * `_other` forms exist).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(__dirname, '../../..');
const LANGS = ['en', 'es', 'zh'] as const;

const PAGES: Array<[file: string, namespace: string]> = [
  ['src/pages/storage/StoragePage.tsx', 'storage'],
  ['src/pages/storage/StorageWriteActions.tsx', 'storage'],
  ['src/pages/storage/AddTrueNASDialog.tsx', 'storage'],
  ['src/pages/enterprise/sla/SLAPage.tsx', 'enterprise'],
  ['src/pages/enterprise/sla/SLAReportsPanel.tsx', 'enterprise'],
];

function locale(lang: string, ns: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(ROOT, 'public/locales', lang, `${ns}.json`), 'utf8'));
}

function has(tree: Record<string, unknown>, key: string): boolean {
  const resolveKey = (k: string) =>
    k.split('.').reduce<unknown>((node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined), tree);
  if (typeof resolveKey(key) === 'string') return true;
  return typeof resolveKey(`${key}_one`) === 'string' && typeof resolveKey(`${key}_other`) === 'string';
}

function literalKeys(source: string): string[] {
  // t('a.b'), t("a.b") and i18nKey="a.b"; template keys are checked by their own tests.
  const keys = new Set<string>();
  for (const m of source.matchAll(/\bt\(\s*['"]([A-Za-z][\w.-]*)['"]/g)) keys.add(m[1]);
  for (const m of source.matchAll(/i18nKey=["']([A-Za-z][\w.-]*)["']/g)) keys.add(m[1]);
  return [...keys];
}

describe('translated pages resolve every key in every language', () => {
  it.each(PAGES)('%s', (file, ns) => {
    const source = readFileSync(resolve(ROOT, file), 'utf8');
    const keys = literalKeys(source).filter((k) => !k.includes(':'));
    expect(keys.length).toBeGreaterThan(5);
    const missing: string[] = [];
    for (const lang of LANGS) {
      const tree = locale(lang, ns);
      for (const key of keys) if (!has(tree, key)) missing.push(`${lang}:${ns}.${key}`);
    }
    expect(missing).toEqual([]);
  });

  it('has no defaultValue fallbacks on these pages', () => {
    for (const [file] of PAGES) {
      expect(readFileSync(resolve(ROOT, file), 'utf8')).not.toMatch(/defaultValue:\s*['"]/);
    }
  });
});
