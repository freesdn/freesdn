// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

/**
 * Sidebar uses ~6 zustand stores + react-query + nested Tooltip/Dropdown
 * providers. Fully rendering it in jsdom triggers infinite re-render loops
 * from the badge-store selectors. Rather than mock 6 stores precisely (which
 * would test the mocks more than the component), we lock down the a11y
 * contract at the source level · if someone deletes an aria-label, this
 * test fails.
 */
const SIDEBAR_SOURCE = readFileSync(
  resolve(__dirname, '../Sidebar.tsx'),
  'utf-8',
);

// aria-labels are now localized via t(), assert the binding exists in
// source AND the English bundle carries the expected copy, preserving the
// a11y contract (the control has a label, and its English text is correct).
const EN_COMMON = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../public/locales/en/common.json'), 'utf-8'),
);
const enValue = (dotted: string): unknown =>
  dotted.split('.').reduce<unknown>((o, p) => (o as Record<string, unknown>)?.[p], EN_COMMON);

describe('Sidebar · accessibility (source-level guards)', () => {
  it('main navigation has aria-label "Main navigation"', () => {
    expect(SIDEBAR_SOURCE).toContain('aria-label="Main navigation"');
  });

  it('search input has a localized aria-label (Search navigation)', () => {
    expect(SIDEBAR_SOURCE).toContain("aria-label={t('Sidebar.search.ariaLabel')");
    expect(enValue('Sidebar.search.ariaLabel')).toBe('Search navigation');
  });

  it('collapse toggle has localized aria-labels reflecting state', () => {
    // aria-label={collapsed ? t('Sidebar.expand') : t('Sidebar.collapse')}
    expect(SIDEBAR_SOURCE).toContain("t('Sidebar.expand')");
    expect(SIDEBAR_SOURCE).toContain("t('Sidebar.collapse')");
    expect(enValue('Sidebar.expand')).toBe('Expand sidebar');
    expect(enValue('Sidebar.collapse')).toBe('Collapse sidebar');
  });

  it('badge settings dropdown trigger has a localized aria-label', () => {
    expect(SIDEBAR_SOURCE).toContain("aria-label={t('Sidebar.badge.settings')");
    expect(enValue('Sidebar.badge.settings')).toBe('Badge Settings');
  });
});
