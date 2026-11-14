// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The Access Control page says what the capability record says, and no more.
 *
 * The page used to read "Coming soon" over a grid of planned features: doors
 * controlled "in real time", biometric credentials, anti-passback and
 * multi-factor rules, and a searchable, exportable audit trail. The record
 * (`access_control` in backend/app/core/capability_maturity.py) says something
 * different: Experimental; door and credential management works; physical door
 * control refuses with 501 until a real door-controller adapter is added;
 * ships disabled. Anti-passback was removed from the backend because no code
 * path implements it.
 *
 * The first test pins the record itself, so a change there (an adapter lands,
 * the grade moves) fails here and the page gets updated with it.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '@/test-utils';
import AccessControlPage from '../AccessControlPage';

vi.mock('@/hooks/useCapabilityMaturity', () => ({
  useCapabilityMaturity: () => ({
    map: undefined,
    isLoading: false,
    maturityFor: () => ({ maturity: 'experimental', title: 'Physical access control', notes: '' }),
  }),
}));

function backendRecord(): string {
  const src = readFileSync(resolve(process.cwd(), '../backend/app/core/capability_maturity.py'), 'utf8').replace(
    /\r\n/g,
    '\n',
  );
  const m = src.match(/^ {4}"access_control": CapabilityInfo\(\n([\s\S]*?)^ {4}\),$/m);
  expect(m, 'access_control entry not found in capability_maturity.py').toBeTruthy();
  return m![1];
}

describe('Access Control page honesty', () => {
  it('is written against the current capability record', () => {
    const record = backendRecord();
    expect(record).toMatch(/_EXPERIMENTAL\b/);
    const notes = [...record.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((s) => s[1]).join('');
    expect(notes).toContain('Door/credential management works');
    expect(notes).toContain('refuses with 501');
    expect(notes).toContain('Ships disabled by default');
  });

  it('states what works, what is refused, and that it ships disabled', () => {
    renderWithProviders(<AccessControlPage />);
    expect(screen.getByRole('heading', { level: 1, name: /Access Control/ })).toBeTruthy();
    expect(screen.getByText('Experimental')).toBeTruthy();
    expect(screen.getByText('Door and credential records work')).toBeTruthy();
    expect(screen.getByText('Physical door control is not available')).toBeTruthy();
    expect(screen.getByText(/refused \(the API answers 501\)/)).toBeTruthy();
    expect(screen.getByText(/FreeSDN cannot open or lock a door/)).toBeTruthy();
    expect(screen.getByText(/ships disabled/)).toBeTruthy();
    expect(screen.getByText(/This page has no screens for them yet/)).toBeTruthy();
  });

  it('advertises nothing the backend does not implement', () => {
    renderWithProviders(<AccessControlPage />);
    const text = document.body.textContent ?? '';
    for (const claim of [/coming soon/i, /real time/i, /anti-passback/i, /biometric/i, /multi-factor/i, /export/i]) {
      expect(text).not.toMatch(claim);
    }
  });
});
