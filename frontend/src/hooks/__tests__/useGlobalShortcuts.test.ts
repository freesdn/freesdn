// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { getShortcutList, isMacPlatform } from '../useGlobalShortcuts';

describe('getShortcutList', () => {
  it('returns the three single-key shortcuts (⌘K, ?, /)', () => {
    const list = getShortcutList();
    expect(list.find((s) => s.key.includes('K'))?.description).toMatch(/command palette/i);
    expect(list.find((s) => s.key === '?')?.description).toMatch(/shortcuts/i);
    expect(list.find((s) => s.key === '/')?.description).toMatch(/sidebar search/i);
  });

  it('returns g-prefix navigation shortcuts marked with gPrefix=true', () => {
    const gShortcuts = getShortcutList().filter((s) => s.gPrefix);
    expect(gShortcuts.length).toBeGreaterThanOrEqual(15);
    gShortcuts.forEach((s) => expect(s.key.startsWith('g ')).toBe(true));
  });

  it('all entries have a description and a non-empty group', () => {
    getShortcutList().forEach((s) => {
      expect(s.description).toBeTruthy();
      expect(s.group).toBeTruthy();
    });
  });

  it('groups are limited to General + Navigation', () => {
    const groups = new Set(getShortcutList().map((s) => s.group));
    expect(groups).toEqual(new Set(['General', 'Navigation']));
  });

  it('every g-prefix shortcut has a unique 1-char letter after "g "', () => {
    const letters = getShortcutList()
      .filter((s) => s.gPrefix)
      .map((s) => s.key.slice(2));
    const unique = new Set(letters);
    expect(unique.size).toBe(letters.length);
  });

  it('every shortcut has an action function (no-op for cheatsheet)', () => {
    getShortcutList().forEach((s) => {
      expect(typeof s.action).toBe('function');
      expect(() => s.action()).not.toThrow();
    });
  });
});

describe('isMacPlatform', () => {
  it('is a boolean', () => {
    expect(typeof isMacPlatform).toBe('boolean');
  });
});
