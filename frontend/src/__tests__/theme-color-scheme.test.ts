// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Each theme tells the browser which palette to use for native controls.
 *
 * Checkboxes, radios, date and time pickers, number spinners, select popups
 * and scrollbars are drawn by the browser from ``color-scheme``, not from the
 * design tokens. Without ``color-scheme: dark`` on the ``.dark`` root (the
 * default theme, set on <html> by public/theme-init.js) they rendered white on
 * the dark surface. Vitest does not process CSS, so this reads the stylesheet
 * and checks the rule that defines each theme's tokens.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

/** Body of the top-level rule whose selector list is exactly `selectors`. */
function ruleBody(selectors: string[]): string {
  const pattern = new RegExp(
    `(^|\\})\\s*${selectors.map((s) => s.replace('.', '\\.')).join('\\s*,\\s*')}\\s*\\{([^}]*)\\}`,
  );
  const match = css.match(pattern);
  if (!match) throw new Error(`no rule for ${selectors.join(', ')}`);
  return match[2];
}

describe('theme color-scheme', () => {
  it('the dark theme root declares color-scheme: dark', () => {
    const body = ruleBody(['.dark']);
    expect(body).toMatch(/--background\s*:/);
    expect(body).toMatch(/(^|;|\s)color-scheme\s*:\s*dark\s*;/);
  });

  it('the light theme root declares color-scheme: light', () => {
    const body = ruleBody([':root', '.light']);
    expect(body).toMatch(/--background\s*:/);
    expect(body).toMatch(/(^|;|\s)color-scheme\s*:\s*light\s*;/);
  });
});

describe('keyboard focus indicator', () => {
  it('every focusable element gets the theme ring on :focus-visible, at zero specificity', () => {
    const rule = css.match(/:where\(([\s\S]*?)\)\s*:focus-visible\s*\{([^}]*)\}/);
    expect(rule).not.toBeNull();
    const [, selectors, body] = rule!;
    for (const selector of ['a[href]', 'button', 'select', 'input', "[role='tab']", "[tabindex]:not([tabindex='-1'])"]) {
      expect(selectors).toContain(selector);
    }
    expect(body).toMatch(/outline:\s*2px solid hsl\(var\(--ring\)\)/);
  });
});

