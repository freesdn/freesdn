/**
 * Every /settings/<tab> the UI navigates to must be a tab SettingsPage accepts.
 *
 * TopBar's "Enable MFA" button navigated to /settings/security. 'security' was
 * never in VALID_TABS, so `currentTab` fell back to 'general' and the operator
 * landed on General settings with no MFA anywhere. Nothing errored, nothing was
 * logged, and the route looked like it worked.
 *
 * That mattered more than one button: UserProfile is the ONLY component in the
 * tree that calls PATCH /auth/me, POST /auth/password and the three
 * /auth/mfa/* endpoints, and no route rendered it -- so changing your own
 * password and enrolling MFA were both unreachable from the shipped UI. The
 * translations for the nav item already existed in en, es and zh; only the
 * wiring was missing.
 *
 * This reads both sides off the real source rather than restating them, so a
 * new navigate() to a tab nobody added fails here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(process.cwd(), 'src');

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

function validTabs(): string[] {
  const src = readFileSync(join(SRC, 'pages/settings/SettingsPage.tsx'), 'utf8');
  const m = src.match(/const VALID_TABS = \[([^\]]+)\]/);
  if (!m) throw new Error('VALID_TABS not found - this test can no longer check anything');
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

function settingsTargets(): { file: string; tab: string }[] {
  const hits: { file: string; tab: string }[] = [];
  for (const file of walk(SRC)) {
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/['"`]\/settings\/([a-z0-9-]+)['"`]/g)) {
      hits.push({ file: file.replace(SRC, 'src'), tab: m[1] });
    }
  }
  return hits;
}

describe('settings tab routing', () => {
  it('exposes the tabs this test depends on', () => {
    const tabs = validTabs();
    expect(tabs.length).toBeGreaterThan(5);
    expect(tabs).toContain('general');
  });

  it('finds the navigation targets it is meant to check', () => {
    // Guard the guard: if the scan matches nothing it would pass forever.
    expect(settingsTargets().length).toBeGreaterThan(0);
  });

  it('every /settings/<tab> the UI links to is a tab SettingsPage renders', () => {
    const tabs = validTabs();
    const bad = settingsTargets().filter((h) => !tabs.includes(h.tab));
    expect(
      bad,
      `these navigate to a settings tab that does not exist, so the router ` +
        `silently falls back to 'general': ` +
        bad.map((b) => `${b.file} -> /settings/${b.tab}`).join(', '),
    ).toEqual([]);
  });

  it('the account-security tab is reachable, so MFA and password change are', () => {
    expect(validTabs()).toContain('security');
    const page = readFileSync(join(SRC, 'pages/settings/SettingsPage.tsx'), 'utf8');
    expect(page).toContain("case 'security'");
    expect(page).toContain('UserProfile');
  });
});
