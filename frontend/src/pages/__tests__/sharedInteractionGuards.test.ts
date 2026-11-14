// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Pages use the shared interaction pieces, not browser primitives:
 *
 * - native `confirm()` showed an unstyled, untranslatable browser box that
 *   could not name what a bulk action affects; pages now ask through
 *   `useConfirm()` (title, consequence, count, items, destructive styling);
 * - `navigator.clipboard` called directly threw on plain-HTTP installs and
 *   several pages then said "Copied" anyway; pages now use `CopyButton` or
 *   `useCopyToClipboard`, which report a failed copy;
 * - a `StatsGrid` with five cards declared four columns, stranding the fifth
 *   card on its own row; five cards use `columns={5}`.
 *
 * These scan the page and component sources (not tests, not the shared layer
 * that implements the pieces) so a new call cannot slip back in.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = resolve(__dirname, '../..');

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === '__tests__' || name === 'node_modules') continue;
      out.push(...sources(path));
    } else if (/\.(tsx?|jsx?)$/.test(name) && !/\.(test|spec|stories)\./.test(name)) {
      out.push(path);
    }
  }
  return out;
}

const SHARED = [/^components[\\/]ui[\\/]/, /^lib[\\/]clipboard\.ts$/, /^hooks[\\/]/];
const FILES = [...sources(join(SRC, 'pages')), ...sources(join(SRC, 'components'))]
  .map((path) => ({ path, rel: relative(SRC, path) }))
  .filter(({ rel }) => !SHARED.some((re) => re.test(rel)));

/** Source without line and block comments, so prose mentioning confirm() does not count. */
function code(path: string): string {
  return readFileSync(path, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

describe('pages use the shared interaction pieces', () => {
  it('scans a real tree', () => {
    expect(FILES.length).toBeGreaterThan(200);
  });

  it('no page calls the native confirm()', () => {
    const offenders = FILES.filter(({ path }) =>
      /(^|[^\w.$])(window\.)?confirm\s*\(\s*(?!\{)/m.test(code(path).replace(/await\s+\w+\s*\(\s*\{/g, '')),
    ).map(({ rel }) => rel);
    expect(offenders).toEqual([]);
  });

  it('no page writes to navigator.clipboard directly', () => {
    const offenders = FILES.filter(({ path }) => /navigator\.clipboard/.test(code(path))).map(({ rel }) => rel);
    expect(offenders).toEqual([]);
  });

  it('a StatsGrid with five inline cards declares five columns', () => {
    const offenders: string[] = [];
    for (const { path, rel } of FILES) {
      const source = code(path);
      for (const m of source.matchAll(/<StatsGrid\b/g)) {
        const tag = source.slice(m.index, source.indexOf('/>', m.index));
        const inline = tag.match(/stats=\{\[([\s\S]*)\]\}/);
        if (!inline) continue;
        const cards = (inline[1].match(/\btitle\s*:/g) ?? []).length;
        const columns = Number(tag.match(/columns=\{(\d)\}/)?.[1] ?? 4);
        if (cards === 5 && columns !== 5) offenders.push(`${rel} (${cards} cards, columns=${columns})`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
