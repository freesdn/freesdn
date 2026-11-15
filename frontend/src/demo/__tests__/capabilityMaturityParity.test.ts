// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The demo's capability maturity record must match the backend's, the single
 * source of truth. A drift either way is a dishonest demo: a capability shown
 * more proven than the product says, or less.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { demoCapabilityMaturity } from '../capabilityMaturity';

type Entry = { maturity: string; title: string; notes: string };

function parseBackendRecord(): Record<string, Entry> {
  const src = readFileSync(
    resolve(process.cwd(), '../backend/app/core/capability_maturity.py'),
    'utf8',
  ).replace(/\r\n/g, '\n');
  const start = src.indexOf('CAPABILITY_MATURITY: dict[str, CapabilityInfo] = {');
  expect(start).toBeGreaterThan(-1);
  const out: Record<string, Entry> = {};
  const entry = /^ {4}"([a-z_]+)": CapabilityInfo\(\n([\s\S]*?)^ {4}\),$/gm;
  entry.lastIndex = start;
  for (let m = entry.exec(src); m; m = entry.exec(src)) {
    const body = m[2]
      .split('\n')
      .filter((line) => !line.trim().startsWith('#'))
      .join('\n');
    const level = body.match(/_(STABLE|BETA|EXPERIMENTAL)\b/);
    const strings = [...body.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((s) =>
      s[1].replace(/\\(["\\])/g, '$1'),
    );
    out[m[1]] = {
      maturity: (level?.[1] ?? '').toLowerCase(),
      title: strings[0] ?? '',
      notes: strings.slice(1).join(''),
    };
  }
  return out;
}

describe('demo capability maturity record', () => {
  it('matches backend/app/core/capability_maturity.py exactly', () => {
    const backend = parseBackendRecord();
    expect(Object.keys(backend).length).toBeGreaterThan(5);
    expect(demoCapabilityMaturity).toEqual(backend);
  });
});
