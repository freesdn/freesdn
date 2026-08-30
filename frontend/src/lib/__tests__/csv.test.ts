// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * `escapeCell` is the single guarded CSV escaper. Eighteen export pages were
 * routed onto it after their hand-rolled copies were found to lack the
 * spreadsheet formula-injection neutralisation.
 *
 * That rewiring introduced a regression those pages had never had: the guard
 * fires on a leading `-`, so a negative NUMBER was prefixed with an apostrophe
 * and became text. A signal strength of -67 dBm exported as '-67 and could no
 * longer be sorted, filtered or charted.
 *
 * These tests pin both halves at once: formulas stay neutralised, numbers stay
 * numbers.
 */
import { describe, expect, it } from 'vitest';

import { escapeCell, toCsv } from '@/lib/csv';

describe('escapeCell — formula injection is neutralised', () => {
  it.each([
    ['=SUM(A1)', "'=SUM(A1)"],
    ['+1+1', "'+1+1"],
    ['@SUM(A1)', "'@SUM(A1)"],
    ['-CMD()', "'-CMD()"],
    ['-1+1', "'-1+1"],
    ["=cmd|'/c calc.exe'!A1", "'=cmd|'/c calc.exe'!A1"],
  ])('neutralises %s', (input, expected) => {
    expect(escapeCell(input)).toBe(expected);
  });

  it('neutralises a device-supplied hostname, which is the real attack path', () => {
    // A client sets its own DHCP hostname; the controller syncs it; the operator
    // opens the export.
    expect(escapeCell('=HYPERLINK("http://attacker/","Invoice")')).toContain("'=HYPERLINK");
  });
});

describe('escapeCell — numbers stay numbers', () => {
  it.each([
    [-67, '-67'],
    [-0.5, '-0.5'],
    [-1000, '-1000'],
    [67, '67'],
    [0, '0'],
    [1.5e-3, '0.0015'],
  ])('leaves %s unquoted and unprefixed', (input, expected) => {
    expect(escapeCell(input)).toBe(expected);
  });

  it('does not prefix a negative signal strength', () => {
    // The concrete regression: dBm values are negative by nature.
    expect(escapeCell(-67).startsWith("'")).toBe(false);
  });
});

describe('escapeCell — RFC 4180 quoting', () => {
  it.each([
    ['a,b', '"a,b"'],
    ['say "hi"', '"say ""hi"""'],
    ['line1\nline2', '"line1\nline2"'],
    ['line1\rline2', '"line1\rline2"'],
  ])('quotes %s', (input, expected) => {
    expect(escapeCell(input)).toBe(expected);
  });

  it.each([
    [null, ''],
    [undefined, ''],
  ])('renders %s as empty', (input, expected) => {
    expect(escapeCell(input)).toBe(expected);
  });
});

describe('toCsv', () => {
  it('escapes every cell through the guard', () => {
    const csv = toCsv([{ name: '=CMD()', rssi: -67 }]);
    expect(csv).toContain("'=CMD()");
    expect(csv).toContain('-67');
    expect(csv).not.toContain("'-67");
  });
});
