// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Detail tabs list vendor key/value pairs as returned by the adapter. They
 * used `String(value)`, so a nested list of DHCP leases printed
 * "[object Object],[object Object],..." across the card.
 */
import { describe, expect, it } from 'vitest';

import { formatConfigValue, type ValueLabels } from '@/lib/format-value';

const labels: ValueLabels = {
  yes: 'Yes',
  no: 'No',
  none: '-',
  entries: (n) => `${n} entries`,
  fields: (n) => `${n} fields`,
};

const fmt = (v: unknown) => formatConfigValue(v, labels);

describe('formatConfigValue', () => {
  it('never prints [object Object]', () => {
    const leases = [{ ip: '10.0.0.5', mac: 'aa' }, { ip: '10.0.0.6', mac: 'bb' }];
    expect(fmt(leases)).toBe('2 entries');
    expect(fmt({ pool: { start: 1, end: 2 }, enabled: true })).toBe('2 fields');
    expect(fmt(leases)).not.toContain('[object');
  });

  it('renders scalars plainly', () => {
    expect(fmt(true)).toBe('Yes');
    expect(fmt(false)).toBe('No');
    expect(fmt(0)).toBe('0');
    expect(fmt('auto')).toBe('auto');
  });

  it('uses a dash for missing and empty values', () => {
    expect(fmt(null)).toBe('-');
    expect(fmt(undefined)).toBe('-');
    expect(fmt('')).toBe('-');
    expect(fmt([])).toBe('-');
    expect(fmt({})).toBe('-');
    expect(fmt(Number.NaN)).toBe('-');
  });

  it('joins short scalar lists and counts the overflow', () => {
    expect(fmt(['1.1.1.1', '8.8.8.8'])).toBe('1.1.1.1, 8.8.8.8');
    expect(fmt([1, 2, 3, 4, 5, 6, 7])).toBe('1, 2, 3, 4, 5, +2');
  });

  it('inlines a small flat object', () => {
    expect(fmt({ mode: 'auto', lease_time: 3600 })).toBe('mode: auto, lease time: 3600');
  });
});
