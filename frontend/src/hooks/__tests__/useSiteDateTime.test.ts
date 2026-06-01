// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useSiteDateTime, DATE_FORMATS, TIME_FORMATS } from '../useSiteDateTime';

// Use a fixed test date (UTC): 2024-12-31T14:30:45Z
const TEST_DATE = new Date('2024-12-31T14:30:45Z');

describe('useSiteDateTime defaults', () => {
  it('uses UTC + YYYY-MM-DD + 24h when no site provided', () => {
    const { result } = renderHook(() => useSiteDateTime(null));
    expect(result.current.timezone).toBe('UTC');
    expect(result.current.dateFormat).toBe('YYYY-MM-DD');
    expect(result.current.timeFormat).toBe('24h');
  });

  it('uses UTC + YYYY-MM-DD + 24h when undefined site provided', () => {
    const { result } = renderHook(() => useSiteDateTime(undefined));
    expect(result.current.timezone).toBe('UTC');
  });

  it('uses provided site settings', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'America/New_York', date_format: 'MM/DD/YYYY', time_format: '12h' })
    );
    expect(result.current.timezone).toBe('America/New_York');
    expect(result.current.dateFormat).toBe('MM/DD/YYYY');
    expect(result.current.timeFormat).toBe('12h');
  });
});

describe('formatSiteDate', () => {
  it('formats with YYYY-MM-DD pattern (default)', () => {
    const { result } = renderHook(() => useSiteDateTime({ timezone: 'UTC' }));
    expect(result.current.formatSiteDate(TEST_DATE)).toBe('2024-12-31');
  });

  it('formats with DD/MM/YYYY (European)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', date_format: 'DD/MM/YYYY' })
    );
    expect(result.current.formatSiteDate(TEST_DATE)).toBe('31/12/2024');
  });

  it('formats with MM/DD/YYYY (US)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', date_format: 'MM/DD/YYYY' })
    );
    expect(result.current.formatSiteDate(TEST_DATE)).toBe('12/31/2024');
  });

  it('formats with DD.MM.YYYY (German/Swiss)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', date_format: 'DD.MM.YYYY' })
    );
    expect(result.current.formatSiteDate(TEST_DATE)).toBe('31.12.2024');
  });

  it('accepts string and number inputs', () => {
    const { result } = renderHook(() => useSiteDateTime({ timezone: 'UTC' }));
    expect(result.current.formatSiteDate('2024-12-31T14:30:45Z')).toBe('2024-12-31');
    expect(result.current.formatSiteDate(TEST_DATE.getTime())).toBe('2024-12-31');
  });
});

describe('formatSiteTime', () => {
  it('formats 24h time', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '24h' })
    );
    expect(result.current.formatSiteTime(TEST_DATE)).toBe('14:30');
  });

  it('formats 12h time with PM', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '12h' })
    );
    expect(result.current.formatSiteTime(TEST_DATE)).toBe('2:30 PM');
  });

  it('formats 12h time with AM', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '12h' })
    );
    const morning = new Date('2024-12-31T08:15:00Z');
    expect(result.current.formatSiteTime(morning)).toBe('8:15 AM');
  });

  it('handles midnight (12 AM in 12h format)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '12h' })
    );
    const midnight = new Date('2024-12-31T00:00:00Z');
    expect(result.current.formatSiteTime(midnight)).toBe('12:00 AM');
  });

  it('handles noon (12 PM in 12h format)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '12h' })
    );
    const noon = new Date('2024-12-31T12:00:00Z');
    expect(result.current.formatSiteTime(noon)).toBe('12:00 PM');
  });

  it('includes seconds when requested (24h)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '24h' })
    );
    expect(result.current.formatSiteTime(TEST_DATE, true)).toBe('14:30:45');
  });

  it('includes seconds when requested (12h, before AM/PM)', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', time_format: '12h' })
    );
    expect(result.current.formatSiteTime(TEST_DATE, true)).toBe('2:30:45 PM');
  });
});

describe('formatSiteDateTime', () => {
  it('combines date + time with site preferences', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'UTC', date_format: 'DD/MM/YYYY', time_format: '12h' })
    );
    expect(result.current.formatSiteDateTime(TEST_DATE)).toBe('31/12/2024 2:30 PM');
  });
});

describe('invalid timezone fallback', () => {
  it('does not throw on invalid timezone · falls back gracefully', () => {
    const { result } = renderHook(() =>
      useSiteDateTime({ timezone: 'Not/A/Real_Timezone' })
    );
    // Should still produce SOME output, just possibly using fallback
    expect(() => result.current.formatSiteDate(TEST_DATE)).not.toThrow();
  });
});

describe('exported constants', () => {
  it('DATE_FORMATS has 6 entries with code/example/description', () => {
    expect(DATE_FORMATS.length).toBe(6);
    DATE_FORMATS.forEach((f) => {
      expect(f.code).toBeTruthy();
      expect(f.example).toBeTruthy();
      expect(f.description).toBeTruthy();
    });
  });

  it('TIME_FORMATS has 24h + 12h', () => {
    expect(TIME_FORMATS).toHaveLength(2);
    expect(TIME_FORMATS.map((f) => f.code).sort()).toEqual(['12h', '24h']);
  });
});
