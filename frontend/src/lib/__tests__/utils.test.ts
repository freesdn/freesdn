// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { cn, formatRelativeTime, formatUptime, formatWatts, safeExternalUrl, safeOpen } from '../utils';

describe('cn (Tailwind class merger)', () => {
  it('combines class names', () => {
    expect(cn('a', 'b')).toBe('a b');
  });
  it('dedupes conflicting Tailwind utilities (later wins)', () => {
    expect(cn('p-2', 'p-4')).toBe('p-4');
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500');
  });
  it('handles falsy values', () => {
    expect(cn('a', false, null, undefined, 'b')).toBe('a b');
  });
  it('handles conditional objects', () => {
    expect(cn('base', { active: true, inactive: false })).toBe('base active');
  });
});

describe('formatUptime', () => {
  it('returns N/A for null/undefined', () => {
    expect(formatUptime(null)).toBe('N/A');
    expect(formatUptime(undefined)).toBe('N/A');
  });
  it('formats minutes', () => {
    expect(formatUptime(125)).toBe('2m');
  });
  it('formats hours and minutes', () => {
    expect(formatUptime(3700)).toBe('1h 1m');
  });
  it('formats days and hours', () => {
    expect(formatUptime(90000)).toBe('1d 1h');
  });
});

describe('formatWatts', () => {
  it('returns N/A for null', () => {
    expect(formatWatts(null)).toBe('N/A');
  });
  it('formats watts to one decimal', () => {
    expect(formatWatts(12.345)).toBe('12.3W');
    expect(formatWatts(0)).toBe('0.0W');
  });
});

describe('formatRelativeTime', () => {
  it('returns Never for missing input', () => {
    expect(formatRelativeTime(null)).toBe('Never');
    expect(formatRelativeTime(undefined)).toBe('Never');
  });
  it('returns Unknown for unparseable', () => {
    expect(formatRelativeTime('not-a-date')).toBe('Unknown');
  });
  it('returns "just now" for recent timestamps', () => {
    const now = new Date().toISOString();
    expect(formatRelativeTime(now)).toBe('just now');
  });
  it('returns minutes-ago for ~5 minutes', () => {
    const t = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(formatRelativeTime(t)).toBe('5m ago');
  });
  it('returns hours-ago for ~3 hours', () => {
    const t = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeTime(t)).toBe('3h ago');
  });
});

describe('safeExternalUrl (XSS guard)', () => {
  it('returns null for empty/null input', () => {
    expect(safeExternalUrl(null)).toBeNull();
    expect(safeExternalUrl(undefined)).toBeNull();
    expect(safeExternalUrl('')).toBeNull();
    expect(safeExternalUrl('   ')).toBeNull();
  });

  it('allows http/https URLs', () => {
    expect(safeExternalUrl('https://example.com')).toBe('https://example.com');
    expect(safeExternalUrl('http://example.com/path')).toBe('http://example.com/path');
  });

  it('allows relative paths and fragments', () => {
    expect(safeExternalUrl('/dashboard')).toBe('/dashboard');
    expect(safeExternalUrl('#section')).toBe('#section');
    expect(safeExternalUrl('?q=test')).toBe('?q=test');
  });

  it('blocks javascript: URIs (XSS vector)', () => {
    expect(safeExternalUrl('javascript:alert(1)')).toBeNull();
    expect(safeExternalUrl('JAVASCRIPT:alert(1)')).toBeNull();
    expect(safeExternalUrl('  javascript:alert(1)')).toBeNull();
  });

  it('blocks data: URIs', () => {
    expect(safeExternalUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
  });

  it('blocks file: URIs', () => {
    expect(safeExternalUrl('file:///etc/passwd')).toBeNull();
  });

  it('blocks vbscript: URIs', () => {
    expect(safeExternalUrl('vbscript:msgbox(1)')).toBeNull();
  });

  it('blocks ftp: and other non-http(s) schemes', () => {
    expect(safeExternalUrl('ftp://example.com/file')).toBeNull();
    expect(safeExternalUrl('chrome://settings')).toBeNull();
  });
});

describe('safeOpen', () => {
  beforeEach(() => {
    // Stub window.open
    (window as unknown as { open: ReturnType<typeof vi.fn> }).open = vi.fn();
  });

  it('opens safe URLs with noopener,noreferrer', () => {
    safeOpen('https://example.com');
    expect(window.open).toHaveBeenCalledWith('https://example.com', '_blank', 'noopener,noreferrer');
  });

  it('does not open dangerous URLs', () => {
    safeOpen('javascript:alert(1)');
    expect(window.open).not.toHaveBeenCalled();
  });

  it('does not open null/undefined', () => {
    safeOpen(null);
    safeOpen(undefined);
    expect(window.open).not.toHaveBeenCalled();
  });

  it('respects custom features string', () => {
    safeOpen('https://example.com', 'width=400');
    expect(window.open).toHaveBeenCalledWith('https://example.com', '_blank', 'width=400');
  });
});
