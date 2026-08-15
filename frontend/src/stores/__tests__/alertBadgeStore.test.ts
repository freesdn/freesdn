// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach } from 'vitest';
import { useAlertBadgeStore, passesThreshold } from '../alertBadgeStore';

describe('passesThreshold', () => {
  it('"all" threshold accepts every severity', () => {
    expect(passesThreshold('critical', 'all')).toBe(true);
    expect(passesThreshold('high', 'all')).toBe(true);
    expect(passesThreshold('warning', 'all')).toBe(true);
    expect(passesThreshold('info', 'all')).toBe(true);
    expect(passesThreshold('low', 'all')).toBe(true);
    expect(passesThreshold('unknown-tier', 'all')).toBe(true);
  });

  it('"critical" threshold accepts only critical', () => {
    expect(passesThreshold('critical', 'critical')).toBe(true);
    expect(passesThreshold('high', 'critical')).toBe(false);
    expect(passesThreshold('warning', 'critical')).toBe(false);
    expect(passesThreshold('info', 'critical')).toBe(false);
  });

  it('"warning" threshold accepts critical/high/warning/medium', () => {
    expect(passesThreshold('critical', 'warning')).toBe(true);
    expect(passesThreshold('high', 'warning')).toBe(true);
    expect(passesThreshold('warning', 'warning')).toBe(true);
    expect(passesThreshold('medium', 'warning')).toBe(true);
    expect(passesThreshold('low', 'warning')).toBe(false);
    expect(passesThreshold('info', 'warning')).toBe(false);
  });

  it('"info" threshold accepts everything except unknown high tiers', () => {
    expect(passesThreshold('critical', 'info')).toBe(true);
    expect(passesThreshold('warning', 'info')).toBe(true);
    expect(passesThreshold('info', 'info')).toBe(true);
    // Unknown severity gets rank 5, info threshold is rank 4 → fails
    expect(passesThreshold('mystery', 'info')).toBe(false);
  });

  it('treats medium as warning-equivalent', () => {
    expect(passesThreshold('medium', 'warning')).toBe(true);
    expect(passesThreshold('medium', 'critical')).toBe(false);
  });
});

describe('useAlertBadgeStore', () => {
  beforeEach(() => {
    useAlertBadgeStore.setState({
      sources: { rules: true, incidents: true, security: true },
      minSeverity: 'all',
      lastReviewedAt: null,
    });
  });

  it('starts with all sources enabled and threshold "all"', () => {
    const s = useAlertBadgeStore.getState();
    expect(s.sources).toEqual({ rules: true, incidents: true, security: true });
    expect(s.minSeverity).toBe('all');
    expect(s.lastReviewedAt).toBeNull();
  });

  it('toggleSource() flips a source', () => {
    useAlertBadgeStore.getState().toggleSource('rules');
    expect(useAlertBadgeStore.getState().sources.rules).toBe(false);
    useAlertBadgeStore.getState().toggleSource('rules');
    expect(useAlertBadgeStore.getState().sources.rules).toBe(true);
  });

  it('toggleSource() leaves other sources unchanged', () => {
    useAlertBadgeStore.getState().toggleSource('incidents');
    expect(useAlertBadgeStore.getState().sources).toEqual({
      rules: true,
      incidents: false,
      security: true,
    });
  });

  it('setMinSeverity() updates threshold', () => {
    useAlertBadgeStore.getState().setMinSeverity('critical');
    expect(useAlertBadgeStore.getState().minSeverity).toBe('critical');
    useAlertBadgeStore.getState().setMinSeverity('warning');
    expect(useAlertBadgeStore.getState().minSeverity).toBe('warning');
  });

  it('markAllReviewed() sets lastReviewedAt to ISO string', () => {
    const before = Date.now();
    useAlertBadgeStore.getState().markAllReviewed();
    const reviewed = useAlertBadgeStore.getState().lastReviewedAt;
    expect(reviewed).toBeTruthy();
    expect(new Date(reviewed!).getTime()).toBeGreaterThanOrEqual(before);
  });

  it('resetPreferences() restores defaults', () => {
    useAlertBadgeStore.getState().toggleSource('rules');
    useAlertBadgeStore.getState().setMinSeverity('critical');
    useAlertBadgeStore.getState().markAllReviewed();

    useAlertBadgeStore.getState().resetPreferences();
    const s = useAlertBadgeStore.getState();
    expect(s.sources).toEqual({ rules: true, incidents: true, security: true });
    expect(s.minSeverity).toBe('all');
    expect(s.lastReviewedAt).toBeNull();
  });
});
