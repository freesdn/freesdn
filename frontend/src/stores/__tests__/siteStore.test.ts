// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach } from 'vitest';
import { useSiteStore, SITE_ONLY_PATHS, GLOBAL_ONLY_PATHS } from '../siteStore';

describe('useSiteStore', () => {
  beforeEach(() => {
    // Reset store state before each test
    useSiteStore.setState({ selectedSiteId: null, sites: [], isLoading: false });
  });

  it('starts in global view by default', () => {
    expect(useSiteStore.getState().selectedSiteId).toBeNull();
    expect(useSiteStore.getState().isGlobalView()).toBe(true);
  });

  it('selectSite() updates the selected site id', () => {
    useSiteStore.getState().selectSite('site-1');
    expect(useSiteStore.getState().selectedSiteId).toBe('site-1');
    expect(useSiteStore.getState().isGlobalView()).toBe(false);
  });

  it('selectSite(null) returns to global view', () => {
    useSiteStore.getState().selectSite('site-1');
    useSiteStore.getState().selectSite(null);
    expect(useSiteStore.getState().isGlobalView()).toBe(true);
  });

  it('getCurrentSite() returns the selected site object', () => {
    const sites = [
      { id: 's1', name: 'HQ' },
      { id: 's2', name: 'Branch' },
    ];
    useSiteStore.getState().setSites(sites);
    useSiteStore.getState().selectSite('s2');
    expect(useSiteStore.getState().getCurrentSite()).toEqual({ id: 's2', name: 'Branch' });
  });

  it('getCurrentSite() returns null when in global view (multiple sites)', () => {
    // With multiple sites, default stays global until user picks one
    useSiteStore.getState().setSites([
      { id: 's1', name: 'HQ' },
      { id: 's2', name: 'Branch' },
    ]);
    expect(useSiteStore.getState().selectedSiteId).toBeNull();
    expect(useSiteStore.getState().getCurrentSite()).toBeNull();
  });

  it('setSites() resets to global if selected site no longer exists', () => {
    useSiteStore.getState().setSites([
      { id: 's1', name: 'HQ' },
      { id: 's2', name: 'Branch' },
    ]);
    useSiteStore.getState().selectSite('s2');
    // s2 removed in next sync
    useSiteStore.getState().setSites([{ id: 's1', name: 'HQ' }]);
    expect(useSiteStore.getState().selectedSiteId).toBeNull();
  });

  it('setSites() auto-selects when there is exactly one site and in global view', () => {
    useSiteStore.getState().setSites([{ id: 'only', name: 'Only Site' }]);
    expect(useSiteStore.getState().selectedSiteId).toBe('only');
  });

  it('setSites() does NOT auto-select when in global view but already had a different selection', () => {
    // Edge case: was selected, then sites refresh to one that includes selection
    useSiteStore.getState().setSites([
      { id: 'a', name: 'A' },
      { id: 'b', name: 'B' },
    ]);
    useSiteStore.getState().selectSite('b');
    useSiteStore.getState().setSites([
      { id: 'a', name: 'A' },
      { id: 'b', name: 'B' },
    ]);
    // Should still be 'b' · sites unchanged, no reset needed
    expect(useSiteStore.getState().selectedSiteId).toBe('b');
  });

  it('setLoading() toggles isLoading', () => {
    useSiteStore.getState().setLoading(true);
    expect(useSiteStore.getState().isLoading).toBe(true);
    useSiteStore.getState().setLoading(false);
    expect(useSiteStore.getState().isLoading).toBe(false);
  });
});

describe('Site path constants', () => {
  it('SITE_ONLY_PATHS contains expected routes', () => {
    expect(SITE_ONLY_PATHS).toContain('/topology');
    expect(SITE_ONLY_PATHS).toContain('/discovery');
  });

  it('GLOBAL_ONLY_PATHS contains tenant-management routes', () => {
    expect(GLOBAL_ONLY_PATHS).toContain('/sites');
    expect(GLOBAL_ONLY_PATHS).toContain('/users');
    expect(GLOBAL_ONLY_PATHS).toContain('/organizations');
  });
});
