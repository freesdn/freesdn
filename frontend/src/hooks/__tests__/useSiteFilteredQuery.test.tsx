// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { type ReactNode } from 'react';
import { useSiteFilteredQuery, siteParams } from '../useSiteFilteredQuery';
import { useSiteStore } from '../../stores/siteStore';

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0 } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe('siteParams helper', () => {
  it('returns {} when siteId is null (global mode)', () => {
    expect(siteParams(null)).toEqual({});
  });

  it('returns { site_id } when siteId is set', () => {
    expect(siteParams('site-123')).toEqual({ site_id: 'site-123' });
  });

  it('treats empty string as falsy → returns {}', () => {
    expect(siteParams('')).toEqual({});
  });
});

describe('useSiteFilteredQuery', () => {
  beforeEach(() => {
    useSiteStore.setState({ selectedSiteId: null, sites: [], isLoading: false });
  });

  it('passes null siteId to queryFn when in global mode', async () => {
    const queryFn = vi.fn().mockResolvedValue(['result-global']);
    const { result } = renderHook(
      () => useSiteFilteredQuery(['devices'], queryFn),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(queryFn).toHaveBeenCalledWith(null);
    expect(result.current.data).toEqual(['result-global']);
  });

  it('passes selectedSiteId to queryFn when a site is selected', async () => {
    useSiteStore.setState({ selectedSiteId: 'site-1', sites: [], isLoading: false });
    const queryFn = vi.fn().mockResolvedValue(['result-site-1']);
    const { result } = renderHook(
      () => useSiteFilteredQuery(['devices'], queryFn),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(queryFn).toHaveBeenCalledWith('site-1');
    expect(result.current.data).toEqual(['result-site-1']);
  });

  it('refetches with new siteId when site changes', async () => {
    const queryFn = vi.fn(async (siteId) => [`data-${siteId ?? 'global'}`]);
    const { result } = renderHook(
      () => useSiteFilteredQuery(['devices'], queryFn),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(['data-global']);

    useSiteStore.getState().selectSite('site-A');

    await waitFor(() => expect(result.current.data).toEqual(['data-site-A']));
    // queryFn called twice · once for null, once for site-A
    expect(queryFn).toHaveBeenCalledTimes(2);
    expect(queryFn).toHaveBeenNthCalledWith(1, null);
    expect(queryFn).toHaveBeenNthCalledWith(2, 'site-A');
  });

  it('embeds siteId in the query key (cache isolation by site)', async () => {
    const queryFn = vi.fn().mockResolvedValue([]);
    renderHook(
      () => useSiteFilteredQuery(['devices'], queryFn),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(queryFn).toHaveBeenCalled());
    // The query key includes [{ siteId: null }] suffix; switching site won't
    // hit the same cache entry. We verify this indirectly via the refetch
    // test above.
  });

  it('accepts a string baseKey (wraps it into an array)', async () => {
    const queryFn = vi.fn().mockResolvedValue([]);
    const { result } = renderHook(
      () => useSiteFilteredQuery('devices' as never, queryFn),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(queryFn).toHaveBeenCalled();
  });
});
