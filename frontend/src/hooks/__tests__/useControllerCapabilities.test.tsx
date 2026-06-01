// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Tests for ``useControllerCapabilities``.
 *
 * Critical invariants:
 * - ``has``/``hasFor`` fail OPEN while loading (don't hide tabs by
 *   accident on first paint).
 * - After the manifest loads, ``has`` returns true ONLY for codes
 *   the adapter advertises.
 * - On error, fail open, the user shouldn't see a stripped UI just
 *   because the capabilities endpoint had a transient failure.
 * - The hook re-keys on ``controllerId`` so switching controllers
 *   refetches.
 */

import type { ReactNode } from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { useControllerCapabilities } from '../useControllerCapabilities';

const mockGet = vi.fn();

vi.mock('@/lib/api/controllers', () => ({
  controllersApi: {
    getCapabilities: (...args: unknown[]) => mockGet(...args),
  },
}));

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0 } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe('useControllerCapabilities', () => {
  beforeEach(() => {
    mockGet.mockReset();
  });

  it('does not query when controllerId is null', () => {
    const { result } = renderHook(() => useControllerCapabilities(null), {
      wrapper: makeWrapper(),
    });
    expect(mockGet).not.toHaveBeenCalled();
    // Fail-open: every check returns true while we don't know what
    // the adapter supports.
    expect(result.current.has('anything')).toBe(true);
    expect(result.current.hasFor('switch', 'anything')).toBe(true);
  });

  it('returns true for advertised capabilities and false for unknown ones', async () => {
    mockGet.mockResolvedValue({
      data: {
        controller_id: 'c1',
        adapter_id: 'omada',
        capabilities: ['switch.sflow', 'switch.mstp', 'wifi.dfs'],
        by_device_type: {
          switch: ['switch.sflow', 'switch.mstp'],
          access_point: ['wifi.dfs'],
        },
      },
    });
    const { result } = renderHook(() => useControllerCapabilities('c1'), {
      wrapper: makeWrapper(),
    });
    // Wait for ``capabilities`` to actually be populated, checking
    // ``has`` would return true (fail-open) even before data loads.
    await waitFor(() => expect(result.current.capabilities).toBeDefined());
    expect(result.current.has('switch.sflow')).toBe(true);
    expect(result.current.has('switch.mstp')).toBe(true);
    expect(result.current.has('switch.qinq')).toBe(false);
    expect(result.current.has('routing.bgp')).toBe(false);
  });

  it('hasFor scopes to a specific device type', async () => {
    mockGet.mockResolvedValue({
      data: {
        controller_id: 'c1',
        adapter_id: 'omada',
        capabilities: ['switch.sflow', 'wifi.dfs'],
        by_device_type: {
          switch: ['switch.sflow'],
          access_point: ['wifi.dfs'],
        },
      },
    });
    const { result } = renderHook(() => useControllerCapabilities('c1'), {
      wrapper: makeWrapper(),
    });
    await waitFor(() => expect(result.current.capabilities).toBeDefined());
    expect(result.current.hasFor('switch', 'switch.sflow')).toBe(true);
    // sFlow is a switch capability, access_points don't have it.
    expect(result.current.hasFor('access_point', 'switch.sflow')).toBe(false);
    expect(result.current.hasFor('access_point', 'wifi.dfs')).toBe(true);
  });

  it('fails open on API error so navigation does not get stripped', async () => {
    mockGet.mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useControllerCapabilities('c1'), {
      wrapper: makeWrapper(),
    });
    // The hook sets retry=1, so an error needs both attempts to
    // finish before it surfaces. Default retry delay is ~1s, give
    // it room.
    await waitFor(
      () => expect(result.current.error).toBeTruthy(),
      { timeout: 5000 },
    );
    // Critical: error path returns true rather than hiding tabs.
    expect(result.current.has('anything')).toBe(true);
    expect(result.current.hasFor('switch', 'anything')).toBe(true);
  });

  it('refetches when controllerId changes', async () => {
    mockGet.mockImplementation((id: string) =>
      Promise.resolve({
        data: {
          controller_id: id,
          adapter_id: 'omada',
          capabilities: id === 'c1' ? ['a'] : ['b'],
          by_device_type: {},
        },
      }),
    );

    const { result, rerender } = renderHook(
      ({ id }: { id: string }) => useControllerCapabilities(id),
      { wrapper: makeWrapper(), initialProps: { id: 'c1' } },
    );
    await waitFor(() =>
      expect(result.current.capabilities?.controller_id).toBe('c1'),
    );
    expect(result.current.has('a')).toBe(true);
    expect(result.current.has('b')).toBe(false);

    rerender({ id: 'c2' });
    await waitFor(() =>
      expect(result.current.capabilities?.controller_id).toBe('c2'),
    );
    expect(result.current.has('b')).toBe(true);
    expect(result.current.has('a')).toBe(false);
  });

  it('returns the raw capabilities object after load', async () => {
    mockGet.mockResolvedValue({
      data: {
        controller_id: 'c1',
        adapter_id: 'omada',
        adapter_name: 'TP-Link Omada',
        vendor: 'TP-Link',
        capabilities: ['switch.sflow'],
        by_device_type: { switch: ['switch.sflow'] },
        auth_methods: ['username_password', 'oauth2_client_credentials'],
        supports_bulk_operations: true,
      },
    });
    const { result } = renderHook(() => useControllerCapabilities('c1'), {
      wrapper: makeWrapper(),
    });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.capabilities?.adapter_name).toBe('TP-Link Omada');
    expect(result.current.capabilities?.vendor).toBe('TP-Link');
    expect(result.current.capabilities?.supports_bulk_operations).toBe(true);
  });
});
