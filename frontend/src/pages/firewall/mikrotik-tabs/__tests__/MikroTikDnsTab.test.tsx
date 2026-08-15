// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikDnsTab, smoke test.
 *
 * Mocks the mikrotik API client and verifies the tab renders both
 * sub-tables without crashing. We don't drill into the form dialog
 * here, the goal is to catch silent regressions in the import graph
 * and the empty-state vs. populated-state rendering branch.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikDnsTab } from '../MikroTikDnsTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getDNSStatic: vi.fn(),
      getDNSCache: vi.fn(),
      createDNSStatic: vi.fn(),
      updateDNSStatic: vi.fn(),
      deleteDNSStatic: vi.fn(),
    },
  };
});

const mockStatic = mikrotikApi.getDNSStatic as unknown as Mock;
const mockCache = mikrotikApi.getDNSCache as unknown as Mock;

beforeEach(() => {
  mockStatic.mockReset();
  mockCache.mockReset();
});

describe('MikroTikDnsTab smoke', () => {
  it('renders both sub-tables with empty data', async () => {
    mockStatic.mockResolvedValue({
      data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
    });
    mockCache.mockResolvedValue({
      data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
    });

    renderWithProviders(<MikroTikDnsTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockStatic).toHaveBeenCalledWith('c1'));
    // Card title + empty-state title both contain the same phrase, so
    // assert at least one match exists rather than uniqueness.
    expect(
      (await screen.findAllByText(/Static DNS entries/i)).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText(/DNS cache/i).length).toBeGreaterThan(0);
  });

  it('renders rows when static + cache data are present', async () => {
    mockStatic.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [{ '.id': '*1', name: 'server.lan', type: 'A', address: '192.168.88.10' }],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockCache.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [{ '.id': '*2', name: 'example.com', type: 'A', data: '1.1.1.1', ttl: '5m' }],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });

    renderWithProviders(<MikroTikDnsTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockStatic).toHaveBeenCalled());
    expect(await screen.findByText('server.lan')).toBeInTheDocument();
    expect(await screen.findByText('example.com')).toBeInTheDocument();
  });

  it('does not crash when isActive is false', async () => {
    renderWithProviders(<MikroTikDnsTab controllerId="c1" isActive={false} />);
    // Query is gated on isActive so it should NOT have run.
    expect(mockStatic).not.toHaveBeenCalled();
    expect(mockCache).not.toHaveBeenCalled();
  });
});
