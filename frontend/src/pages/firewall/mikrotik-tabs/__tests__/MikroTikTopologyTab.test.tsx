// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikTopologyTab, smoke test.
 *
 * The topology graph uses @xyflow/react. The smoke test verifies:
 *   - All three cards render with empty / null data (lab CHR shape).
 *   - The EmptyState surfaces when no neighbors are discovered (a
 *     common state, must NOT crash @xyflow with empty arrays).
 *   - LLDP table populates when data arrives.
 *   - isActive=false short-circuits all fetches.
 *
 * @xyflow/react requires a DOM environment with measured dimensions;
 * the empty path (rfNodes.length === 0) renders an EmptyState rather
 * than mounting ReactFlow, so the test never hits the actual graph.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikTopologyTab } from '../MikroTikTopologyTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      buildTopology: vi.fn(),
      getNeighbors: vi.fn(),
      getNeighborDiscoverySettings: vi.fn(),
      getLldpInterfaces: vi.fn(),
      updateNeighborDiscoverySettings: vi.fn(),
    },
  };
});

const mockTopology = mikrotikApi.buildTopology as unknown as Mock;
const mockNeighbors = mikrotikApi.getNeighbors as unknown as Mock;
const mockSettings = mikrotikApi.getNeighborDiscoverySettings as unknown as Mock;
const mockLldp = mikrotikApi.getLldpInterfaces as unknown as Mock;

beforeEach(() => {
  mockTopology.mockReset();
  mockNeighbors.mockReset();
  mockSettings.mockReset();
  mockLldp.mockReset();
});

const emptyList = {
  data: {
    controller_id: 'c1',
    items: [],
    fetched_at: '',
    limit: 200,
    offset: 0,
    total: 0,
  },
};

// Neighbors + discovery-settings now return BARE shapes (no envelope).
const emptyNeighbors = { data: [] };

describe('MikroTikTopologyTab smoke', () => {
  it('renders empty-state for topology when no neighbors are discovered', async () => {
    mockTopology.mockResolvedValue({
      data: {
        controller_id: 'c1',
        nodes: [],
        edges: [],
        fetched_at: '',
      },
    });
    mockNeighbors.mockResolvedValue(emptyNeighbors);
    mockSettings.mockResolvedValue({
      data: { protocol: 'lldp,cdp,mndp', 'discover-interface-list': 'all' },
    });
    mockLldp.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockTopology).toHaveBeenCalledWith('c1'));
    expect(await screen.findByText(/Topology graph/i)).toBeInTheDocument();
    expect(
      screen.getByText(/No neighbors discovered/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Neighbor discovery settings/i)).toBeInTheDocument();
    expect(screen.getByText(/LLDP per-interface/i)).toBeInTheDocument();
  });

  it('renders an LLDP row when interfaces report neighbors', async () => {
    mockTopology.mockResolvedValue({
      data: {
        controller_id: 'c1',
        nodes: [],
        edges: [],
        fetched_at: '',
      },
    });
    mockNeighbors.mockResolvedValue(emptyNeighbors);
    mockSettings.mockResolvedValue({
      data: { protocol: 'lldp', 'discover-interface-list': 'all' },
    });
    mockLldp.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            interface: 'ether1',
            'system-name': 'upstream-sw',
            'port-id': 'Gi0/1',
            'management-address': '10.0.0.1',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });

    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockLldp).toHaveBeenCalled());
    expect(await screen.findByText('upstream-sw')).toBeInTheDocument();
    expect(screen.getByText('Gi0/1')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={false} />);
    expect(mockTopology).not.toHaveBeenCalled();
    expect(mockNeighbors).not.toHaveBeenCalled();
    expect(mockSettings).not.toHaveBeenCalled();
    expect(mockLldp).not.toHaveBeenCalled();
  });
});
