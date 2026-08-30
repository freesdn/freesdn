// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikTopologyTab, smoke test.
 *
 * The topology graph uses @xyflow/react. The smoke test verifies:
 *   - All three cards render with empty / null data (lab CHR shape).
 *   - The EmptyState surfaces when no neighbors are discovered (a
 *     common state, must NOT crash @xyflow with empty arrays).
 *   - LLDP table populates from the shape the backend ACTUALLY returns.
 *     ``GET /lldp`` declares ``response_model=list[MikroTikLldpInterface]``
 *     so the wire shape is a bare array. This file used to feed a
 *     fabricated ``{items:[...]}`` envelope, which is why it stayed green
 *     while the tab read ``.data.items`` off an Array (undefined) and
 *     rendered an empty table on every real router.
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

// LLDP + neighbors + discovery-settings all return BARE shapes (no envelope).
const emptyLldp = { data: [] };
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
    mockLldp.mockResolvedValue(emptyLldp);

    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockTopology).toHaveBeenCalledWith('c1'));
    expect(await screen.findByText(/Topology graph/i)).toBeInTheDocument();
    expect(
      screen.getByText(/No neighbors discovered/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Neighbor discovery settings/i)).toBeInTheDocument();
    expect(screen.getByText(/LLDP per-interface/i)).toBeInTheDocument();
  });

  // MUTATION GUARD: reverting the read to ``lldpQuery.data?.data.items``
  // yields undefined -> ``?? []`` -> the LLDP empty-state renders and
  // 'upstream-sw' is never found, so this fails for the original reason.
  // The chassis-id assertion pins the column swap: the backend schema is
  // extra="forbid" and has no management-address, so the old column could
  // only ever render "-".
  it('renders an LLDP row from the bare array the backend returns', async () => {
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
      data: [
        {
          '.id': '*1',
          interface: 'ether1',
          'system-name': 'upstream-sw',
          'port-id': 'Gi0/1',
          'chassis-id': '00:0C:29:AA:BB:CC',
        },
      ],
    });

    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockLldp).toHaveBeenCalled());
    expect(await screen.findByText('upstream-sw')).toBeInTheDocument();
    expect(screen.getByText('Gi0/1')).toBeInTheDocument();
    expect(screen.getByText('00:0C:29:AA:BB:CC')).toBeInTheDocument();
    expect(
      screen.queryByText(/No LLDP neighbors/i),
    ).not.toBeInTheDocument();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikTopologyTab controllerId="c1" isActive={false} />);
    expect(mockTopology).not.toHaveBeenCalled();
    expect(mockNeighbors).not.toHaveBeenCalled();
    expect(mockSettings).not.toHaveBeenCalled();
    expect(mockLldp).not.toHaveBeenCalled();
  });
});
