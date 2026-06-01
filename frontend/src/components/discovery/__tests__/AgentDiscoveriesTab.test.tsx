// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils/render';
import { AgentDiscoveriesTab } from '../AgentDiscoveriesTab';

vi.mock('@/lib/api/discovery', () => ({
  discoveryApi: {
    listDiscoveredHosts: vi.fn(),
    bulkAdoptDevices: vi.fn(),
  },
}));

import { discoveryApi } from '@/lib/api/discovery';

const SITE_ID = 'site-1';

describe('AgentDiscoveriesTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty state for no hosts', async () => {
    (discoveryApi.listDiscoveredHosts as any).mockResolvedValue({ data: [] });
    renderWithProviders(<AgentDiscoveriesTab siteId={SITE_ID} />);
    expect(
      await screen.findByText(/No discovered hosts yet/i),
    ).toBeInTheDocument();
  });

  it('renders host rows with status badges', async () => {
    (discoveryApi.listDiscoveredHosts as any).mockResolvedValue({
      data: [
        {
          id: 'h1',
          site_id: SITE_ID,
          organization_id: 'org-1',
          ip_address: '192.168.1.150',
          mac_address: 'aa:bb:cc:dd:ee:01',
          hostname: 'switch-01',
          vendor: 'NETGEAR',
          device_type: 'switch',
          discovered_via: ['arp', 'ping'],
          open_ports: [],
          services: {},
          mdns_services: [],
          ssdp_info: null,
          http_title: null,
          http_server: null,
          lldp_chassis_id: null,
          lldp_port_id: null,
          lldp_system_name: null,
          lldp_capabilities: null,
          likely_device_types: [],
          recommended_driver: null,
          is_adopted: false,
          adopted_device_id: null,
          ignored: false,
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          discovered_by_agent_id: null,
        },
      ],
    });

    renderWithProviders(<AgentDiscoveriesTab siteId={SITE_ID} />);
    expect(await screen.findByText('192.168.1.150')).toBeInTheDocument();
    expect(screen.getByText('switch-01')).toBeInTheDocument();
    expect(screen.getByText('NETGEAR')).toBeInTheDocument();
    // discovered_via badges
    expect(screen.getByText('arp')).toBeInTheDocument();
    expect(screen.getByText('ping')).toBeInTheDocument();
  });

  it('filters by IP via the search input', async () => {
    const user = userEvent.setup();
    (discoveryApi.listDiscoveredHosts as any).mockResolvedValue({
      data: [
        {
          id: 'h1',
          site_id: SITE_ID,
          organization_id: 'org-1',
          ip_address: '192.168.1.150',
          mac_address: null,
          hostname: null,
          vendor: null,
          device_type: null,
          discovered_via: [],
          open_ports: [],
          services: {},
          mdns_services: [],
          ssdp_info: null,
          http_title: null,
          http_server: null,
          lldp_chassis_id: null,
          lldp_port_id: null,
          lldp_system_name: null,
          lldp_capabilities: null,
          likely_device_types: [],
          recommended_driver: null,
          is_adopted: false,
          adopted_device_id: null,
          ignored: false,
          first_seen: null,
          last_seen: null,
          discovered_by_agent_id: null,
        },
        {
          id: 'h2',
          site_id: SITE_ID,
          organization_id: 'org-1',
          ip_address: '10.0.0.1',
          mac_address: null,
          hostname: null,
          vendor: null,
          device_type: null,
          discovered_via: [],
          open_ports: [],
          services: {},
          mdns_services: [],
          ssdp_info: null,
          http_title: null,
          http_server: null,
          lldp_chassis_id: null,
          lldp_port_id: null,
          lldp_system_name: null,
          lldp_capabilities: null,
          likely_device_types: [],
          recommended_driver: null,
          is_adopted: false,
          adopted_device_id: null,
          ignored: false,
          first_seen: null,
          last_seen: null,
          discovered_by_agent_id: null,
        },
      ],
    });

    renderWithProviders(<AgentDiscoveriesTab siteId={SITE_ID} />);
    expect(await screen.findByText('192.168.1.150')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();

    await user.type(
      screen.getByPlaceholderText(/Filter by IP, MAC/i),
      '192.168',
    );

    // The 10.0.0.1 row should disappear
    await waitFor(() => {
      expect(screen.queryByText('10.0.0.1')).not.toBeInTheDocument();
    });
    expect(screen.getByText('192.168.1.150')).toBeInTheDocument();
  });
});
