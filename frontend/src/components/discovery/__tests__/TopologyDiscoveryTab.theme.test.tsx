// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The discovery topology's nodes follow the theme. They were bg-white,
 * bg-emerald-50 and bg-sky-50 boxes that inherited the page's text colour,
 * so in dark mode (the default) a host's address and a subnet's name were
 * light text on a white box. They now use the card tokens and translucent
 * accents, with dark variants for the coloured text.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ReactFlowProvider, type NodeProps } from '@xyflow/react';
import { HostNodeView, SubnetNodeView } from '../TopologyDiscoveryTab';

const LIGHT_ONLY = /\b(bg-white|bg-(emerald|sky)-50|text-slate-\d+|border-slate-\d+)\b/;

function nodeProps(data: Record<string, unknown>): NodeProps {
  return { id: 'n', data, type: 'host', selected: false, dragging: false, zIndex: 0, isConnectable: false, positionAbsoluteX: 0, positionAbsoluteY: 0, selectable: false, deletable: false, draggable: false } as unknown as NodeProps;
}

function renderNode(node: React.ReactNode) {
  return render(
    <MemoryRouter>
      <ReactFlowProvider>{node}</ReactFlowProvider>
    </MemoryRouter>,
  );
}

describe('discovery topology nodes', () => {
  it('draws a host on the card tokens in either state', () => {
    const { unmount } = renderNode(<HostNodeView {...nodeProps({ host: { ip_address: '10.0.0.5', hostname: 'printer', is_adopted: false } })} />);
    let node = screen.getByTestId('discovery-host-node');
    expect(node.className).toMatch(/\bbg-card\b/);
    expect(node.className).toMatch(/\btext-card-foreground\b/);
    expect(node.outerHTML).not.toMatch(LIGHT_ONLY);
    unmount();

    renderNode(<HostNodeView {...nodeProps({ host: { ip_address: '10.0.0.6', is_adopted: true, adopted_device_id: 'd1' } })} />);
    node = screen.getByTestId('discovery-host-node');
    expect(node.className).toMatch(/\btext-card-foreground\b/);
    expect(node.outerHTML).not.toMatch(LIGHT_ONLY);
  });

  it('draws a subnet on the card tokens', () => {
    renderNode(<SubnetNodeView {...nodeProps({ subnet: { label: 'LAN', cidr: '10.0.0.0/24', host_count: 3, vlan_id: 10 } })} />);
    const node = screen.getByTestId('discovery-subnet-node');
    expect(node.className).toMatch(/\btext-card-foreground\b/);
    expect(node.outerHTML).not.toMatch(LIGHT_ONLY);
  });
});
