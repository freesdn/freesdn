// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A refused reboot shows the server's reason. The toast used to print
 * err.message, which for an HTTP error is axios's own "Request failed with
 * status code 403", never what the backend said.
 */
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';
import { DeviceDetailPanel } from '../TopologyPage';
import { renderWithProviders } from '@/test-utils';
import type { TopologyGraph, TopologyNode } from '@/lib/api';

const reboot = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, deviceControlApi: { ...actual.deviceControlApi, reboot } };
});

const node: TopologyNode = {
  id: 'dev-1', label: 'core-sw-1', device_type: 'switch', status: 'online', ip_address: '10.0.0.2',
  mac_address: null, model: null, site_id: null, site_name: null, health_score: null, health_status: null,
  x: null, y: null, pinned: false, layer: null, metadata: {},
};
const graph = { nodes: [node], edges: [], site_id: null, generated_at: '2026-11-13T00:00:00Z', stats: { total_nodes: 1, total_edges: 0, nodes_by_type: {} } } as unknown as TopologyGraph;

it("shows the server's reason when a reboot is refused", async () => {
  const message = 'Read-only mode is on: nothing changes a device except an approved apply.';
  const response = {
    status: 403,
    statusText: '',
    headers: {},
    config: { headers: new AxiosHeaders() },
    data: { error: { code: 403, type: 'adapter_read_only', message, request_id: 'r1' } },
  } as AxiosResponse;
  reboot.mockRejectedValue(new AxiosError('Request failed with status code 403', 'ERR_BAD_REQUEST', response.config, null, response));
  const user = userEvent.setup();
  renderWithProviders(<DeviceDetailPanel node={node} graph={graph} onSelectNode={vi.fn()} />);
  await user.click(screen.getByRole('button', { name: /Reboot/ }));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: 'Reboot device' }));
  expect(await screen.findByText(message)).toBeInTheDocument();
  expect(screen.getByText('Reboot failed')).toBeInTheDocument();
  expect(screen.queryByText('Request failed with status code 403')).not.toBeInTheDocument();
});

describe('DeviceDetailPanel', () => {
  it('still names an unknown failure', async () => {
    reboot.mockRejectedValue({});
    const user = userEvent.setup();
    renderWithProviders(<DeviceDetailPanel node={node} graph={graph} onSelectNode={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: /Reboot/ }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Reboot device' }));
    expect(await screen.findByText('Unknown error')).toBeInTheDocument();
  });
});
