// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SdnAttachments } from '../SdnAttachments';
import { hypervisorApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import type { SdnAttachmentInspection } from '@/lib/api/hypervisor';

vi.mock('@/lib/api', () => ({ hypervisorApi: { inspectSdnAttachments: vi.fn() } }));
const time = '2026-09-18T14:00:00Z';
const read = { status: 'available' as const, observed_at: time, omitted_fields: 0 };
function observation(): SdnAttachmentInspection {
  const inventory = { ...read, visible_count: 1, selected: 1, omitted_by_limit: 0, visibility_complete: false as const };
  return {
    controller_id: 'controller', started_at: time, finished_at: time,
    guest_inventory: { ...inventory, selection_limit: 32 }, node_inventory: { ...inventory, selection_limit: 8 },
    vnets: [{ ...read, view: 'configured', identities: ['v1'] }, { ...read, view: 'running', identities: ['v1'] }],
    guests: [
      { ...read, node: 'pve1', vmid: 101, guest_type: 'qemu', view: 'current', nics: [{ key: 'net0', bridge: 'v1', tag: 20, trunks: '30-40', firewall: false, link_down: true, omitted_options: 1, configured_vnet: 'visible', running_vnet: 'not_visible', host_interface: 'target_unavailable' }] },
      { ...read, node: 'pve1', vmid: 101, guest_type: 'qemu', view: 'pending_merged', nics: [] },
    ],
    hosts: [{ ...read, node: 'pve1', view: 'native_report', interfaces: [{ iface: 'v1', interface_type: 'vnet', active: false, exists: true, bridge_ports: [] }] }],
    request_limit: 76, requests_made: 7, response_limit_reached: false,
    visibility: 'partial_or_unverified', atomic_snapshot: false, dependency_graph_complete: false, connectivity_verified: false, writes_enabled: false,
  };
}
function respond(data: SdnAttachmentInspection) {
  vi.mocked(hypervisorApi.inspectSdnAttachments).mockResolvedValue({ data } as Awaited<ReturnType<typeof hypervisorApi.inspectSdnAttachments>>);
}
async function inspect() {
  await userEvent.click(screen.getByRole('button', { name: 'Inspect guest and host attachments' }));
}
beforeEach(() => { vi.resetAllMocks(); respond(observation()); });

describe('SDN guest and host observations', () => {
  it('fetches only on demand and explains name matches and native flags', async () => {
    renderWithProviders(<SdnAttachments controllerId="controller" />);
    expect(hypervisorApi.inspectSdnAttachments).not.toHaveBeenCalled();
    expect(screen.getByText(/SDN apply remains blocked/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /apply|delete|create/i })).not.toBeInTheDocument();
    await inspect(); await screen.findByText('net0 → v1');
    expect(hypervisorApi.inspectSdnAttachments).toHaveBeenCalledExactlyOnceWith('controller');
    expect(screen.getByText('Configured VNet name: Name visible; connectivity unverified')).toBeInTheDocument();
    expect(screen.getByText(/Running VNet name: Name not visible/)).toBeInTheDocument();
    expect(screen.getByText(/Interface name on the guest node: Target observation unavailable/)).toBeInTheDocument();
    expect(screen.getByText('Configured firewall flag: No')).toBeInTheDocument();
    expect(screen.getByText('Native active flag: No')).toBeInTheDocument();
    expect(screen.getByText(/Host pending diffs and result metadata are not inspected/)).toBeInTheDocument();
  });
  it('keeps pending NIC deletion separate from current configuration without refetching', async () => {
    renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText('net0 → v1');
    await userEvent.selectOptions(screen.getByLabelText('Guest configuration view'), 'pending_merged');
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
    expect(screen.getByText(/No NIC entries are visible in this configuration view/)).toBeInTheDocument();
    expect(hypervisorApi.inspectSdnAttachments).toHaveBeenCalledTimes(1);
  });
  it('does not present denied guest or host reads as empty inventories', async () => {
    const data = observation();
    data.guests[0] = { ...data.guests[0], status: 'denied', nics: null };
    data.hosts[0] = { ...data.hosts[0], status: 'invalid', interfaces: null };
    respond(data); renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText('Permission denied');
    expect(screen.queryByText(/No NIC entries/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No visible objects/)).not.toBeInTheDocument();
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
  });
  it('hides stale observations while refreshing and after errors without exposing diagnostics', async () => {
    renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText('net0 → v1');
    let reject!: (error: Error) => void;
    vi.mocked(hypervisorApi.inspectSdnAttachments).mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
    await userEvent.click(screen.getByRole('button', { name: 'Refresh attachment observations' }));
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh attachment observations' })).toBeDisabled();
    reject(new Error('secret native config'));
    await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
    expect(screen.queryByText(/secret native/)).not.toBeInTheDocument();
    expect(hypervisorApi.inspectSdnAttachments).toHaveBeenCalledTimes(2);
  });
  it('rejects a response bound to a different controller', async () => {
    respond({ ...observation(), controller_id: 'foreign' });
    renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
  });
  it('clears observations and restores an explicit request after changing controllers', async () => {
    const rendered = renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText('net0 → v1');
    rendered.rerender(<SdnAttachments controllerId="other" />);
    expect(screen.queryByText('net0 → v1')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Inspect guest and host attachments' })).toBeEnabled();
    expect(hypervisorApi.inspectSdnAttachments).toHaveBeenCalledTimes(1);
  });
  it('shows selection, response and presentation limits without claiming complete coverage', async () => {
    const data = observation();
    data.guest_inventory.omitted_by_limit = 5;
    data.response_limit_reached = true;
    data.guests[0] = { ...data.guests[0], status: 'not_observed', reason: 'response_limit', nics: null };
    data.hosts[0].interfaces = Array.from({ length: 51 }, (_, i) => ({ iface: `if${i}`, interface_type: 'eth' }));
    respond(data); renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText(/5 omitted by the selection limit/);
    expect(screen.getByRole('alert')).toHaveTextContent(/must not be treated as empty/);
    expect(screen.getByText(/snapshots, passthrough devices/)).toBeInTheDocument();
    expect(screen.getByText('Showing the first 50 of 51 returned entries.')).toBeInTheDocument();
    expect(screen.queryByText('if50 · eth')).not.toBeInTheDocument();
  });
  it('leaves selection disabled when parent inventories could not be observed', async () => {
    const data = observation();
    data.guest_inventory = { ...data.guest_inventory, status: 'denied', visible_count: null, selected: 0 };
    data.node_inventory = { ...data.node_inventory, status: 'not_observed', reason: 'inspection_deadline', visible_count: null, selected: 0 };
    data.guests = []; data.hosts = [];
    respond(data); renderWithProviders(<SdnAttachments controllerId="controller" />);
    await inspect(); await screen.findByText('Permission denied');
    expect(screen.getByLabelText('Selected guest')).toBeDisabled();
    expect(screen.getByLabelText('Selected host')).toBeDisabled();
    expect(screen.queryByText(/Selected 0 of 0/)).not.toBeInTheDocument();
  });
});
