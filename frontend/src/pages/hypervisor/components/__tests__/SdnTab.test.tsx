// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SdnTab } from '../SdnTab';
import { hypervisorApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import type { SdnInspection, SdnDryRunObservation } from '@/lib/api/hypervisor';

vi.mock('@/lib/api', () => ({ hypervisorApi: { inspectSdn: vi.fn(), getSdnDryRun: vi.fn() } }));
const time = '2026-09-18T09:00:00Z';
function observation(cid = 'controller'): SdnInspection {
  const collection = { status: 'available' as const, items: [], omitted_fields: 0, observed_at: time };
  return { controller_id: cid, started_at: time, finished_at: time, resources: [{ resource: 'zones', configured: { ...collection, items: [{ zone: 'draft-zone' }] }, running: { ...collection, items: [{ zone: 'running-zone' }] }, pending: { ...collection, items: [{ zone: 'pending-zone', state: 'new' }] } }], permissions_status: 'available', audit_at_sdn: false, allocate_at_sdn: false, pending_state: 'changes_detected', visibility: 'partial_or_unverified', atomic_snapshot: false, writes_enabled: false, unobserved_resources: ['subnets'], blockers: [] };
}
function preview(cid = 'controller', node = 'pve1'): SdnDryRunObservation {
  return { controller_id: cid, node, status: 'available', observed_at: time, interfaces: { changed: true, added_lines: 2, removed_lines: 1 }, frr: { changed: false, added_lines: 0, removed_lines: 0 }, content_withheld: true, connectivity_verified: false };
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(hypervisorApi.inspectSdn).mockResolvedValue({ data: observation() } as Awaited<ReturnType<typeof hypervisorApi.inspectSdn>>);
  vi.mocked(hypervisorApi.getSdnDryRun).mockResolvedValue({ data: preview() } as Awaited<ReturnType<typeof hypervisorApi.getSdnDryRun>>);
});

describe('SDN inspection boundary', () => {
  it('separates all three views and never offers create, delete or apply', async () => {
    renderWithProviders(<SdnTab controllerId="controller" />);
    await screen.findByText('Configured (desired)');
    expect(screen.getByText('Running (committed)')).toBeInTheDocument();
    expect(screen.getByText('Native pending changes')).toBeInTheDocument();
    for (const name of ['draft-zone', 'running-zone', 'pending-zone']) expect(screen.getByText(new RegExp(name))).toBeInTheDocument();
    expect(within(screen.getByRole('note')).getByText(/permission-filtered observations/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /apply|create|delete/i })).not.toBeInTheDocument();
    expect(hypervisorApi.getSdnDryRun).not.toHaveBeenCalled();
  });
  it('shows a denied view independently instead of an empty success', async () => {
    const data = observation(); data.resources[0].running = { status: 'denied', items: null, observed_at: time, omitted_fields: 0 }; data.pending_state = 'unknown';
    vi.mocked(hypervisorApi.inspectSdn).mockResolvedValue({ data } as Awaited<ReturnType<typeof hypervisorApi.inspectSdn>>);
    renderWithProviders(<SdnTab controllerId="controller" />);
    await screen.findByText('Permission denied');
    expect(screen.getByText('Pending state is unknown')).toBeInTheDocument();
    expect(screen.queryByText(/No visible objects/)).not.toBeInTheDocument();
  });
  it('does not present stale configuration after a refresh failure', async () => {
    renderWithProviders(<SdnTab controllerId="controller" />);
    await screen.findByText(/draft-zone/);
    vi.mocked(hypervisorApi.inspectSdn).mockRejectedValue(new Error('private transport diagnostic'));
    await userEvent.click(screen.getByRole('button', { name: 'Refresh observations' }));
    await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText(/draft-zone/)).not.toBeInTheDocument();
    expect(screen.queryByText(/private transport/)).not.toBeInTheDocument();
    expect(hypervisorApi.inspectSdn).toHaveBeenCalledTimes(2);
  });
  it('binds a GET preview to the explicit node and withholds raw content', async () => {
    renderWithProviders(<SdnTab controllerId="controller" />);
    await screen.findByText(/draft-zone/);
    await userEvent.type(screen.getByLabelText('Exact Proxmox node name'), 'pve1');
    await userEvent.click(screen.getByRole('button', { name: 'Read dry-run' }));
    await screen.findByText(/2 added lines, 1 removed lines/);
    expect(hypervisorApi.getSdnDryRun).toHaveBeenCalledWith('controller', 'pve1');
    expect(screen.getByText(/Raw content is withheld/)).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('Exact Proxmox node name'));
    expect(screen.queryByText(/2 added lines/)).not.toBeInTheDocument();
  });
  it('rejects invalid node paths without submitting a request', async () => {
    renderWithProviders(<SdnTab controllerId="controller" />);
    await userEvent.type(screen.getByLabelText('Exact Proxmox node name'), '../pve1');
    expect(screen.getByRole('button', { name: 'Read dry-run' })).toBeDisabled();
    expect(hypervisorApi.getSdnDryRun).not.toHaveBeenCalled();
  });
  it('rejects observations belonging to a different controller', async () => {
    vi.mocked(hypervisorApi.inspectSdn).mockResolvedValue({ data: observation('foreign') } as Awaited<ReturnType<typeof hypervisorApi.inspectSdn>>);
    renderWithProviders(<SdnTab controllerId="controller" />);
    await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText(/draft-zone/)).not.toBeInTheDocument();
  });
  it('resets node selection when controller changes', async () => {
    const rendered = renderWithProviders(<SdnTab controllerId="controller" />);
    await userEvent.type(screen.getByLabelText('Exact Proxmox node name'), 'pve1');
    await userEvent.click(screen.getByRole('button', { name: 'Read dry-run' }));
    await screen.findByText(/2 added lines/);
    vi.mocked(hypervisorApi.inspectSdn).mockResolvedValue({ data: observation('other') } as Awaited<ReturnType<typeof hypervisorApi.inspectSdn>>);
    rendered.rerender(<SdnTab controllerId="other" />);
    await waitFor(() => expect(hypervisorApi.inspectSdn).toHaveBeenCalledWith('other'));
    expect(screen.getByLabelText('Exact Proxmox node name')).toHaveValue('');
    expect(screen.queryByText(/2 added lines/)).not.toBeInTheDocument();
    expect(hypervisorApi.getSdnDryRun).toHaveBeenCalledTimes(1);
  });
  it('does not show preview results with the wrong node identity', async () => {
    vi.mocked(hypervisorApi.getSdnDryRun).mockResolvedValue({ data: preview('controller', 'pve2') } as Awaited<ReturnType<typeof hypervisorApi.getSdnDryRun>>);
    renderWithProviders(<SdnTab controllerId="controller" />);
    await userEvent.type(screen.getByLabelText('Exact Proxmox node name'), 'pve1');
    await userEvent.click(screen.getByRole('button', { name: 'Read dry-run' }));
    await screen.findByText(/Previous data must not be treated as current/);
    expect(screen.queryByText(/2 added lines/)).not.toBeInTheDocument();
  });
});
