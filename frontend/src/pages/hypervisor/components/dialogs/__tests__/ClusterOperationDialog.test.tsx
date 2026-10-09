// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { ClusterOperationDialog } from '../ClusterOperationDialog';
import { hypervisorApi } from '@/lib/api';
import type { ClusterOperationAction, ClusterOperationSpec } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewClusterOperation: vi.fn(), rebootNode: vi.fn(), shutdownNode: vi.fn(), createHAResource: vi.fn(), deleteHAResource: vi.fn(), createHAGroup: vi.fn(), deleteHAGroup: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const review = (action: ClusterOperationAction = 'node.reboot', target = 'pve1') => ({ expected_digest: 'a'.repeat(64), snapshot: { action, target, selected_group: '', cluster: { name: 'test-cluster', quorate: 1 }, nodes: [{ name: 'pve1', online: 1 }], guests: [{ vmid: 101, type: 'qemu', node: 'pve1', status: 'running', name: 'database', template: 0 }], resources: [], groups: [] } });
const intent: ClusterOperationSpec = { action: 'node.reboot', target: 'pve1' };
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewClusterOperation).mockResolvedValue(ok(review()));
});
function setup(selected = intent) {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  return { user: userEvent.setup(), ...renderWithProviders(<ClusterOperationDialog controllerId="controller" intent={selected} onClose={vi.fn()} onTracked={vi.fn()} />, { queryClient }) };
}
describe('cluster operation review', () => {
  it('shows guest impact and requires the exact target before submitting', async () => {
    vi.mocked(hypervisorApi.rebootNode).mockResolvedValue(ok({ action: 'node.reboot', target: 'pve1', request_id: 'id', change_id: 'receipt', status: 'applied', message: 'Recorded', provider_task: { status: 'unknown' } }));
    const { user } = setup();
    expect(await screen.findByText(/qemu 101 database/)).toBeInTheDocument();
    expect(screen.getByText(/independent management path/)).toBeInTheDocument();
    const button = screen.getByRole('button', { name: 'Submit reviewed operation' });
    expect(button).toBeDisabled();
    await user.type(screen.getByLabelText('Type the exact target to confirm: pve1'), 'pve1');
    await user.click(button);
    expect(await screen.findByText(/Request recorded/)).toBeInTheDocument();
    expect(screen.getByText(/applied · receipt · unknown/)).toBeInTheDocument();
    expect(button).toBeDisabled();
    expect(hypervisorApi.rebootNode).toHaveBeenCalledWith('controller', 'pve1', expect.objectContaining({ expected_digest: 'a'.repeat(64), force: true, confirmed: true, request_id: expect.any(String) }));
  });
  it('does not automatically retry and manual retry preserves the entire intent', async () => {
    vi.mocked(hypervisorApi.rebootNode).mockRejectedValue(new Error('lost'));
    const { user } = setup();
    await screen.findByText(/qemu 101 database/);
    await user.type(screen.getByLabelText('Type the exact target to confirm: pve1'), 'pve1');
    await user.click(screen.getByRole('button', { name: 'Submit reviewed operation' }));
    await screen.findByRole('alert');
    expect(hypervisorApi.rebootNode).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.rebootNode).mock.calls[0];
    await user.click(screen.getByRole('button', { name: 'Submit reviewed operation' }));
    await waitFor(() => expect(hypervisorApi.rebootNode).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.rebootNode).mock.calls[1]).toEqual(first);
    expect(hypervisorApi.reviewClusterOperation).toHaveBeenCalledTimes(1);
  });
  it('blocks dispatch when the controller changes', async () => {
    const { user, rerender } = setup();
    await screen.findByText(/qemu 101 database/);
    await user.type(screen.getByLabelText('Type the exact target to confirm: pve1'), 'pve1');
    rerender(<ClusterOperationDialog controllerId="other" intent={intent} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
    expect(hypervisorApi.rebootNode).not.toHaveBeenCalled();
  });
  it('blocks dispatch in read-only mode', async () => {
    useUIStore.setState({ readOnlyMode: true });
    const { user } = setup();
    await screen.findByText(/qemu 101 database/);
    await user.type(screen.getByLabelText('Type the exact target to confirm: pve1'), 'pve1');
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
  });
  it('fails closed when review is unavailable', async () => {
    vi.mocked(hypervisorApi.reviewClusterOperation).mockRejectedValue(new Error('denied'));
    const { user } = setup();
    await screen.findByRole('alert');
    await user.type(screen.getByLabelText('Type the exact target to confirm: pve1'), 'pve1');
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
    expect(hypervisorApi.reviewClusterOperation).toHaveBeenCalledTimes(1);
  });
  it('displays the frozen HA options including automatic start and detects edited options', async () => {
    const selected: ClusterOperationSpec = { action: 'ha.resource.create', target: 'vm:101', options: { sid: 'vm:101', group: '', state: 'started', max_restart: 1, max_relocate: 1, comment: '' } };
    vi.mocked(hypervisorApi.reviewClusterOperation).mockResolvedValue(ok(review(selected.action, selected.target)));
    const { user, rerender } = setup(selected);
    await screen.findByText(/qemu 101 database/);
    expect(screen.getByText(/"state": "started"/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Type the exact target to confirm: vm:101'), 'vm:101');
    rerender(<ClusterOperationDialog controllerId="controller" intent={{ ...selected, options: { ...selected.options, group: 'other' } }} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
    expect(hypervisorApi.createHAResource).not.toHaveBeenCalled();
  });
});
