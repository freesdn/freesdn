// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { DeleteGuestDialog } from '../DeleteGuestDialog';
import { hypervisorApi } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';
vi.mock('@/lib/api', () => ({ hypervisorApi: { getVMConfig: vi.fn(), deleteVM: vi.fn(), bulkAction: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const target = { node: 'pve1', vm_type: 'qemu', vmid: 101 };
beforeEach(() => {
  vi.resetAllMocks();
  useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok({ digest: 'a'.repeat(40), name: 'reviewed-guest', scsi0: 'local:disk,size=32G', cipassword: 'never-display-secret' }));
});
async function setup(targets = [target]) {
  const user = userEvent.setup();
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  renderWithProviders(<DeleteGuestDialog controllerId="controller" targets={targets} onClose={vi.fn()} />, { queryClient });
  await screen.findAllByText(/reviewed-guest/);
  return { user, queryClient };
}
describe('reviewed guest deletion', () => {
  it('requires typed confirmation, preserves ID/digest on response loss and disables automatic retry', async () => {
    vi.mocked(hypervisorApi.deleteVM).mockRejectedValue(new Error('Lost response'));
    const { user, queryClient } = await setup();
    const submit = screen.getByRole('button', { name: 'Submit deletion' });
    expect(submit).toBeDisabled();
    expect(screen.queryByText('never-display-secret')).not.toBeInTheDocument();
    await user.type(screen.getByRole('textbox'), 'DELETE');
    await user.click(submit);
    await waitFor(() => expect(hypervisorApi.deleteVM).toHaveBeenCalledTimes(1));
    await screen.findByRole('alert');
    const first = vi.mocked(hypervisorApi.deleteVM).mock.calls[0];
    expect(first).toEqual(['controller', 'pve1', 'qemu', 101, { request_id: expect.any(String), expected_digest: 'a'.repeat(40) }]);
    vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok({ digest: 'b'.repeat(40), name: 'replacement' }));
    await queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    await user.click(submit);
    await waitFor(() => expect(hypervisorApi.deleteVM).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.deleteVM).mock.calls[1]).toEqual(first);
    expect(hypervisorApi.getVMConfig).toHaveBeenCalledTimes(1);
  });
  it('freezes distinct IDs and digests for every bulk target', async () => {
    vi.mocked(hypervisorApi.bulkAction).mockRejectedValue(new Error('Lost response'));
    const { user } = await setup([target, { ...target, vmid: 102 }]);
    await user.type(screen.getByRole('textbox'), 'DELETE');
    await user.click(screen.getByRole('button', { name: 'Submit deletion' }));
    await screen.findByRole('alert');
    const first = vi.mocked(hypervisorApi.bulkAction).mock.calls[0][1];
    expect(new Set(first.targets.map((t) => t.request_id)).size).toBe(2);
    expect(first.targets.every((t) => t.expected_digest === 'a'.repeat(40))).toBe(true);
    await user.click(screen.getByRole('button', { name: 'Submit deletion' }));
    await waitFor(() => expect(hypervisorApi.bulkAction).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.bulkAction).mock.calls[1][1]).toEqual(first);
  });
  it.each([{ name: 'no digest' }, { digest: 'a'.repeat(40), protection: 1 }, { digest: 'a'.repeat(40), lock: 'backup' }])('fails closed when review is unsafe: %j', async (config) => {
    vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok(config));
    renderWithProviders(<DeleteGuestDialog controllerId="controller" targets={[target]} onClose={vi.fn()} />);
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit deletion' })).toBeDisabled();
    expect(hypervisorApi.deleteVM).not.toHaveBeenCalled();
  });
  it('displays receipts as accepted rather than completed and prevents a second submit', async () => {
    vi.mocked(hypervisorApi.deleteVM).mockResolvedValue(ok({ action: 'destroy', vmid: 101, request_id: crypto.randomUUID(), change_id: 'receipt-1', status: 'applied', message: 'Accepted', upid: null, provider_task: { status: 'pending' } }));
    const { user } = await setup();
    await user.type(screen.getByRole('textbox'), 'DELETE');
    await user.click(screen.getByRole('button', { name: 'Submit deletion' }));
    await screen.findByText(/accepted does not mean deleted/);
    expect(screen.getByRole('button', { name: 'Submit deletion' })).toBeDisabled();
  });
  it('honors read-only mode', async () => {
    useUIStore.setState({ readOnlyMode: true });
    const { user } = await setup();
    await user.type(screen.getByRole('textbox'), 'DELETE');
    expect(screen.getByRole('button', { name: 'Submit deletion' })).toBeDisabled();
  });
});
