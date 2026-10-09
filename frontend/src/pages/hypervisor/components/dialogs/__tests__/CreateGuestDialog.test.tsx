// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { CreateGuestDialog } from '../CreateGuestDialog';
import { hypervisorApi } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';
vi.mock('@/lib/api', () => ({ hypervisorApi: { getNextVMID: vi.fn(), createVM: vi.fn(), createContainer: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
beforeEach(() => { vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false }); });
async function setup(kind: 'vm' | 'ct' = 'vm') {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const user = userEvent.setup();
  const rendered = renderWithProviders(<CreateGuestDialog controllerId="controller" kind={kind} nodes={['pve1']} onClose={vi.fn()} />, { queryClient });
  await user.type(screen.getByLabelText('VMID'), '101');
  await user.type(screen.getByLabelText('Name'), 'reviewed-guest');
  if (kind === 'ct') await user.type(screen.getByLabelText('OS Template'), 'local:vztmpl/debian.tar.zst');
  return { user, ...rendered };
}
describe('reviewed guest creation', () => {
  it('freezes intent, disables automatic retries and reuses the same request after a lost response', async () => {
    vi.mocked(hypervisorApi.createVM).mockRejectedValue(new Error('lost'));
    const { user } = await setup();
    await user.click(screen.getByRole('button', { name: 'Review creation' }));
    expect(screen.getByLabelText('VMID')).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Submit creation' }));
    await screen.findByRole('alert');
    expect(hypervisorApi.createVM).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.createVM).mock.calls[0];
    expect(first).toEqual(['controller', expect.objectContaining({ request_id: expect.any(String), vmid: 101, node: 'pve1', force: true, disk_size: '32G' })]);
    await user.click(screen.getByRole('button', { name: 'Submit creation' }));
    await waitFor(() => expect(hypervisorApi.createVM).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.createVM).mock.calls[1]).toEqual(first);
  });
  it('sends a container password but never renders it in the review or receipt', async () => {
    vi.mocked(hypervisorApi.createContainer).mockResolvedValue(ok({ action: 'create', vmid: 101, status: 'applied', request_id: 'intent', change_id: 'receipt', upid: null, message: 'Accepted', provider_task: { status: 'pending' } }));
    const { user } = await setup('ct');
    await user.type(screen.getByLabelText('Container root password (optional)'), 'test-secret');
    await user.click(screen.getByRole('button', { name: 'Review creation' }));
    expect(screen.getByLabelText('Container root password (optional)')).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Submit creation' }));
    await screen.findByText(/Accepted does not mean the guest/);
    expect(hypervisorApi.createContainer).toHaveBeenCalledWith('controller', expect.objectContaining({ password: 'test-secret', rootfs_size: '32', ostemplate: 'local:vztmpl/debian.tar.zst' }));
    expect(screen.queryByText('test-secret')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit creation' })).toBeDisabled();
  });
  it('requires an explicit valid ID and treats suggestions as editable', async () => {
    vi.mocked(hypervisorApi.getNextVMID).mockResolvedValue(ok({ vmid: 150 }));
    const { user } = await setup();
    await user.clear(screen.getByLabelText('VMID'));
    await user.click(screen.getByRole('button', { name: 'Review creation' }));
    await screen.findByRole('alert');
    expect(hypervisorApi.createVM).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Suggest available ID' }));
    await waitFor(() => expect(screen.getByLabelText('VMID')).toHaveValue('150'));
    expect(screen.getByLabelText('VMID')).toBeEnabled();
  });
  it('blocks submission when the controller changes after review', async () => {
    const { user, rerender } = await setup();
    await user.click(screen.getByRole('button', { name: 'Review creation' }));
    rerender(<CreateGuestDialog controllerId="other" kind="vm" nodes={['other']} onClose={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit creation' })).toBeDisabled();
    expect(hypervisorApi.createVM).not.toHaveBeenCalled();
  });
  it('blocks creation in read-only mode', async () => {
    useUIStore.setState({ readOnlyMode: true });
    renderWithProviders(<CreateGuestDialog controllerId="controller" kind="vm" nodes={['pve1']} onClose={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Review creation' })).toBeDisabled();
  });
});
