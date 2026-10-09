// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { StorageOperationDialog } from '../StorageOperationDialog';
import { hypervisorApi } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewStorageOperation: vi.fn(), uploadToStorage: vi.fn(), deleteStorageVolume: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const review = (action: 'delete' | 'upload' = 'delete') => ({ expected_digest: 'a'.repeat(64), snapshot: { endpoint_node: 'pve1', node: 'pve1', storage: 'local', action, volume: `local:iso/${action === 'upload' ? 'new' : 'old'}.iso`, size: 3, content: 'iso', storage_type: 'dir', storage_digest: 'b'.repeat(64), volume_digest: 'c'.repeat(64), references_digest: 'd'.repeat(64), owner: null } });
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewStorageOperation).mockResolvedValue(ok(review()));
});
function setup(action: 'delete' | 'upload' = 'delete') {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const onTracked = vi.fn();
  return { user: userEvent.setup(), onTracked, ...renderWithProviders(<StorageOperationDialog controllerId="controller" node="pve1" storage="local" action={action} volume={action === 'delete' ? 'local:iso/old.iso' : ''} onClose={vi.fn()} onTracked={onTracked} />, { queryClient }) };
}
async function doReview(user: ReturnType<typeof userEvent.setup>, action: 'delete' | 'upload' = 'delete') {
  if (action === 'upload') await user.upload(screen.getByLabelText('File'), new File(['iso'], 'new.iso'));
  await user.click(screen.getByRole('button', { name: 'Review storage state' }));
  return screen.findByLabelText(`Type the full volume ID: local:iso/${action === 'upload' ? 'new' : 'old'}.iso`);
}

describe('storage operation review', () => {
  it.each(['delete', 'upload'] as const)('requires exact confirmation and sends a durable %s intent', async (action) => {
    vi.mocked(hypervisorApi.reviewStorageOperation).mockResolvedValue(ok(review(action)));
    const method = action === 'delete' ? hypervisorApi.deleteStorageVolume : hypervisorApi.uploadToStorage;
    vi.mocked(method).mockResolvedValue(ok({ action, target: review(action).snapshot.volume, request_id: 'id', change_id: 'receipt', status: 'applied', message: 'Recorded', provider_task: { status: 'pending' } }));
    const { user, onTracked } = setup(action);
    const confirm = await doReview(user, action);
    const button = screen.getByRole('button', { name: 'Submit reviewed operation' });
    expect(button).toBeDisabled();
    await user.type(confirm, review(action).snapshot.volume);
    await user.click(button);
    await waitFor(() => expect(onTracked).toHaveBeenCalledTimes(1));
    expect(method).toHaveBeenCalledTimes(1);
    expect(vi.mocked(method).mock.calls[0][4]).toEqual(expect.objectContaining({ action, expected_digest: 'a'.repeat(64), force: true, confirmed: true, request_id: expect.any(String) }));
  });
  it('never automatically retries and keeps the same file and request ID on manual retry', async () => {
    vi.mocked(hypervisorApi.reviewStorageOperation).mockResolvedValue(ok(review('upload')));
    vi.mocked(hypervisorApi.uploadToStorage).mockRejectedValue(new Error('response lost'));
    const { user } = setup('upload');
    await user.type(await doReview(user, 'upload'), 'local:iso/new.iso');
    const button = screen.getByRole('button', { name: 'Submit reviewed operation' });
    await user.click(button); await screen.findByRole('alert');
    expect(hypervisorApi.uploadToStorage).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.uploadToStorage).mock.calls[0];
    expect(screen.getByLabelText('File')).toBeDisabled();
    await user.click(button);
    await waitFor(() => expect(hypervisorApi.uploadToStorage).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.uploadToStorage).mock.calls[1]).toEqual(first);
  });
  it('blocks dispatch if controller changes after review', async () => {
    const { user, rerender } = setup();
    await user.type(await doReview(user), 'local:iso/old.iso');
    rerender(<StorageOperationDialog controllerId="other" node="pve1" storage="local" action="delete" volume="local:iso/old.iso" onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
    expect(hypervisorApi.deleteStorageVolume).not.toHaveBeenCalled();
  });
  it('blocks read-only writes', async () => {
    const { user } = setup(); useUIStore.setState({ readOnlyMode: true });
    await user.type(await doReview(user), 'local:iso/old.iso');
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
  });
  it('fails closed when review refers to another volume', async () => {
    vi.mocked(hypervisorApi.reviewStorageOperation).mockResolvedValue(ok(review('upload')));
    const { user } = setup();
    await user.click(screen.getByRole('button', { name: 'Review storage state' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit reviewed operation' })).toBeDisabled();
  });
  it('refuses invalid upload names before review', async () => {
    const { user } = setup('upload');
    await user.upload(screen.getByLabelText('File'), new File(['iso'], 'bad..iso'));
    expect(screen.getByRole('button', { name: 'Review storage state' })).toBeDisabled();
    expect(hypervisorApi.reviewStorageOperation).not.toHaveBeenCalled();
  });
});
