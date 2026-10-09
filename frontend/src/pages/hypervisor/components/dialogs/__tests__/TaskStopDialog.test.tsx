// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { TaskStopDialog } from '../TaskStopDialog';
import { hypervisorApi } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewTaskStop: vi.fn(), stopTask: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const target = { controllerId: 'controller', node: 'pve1', upid: 'UPID:pve1:00001234:00ABCDEF:00000000:qmstart:101:root@pam!audit:' };
const review = { expected_digest: 'a'.repeat(64), snapshot: { node: target.node, upid: target.upid, task_type: 'qmstart', status: 'running' as const }, warnings: [] };
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewTaskStop).mockResolvedValue(ok(review));
});
function setup() {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const onTracked = vi.fn();
  return { user: userEvent.setup(), onTracked, ...renderWithProviders(<TaskStopDialog controllerId="controller" target={target} onClose={vi.fn()} onTracked={onTracked} />, { queryClient }) };
}
async function confirm(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Review running task' }));
  await user.type(await screen.findByLabelText('Type the node name to confirm: pve1'), 'pve1');
}
describe('reviewed task termination', () => {
  it('requires review and typed confirmation and tracks the receipt', async () => {
    vi.mocked(hypervisorApi.stopTask).mockResolvedValue(ok({ node: 'pve1', upid: target.upid, request_id: 'request', change_id: 'receipt', status: 'applied', provider_task: { status: 'pending' }, message: 'Recorded' }));
    const { user, onTracked } = setup();
    expect(screen.getByRole('button', { name: 'Submit tracked stop request' })).toBeDisabled();
    expect(screen.getByText(/Stopping a worker does not undo its changes/)).toBeVisible();
    await confirm(user);
    await user.click(screen.getByRole('button', { name: 'Submit tracked stop request' }));
    await waitFor(() => expect(onTracked).toHaveBeenCalledTimes(1));
    expect(hypervisorApi.stopTask).toHaveBeenCalledWith('controller', 'pve1', target.upid, expect.objectContaining({ expected_digest: 'a'.repeat(64), request_id: expect.any(String), force: true, confirmed: true }));
  });
  it('does not automatically retry and reuses the request identity on manual retry', async () => {
    vi.mocked(hypervisorApi.stopTask).mockRejectedValue(new Error('lost reply'));
    const { user } = setup();
    await confirm(user);
    const submit = screen.getByRole('button', { name: 'Submit tracked stop request' });
    await user.click(submit); await screen.findByRole('alert');
    expect(hypervisorApi.stopTask).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Review running task' })).toBeDisabled();
    const first = vi.mocked(hypervisorApi.stopTask).mock.calls[0];
    await user.click(submit);
    await waitFor(() => expect(hypervisorApi.stopTask).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.stopTask).mock.calls[1]).toEqual(first);
  });
  it('blocks a controller switch after review', async () => {
    const { user, rerender } = setup();
    await confirm(user);
    rerender(<TaskStopDialog controllerId="other" target={target} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit tracked stop request' })).toBeDisabled();
    expect(hypervisorApi.stopTask).not.toHaveBeenCalled();
  });
  it('blocks another task replacing the reviewed target', async () => {
    const { user, rerender } = setup();
    await confirm(user);
    rerender(<TaskStopDialog controllerId="controller" target={{ ...target, upid: target.upid.replace('101:', '102:') }} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit tracked stop request' })).toBeDisabled();
  });
  it('blocks read-only dispatch', async () => {
    const { user } = setup(); useUIStore.setState({ readOnlyMode: true });
    await confirm(user);
    expect(screen.getByRole('button', { name: 'Submit tracked stop request' })).toBeDisabled();
  });
  it('rejects a mismatched provider review', async () => {
    vi.mocked(hypervisorApi.reviewTaskStop).mockResolvedValue(ok({ ...review, snapshot: { ...review.snapshot, node: 'pve2' } }));
    const { user } = setup();
    await user.click(screen.getByRole('button', { name: 'Review running task' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit tracked stop request' })).toBeDisabled();
  });
});
