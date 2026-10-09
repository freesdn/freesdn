// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { BackupJobDialog } from '../BackupJobDialog';
import { hypervisorApi, type HypervisorBackupJob } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewBackupJob: vi.fn(), createBackupJob: vi.fn(), updateBackupJob: vi.fn(), deleteBackupJob: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const job: HypervisorBackupJob = { id: 'nightly', storage: 'local', schedule: 'sat 02:00', vmid: '101', node: 'pve1', mode: 'snapshot', compress: 'zstd', enabled: true, mailto: '' };
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewBackupJob).mockImplementation(async (_controller, body) => ok({ expected_digest: 'a'.repeat(64), warnings: [], snapshot: {
    action: body.action, job_id: body.job_id, before: body.action === 'create' ? null : job,
    desired: body.settings ? { ...body.settings, enabled: Number(body.settings.enabled) } : null,
  } }));
});
function setup(action: 'create' | 'update' | 'delete' = 'update') {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const onTracked = vi.fn();
  return { user: userEvent.setup(), onTracked, ...renderWithProviders(<BackupJobDialog open controllerId="controller" nodes={[]} editJob={action === 'update' ? job : null} deleteJob={action === 'delete' ? job : null} onClose={vi.fn()} onTracked={onTracked} />, { queryClient }) };
}
async function doReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Review backup schedule' }));
  return screen.findByLabelText(/Type the exact job ID:/);
}
describe('reviewed backup schedules', () => {
  it.each(['create', 'update', 'delete'] as const)('confirms and tracks %s without claiming backup success', async (action) => {
    const method = action === 'create' ? hypervisorApi.createBackupJob : action === 'update' ? hypervisorApi.updateBackupJob : hypervisorApi.deleteBackupJob;
    vi.mocked(method).mockResolvedValue(ok({ action, job_id: 'nightly', request_id: 'id', change_id: 'receipt', status: 'applied', provider_task: { status: 'pending' }, message: 'Recorded' }));
    const { user, onTracked } = setup(action);
    if (action === 'create') {
      expect(screen.getByRole('checkbox')).not.toBeChecked();
      await user.type(screen.getByLabelText('Node'), 'pve1');
      await user.type(screen.getByLabelText('Guest IDs (comma-separated, no spaces)'), '101');
    }
    const confirm = await doReview(user);
    const body = vi.mocked(hypervisorApi.reviewBackupJob).mock.calls[0][1];
    const submit = screen.getByRole('button', { name: 'Submit reviewed schedule' });
    expect(submit).toBeDisabled();
    await user.type(confirm, body.job_id);
    await user.click(submit);
    await waitFor(() => expect(onTracked).toHaveBeenCalledTimes(1));
    const call = vi.mocked(method).mock.calls[0];
    expect(call[call.length - 1]).toEqual(expect.objectContaining({ ...body, force: true, confirmed: true, expected_digest: 'a'.repeat(64), request_id: expect.any(String) }));
    expect(method).toHaveBeenCalledTimes(1);
  });
  it('reuses a frozen intent and does not retry automatically after a lost response', async () => {
    vi.mocked(hypervisorApi.updateBackupJob).mockRejectedValue(new Error('lost response'));
    const { user } = setup();
    await user.type(await doReview(user), 'nightly');
    const submit = screen.getByRole('button', { name: 'Submit reviewed schedule' });
    await user.click(submit); await screen.findByRole('alert');
    expect(hypervisorApi.updateBackupJob).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText('Schedule')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Review backup schedule' })).toBeDisabled();
    const first = vi.mocked(hypervisorApi.updateBackupJob).mock.calls[0];
    await user.click(submit);
    await waitFor(() => expect(hypervisorApi.updateBackupJob).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.updateBackupJob).mock.calls[1]).toEqual(first);
  });
  it('blocks changed controller after review', async () => {
    const { user, rerender } = setup();
    await user.type(await doReview(user), 'nightly');
    rerender(<BackupJobDialog open controllerId="other" nodes={[]} editJob={job} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit reviewed schedule' })).toBeDisabled();
    expect(hypervisorApi.updateBackupJob).not.toHaveBeenCalled();
  });
  it('blocks read-only dispatch', async () => {
    const { user } = setup(); useUIStore.setState({ readOnlyMode: true });
    await user.type(await doReview(user), 'nightly');
    expect(screen.getByRole('button', { name: 'Submit reviewed schedule' })).toBeDisabled();
  });
  it('refuses review for different settings', async () => {
    vi.mocked(hypervisorApi.reviewBackupJob).mockResolvedValue(ok({ expected_digest: 'a'.repeat(64), warnings: [], snapshot: { action: 'update', job_id: 'nightly', desired: { ...job, schedule: '03:00', enabled: 1 } } }));
    const { user } = setup();
    await user.click(screen.getByRole('button', { name: 'Review backup schedule' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit reviewed schedule' })).toBeDisabled();
  });
});
