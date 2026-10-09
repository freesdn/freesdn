// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { FirewallOperationDialog } from '../FirewallOperationDialog';
import { hypervisorApi } from '@/lib/api';
import type { FirewallReviewIntent } from '@/lib/api/hypervisor';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewFirewallOperation: vi.fn(), submitFirewallOperation: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
const intent: FirewallReviewIntent = { target: { scope: 'cluster' }, action: 'delete', pos: 0 };
const review = { expected_digest: 'a'.repeat(64), target: intent.target, action: intent.action, before: { rules: [{ action: 'ACCEPT' }] }, desired: { rules: [] }, warnings: ['No rollback'] };
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewFirewallOperation).mockResolvedValue(ok(review));
});
function setup() {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const onTracked = vi.fn();
  return { user: userEvent.setup(), onTracked, ...renderWithProviders(<FirewallOperationDialog controllerId="controller" intent={intent} onClose={vi.fn()} onTracked={onTracked} />, { queryClient }) };
}
async function confirm(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Review firewall change' }));
  await user.type(await screen.findByLabelText('Type the target to confirm: cluster:::'), 'cluster:::');
}
describe('reviewed firewall operations', () => {
  it('requires review, typed scope and independent recovery confirmation', async () => {
    vi.mocked(hypervisorApi.submitFirewallOperation).mockResolvedValue(ok({ request_id: 'request', change_id: 'receipt', status: 'applied', provider_task: { status: 'pending' }, message: 'Recorded' }));
    const { user, onTracked } = setup();
    const submit = screen.getByRole('button', { name: 'Submit tracked firewall request' });
    expect(submit).toBeDisabled();
    await confirm(user); expect(submit).toBeDisabled();
    expect(screen.getByText('Current configuration')).toBeVisible();
    expect(screen.getByText('Expected configuration')).toBeVisible();
    await user.click(screen.getByRole('checkbox'));
    await user.click(submit);
    await waitFor(() => expect(onTracked).toHaveBeenCalledTimes(1));
    expect(hypervisorApi.submitFirewallOperation).toHaveBeenCalledWith('controller', expect.objectContaining({ ...intent, expected_digest: 'a'.repeat(64), request_id: expect.any(String), force: true, confirmed: true, recovery_confirmed: true }));
  });
  it('does not automatically retry and reuses the identical request after a lost reply', async () => {
    vi.mocked(hypervisorApi.submitFirewallOperation).mockRejectedValue(new Error('lost reply'));
    const { user } = setup(); await confirm(user); await user.click(screen.getByRole('checkbox'));
    const submit = screen.getByRole('button', { name: 'Submit tracked firewall request' });
    await user.click(submit); await screen.findByRole('alert');
    expect(hypervisorApi.submitFirewallOperation).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.submitFirewallOperation).mock.calls[0];
    await user.click(submit);
    await waitFor(() => expect(hypervisorApi.submitFirewallOperation).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.submitFirewallOperation).mock.calls[1]).toEqual(first);
  });
  it.each(['controller', 'scope', 'rule'] as const)('blocks a changed %s', async (kind) => {
    const { user, rerender } = setup(); await confirm(user); await user.click(screen.getByRole('checkbox'));
    const replacement: FirewallReviewIntent = kind === 'scope' ? { ...intent, target: { scope: 'node', node: 'pve1' } } : kind === 'rule' ? { ...intent, pos: 1 } : intent;
    rerender(<FirewallOperationDialog controllerId={kind === 'controller' ? 'other' : 'controller'} intent={replacement} onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit tracked firewall request' })).toBeDisabled();
    expect(hypervisorApi.submitFirewallOperation).not.toHaveBeenCalled();
  });
  it('blocks dispatch in read-only mode', async () => {
    const { user } = setup(); useUIStore.setState({ readOnlyMode: true });
    await confirm(user); await user.click(screen.getByRole('checkbox'));
    expect(screen.getByRole('button', { name: 'Submit tracked firewall request' })).toBeDisabled();
  });
  it('rejects a review for a different scope', async () => {
    vi.mocked(hypervisorApi.reviewFirewallOperation).mockResolvedValue(ok({ ...review, target: { scope: 'node', node: 'pve1' } }));
    const { user } = setup(); await user.click(screen.getByRole('button', { name: 'Review firewall change' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit tracked firewall request' })).toBeDisabled();
  });
});
