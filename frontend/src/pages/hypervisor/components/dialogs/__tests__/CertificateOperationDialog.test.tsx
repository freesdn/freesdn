// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { CertificateOperationDialog } from '../CertificateOperationDialog';
import { hypervisorApi } from '@/lib/api';
import { useUIStore } from '@/stores';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: { reviewCertificate: vi.fn(), uploadCustomCertificate: vi.fn(), deleteCustomCertificate: vi.fn(), renewAcmeCertificate: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 202, statusText: 'Accepted', headers: {}, config: { headers: new AxiosHeaders() } });
type Action = 'upload' | 'delete' | 'renew';
const review = (action: Action = 'upload') => ({ expected_digest: 'a'.repeat(64), snapshot: { action, node: 'pve1', endpoint_node: 'pve1', overwrite: false, restart: false, acme_force: false, expected_domains: ['pve1.example.invalid'], inventory: { 'pve-ssl.pem': { fingerprint: 'b'.repeat(64) } }, candidate: action === 'upload' ? { subject: 'CN=pve1.example.invalid', san: ['pve1.example.invalid'], notafter: 1900000000, fingerprint: 'c'.repeat(64) } : null } });
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  vi.mocked(hypervisorApi.reviewCertificate).mockResolvedValue(ok(review()));
});
function setup(action: Action = 'upload') {
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  return { user: userEvent.setup(), ...renderWithProviders(<CertificateOperationDialog controllerId="controller" node="pve1" action={action} onClose={vi.fn()} onTracked={vi.fn()} />, { queryClient }) };
}
async function uploadReview(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Certificate (PEM)'), 'public-certificate');
  await user.type(screen.getByLabelText('Private Key (PEM)'), 'private-key-fixture');
  await user.click(screen.getByRole('button', { name: 'Validate and review' }));
  await screen.findByText('Validated candidate certificate');
}

describe('certificate operation review', () => {
  it('shows only metadata after review and requires exact typed confirmation', async () => {
    vi.mocked(hypervisorApi.uploadCustomCertificate).mockResolvedValue(ok({ action: 'upload', target: 'pve1', request_id: 'id', change_id: 'receipt', status: 'applied', message: 'Recorded', provider_task: { status: 'pending' } }));
    const { user, queryClient } = setup();
    await uploadReview(user);
    expect(screen.queryByDisplayValue('private-key-fixture')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('private-key-fixture');
    expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain('private-key-fixture');
    const button = screen.getByRole('button', { name: 'Submit reviewed certificate change' });
    expect(button).toBeDisabled();
    await user.type(screen.getByLabelText('Type the exact node to confirm: pve1'), 'pve1');
    await user.click(button);
    expect(await screen.findByText(/applied · receipt · pending/)).toBeInTheDocument();
    expect(screen.getByText(/Acceptance does not prove activation/)).toBeInTheDocument();
    expect(hypervisorApi.uploadCustomCertificate).toHaveBeenCalledWith('controller', 'pve1', expect.objectContaining({ key: 'private-key-fixture', certificates: 'public-certificate', expected_digest: 'a'.repeat(64), force: true, confirmed: true, request_id: expect.any(String) }));
    expect(button).toBeDisabled();
  });
  it('does not automatically retry a write and preserves frozen parameters on manual retry', async () => {
    vi.mocked(hypervisorApi.uploadCustomCertificate).mockRejectedValue(new Error('response lost'));
    const { user } = setup();
    await uploadReview(user);
    await user.type(screen.getByLabelText('Type the exact node to confirm: pve1'), 'pve1');
    const button = screen.getByRole('button', { name: 'Submit reviewed certificate change' });
    await user.click(button);
    await screen.findByRole('alert');
    expect(hypervisorApi.uploadCustomCertificate).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.uploadCustomCertificate).mock.calls[0];
    await user.click(button);
    await waitFor(() => expect(hypervisorApi.uploadCustomCertificate).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.uploadCustomCertificate).mock.calls[1]).toEqual(first);
    expect(hypervisorApi.reviewCertificate).toHaveBeenCalledTimes(1);
  });
  it.each(['delete', 'renew'] as const)('reviews and dispatches %s with an explicit durable body', async (action) => {
    vi.mocked(hypervisorApi.reviewCertificate).mockResolvedValue(ok(review(action)));
    const method = action === 'delete' ? hypervisorApi.deleteCustomCertificate : hypervisorApi.renewAcmeCertificate;
    vi.mocked(method).mockResolvedValue(ok({ action, target: 'pve1', request_id: 'id', change_id: 'receipt', status: 'applied', message: 'Recorded', provider_task: { status: 'pending' } }));
    const { user } = setup(action);
    expect(screen.queryByLabelText('Private Key (PEM)')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Validate and review' }));
    await user.type(await screen.findByLabelText('Type the exact node to confirm: pve1'), 'pve1');
    await user.click(screen.getByRole('button', { name: 'Submit reviewed certificate change' }));
    await waitFor(() => expect(method).toHaveBeenCalledTimes(1));
    expect(method).toHaveBeenCalledWith('controller', 'pve1', expect.objectContaining({ action, request_id: expect.any(String), confirmed: true, force: true, expected_digest: 'a'.repeat(64) }));
  });
  it('blocks submission after a target change', async () => {
    const { user, rerender } = setup();
    await uploadReview(user);
    await user.type(screen.getByLabelText('Type the exact node to confirm: pve1'), 'pve1');
    rerender(<CertificateOperationDialog controllerId="other" node="pve1" action="upload" onClose={vi.fn()} onTracked={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Submit reviewed certificate change' })).toBeDisabled();
    expect(hypervisorApi.uploadCustomCertificate).not.toHaveBeenCalled();
  });
  it('allows review but blocks submission in read-only mode', async () => {
    useUIStore.setState({ readOnlyMode: true });
    const { user } = setup();
    await uploadReview(user);
    await user.type(screen.getByLabelText('Type the exact node to confirm: pve1'), 'pve1');
    expect(screen.getByRole('button', { name: 'Submit reviewed certificate change' })).toBeDisabled();
  });
  it('fails closed without automatic retry if review is unavailable', async () => {
    vi.mocked(hypervisorApi.reviewCertificate).mockRejectedValue(new Error('denied'));
    const { user } = setup('delete');
    await user.click(screen.getByRole('button', { name: 'Validate and review' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit reviewed certificate change' })).toBeDisabled();
    expect(hypervisorApi.reviewCertificate).toHaveBeenCalledTimes(1);
  });
  it('fails closed if review belongs to another action', async () => {
    vi.mocked(hypervisorApi.reviewCertificate).mockResolvedValue(ok(review('renew')));
    const { user } = setup('delete');
    await user.click(screen.getByRole('button', { name: 'Validate and review' }));
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: 'Submit reviewed certificate change' })).toBeDisabled();
  });
});
