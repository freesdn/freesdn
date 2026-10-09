// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';

import { BulkActionBar } from '../BulkActionBar';
import { hypervisorApi, type HypervisorNode } from '@/lib/api';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));
vi.mock('@/lib/api', () => ({ hypervisorApi: { bulkMigrate: vi.fn(), bulkAction: vi.fn() } }));

const node: HypervisorNode = {
  id: null, node: 'pve2', status: 'online', ip_address: null,
  cpu_count: 8, cpu_usage: 0, cpu_percent: 0, memory_total: 0, memory_used: 0,
  memory_percent: 0, storage_total: 0, storage_used: 0, storage_percent: 0,
  uptime: 100, pve_version: '', kernel_version: '', cpu_model: '', subscription_level: '',
};
const targets = [
  { node: 'pve1', vm_type: 'qemu', vmid: 101 },
  { node: 'pve1', vm_type: 'lxc', vmid: 102 },
];

beforeEach(() => { vi.clearAllMocks(); vi.mocked(hypervisorApi.bulkMigrate).mockReset(); });

async function openMigration() {
  const user = userEvent.setup();
  const queryClient = makeTestQueryClient();
  // Component must override even an application-wide retry policy.
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  renderWithProviders(<BulkActionBar controllerId="controller" selectedTargets={targets} nodes={[node]} onClear={() => {}} />, { queryClient });
  await user.click(screen.getByRole('button', { name: /^migrate$/i }));
  const dialog = screen.getByRole('dialog');
  await user.click(within(dialog).getByRole('combobox'));
  await user.click(screen.getByRole('option', { name: 'pve2' }));
  return { user, dialog };
}

describe('bulk migration operator safety', () => {
  it('requires explicit container restart consent and reuses IDs after response loss', async () => {
    vi.mocked(hypervisorApi.bulkMigrate).mockRejectedValue(new Error('Response lost'));
    const { user, dialog } = await openMigration();
    const restart = within(dialog).getByRole('checkbox', { name: /allow container shutdown and restart/i });
    expect(restart).not.toBeChecked();
    expect(within(dialog).getByText(/container migration is not live/i)).toBeInTheDocument();
    await user.click(restart);
    await user.click(within(dialog).getByRole('button', { name: /^migrate/i }));
    await screen.findByText('Response lost');
    expect(hypervisorApi.bulkMigrate).toHaveBeenCalledTimes(1);
    const first = vi.mocked(hypervisorApi.bulkMigrate).mock.calls[0][1];
    expect(first).toMatchObject({ online: true, restart: true, target_node: 'pve2' });
    expect(first.targets[0].request_id).toEqual(expect.any(String));
    expect(first.targets[0].request_id).not.toBe(first.targets[1].request_id);
    await user.click(within(dialog).getByRole('button', { name: /^migrate/i }));
    await waitFor(() => expect(hypervisorApi.bulkMigrate).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.bulkMigrate).mock.calls[1][1]).toEqual(first);
  });

  it('reports mixed acknowledgement and uncertainty without claiming completed migration', async () => {
    vi.mocked(hypervisorApi.bulkMigrate).mockResolvedValue({
      status: 200, statusText: 'OK', headers: {}, config: { headers: new AxiosHeaders() },
      data: [
        { vmid: 101, node: 'pve1', success: true, status: 'applied', change_id: 'accepted' },
        { vmid: 102, node: 'pve1', success: false, status: 'reconciliation_required', change_id: 'uncertain', error: 'Check Pending Changes' },
      ],
    });
    const { user, dialog } = await openMigration();
    await user.click(within(dialog).getByRole('button', { name: /^migrate/i }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Requests processed', variant: 'destructive',
      description: expect.stringContaining('1 acknowledged, 1 need review'),
    })));
    expect(vi.mocked(hypervisorApi.bulkMigrate).mock.calls[0][1].restart).toBe(false);
    expect(screen.getByText('Check Pending Changes')).toBeInTheDocument();
  });
});
