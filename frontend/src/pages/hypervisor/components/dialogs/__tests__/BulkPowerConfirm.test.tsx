// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';

import { BulkActionBar } from '../BulkActionBar';
import { hypervisorApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));
vi.mock('@/lib/api', () => ({ hypervisorApi: { bulkMigrate: vi.fn(), bulkAction: vi.fn() } }));

const targets = [
  { node: 'pve1', vm_type: 'qemu', vmid: 101, name: 'web-01' },
  { node: 'pve2', vm_type: 'lxc', vmid: 102 },
];

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(hypervisorApi.bulkAction).mockResolvedValue({
    status: 200, statusText: 'OK', headers: {}, config: { headers: new AxiosHeaders() },
    data: [
      { vmid: 101, node: 'pve1', success: true, status: 'applied', change_id: 'c1' },
      { vmid: 102, node: 'pve2', success: true, status: 'applied', change_id: 'c2' },
    ],
  });
});

function renderBar() {
  const user = userEvent.setup();
  renderWithProviders(
    <BulkActionBar controllerId="controller" selectedTargets={targets} nodes={[]} onClear={() => {}} />,
  );
  return user;
}

describe('bulk guest power actions ask before reaching the host', () => {
  it('names every guest and the count, and sends nothing on Cancel', async () => {
    const user = renderBar();
    await user.click(screen.getByRole('button', { name: /^force stop$/i }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Force stop 2 VMs/CTs?')).toBeInTheDocument();
    expect(within(dialog).getByText(/like pulling the power cord/i)).toBeInTheDocument();
    expect(within(dialog).getByTestId('confirm-count')).toHaveTextContent('This affects 2 items.');
    const items = within(dialog).getByRole('list', { name: 'Affected items' });
    expect(within(items).getByText('web-01 (VM 101) · pve1')).toBeInTheDocument();
    expect(within(items).getByText('CT 102 · pve2')).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(hypervisorApi.bulkAction).not.toHaveBeenCalled();
  });

  it('sends the action for exactly the selected guests once confirmed', async () => {
    const user = renderBar();
    await user.click(screen.getByRole('button', { name: /^reboot$/i }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Reboot 2 VMs/CTs?')).toBeInTheDocument();
    expect(hypervisorApi.bulkAction).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Reboot' }));

    await waitFor(() => expect(hypervisorApi.bulkAction).toHaveBeenCalledTimes(1));
    expect(hypervisorApi.bulkAction).toHaveBeenCalledWith('controller', {
      action: 'reboot',
      targets: [
        { node: 'pve1', vm_type: 'qemu', vmid: 101 },
        { node: 'pve2', vm_type: 'lxc', vmid: 102 },
      ],
    });
  });
});
