// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GuestDetailDrawer } from '../GuestDetailDrawer';
import type { HypervisorVM } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({ hypervisorApi: {} }));
vi.mock('../FirewallPanel', () => ({ FirewallPanel: () => null }));

const vm: HypervisorVM = {
  id: null, vmid: 104, name: 'db-01', node: 'pve1', vm_type: 'qemu', status: 'running',
  cpu_cores: 2, cpu_usage: 0, cpu_percent: 5, memory_mb: 2048, memory_used_mb: 1024,
  memory_percent: 50, disk_gb: 32, disk_used_gb: 8, disk_percent: 25, ip_address: null,
  net_in: 0, net_out: 0, uptime: 3600, tags: [], template: false, ha_state: null, lock: null,
  os_type: null,
};

describe('guest drawer power actions', () => {
  it('shuts down only after the operator confirms, and does nothing on Cancel', async () => {
    const user = userEvent.setup();
    const onAction = vi.fn();
    renderWithProviders(
      <GuestDetailDrawer vm={vm} controllerId="controller" isOpen onClose={() => {}} onAction={onAction} />,
    );

    await user.click(screen.getByRole('button', { name: /^shutdown$/i }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Shutdown VM 104?')).toBeInTheDocument();
    expect(within(dialog).getByText(/graceful shutdown signal to db-01 \(VM 104\) on node pve1/i)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(onAction).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: /^shutdown$/i }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Shutdown' }));
    await waitFor(() => expect(onAction).toHaveBeenCalledTimes(1));
    expect(onAction).toHaveBeenCalledWith({ node: 'pve1', vmType: 'qemu', vmid: 104, action: 'shutdown' });
  });
});
