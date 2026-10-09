// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FirewallPanel } from '../FirewallPanel';
import { hypervisorApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';
import { useUIStore } from '@/stores';
import type { FirewallReviewIntent } from '@/lib/api/hypervisor';

vi.mock('@/lib/api', () => ({ hypervisorApi: { getClusterFirewallRules: vi.fn(), getNodeFirewallRules: vi.fn(), getGuestFirewallRules: vi.fn() } }));
vi.mock('@/components/gateways/PendingChangesDrawer', () => ({ PendingChangesDrawer: () => null }));
vi.mock('../dialogs/FirewallOperationDialog', () => ({ FirewallOperationDialog: ({ intent }: { intent: FirewallReviewIntent }) => <output aria-label="selected intent">{JSON.stringify(intent)}</output> }));
beforeEach(() => {
  vi.resetAllMocks(); useUIStore.setState({ readOnlyMode: false });
  const response = { data: [{ pos: 0, action: 'ACCEPT', type: 'in', enable: true, comment: 'scope-rule' }] };
  for (const method of [hypervisorApi.getClusterFirewallRules, hypervisorApi.getNodeFirewallRules, hypervisorApi.getGuestFirewallRules]) {
    vi.mocked(method).mockResolvedValue(response as Awaited<ReturnType<typeof method>>);
  }
});
describe('firewall scope selection', () => {
  it('deletes a displayed cluster rule at cluster scope, even when nodes exist', async () => {
    renderWithProviders(<FirewallPanel controllerId="controller" nodes={[{ node: 'pve1' }]} />);
    await screen.findByText('scope-rule');
    await userEvent.click(screen.getByRole('button', { name: 'Review delete' }));
    expect(JSON.parse(screen.getByLabelText('selected intent').textContent!)).toMatchObject({ target: { scope: 'cluster' }, action: 'delete', pos: 0 });
    expect(hypervisorApi.getNodeFirewallRules).not.toHaveBeenCalled();
  });
  it('changes both the rule query and operation target when a node is selected', async () => {
    renderWithProviders(<FirewallPanel controllerId="controller" nodes={[{ node: 'pve1' }]} />);
    await userEvent.selectOptions(screen.getByLabelText('Firewall scope'), 'pve1');
    await waitFor(() => expect(hypervisorApi.getNodeFirewallRules).toHaveBeenCalledWith('controller', 'pve1'));
    await screen.findByText('scope-rule');
    await userEvent.click(screen.getByRole('button', { name: 'Review delete' }));
    expect(JSON.parse(screen.getByLabelText('selected intent').textContent!)).toMatchObject({ target: { scope: 'node', node: 'pve1' }, action: 'delete', pos: 0 });
  });
  it('keeps container identity in guest queries and intents', async () => {
    renderWithProviders(<FirewallPanel controllerId="controller" guest={{ node: 'pve2', vm_type: 'lxc', vmid: 120 }} />);
    await screen.findByText('scope-rule');
    await userEvent.click(screen.getByRole('button', { name: 'Review delete' }));
    expect(hypervisorApi.getGuestFirewallRules).toHaveBeenCalledWith('controller', 'pve2', 'lxc', 120);
    expect(JSON.parse(screen.getByLabelText('selected intent').textContent!)).toMatchObject({ target: { scope: 'guest', node: 'pve2', vm_type: 'lxc', vmid: 120 } });
  });
  it('refuses an unknown guest type instead of selecting QEMU implicitly', async () => {
    renderWithProviders(<FirewallPanel controllerId="controller" guest={{ node: 'pve1', vm_type: 'unknown', vmid: 101 }} />);
    expect(screen.getByRole('alert')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Review new rule' })).toBeDisabled();
    expect(hypervisorApi.getGuestFirewallRules).not.toHaveBeenCalled();
  });

});
