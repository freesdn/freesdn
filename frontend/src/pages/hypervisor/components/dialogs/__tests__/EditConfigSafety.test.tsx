// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosHeaders } from 'axios';
import { EditConfigDialog } from '../EditConfigDialog';
import { hypervisorApi, type HypervisorVM } from '@/lib/api';
import { makeTestQueryClient, renderWithProviders } from '@/test-utils';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));
vi.mock('@/lib/api', () => ({ hypervisorApi: { getVMConfig: vi.fn(), updateConfig: vi.fn(), getGuestAgentInfo: vi.fn() } }));
const ok = <T,>(data: T) => ({ data, status: 200, statusText: 'OK', headers: {}, config: { headers: new AxiosHeaders() } });
const vm: HypervisorVM = {
  id: null, vmid: 101, name: 'guest', node: 'pve1', vm_type: 'lxc', status: 'stopped',
  cpu_cores: 2, cpu_usage: 0, cpu_percent: 0, memory_mb: 512, memory_used_mb: 0, memory_percent: 0,
  disk_gb: 32, disk_used_gb: 0, disk_percent: 0, ip_address: null, net_in: 0, net_out: 0,
  uptime: 0, tags: [], template: false, ha_state: null, lock: null, os_type: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(hypervisorApi.updateConfig).mockReset();
  vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok({ digest: 'a'.repeat(40), cores: 2, memory: 512, rootfs: 'local:disk,size=32G' }));
});

async function openConfig() {
  const user = userEvent.setup();
  const queryClient = makeTestQueryClient();
  queryClient.setDefaultOptions({ mutations: { retry: 2, retryDelay: 0 } });
  const onTracked = vi.fn();
  renderWithProviders(<EditConfigDialog open onClose={() => {}} controllerId="controller" vm={vm} onTracked={onTracked} />, { queryClient });
  const cores = await screen.findByRole('spinbutton', { name: /cpu cores/i });
  await user.clear(cores);
  await user.type(cores, '4');
  return { user, queryClient, cores, onTracked };
}

describe('configuration review safety', () => {
  it('preserves the review across query refresh and retries; refuses a changed submitted intent', async () => {
    vi.mocked(hypervisorApi.updateConfig).mockRejectedValue(new Error('Response lost'));
    const { user, queryClient, cores, onTracked } = await openConfig();
    expect(screen.queryByRole('spinbutton', { name: /balloon/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /save/i }));
    await screen.findByText('Response lost');
    expect(hypervisorApi.updateConfig).toHaveBeenCalledTimes(1);
    expect(onTracked).toHaveBeenCalled();
    const first = vi.mocked(hypervisorApi.updateConfig).mock.calls[0][4];
    expect(first).toEqual({ cores: 4, request_id: expect.any(String), expected_digest: 'a'.repeat(40) });
    vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok({ digest: 'b'.repeat(40), cores: 4, memory: 512 }));
    await queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    expect(hypervisorApi.getVMConfig).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(hypervisorApi.updateConfig).toHaveBeenCalledTimes(2));
    expect(vi.mocked(hypervisorApi.updateConfig).mock.calls[1][4]).toEqual(first);
    await screen.findByText('Response lost');
    await user.clear(cores);
    await user.type(cores, '8');
    await user.click(screen.getByRole('button', { name: /save/i }));
    await screen.findByText(/This request has already been submitted/);
    expect(hypervisorApi.updateConfig).toHaveBeenCalledTimes(2);
  });

  it('says restart required when the provider saved but has not activated the configuration', async () => {
    vi.mocked(hypervisorApi.updateConfig).mockResolvedValue(ok({ action: 'config', vmid: 101, request_id: crypto.randomUUID(), status: 'applied', change_id: 'change', provider_task: { status: 'pending', detail: 'configuration_pending_restart' }, message: 'Accepted', upid: null }));
    const { user } = await openConfig();
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Configuration saved; restart is still required' })));
  });

  it('disables writes if the provider did not supply a review digest', async () => {
    vi.mocked(hypervisorApi.getVMConfig).mockResolvedValue(ok({ cores: 2, memory: 512 }));
    await openConfig();
    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled();
    expect(hypervisorApi.updateConfig).not.toHaveBeenCalled();
  });
});
