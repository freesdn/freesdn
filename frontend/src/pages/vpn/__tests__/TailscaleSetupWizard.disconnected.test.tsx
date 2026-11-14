// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils/render';
import TailscaleSetupWizard from '../TailscaleSetupWizard';

vi.mock('@/lib/api/vpn', () => ({
  vpnApi: {
    tailscale: {
      setup: {
        getStatus: vi.fn(),
        startDaemon: vi.fn(),
        reconnect: vi.fn(),
      },
    },
  },
}));

import { vpnApi } from '@/lib/api/vpn';

const disconnected = {
  state: 'disconnected',
  installed: true,
  daemon_running: true,
  authenticated: true,
  connected: false,
  version: '1.104.5',
  hostname: 'office-controller',
  tailscale_ip: null,
  tailnet: null,
  login_url: null,
  message: 'Tailscale is disconnected.',
};

describe('TailscaleSetupWizard after Disconnect', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(vpnApi.tailscale.setup.getStatus).mockResolvedValue({ data: disconnected } as never);
    vi.mocked(vpnApi.tailscale.setup.reconnect).mockResolvedValue({
      data: { success: true, message: 'Tailscale reconnected.', state: 'connected' },
    } as never);
  });

  it('offers Reconnect, not Start daemon, and reconnects', async () => {
    const user = userEvent.setup();
    renderWithProviders(<TailscaleSetupWizard />);

    await screen.findByText('Tailscale Is Disconnected');
    expect(screen.queryByRole('button', { name: /Start Tailscale Daemon/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Reconnect' }));
    await waitFor(() => expect(vpnApi.tailscale.setup.reconnect).toHaveBeenCalledTimes(1));
    expect(vpnApi.tailscale.setup.startDaemon).not.toHaveBeenCalled();
  });
});
