// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils/render';
import { AgentSettingsPanel } from '../AgentSettingsPanel';

vi.mock('@/lib/api/agents', () => ({
  agentsApi: {
    update: vi.fn(),
  },
}));

import { agentsApi } from '@/lib/api/agents';

const agent: any = {
  id: 'agent-1',
  name: 'laptop_agent',
  description: 'Field lab laptop',
  agent_type: 'site',
  capabilities: {},
  supported_vendors: [],
  config: {},
  status: 'online',
  uptime_seconds: 0,
  total_connections: 1,
  total_tasks_executed: 0,
  failed_tasks: 0,
  poll_interval: 30,
  is_approved: true,
  is_enabled: true,
  notification_channels: { email: { to: ['ops@example.com'] } },
  offline_threshold_seconds: 240,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('AgentSettingsPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('prefills fields from the agent shape', () => {
    renderWithProviders(<AgentSettingsPanel agent={agent} />);
    expect(screen.getByDisplayValue('Field lab laptop')).toBeInTheDocument();
    expect(screen.getByDisplayValue('30')).toBeInTheDocument();
    expect(screen.getByDisplayValue('240')).toBeInTheDocument();
    expect(screen.getByDisplayValue('ops@example.com')).toBeInTheDocument();
  });

  it('save dispatches PATCH with collated notification channels', async () => {
    const user = userEvent.setup();
    (agentsApi.update as any).mockResolvedValue({ data: agent });
    renderWithProviders(<AgentSettingsPanel agent={agent} />);

    const emailInput = screen.getByDisplayValue('ops@example.com');
    await user.clear(emailInput);
    await user.type(emailInput, 'ops@example.com, oncall@example.com');

    const slackInput = screen.getByPlaceholderText('#alerts');
    await user.type(slackInput, '#fleet');

    await user.click(screen.getByRole('button', { name: /Save settings/i }));

    await waitFor(() => expect(agentsApi.update).toHaveBeenCalled());
    const [calledId, payload] = (agentsApi.update as any).mock.calls[0];
    expect(calledId).toBe('agent-1');
    expect(payload.notification_channels.email.to).toEqual([
      'ops@example.com',
      'oncall@example.com',
    ]);
    expect(payload.notification_channels.slack.channel).toBe('#fleet');
    expect(payload.offline_threshold_seconds).toBe(240);
    expect(payload.is_enabled).toBe(true);
  });

  it('renders the offline-alert banner when offline_notified_at is set', () => {
    const withAlert = {
      ...agent,
      offline_notified_at: new Date().toISOString(),
    };
    renderWithProviders(<AgentSettingsPanel agent={withAlert} />);
    expect(screen.getByText(/Last alert dispatched/i)).toBeInTheDocument();
  });
});
