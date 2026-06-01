// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { StatusBadge, StatusIndicator, type StatusVariant } from './status-indicator';

const meta: Meta<typeof StatusBadge> = {
  title: 'Primitives/StatusBadge',
  component: StatusBadge,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Pill badge for status / severity. 21 variants (online/offline/warning/connected/disconnected/syncing/severity_critical/etc.) all map onto 5 visual tones (success/destructive/warning/info/muted).',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof StatusBadge>;

export const Online: Story = { args: { variant: 'online' } };
export const Offline: Story = { args: { variant: 'offline' } };
export const Warning: Story = { args: { variant: 'warning' } };
export const Connected: Story = { args: { variant: 'connected' } };
export const SeverityCritical: Story = { args: { variant: 'severity_critical' } };

export const WithCustomLabel: Story = {
  args: { variant: 'online', children: 'All systems normal' },
};

export const Compact: Story = {
  args: { variant: 'online', size: 'sm' },
};

export const HiddenIcon: Story = {
  args: { variant: 'info', children: 'Just text', hideIcon: true },
};

const allVariants: StatusVariant[] = [
  'online', 'offline', 'warning', 'updating', 'disabled', 'pending',
  'success', 'error', 'neutral', 'info', 'syncing',
  'connected', 'disconnected', 'unknown', 'critical',
  'severity_critical', 'severity_high', 'severity_medium', 'severity_low', 'severity_info',
];

export const AllVariants: Story = {
  name: 'All 20 variants',
  render: () => (
    <div className="flex flex-wrap gap-2 max-w-3xl">
      {allVariants.map((v) => (
        <StatusBadge key={v} variant={v} />
      ))}
    </div>
  ),
};

export const IndicatorOnly: Story = {
  name: 'StatusIndicator (dot only)',
  render: () => (
    <div className="flex items-center gap-4">
      {(['online', 'offline', 'warning', 'updating', 'syncing'] as StatusVariant[]).map((v) => (
        <div key={v} className="flex items-center gap-2 text-sm">
          <StatusIndicator status={v} />
          <span className="text-muted-foreground">{v}</span>
        </div>
      ))}
    </div>
  ),
};
