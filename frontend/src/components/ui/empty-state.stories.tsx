// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Camera, Server, Search, Plus } from 'lucide-react';
import { EmptyState } from './empty-state';

const meta: Meta<typeof EmptyState> = {
  title: 'Primitives/EmptyState',
  component: EmptyState,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Consistent empty state UI for lists, tables, and pages. 3 variants: default (large), compact (inline), card (dashed border).',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof EmptyState>;

export const Default: Story = {
  args: {
    icon: Camera,
    title: 'No cameras configured',
    description: 'Get started by adding your first camera or running a discovery scan to find cameras on your network.',
    action: { label: 'Add camera', icon: Plus, onClick: () => alert('add') },
    secondaryAction: { label: 'Run discovery', onClick: () => alert('discover') },
  },
};

export const Compact: Story = {
  args: {
    icon: Search,
    title: 'No results match your filters',
    variant: 'compact',
  },
};

export const Card: Story = {
  args: {
    icon: Server,
    title: 'No devices in this site',
    description: 'Add a device to see status, alerts and metrics here.',
    action: { label: 'Add device', icon: Plus, onClick: () => {} },
    variant: 'card',
  },
};

export const TitleOnly: Story = {
  args: { title: 'Nothing to show' },
};

export const TwoActions: Story = {
  args: {
    icon: Camera,
    title: 'No cameras yet',
    description: 'Add one manually or import from CSV.',
    action: { label: 'Add camera', icon: Plus, onClick: () => {} },
    secondaryAction: { label: 'Import CSV', onClick: () => {} },
  },
};
