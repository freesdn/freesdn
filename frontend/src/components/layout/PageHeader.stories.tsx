// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Server, Plus, Download, Upload, Settings } from 'lucide-react';
import { PageHeader } from './PageHeader';

const meta: Meta<typeof PageHeader> = {
  title: 'Layout/PageHeader',
  component: PageHeader,
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component:
          'Unified page header used across every list and detail page. Supports a simple `actions` slot, or a structured primary/secondary/refresh API.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof PageHeader>;

export const Minimal: Story = {
  args: {
    title: 'Controllers',
    description: 'Manage network controllers and device managers',
    icon: Server,
  },
};

export const WithRefresh: Story = {
  args: {
    title: 'Controllers',
    description: 'Auto-refreshing every 30s',
    icon: Server,
    onRefresh: () => alert('refresh!'),
  },
};

export const WithActions: Story = {
  args: {
    title: 'Controllers',
    description: 'Manage network controllers',
    icon: Server,
    onRefresh: () => {},
    primaryAction: { label: 'Add Controller', icon: Plus, onClick: () => alert('add') },
    secondaryActions: [
      { label: 'Export CSV', icon: Download, onClick: () => alert('export') },
      { label: 'Import', icon: Upload, onClick: () => alert('import') },
    ],
  },
};

export const Loading: Story = {
  args: {
    title: 'Controllers',
    description: 'Refreshing…',
    icon: Server,
    onRefresh: () => {},
    refreshing: true,
    primaryAction: { label: 'Add Controller', icon: Plus, onClick: () => {}, loading: true },
  },
};

export const HiddenAction: Story = {
  name: 'Hidden secondary actions',
  args: {
    title: 'Settings',
    description: 'Some secondary actions hidden by permission',
    icon: Settings,
    secondaryActions: [
      { label: 'Visible', icon: Download, onClick: () => {} },
      { label: 'Hidden (admin only)', icon: Settings, onClick: () => {}, hidden: true },
    ],
  },
};
