// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import {
  Server,
  CheckCircle,
  AlertCircle,
  Activity,
  Wifi,
  HardDrive,
  Camera,
  Phone,
} from 'lucide-react';
import { StatsGrid } from './stats-grid';

const meta: Meta<typeof StatsGrid> = {
  title: 'Primitives/StatsGrid',
  component: StatsGrid,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Animated KPI grid used at the top of every list page. Supports 2/3/4 columns and 6 semantic variants (default, primary, success, warning, destructive, info).',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof StatsGrid>;

const baseStats = [
  { title: 'Total Devices', value: 142, icon: Server, variant: 'primary' as const, description: 'All registered' },
  { title: 'Online', value: 128, icon: CheckCircle, variant: 'success' as const, description: '90% reachable' },
  { title: 'Recording', value: 12, icon: Activity, variant: 'info' as const, description: 'Live streams' },
  { title: 'Issues', value: 3, icon: AlertCircle, variant: 'destructive' as const, description: '2 offline · 1 error' },
];

export const FourColumn: Story = {
  args: { stats: baseStats, columns: 4 },
};

export const ThreeColumn: Story = {
  args: { stats: baseStats.slice(0, 3), columns: 3 },
};

export const TwoColumn: Story = {
  args: { stats: baseStats.slice(0, 2), columns: 2 },
};

export const Loading: Story = {
  args: { stats: baseStats, columns: 4, isLoading: true },
};

export const AllVariants: Story = {
  args: {
    columns: 4,
    stats: [
      { title: 'Default', value: 10, icon: Wifi, variant: 'default' },
      { title: 'Primary', value: 142, icon: Server, variant: 'primary' },
      { title: 'Success', value: 128, icon: CheckCircle, variant: 'success' },
      { title: 'Warning', value: 4, icon: AlertCircle, variant: 'warning' },
      { title: 'Destructive', value: 3, icon: AlertCircle, variant: 'destructive' },
      { title: 'Info', value: 12, icon: Activity, variant: 'info' },
      { title: 'Cameras', value: 64, icon: Camera, variant: 'primary', description: 'Across 4 sites' },
      { title: 'Storage', value: '4.2 TB', icon: HardDrive, variant: 'info', description: '78% used' },
    ],
  },
};

export const StringValues: Story = {
  name: 'String values (e.g. "4.2 TB")',
  args: {
    columns: 3,
    stats: [
      { title: 'Bandwidth', value: '1.2 Gbps', icon: Activity, variant: 'success' },
      { title: 'Storage', value: '4.2 TB', icon: HardDrive, variant: 'info' },
      { title: 'Active calls', value: '- none -', icon: Phone, variant: 'default' },
    ],
  },
};
