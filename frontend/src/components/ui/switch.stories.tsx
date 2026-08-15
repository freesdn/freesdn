// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { Switch } from './switch';
import { Label } from './label';

const meta: Meta<typeof Switch> = {
  title: 'Primitives/Switch',
  component: Switch,
  parameters: { layout: 'padded' },
};

export default meta;
type Story = StoryObj<typeof Switch>;

export const Basic: Story = {
  render: () => {
    function Demo() {
      const [enabled, setEnabled] = useState(false);
      return (
        <div className="flex items-center space-x-2">
          <Switch id="basic" checked={enabled} onCheckedChange={setEnabled} />
          <Label htmlFor="basic">Enable notifications</Label>
        </div>
      );
    }
    return <Demo />;
  },
};

export const SettingRow: Story = {
  name: 'Settings row pattern (label + description + switch)',
  render: () => {
    function Demo() {
      const [enabled, setEnabled] = useState(true);
      return (
        <div className="flex items-start justify-between max-w-md py-3">
          <div className="space-y-0.5">
            <Label htmlFor="setting" className="text-sm font-medium">Auto-discovery</Label>
            <p className="text-xs text-muted-foreground">
              Automatically scan the network every 30 minutes.
            </p>
          </div>
          <Switch id="setting" checked={enabled} onCheckedChange={setEnabled} />
        </div>
      );
    }
    return <Demo />;
  },
};

export const Disabled: Story = {
  render: () => (
    <div className="space-y-2">
      <div className="flex items-center space-x-2">
        <Switch id="d1" disabled />
        <Label htmlFor="d1">Disabled, off</Label>
      </div>
      <div className="flex items-center space-x-2">
        <Switch id="d2" disabled checked />
        <Label htmlFor="d2">Disabled, on</Label>
      </div>
    </div>
  ),
};
