// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './select';
import { Label } from './label';

const meta: Meta = {
  title: 'Primitives/Select',
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Radix-based Select. **Important**: Radix forbids empty-string SelectItem values. For a "show all" option, use a sentinel like `"all"` and translate to `undefined` at the API boundary · NOT `value=""`.',
      },
    },
  },
};

export default meta;
type Story = StoryObj;

export const Basic: Story = {
  render: () => {
    function Demo() {
      const [value, setValue] = useState<string>();
      return (
        <div className="max-w-xs space-y-2">
          <Label>Vendor</Label>
          <Select value={value} onValueChange={setValue}>
            <SelectTrigger>
              <SelectValue placeholder="Select vendor" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="cisco">Cisco</SelectItem>
              <SelectItem value="aruba">Aruba</SelectItem>
              <SelectItem value="ubiquiti">Ubiquiti</SelectItem>
              <SelectItem value="mikrotik">MikroTik</SelectItem>
            </SelectContent>
          </Select>
          {value && <p className="text-xs text-muted-foreground">Selected: {value}</p>}
        </div>
      );
    }
    return <Demo />;
  },
};

export const WithAllSentinel: Story = {
  name: 'With "all" sentinel for filters',
  render: () => {
    function Demo() {
      const [value, setValue] = useState<string>('all');
      // At API boundary: const apiValue = value === 'all' ? undefined : value;
      return (
        <div className="max-w-xs space-y-2">
          <Label>Status filter</Label>
          <Select value={value} onValueChange={setValue}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="online">Online</SelectItem>
              <SelectItem value="offline">Offline</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
            </SelectContent>
          </Select>
        </div>
      );
    }
    return <Demo />;
  },
};

export const Disabled: Story = {
  render: () => (
    <div className="max-w-xs space-y-2">
      <Label>Vendor</Label>
      <Select disabled>
        <SelectTrigger>
          <SelectValue placeholder="Cannot edit" />
        </SelectTrigger>
      </Select>
    </div>
  ),
};
