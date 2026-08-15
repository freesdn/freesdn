// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { ComponentProps } from 'react';
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Search } from 'lucide-react';
import { Input } from './input';
import { Label } from './label';

type InputArgs = ComponentProps<typeof Input>;

const meta: Meta<typeof Input> = {
  title: 'Primitives/Input',
  component: Input,
  parameters: { layout: 'padded' },
};

export default meta;
type Story = StoryObj<typeof Input>;

export const Basic: Story = {
  args: { placeholder: 'Type here…' },
  render: (args: InputArgs) => (
    <div className="max-w-sm">
      <Input {...args} />
    </div>
  ),
};

export const WithLabel: Story = {
  render: () => (
    <div className="max-w-sm space-y-2">
      <Label htmlFor="email">Email</Label>
      <Input id="email" type="email" placeholder="you@example.com" />
    </div>
  ),
};

export const WithIcon: Story = {
  name: 'With prefix icon (search bar pattern)',
  render: () => (
    <div className="relative max-w-sm">
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input className="pl-9" placeholder="Search devices…" />
    </div>
  ),
};

export const Disabled: Story = {
  args: { placeholder: 'Cannot edit', disabled: true, value: 'Locked value' },
  render: (args: InputArgs) => <div className="max-w-sm"><Input {...args} /></div>,
};

export const WithError: Story = {
  name: 'With error state (manual)',
  render: () => (
    <div className="max-w-sm space-y-2">
      <Label htmlFor="port" className="text-destructive">Port</Label>
      <Input id="port" type="number" defaultValue="99999" aria-invalid />
      <p className="text-xs text-destructive">Port must be between 1 and 65535</p>
    </div>
  ),
};

export const Number: Story = {
  args: { type: 'number', placeholder: '0', defaultValue: 443 },
  render: (args: InputArgs) => <div className="max-w-sm"><Input {...args} /></div>,
};
