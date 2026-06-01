// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { Checkbox } from './checkbox';
import { Label } from './label';

const meta: Meta<typeof Checkbox> = {
  title: 'Primitives/Checkbox',
  component: Checkbox,
  parameters: { layout: 'padded' },
};

export default meta;
type Story = StoryObj<typeof Checkbox>;

export const Basic: Story = {
  render: () => {
    function Demo() {
      const [checked, setChecked] = useState(false);
      return (
        <div className="flex items-center space-x-2">
          <Checkbox id="basic" checked={checked} onCheckedChange={(v) => setChecked(!!v)} />
          <Label htmlFor="basic" className="cursor-pointer">Accept terms and conditions</Label>
        </div>
      );
    }
    return <Demo />;
  },
};

export const Indeterminate: Story = {
  render: () => (
    <div className="flex items-center space-x-2">
      <Checkbox id="indet" checked="indeterminate" />
      <Label htmlFor="indet">Some items selected</Label>
    </div>
  ),
};

export const Disabled: Story = {
  render: () => (
    <div className="space-y-2">
      <div className="flex items-center space-x-2">
        <Checkbox id="d1" disabled />
        <Label htmlFor="d1">Disabled, unchecked</Label>
      </div>
      <div className="flex items-center space-x-2">
        <Checkbox id="d2" disabled checked />
        <Label htmlFor="d2">Disabled, checked</Label>
      </div>
    </div>
  ),
};
