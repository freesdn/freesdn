// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Info, AlertCircle, HelpCircle } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './tooltip';
import { Button } from './button';

const meta: Meta = {
  title: 'Primitives/Tooltip',
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'Radix-based tooltip. Always wrap in `<TooltipProvider>` (already done in MainLayout · bare stories need their own provider). Default delay is short; set `delayDuration={0}` for instant, or `300` for hover-deliberate.',
      },
    },
  },
};

export default meta;
type Story = StoryObj;

export const Basic: Story = {
  render: () => (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline">Hover me</Button>
        </TooltipTrigger>
        <TooltipContent>
          <p>I'm a tooltip</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  ),
};

export const IconWithHelp: Story = {
  name: 'Help icon next to a label',
  render: () => (
    <TooltipProvider>
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">Site latency</span>
        <Tooltip>
          <TooltipTrigger asChild>
            <button aria-label="What is site latency?" className="text-muted-foreground hover:text-foreground">
              <HelpCircle className="h-4 w-4" />
            </button>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            <p>
              Round-trip time between the controller and edge devices.
              Anything above 80ms typically degrades real-time features.
            </p>
          </TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  ),
};

export const Sides: Story = {
  name: 'Sides (top, right, bottom, left)',
  render: () => (
    <TooltipProvider>
      <div className="grid grid-cols-2 gap-4">
        {(['top', 'right', 'bottom', 'left'] as const).map((side) => (
          <Tooltip key={side}>
            <TooltipTrigger asChild>
              <Button variant="outline">{side}</Button>
            </TooltipTrigger>
            <TooltipContent side={side}>
              <p>Tooltip on {side}</p>
            </TooltipContent>
          </Tooltip>
        ))}
      </div>
    </TooltipProvider>
  ),
};

export const InlineIconList: Story = {
  name: 'Inline icon list (each with own tooltip)',
  render: () => (
    <TooltipProvider>
      <div className="flex items-center gap-3 text-sm">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="flex items-center gap-1 text-success">
              <Info className="h-3.5 w-3.5" /> 128
            </span>
          </TooltipTrigger>
          <TooltipContent><p>128 devices online</p></TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="flex items-center gap-1 text-destructive">
              <AlertCircle className="h-3.5 w-3.5" /> 3
            </span>
          </TooltipTrigger>
          <TooltipContent><p>3 devices in error state</p></TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  ),
};
