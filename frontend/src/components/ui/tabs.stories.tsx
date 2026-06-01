// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './tabs';

const meta: Meta<typeof Tabs> = {
  title: 'Primitives/Tabs',
  component: Tabs,
  parameters: {
    docs: {
      description: {
        component:
          'Horizontally scrollable tab strip. The TabsList wrapper handles overflow with edge fade gradients, scroll chevrons that appear when overflowing, automatic scroll-into-view on the active tab, and wheel-to-horizontal scrolling on desktop.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof Tabs>;

export const Basic: Story = {
  render: () => (
    <Tabs defaultValue="overview" className="w-full max-w-2xl">
      <TabsList>
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="settings">Settings</TabsTrigger>
        <TabsTrigger value="logs">Logs</TabsTrigger>
      </TabsList>
      <TabsContent value="overview" className="p-4">
        Overview content goes here.
      </TabsContent>
      <TabsContent value="settings" className="p-4">
        Settings content goes here.
      </TabsContent>
      <TabsContent value="logs" className="p-4">
        Logs content goes here.
      </TabsContent>
    </Tabs>
  ),
};

export const Overflowing: Story = {
  name: 'Overflowing (scroll + chevrons + fades)',
  render: () => (
    <div className="max-w-md border border-dashed border-muted-foreground/30 rounded p-2">
      <p className="text-xs text-muted-foreground mb-2">
        Container is constrained to 400px so the tabs overflow. Try scrolling horizontally,
        clicking the chevron buttons, or scrolling with your mouse wheel over the strip.
      </p>
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="vlans">VLANs</TabsTrigger>
          <TabsTrigger value="lag">LAG</TabsTrigger>
          <TabsTrigger value="poe">PoE</TabsTrigger>
          <TabsTrigger value="rf-health">RF Health</TabsTrigger>
          <TabsTrigger value="rogue">Rogue APs</TabsTrigger>
          <TabsTrigger value="firmware">Firmware</TabsTrigger>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="topology">Topology</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="p-4 text-sm">
          Active tab auto-scrolls into view when changed.
        </TabsContent>
      </Tabs>
    </div>
  ),
};

export const WithCounts: Story = {
  render: () => (
    <Tabs defaultValue="all" className="w-full max-w-2xl">
      <TabsList>
        <TabsTrigger value="all">
          All
          <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium leading-none text-muted-foreground">
            142
          </span>
        </TabsTrigger>
        <TabsTrigger value="online">
          Online
          <span className="ml-1.5 rounded-full bg-success/15 text-success px-1.5 py-0.5 text-[10px] font-medium leading-none">
            128
          </span>
        </TabsTrigger>
        <TabsTrigger value="offline">
          Offline
          <span className="ml-1.5 rounded-full bg-destructive/15 text-destructive px-1.5 py-0.5 text-[10px] font-medium leading-none">
            14
          </span>
        </TabsTrigger>
      </TabsList>
      <TabsContent value="all" className="p-4 text-sm">
        Showing all 142 items.
      </TabsContent>
    </Tabs>
  ),
};
