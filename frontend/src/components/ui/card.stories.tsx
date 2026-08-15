// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Camera, Server } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './card';
import { Button } from './button';
import { StatusBadge } from './status-indicator';

const meta: Meta<typeof Card> = {
  title: 'Primitives/Card',
  component: Card,
  parameters: { layout: 'padded' },
};

export default meta;
type Story = StoryObj<typeof Card>;

export const Basic: Story = {
  render: () => (
    <Card className="max-w-md">
      <CardHeader>
        <CardTitle>switch-core-01</CardTitle>
        <CardDescription>Primary core switch · Cisco Catalyst 9300</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">48 ports · 12 in use</span>
          <StatusBadge variant="online" />
        </div>
      </CardContent>
    </Card>
  ),
};

export const WithIcon: Story = {
  render: () => (
    <Card className="max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-5 w-5 text-muted-foreground" />
          Core Network
        </CardTitle>
        <CardDescription>4 switches · 2 routers · 1 firewall</CardDescription>
      </CardHeader>
      <CardContent>
        <Button size="sm">View topology</Button>
      </CardContent>
    </Card>
  ),
};

export const Grid: Story = {
  name: 'Grid of cards (dashboard pattern)',
  render: () => (
    <div className="grid gap-4 md:grid-cols-3 max-w-4xl">
      {[
        { title: 'Cameras', icon: Camera, count: '64', sub: 'Across 4 sites' },
        { title: 'Switches', icon: Server, count: '12', sub: 'All online' },
        { title: 'Access Points', icon: Server, count: '38', sub: '2 offline' },
      ].map((c) => (
        <Card key={c.title}>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <c.icon className="h-4 w-4 text-muted-foreground" />
              {c.title}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">{c.count}</div>
            <p className="text-xs text-muted-foreground mt-1">{c.sub}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  ),
};
