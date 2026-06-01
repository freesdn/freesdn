// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Routes, Route } from 'react-router-dom';
import { PageTabs } from './PageTabs';

const meta: Meta<typeof PageTabs> = {
  title: 'Layout/PageTabs',
  component: PageTabs,
  parameters: {
    docs: {
      description: {
        component:
          'URL-aware page tabs. The first tab maps to the basePath (e.g. `/firmware`), subsequent tabs map to `/{basePath}/{value}` (e.g. `/firmware/repository`). Reload + bookmark friendly.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof PageTabs>;

const sampleTabs = [
  { value: 'devices', label: 'Devices', count: 142, content: <div className="p-4">Devices content</div> },
  { value: 'repository', label: 'Repository', count: 18, content: <div className="p-4">Repository content</div> },
  { value: 'history', label: 'History', content: <div className="p-4">History content</div> },
];

export const Basic: Story = {
  render: () => (
    <Routes>
      <Route path="/" element={<PageTabs basePath="/" tabs={sampleTabs} />} />
      <Route path="/:tab" element={<PageTabs basePath="/" tabs={sampleTabs} />} />
    </Routes>
  ),
};

export const ManyTabs: Story = {
  name: 'Many tabs (overflow scroll)',
  render: () => {
    const manyTabs = Array.from({ length: 14 }, (_, i) => ({
      value: `tab-${i}`,
      label: ['Overview', 'Ports', 'VLANs', 'LAG', 'PoE', 'RF Health', 'Rogue APs', 'Firmware', 'Config', 'Topology', 'History', 'Logs', 'Alerts', 'Settings'][i],
      content: <div className="p-4">Content for tab {i}</div>,
    }));
    return (
      <div className="max-w-md border border-dashed border-muted-foreground/30 rounded p-2">
        <p className="text-xs text-muted-foreground mb-2">
          Constrained to 400px so the tabs overflow · chevrons + edge fades appear.
        </p>
        <Routes>
          <Route path="/" element={<PageTabs basePath="/" tabs={manyTabs} />} />
          <Route path="/:tab" element={<PageTabs basePath="/" tabs={manyTabs} />} />
        </Routes>
      </div>
    );
  },
};
