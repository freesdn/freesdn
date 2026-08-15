// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { Trash2, Download, Tag, Folder, Power, RefreshCw } from 'lucide-react';
import { BulkActionsBar } from './bulk-actions-bar';

const meta: Meta<typeof BulkActionsBar> = {
  title: 'Primitives/BulkActionsBar',
  component: BulkActionsBar,
  // `skip-visual`: this component is `position: fixed` bottom-center and renders
  // OUTSIDE the Storybook story root at viewport scale, which makes screenshot
  // diffs unstable (anti-aliasing on the floating pill, varying viewport
  // chrome). Visual verification is done manually for now.
  tags: ['skip-visual'],
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component:
          'Fixed bottom-center floating pill that appears when items are selected in a DataTable. Used across every list page for consistent bulk operation UX.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof BulkActionsBar>;

const Sandbox = ({ children }: { children: React.ReactNode }) => (
  <div className="min-h-[400px] bg-muted/20 p-8 relative">
    <p className="text-sm text-muted-foreground">
      The pill renders fixed to the bottom of the viewport. Scroll to see it persist.
    </p>
    {children}
  </div>
);

export const SingleItem: Story = {
  render: () => (
    <Sandbox>
      <BulkActionsBar
        selectedCount={1}
        onClear={() => {}}
        itemName="device"
        actions={[
          { label: 'Reboot', icon: Power, onClick: () => {} },
          { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: () => {} },
        ]}
      />
    </Sandbox>
  ),
};

export const MultipleItems: Story = {
  render: () => (
    <Sandbox>
      <BulkActionsBar
        selectedCount={12}
        onClear={() => {}}
        itemName="camera"
        actions={[
          { label: 'Tag', icon: Tag, onClick: () => {} },
          { label: 'Move to group', icon: Folder, onClick: () => {} },
          { label: 'Reboot', icon: RefreshCw, onClick: () => {} },
          { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: () => {} },
        ]}
      />
    </Sandbox>
  ),
};

export const WithSelectAllPrompt: Story = {
  name: 'With "Select all on all pages" link',
  render: () => (
    <Sandbox>
      <BulkActionsBar
        selectedCount={25}
        totalCount={142}
        isAllPageSelected
        onSelectAll={() => alert('select all 142')}
        onClear={() => {}}
        itemName="device"
        actions={[
          { label: 'Export', icon: Download, onClick: () => {} },
          { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: () => {} },
        ]}
      />
    </Sandbox>
  ),
};

export const Hidden: Story = {
  name: 'Hidden when 0 selected',
  render: () => (
    <Sandbox>
      <p className="mt-4 text-sm">No bar should be visible below.</p>
      <BulkActionsBar selectedCount={0} onClear={() => {}} actions={[]} />
    </Sandbox>
  ),
};
