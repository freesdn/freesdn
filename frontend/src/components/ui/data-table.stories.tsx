// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { DataTable, type DataTableColumn } from './data-table';
import { StatusBadge } from './status-indicator';
import { BulkActionsBar } from './bulk-actions-bar';
import { Trash2, Download } from 'lucide-react';

interface Device {
  id: string;
  name: string;
  ip: string;
  status: 'online' | 'offline' | 'warning';
  vendor: string;
  uptime: string;
}

const mockDevices: Device[] = [
  { id: '1', name: 'switch-core-01', ip: '10.0.0.1', status: 'online', vendor: 'Cisco', uptime: '94d' },
  { id: '2', name: 'switch-edge-02', ip: '10.0.0.2', status: 'online', vendor: 'Aruba', uptime: '12d' },
  { id: '3', name: 'ap-floor3-east', ip: '10.0.1.21', status: 'warning', vendor: 'Ubiquiti', uptime: '4h' },
  { id: '4', name: 'ap-floor3-west', ip: '10.0.1.22', status: 'offline', vendor: 'Ubiquiti', uptime: '-' },
  { id: '5', name: 'firewall-edge', ip: '10.0.0.254', status: 'online', vendor: 'pfSense', uptime: '247d' },
];

const columns: DataTableColumn<Device>[] = [
  { id: 'name', header: 'Device', accessorKey: 'name', sortable: true },
  { id: 'ip', header: 'IP Address', cell: (r) => <code className="text-xs">{r.ip}</code> },
  { id: 'vendor', header: 'Vendor', accessorKey: 'vendor', sortable: true },
  { id: 'status', header: 'Status', cell: (r) => <StatusBadge variant={r.status} /> },
  { id: 'uptime', header: 'Uptime', accessorKey: 'uptime' },
];

const meta: Meta<typeof DataTable> = {
  title: 'Primitives/DataTable',
  component: DataTable,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Enterprise data table built on @tanstack/react-table. Features: row selection, sorting, pagination, search, custom cells, embedded mode, loading skeleton.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof DataTable>;

export const Basic: Story = {
  render: () => <DataTable data={mockDevices} columns={columns} />,
};

export const Empty: Story = {
  render: () => <DataTable data={[]} columns={columns} />,
};

export const Loading: Story = {
  render: () => <DataTable data={[]} columns={columns} isLoading />,
};

export const Selectable: Story = {
  render: () => (
    <DataTable
      data={mockDevices}
      columns={columns}
      selectable
      getRowId={(r) => r.id}
      onSelectionChange={(rows) => console.log('selected:', rows)}
    />
  ),
};

export const SelectableWithBulkBar: Story = {
  name: 'Selectable + BulkActionsBar (full integration)',
  render: () => {
    function Demo() {
      const [selected, setSelected] = useState<Device[]>([]);
      return (
        <>
          <DataTable
            data={mockDevices}
            columns={columns}
            selectable
            getRowId={(r) => r.id}
            onSelectionChange={(rows) => setSelected(rows)}
          />
          <BulkActionsBar
            selectedCount={selected.length}
            onClear={() => setSelected([])}
            itemName="device"
            actions={[
              { label: 'Export', icon: Download, onClick: () => {} },
              { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: () => {} },
            ]}
          />
        </>
      );
    }
    return <Demo />;
  },
};

export const Clickable: Story = {
  render: () => (
    <DataTable
      data={mockDevices}
      columns={columns}
      onRowClick={(r) => alert(`clicked ${r.name}`)}
    />
  ),
};
