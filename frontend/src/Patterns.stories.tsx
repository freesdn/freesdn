// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import {
  Server,
  Plus,
  Download,
  CheckCircle,
  AlertCircle,
  Activity,
  Wifi,
  Trash2,
  Power,
} from 'lucide-react';
import { PageHeader } from './components/layout/PageHeader';
import { StatsGrid } from './components/ui/stats-grid';
import { DataTable, type DataTableColumn } from './components/ui/data-table';
import { BulkActionsBar } from './components/ui/bulk-actions-bar';
import { StatusBadge } from './components/ui/status-indicator';
import { EmptyState } from './components/ui/empty-state';
import { SectionBoundary } from './components/SectionBoundary';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';

const meta: Meta = {
  title: 'Patterns/Canonical page compositions',
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component:
          'Reference implementations of full-page compositions. Every list page in FreeSDN follows one of these patterns. Match these compositions exactly when adding new pages · do not invent variants.',
      },
    },
  },
};

export default meta;

interface Device {
  id: string;
  name: string;
  ip: string;
  vendor: string;
  status: 'online' | 'offline' | 'warning';
  uptime: string;
}

const mockDevices: Device[] = [
  { id: '1', name: 'switch-core-01', ip: '10.0.0.1', vendor: 'Cisco', status: 'online', uptime: '94d' },
  { id: '2', name: 'switch-edge-02', ip: '10.0.0.2', vendor: 'Aruba', status: 'online', uptime: '12d' },
  { id: '3', name: 'ap-floor3-east', ip: '10.0.1.21', vendor: 'Ubiquiti', status: 'warning', uptime: '4h' },
  { id: '4', name: 'ap-floor3-west', ip: '10.0.1.22', vendor: 'Ubiquiti', status: 'offline', uptime: '-' },
  { id: '5', name: 'firewall-edge', ip: '10.0.0.254', vendor: 'pfSense', status: 'online', uptime: '247d' },
];

const columns: DataTableColumn<Device>[] = [
  { id: 'name', header: 'Device', accessorKey: 'name', sortable: true },
  { id: 'ip', header: 'IP', cell: (r) => <code className="text-xs">{r.ip}</code> },
  { id: 'vendor', header: 'Vendor', accessorKey: 'vendor', sortable: true },
  { id: 'status', header: 'Status', cell: (r) => <StatusBadge variant={r.status} /> },
  { id: 'uptime', header: 'Uptime', accessorKey: 'uptime' },
];

export const CanonicalListPage: StoryObj = {
  name: 'Canonical list page (PageHeader + StatsGrid + DataTable + BulkActionsBar)',
  render: () => {
    function Demo() {
      const [selected, setSelected] = useState<Device[]>([]);
      return (
        <div className="space-y-6 p-6 bg-background min-h-screen">
          <PageHeader
            icon={Server}
            title="Devices"
            description="142 devices across 4 sites"
            onRefresh={() => {}}
            primaryAction={{ label: 'Add device', icon: Plus, onClick: () => {} }}
            secondaryActions={[{ label: 'Export CSV', icon: Download, onClick: () => {} }]}
          />

          <StatsGrid
            columns={4}
            stats={[
              { title: 'Total devices', value: 142, icon: Server, variant: 'primary', description: 'All registered' },
              { title: 'Online', value: 128, icon: CheckCircle, variant: 'success', description: '90% reachable' },
              { title: 'Recording', value: 12, icon: Activity, variant: 'info', description: 'Live streams' },
              { title: 'Issues', value: 3, icon: AlertCircle, variant: 'destructive', description: '2 offline · 1 error' },
            ]}
          />

          <DataTable
            data={mockDevices}
            columns={columns}
            selectable
            getRowId={(r) => r.id}
            onSelectionChange={(rows) => setSelected(rows)}
            searchable
            searchPlaceholder="Search devices…"
          />

          <BulkActionsBar
            selectedCount={selected.length}
            onClear={() => setSelected([])}
            itemName="device"
            actions={[
              { label: 'Reboot', icon: Power, onClick: () => {} },
              { label: 'Delete', icon: Trash2, variant: 'destructive', onClick: () => {} },
            ]}
          />
        </div>
      );
    }
    return <Demo />;
  },
};

export const DashboardPage: StoryObj = {
  name: 'Dashboard with section boundaries (one bad widget cannot blank the page)',
  render: () => (
    <div className="space-y-6 p-6 bg-background min-h-screen">
      <PageHeader icon={Wifi} title="Network Dashboard" description="Real-time overview" onRefresh={() => {}} />

      <StatsGrid
        columns={4}
        stats={[
          { title: 'Devices online', value: 128, icon: CheckCircle, variant: 'success' },
          { title: 'Total clients', value: '1.2k', icon: Activity, variant: 'info' },
          { title: 'Issues', value: 3, icon: AlertCircle, variant: 'destructive' },
          { title: 'Bandwidth', value: '2.4 Gbps', icon: Wifi, variant: 'primary' },
        ]}
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle className="text-base">Network traffic</CardTitle></CardHeader>
          <CardContent>
            <SectionBoundary>
              <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                Chart widget would render here
              </div>
            </SectionBoundary>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Recent alerts</CardTitle></CardHeader>
          <CardContent>
            <SectionBoundary>
              <ul className="text-sm space-y-2">
                <li className="flex items-center gap-2">
                  <StatusBadge variant="severity_high" size="sm" />
                  switch-edge-02 high CPU
                </li>
                <li className="flex items-center gap-2">
                  <StatusBadge variant="severity_medium" size="sm" />
                  ap-floor3-west offline
                </li>
              </ul>
            </SectionBoundary>
          </CardContent>
        </Card>
      </div>
    </div>
  ),
};

export const EmptyListPage: StoryObj = {
  name: 'List page in empty state (first-time user)',
  render: () => (
    <div className="space-y-6 p-6 bg-background min-h-screen">
      <PageHeader
        icon={Server}
        title="Devices"
        description="No devices yet"
        primaryAction={{ label: 'Add device', icon: Plus, onClick: () => {} }}
      />
      <Card>
        <CardContent noOffset className="py-16">
          <EmptyState
            icon={Server}
            title="No devices in your inventory"
            description="Get started by adding your first device, or run network discovery to find devices automatically."
            action={{ label: 'Add device', icon: Plus, onClick: () => {} }}
            secondaryAction={{ label: 'Run discovery', onClick: () => {} }}
          />
        </CardContent>
      </Card>
    </div>
  ),
};
