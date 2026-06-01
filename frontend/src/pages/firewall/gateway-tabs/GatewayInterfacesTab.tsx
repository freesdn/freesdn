// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayInterfacesTab · physical/virtual interfaces, VLANs, LAGG, virtual IPs,
 * NDP table, and network bridges.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * interfaceColumns definition (only used here) and receives all data plus the
 * Flush ARP callback via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

export interface GatewayInterfacesTabProps {
  interfaces: any[];
  interfacesLoading: boolean;
  vlanDevicesData: any;
  vlanDevicesLoading: boolean;
  laggDevicesData: any;
  laggDevicesLoading: boolean;
  virtualIpsData: any;
  virtualIpsLoading: boolean;
  vipData: any;
  vipLoading: boolean;
  ndpData: any;
  ndpLoading: boolean;
  bridgesData: any;
  bridgesLoading: boolean;
  onFlushArp: () => void;
}

export function GatewayInterfacesTab({
  interfaces,
  interfacesLoading,
  vlanDevicesData,
  vlanDevicesLoading,
  laggDevicesData,
  laggDevicesLoading,
  virtualIpsData,
  virtualIpsLoading,
  vipData,
  vipLoading,
  ndpData,
  ndpLoading,
  bridgesData,
  bridgesLoading,
  onFlushArp,
}: GatewayInterfacesTabProps) {
  const { t } = useTranslation('firewall');
  // Flush ARP confirmation, disrupts every L2 conversation on the LAN.
  const [showFlushArp, setShowFlushArp] = useState(false);

  const interfaceColumns: DataTableColumn<any>[] = [
    { id: 'name', header: t('GatewayInterfacesTab.columns.name'), accessorFn: (r: any) => r.name || r.description || r.descr || '-', sortable: true },
    { id: 'status', header: t('GatewayInterfacesTab.columns.status'), cell: (r: any) => {
      const up = r.status === 'up' || r.running === 'true' || r.running === true;
      return <Badge variant={up ? 'default' : 'secondary'}>{up ? t('GatewayInterfacesTab.status.up') : t('GatewayInterfacesTab.status.down')}</Badge>;
    }},
    { id: 'address', header: t('GatewayInterfacesTab.columns.address'), cell: (r: any) => {
      const addr = r.ipv4_address || r.ipaddr || r.address;
      const subnet = r.ipv4_subnet;
      if (!addr) return <span className="text-muted-foreground">-</span>;
      return <span className="font-mono text-xs">{addr}{subnet ? `/${subnet}` : ''}</span>;
    }},
    { id: 'vlan', header: t('GatewayInterfacesTab.columns.vlan'), cell: (r: any) => {
      const tag = r.vlan_id || r.vlan_tag;
      if (!tag) return <span className="text-muted-foreground">-</span>;
      return <Badge variant="outline" className="font-mono text-xs">{tag}</Badge>;
    }, sortable: true },
    { id: 'parent', header: t('GatewayInterfacesTab.columns.parent'), accessorFn: (r: any) => r.parent_interface || '-' },
    { id: 'device', header: t('GatewayInterfacesTab.columns.device'), accessorFn: (r: any) => r.device || r.identifier || '-' },
    { id: 'type', header: t('GatewayInterfacesTab.columns.type'), accessorFn: (r: any) => r.link_type || r.media || '-' },
    { id: 'mac', header: t('GatewayInterfacesTab.columns.mac'), accessorFn: (r: any) => r.mac_address || r.mac || '-' },
    { id: 'mtu', header: t('GatewayInterfacesTab.columns.mtu'), accessorFn: (r: any) => r.mtu || '-' },
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayInterfacesTab.interfaces.title')}</CardTitle>
              <CardDescription>{t('GatewayInterfacesTab.interfaces.description')}</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => setShowFlushArp(true)}>
              <Trash2 className="h-4 w-4 mr-1" /> {t('GatewayInterfacesTab.actions.flushArp')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={interfaces} columns={interfaceColumns} isLoading={interfacesLoading} searchable embedded />
      </Card>

      {/* VLAN Devices */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayInterfacesTab.vlan.title')}</CardTitle>
          <CardDescription>{t('GatewayInterfacesTab.vlan.description')}</CardDescription>
        </CardHeader>
        <DataTable
          data={vlanDevicesData?.data?.vlans || []}
          isLoading={vlanDevicesLoading}
          columns={[
            { id: 'device', header: t('GatewayInterfacesTab.columns.device'), accessorKey: 'device' },
            { id: 'tag', header: t('GatewayInterfacesTab.columns.vlanTag'), cell: (r: any) => <Badge variant="outline" className="font-mono">{r.tag}</Badge> },
            { id: 'parent', header: t('GatewayInterfacesTab.columns.parent'), cell: (r: any) => <span className="font-mono text-xs">{r.parent_label || r.parent}</span> },
            { id: 'priority', header: t('GatewayInterfacesTab.columns.priority'), accessorKey: 'priority' },
            { id: 'description', header: t('GatewayInterfacesTab.columns.description'), accessorKey: 'description' },
          ] as DataTableColumn<any>[]}
          searchable
          embedded
        />
      </Card>

      {/* LAGG Devices */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayInterfacesTab.lagg.title')}</CardTitle>
          <CardDescription>{t('GatewayInterfacesTab.lagg.description')}</CardDescription>
        </CardHeader>
        <DataTable
          data={laggDevicesData?.data?.laggs || []}
          isLoading={laggDevicesLoading}
          columns={[
            { id: 'device', header: t('GatewayInterfacesTab.columns.device'), accessorFn: (r: any) => r.device, cell: (r: any) => <span className="font-mono font-medium">{r.device}</span> },
            { id: 'protocol', header: t('GatewayInterfacesTab.columns.protocol'), cell: (r: any) => <Badge variant="outline" className="uppercase">{r.protocol || '-'}</Badge> },
            { id: 'members', header: t('GatewayInterfacesTab.columns.members'), cell: (r: any) => (
              <div className="flex flex-wrap gap-1">{(r.members || '').split(',').filter(Boolean).map((m: string) => <Badge key={m} variant="secondary" className="font-mono text-xs">{m.trim()}</Badge>)}</div>
            )},
            { id: 'members_detail', header: t('GatewayInterfacesTab.columns.memberDetails'), accessorFn: (r: any) => r.members_label || '-' },
          ] as DataTableColumn<any>[]}
          embedded
        />
      </Card>

      {/* Virtual IPs (Settings-based · full CRUD data) */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayInterfacesTab.virtualIps.title')}</CardTitle>
          <CardDescription>{t('GatewayInterfacesTab.virtualIps.description', { count: (virtualIpsData?.data?.virtual_ips || []).length })}</CardDescription>
        </CardHeader>
        <DataTable
          data={virtualIpsData?.data?.virtual_ips || vipData?.data?.virtual_ips || []}
          isLoading={virtualIpsLoading || vipLoading}
          columns={[
            { id: 'address', header: t('GatewayInterfacesTab.columns.address'), cell: (r: any) => <span className="font-mono text-xs">{r.address}{r.subnet_bits ? `/${r.subnet_bits}` : ''}</span> },
            { id: 'interface', header: t('GatewayInterfacesTab.columns.interface'), accessorKey: 'interface' },
            { id: 'mode', header: t('GatewayInterfacesTab.columns.mode'), cell: (r: any) => <Badge variant="outline">{r.mode || '-'}</Badge> },
            { id: 'description', header: t('GatewayInterfacesTab.columns.description'), accessorKey: 'description' },
            { id: 'vhid', header: t('GatewayInterfacesTab.columns.vhid'), accessorFn: (r: any) => r.vhid || '-' },
          ] as DataTableColumn<any>[]}
          searchable
          embedded
        />
      </Card>

      {/* NDP Table */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayInterfacesTab.ndp.title')}</CardTitle>
          <CardDescription>{t('GatewayInterfacesTab.ndp.description')}</CardDescription>
        </CardHeader>
        <DataTable
          data={ndpData?.data?.ndp_entries || []}
          isLoading={ndpLoading}
          columns={[
            { header: t('GatewayInterfacesTab.columns.ipv6Address'), accessorKey: 'ipv6' },
            { header: t('GatewayInterfacesTab.columns.mac'), accessorKey: 'mac' },
            { header: t('GatewayInterfacesTab.columns.interface'), accessorKey: 'interface' },
            { header: t('GatewayInterfacesTab.columns.expire'), accessorKey: 'expire' },
          ] as DataTableColumn<any>[]}
          searchable
          embedded
        />
      </Card>

      {/* ─── Network Bridges ────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayInterfacesTab.bridges.title')}</CardTitle>
          <CardDescription>{t('GatewayInterfacesTab.bridges.description')}</CardDescription>
        </CardHeader>
        {bridgesLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayInterfacesTab.bridges.loading')}</div></CardContent>
        ) : (() => {
          const bridges = bridgesData?.data?.bridges || [];
          return bridges.length === 0 ? (
            <CardContent><p className="text-muted-foreground text-sm">{t('GatewayInterfacesTab.bridges.empty')}</p></CardContent>
          ) : (
            <DataTable
              data={bridges}
              isLoading={bridgesLoading}
              columns={[
                { header: t('GatewayInterfacesTab.columns.device'), accessorKey: 'device' },
                { header: t('GatewayInterfacesTab.columns.description'), accessorKey: 'descr' },
                { header: t('GatewayInterfacesTab.columns.members'), accessorKey: 'members' },
                { header: t('GatewayInterfacesTab.columns.linkLocal'), accessorKey: 'linklocal' },
                { header: t('GatewayInterfacesTab.columns.bridgeId'), accessorKey: 'bridgeid' },
              ] as DataTableColumn<any>[]}
              searchable
              embedded
            />
          );
        })()}
      </Card>

      {/* Flush ARP Confirmation */}
      <AlertDialog open={showFlushArp} onOpenChange={setShowFlushArp}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayInterfacesTab.flushArpDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayInterfacesTab.flushArpDialog.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayInterfacesTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                onFlushArp();
                setShowFlushArp(false);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('GatewayInterfacesTab.actions.flushArp')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
