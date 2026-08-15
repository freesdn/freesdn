// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayRoutingTab · static routes, kernel routing table, and ARP entries.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * three column definitions (only used in this tab) and receives all data,
 * loading flags, and add/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { CheckCircle, Plus, Trash2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayRoutingTabProps {
  staticRoutes: any[];
  routesLoading: boolean;
  routingTable: any[];
  rtLoading: boolean;
  arpEntries: any[];
  arpLoading: boolean;
  onAddRoute: () => void;
  onDeleteRoute: (item: any, vid: string) => void;
}

export function GatewayRoutingTab({
  staticRoutes,
  routesLoading,
  routingTable,
  rtLoading,
  arpEntries,
  arpLoading,
  onAddRoute,
  onDeleteRoute,
}: GatewayRoutingTabProps) {
  const { t } = useTranslation('firewall');

  const staticRouteColumns: DataTableColumn<any>[] = [
    { id: 'network', header: t('GatewayRoutingTab.staticRoutes.columns.network'), accessorFn: (r: any) => r.network || '-', sortable: true },
    { id: 'gateway', header: t('GatewayRoutingTab.staticRoutes.columns.gateway'), accessorFn: (r: any) => r.gateway || '-' },
    { id: 'description', header: t('GatewayRoutingTab.staticRoutes.columns.description'), accessorFn: (r: any) => r.description || r.descr || '-' },
    { id: 'disabled', header: t('GatewayRoutingTab.staticRoutes.columns.active'), cell: (r: any) => {
      const active = !r.disabled;
      return active ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeleteRoute(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  const routingTableColumns: DataTableColumn<any>[] = [
    { id: 'destination', header: t('GatewayRoutingTab.routingTable.columns.destination'), accessorFn: (r: any) => r.destination || r.network || '-', sortable: true },
    { id: 'gateway', header: t('GatewayRoutingTab.routingTable.columns.gateway'), accessorFn: (r: any) => r.gateway || r.nexthop || '-' },
    { id: 'interface', header: t('GatewayRoutingTab.routingTable.columns.interface'), accessorFn: (r: any) => r.interface || r.netif || '-' },
    { id: 'flags', header: t('GatewayRoutingTab.routingTable.columns.flags'), accessorFn: (r: any) => r.flags || '-' },
    { id: 'type', header: t('GatewayRoutingTab.routingTable.columns.type'), accessorFn: (r: any) => r.type || r.protocol || '-' },
  ];

  const arpColumns: DataTableColumn<any>[] = [
    { id: 'ip', header: t('GatewayRoutingTab.arpTable.columns.ip'), accessorFn: (r: any) => r.ip_address || r.ip || '-', sortable: true },
    { id: 'mac', header: t('GatewayRoutingTab.arpTable.columns.mac'), accessorFn: (r: any) => r.mac_address || r.mac || '-' },
    { id: 'hostname', header: t('GatewayRoutingTab.arpTable.columns.hostname'), accessorFn: (r: any) => r.hostname || '-' },
    { id: 'interface', header: t('GatewayRoutingTab.arpTable.columns.interface'), accessorFn: (r: any) => r.interface_name || r.interface || '-' },
    { id: 'manufacturer', header: t('GatewayRoutingTab.arpTable.columns.manufacturer'), accessorFn: (r: any) => r.manufacturer || '-' },
    { id: 'type', header: t('GatewayRoutingTab.arpTable.columns.type'), cell: (r: any) => {
      const perm = r.permanent === true || r.permanent === 'True';
      return <Badge variant={perm ? 'default' : 'secondary'}>{perm ? t('GatewayRoutingTab.arpTable.permanent') : t('GatewayRoutingTab.arpTable.dynamic')}</Badge>;
    }},
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayRoutingTab.staticRoutes.title')}</CardTitle>
              <CardDescription>{t('GatewayRoutingTab.staticRoutes.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddRoute}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayRoutingTab.staticRoutes.addRoute')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={staticRoutes} columns={staticRouteColumns} isLoading={routesLoading} searchable embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayRoutingTab.routingTable.title')}</CardTitle>
          <CardDescription>{t('GatewayRoutingTab.routingTable.description')}</CardDescription>
        </CardHeader>
        <DataTable data={routingTable} columns={routingTableColumns} isLoading={rtLoading} searchable searchPlaceholder={t('GatewayRoutingTab.routingTable.searchPlaceholder')} embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayRoutingTab.arpTable.title')}</CardTitle>
          <CardDescription>{t('GatewayRoutingTab.arpTable.description')}</CardDescription>
        </CardHeader>
        <DataTable data={arpEntries} columns={arpColumns} isLoading={arpLoading} searchable searchPlaceholder={t('GatewayRoutingTab.arpTable.searchPlaceholder')} embedded />
      </Card>
    </>
  );
}
