// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayNatTab · NAT rules, port forwards, and 1:1 (binat) NAT.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * natColumns and portFwdColumns definitions (only used here) and receives all
 * data, loading flags, and add/edit/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { CheckCircle, Pencil, Plus, RefreshCw, Trash2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayNatTabProps {
  natRules: any[];
  natLoading: boolean;
  portForwards: any[];
  portFwdLoading: boolean;
  oneToOneNatData: any;
  oneToOneNatLoading: boolean;
  onAddSourceNat: () => void;
  onAddPortForward: () => void;
  onEditPortForward: (item: any) => void;
  onDeleteNatRule: (item: any, vid: string) => void;
  onDeletePortForward: (item: any, vid: string) => void;
}

export function GatewayNatTab({
  natRules,
  natLoading,
  portForwards,
  portFwdLoading,
  oneToOneNatData,
  oneToOneNatLoading,
  onAddSourceNat,
  onAddPortForward,
  onEditPortForward,
  onDeleteNatRule,
  onDeletePortForward,
}: GatewayNatTabProps) {
  const { t } = useTranslation('firewall');

  const natColumns: DataTableColumn<any>[] = [
    { id: 'type', header: t('GatewayNatTab.columns.type'), accessorFn: (r: any) => r.type || r.chain || 'nat' },
    { id: 'protocol', header: t('GatewayNatTab.columns.protocol'), accessorFn: (r: any) => r.protocol || 'any' },
    { id: 'source', header: t('GatewayNatTab.columns.source'), accessorFn: (r: any) => r.source || r.src_address || 'any' },
    { id: 'destination', header: t('GatewayNatTab.columns.destination'), accessorFn: (r: any) => r.destination || r.dst_address || 'any' },
    { id: 'target', header: t('GatewayNatTab.columns.target'), accessorFn: (r: any) => r.target || r.to_addresses || r.to_ports || '-' },
    { id: 'description', header: t('GatewayNatTab.columns.description'), accessorFn: (r: any) => r.description || r.comment || '-' },
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeleteNatRule(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  const portFwdColumns: DataTableColumn<any>[] = [
    { id: 'interface', header: t('GatewayNatTab.columns.interface'), accessorFn: (r: any) => r.interface || '-' },
    { id: 'protocol', header: t('GatewayNatTab.columns.protocol'), accessorFn: (r: any) => r.protocol || 'any' },
    { id: 'src', header: t('GatewayNatTab.columns.source'), accessorFn: (r: any) => r.source || r.src_address || 'any' },
    { id: 'dst_port', header: t('GatewayNatTab.columns.destPort'), accessorFn: (r: any) => r.dst_port || r.destination_port || '-' },
    { id: 'target', header: t('GatewayNatTab.columns.target'), accessorFn: (r: any) => `${r.target_ip || r.target || '-'}:${r.target_port || ''}` },
    { id: 'description', header: t('GatewayNatTab.columns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'enabled', header: t('GatewayNatTab.columns.enabled'), cell: (r: any) => {
      const enabled = r.enabled !== false && r.disabled !== true;
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => onEditPortForward(r)}><Pencil className="h-3.5 w-3.5" /></Button>
          {vid && <Button variant="ghost" size="sm" onClick={() => onDeletePortForward(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>}
        </div>
      );
    }},
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayNatTab.natRules.title')}</CardTitle>
              <CardDescription>{t('GatewayNatTab.natRules.description')}</CardDescription>
            </div>
            <Button size="sm" variant="outline" onClick={onAddSourceNat}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayNatTab.actions.sourceNat')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={natRules} columns={natColumns} isLoading={natLoading} searchable embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayNatTab.portForwards.title')}</CardTitle>
              <CardDescription>{t('GatewayNatTab.portForwards.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddPortForward}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayNatTab.actions.addForward')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={portForwards} columns={portFwdColumns} isLoading={portFwdLoading} searchable embedded />
      </Card>

      {/* ─── 1:1 NAT (Binat) Rules ──────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayNatTab.binat.title')}</CardTitle>
          <CardDescription>{t('GatewayNatTab.binat.description')}</CardDescription>
        </CardHeader>
        {oneToOneNatLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayNatTab.binat.loading')}</div></CardContent>
        ) : (() => {
          const rules = oneToOneNatData?.data?.onetoone_nat_rules || [];
          return (
            <DataTable
              data={rules}
              isLoading={oneToOneNatLoading}
              columns={[
                { header: t('GatewayNatTab.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={String(row.original.enabled) === '1' ? 'default' : 'secondary'}>{String(row.original.enabled) === '1' ? t('GatewayNatTab.values.yes') : t('GatewayNatTab.values.no')}</Badge> },
                { header: t('GatewayNatTab.columns.interface'), accessorKey: 'interface' },
                { header: t('GatewayNatTab.columns.type'), accessorKey: 'type' },
                { header: t('GatewayNatTab.columns.externalIp'), accessorKey: 'external' },
                { header: t('GatewayNatTab.columns.internalIp'), accessorKey: 'internal' },
                { header: t('GatewayNatTab.columns.destination'), accessorKey: 'destination' },
                { header: t('GatewayNatTab.columns.description'), accessorKey: 'description' },
              ] as DataTableColumn<any>[]}
              searchable
              embedded
            />
          );
        })()}
      </Card>
    </>
  );
}
