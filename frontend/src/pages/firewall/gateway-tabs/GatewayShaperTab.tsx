// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayShaperTab · traffic shaper pipes, queues, and rules.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * shaperPipeColumns definition (only used here) and receives data, loading
 * flags, and add/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { CheckCircle, Gauge, Plus, Trash2, XCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayShaperTabProps {
  shaperPipes: any[];
  shaperLoading: boolean;
  shaperQueues: any[];
  shaperRules: any[];
  onAddPipe: () => void;
  onDeletePipe: (item: any, vid: string) => void;
  onAddQueue: () => void;
  onDeleteQueue: (item: any, vid: string) => void;
  onAddRule: () => void;
  onDeleteRule: (item: any, vid: string) => void;
}

export function GatewayShaperTab({
  shaperPipes,
  shaperLoading,
  shaperQueues,
  shaperRules,
  onAddPipe,
  onDeletePipe,
  onAddQueue,
  onDeleteQueue,
  onAddRule,
  onDeleteRule,
}: GatewayShaperTabProps) {
  const { t } = useTranslation('firewall');

  const shaperPipeColumns: DataTableColumn<any>[] = [
    { id: 'description', header: t('GatewayShaperTab.columns.description'), accessorFn: (r: any) => r.description || r.descr || '-', sortable: true },
    { id: 'bandwidth', header: t('GatewayShaperTab.columns.bandwidth'), accessorFn: (r: any) => r.bandwidth ? `${r.bandwidth} ${r.bandwidth_metric || 'Kbit/s'}` : '-' },
    { id: 'mask', header: t('GatewayShaperTab.columns.mask'), accessorFn: (r: any) => r.mask || 'none' },
    { id: 'enabled', header: t('GatewayShaperTab.columns.enabled'), cell: (r: any) => {
      const enabled = r.enabled !== false && r.enabled !== '0';
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeletePipe(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Gauge className="h-4 w-4" /> {t('GatewayShaperTab.pipes.title')}</CardTitle>
              <CardDescription>{t('GatewayShaperTab.pipes.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddPipe}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayShaperTab.actions.addPipe')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={shaperPipes} columns={shaperPipeColumns} isLoading={shaperLoading} searchable embedded />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayShaperTab.queues.title', { count: shaperQueues.length })}</CardTitle>
              <CardDescription>{t('GatewayShaperTab.queues.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddQueue}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayShaperTab.actions.addQueue')}
            </Button>
          </div>
        </CardHeader>
        <DataTable
          data={shaperQueues}
          columns={[
            { header: t('GatewayShaperTab.columns.description'), accessorKey: 'description' },
            { header: t('GatewayShaperTab.columns.pipe'), accessorKey: 'pipe' },
            { header: t('GatewayShaperTab.columns.weight'), accessorKey: 'weight' },
            { header: t('GatewayShaperTab.columns.mask'), accessorKey: 'mask' },
            { header: t('GatewayShaperTab.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={row.original.enabled !== false ? 'default' : 'secondary'}>{row.original.enabled !== false ? t('GatewayShaperTab.values.yes') : t('GatewayShaperTab.values.no')}</Badge> },
            { header: t('GatewayShaperTab.columns.actions'), id: 'actions', cell: ({ row }: any) => (
              <Button variant="ghost" size="sm" className="text-destructive" onClick={() => onDeleteQueue(row.original, row.original.uuid)}>
                <Trash2 className="h-4 w-4" />
              </Button>
            )},
          ] as DataTableColumn<any>[]}
          embedded
        />
      </Card>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayShaperTab.rules.title', { count: shaperRules.length })}</CardTitle>
              <CardDescription>{t('GatewayShaperTab.rules.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={onAddRule}>
              <Plus className="h-4 w-4 mr-1" /> {t('GatewayShaperTab.actions.addRule')}
            </Button>
          </div>
        </CardHeader>
        <DataTable
          data={shaperRules}
          columns={[
            { header: '#', accessorKey: 'sequence' },
            { header: t('GatewayShaperTab.columns.description'), accessorKey: 'description' },
            { header: t('GatewayShaperTab.columns.interface'), accessorKey: 'interface' },
            { header: t('GatewayShaperTab.columns.protocol'), accessorKey: 'protocol' },
            { header: t('GatewayShaperTab.columns.source'), accessorKey: 'source' },
            { header: t('GatewayShaperTab.columns.destination'), accessorKey: 'destination' },
            { header: t('GatewayShaperTab.columns.pipe'), accessorKey: 'target_pipe' },
            { header: t('GatewayShaperTab.columns.queue'), accessorKey: 'target_queue' },
            { header: t('GatewayShaperTab.columns.enabled'), accessorKey: 'enabled', cell: ({ row }: any) => <Badge variant={row.original.enabled !== false ? 'default' : 'secondary'}>{row.original.enabled !== false ? t('GatewayShaperTab.values.yes') : t('GatewayShaperTab.values.no')}</Badge> },
            { header: t('GatewayShaperTab.columns.actions'), id: 'actions', cell: ({ row }: any) => (
              <Button variant="ghost" size="sm" className="text-destructive" onClick={() => onDeleteRule(row.original, row.original.uuid)}>
                <Trash2 className="h-4 w-4" />
              </Button>
            )},
          ] as DataTableColumn<any>[]}
          searchable
          embedded
        />
      </Card>
    </>
  );
}
