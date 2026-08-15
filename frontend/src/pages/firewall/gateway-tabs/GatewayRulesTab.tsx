// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayRulesTab · firewall rules table with push/delete actions.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * ruleColumns definition (only used here) and receives the rules data, vendor
 * label, and add/delete callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { CheckCircle, Plus, Trash2, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayRulesTabProps {
  rules: any[];
  rulesLoading: boolean;
  vendorLabel: string;
  onAddRule: () => void;
  onDeleteRule: (rule: any, vid: string) => void;
}

export function GatewayRulesTab({
  rules,
  rulesLoading,
  vendorLabel,
  onAddRule,
  onDeleteRule,
}: GatewayRulesTabProps) {
  const { t } = useTranslation('firewall');
  const ruleColumns: DataTableColumn<any>[] = [
    { id: 'action', header: t('GatewayRulesTab.columns.action'), accessorKey: 'action', cell: (r: any) => (
      <Badge variant={r.action === 'pass' || r.action === 'accept' || r.action === 'allow' ? 'default' : 'destructive'} className="text-xs uppercase">
        {r.action}
      </Badge>
    )},
    { id: 'direction', header: t('GatewayRulesTab.columns.direction'), accessorFn: (r: any) => r.direction || 'in' },
    { id: 'protocol', header: t('GatewayRulesTab.columns.protocol'), accessorFn: (r: any) => r.protocol || 'any' },
    { id: 'source', header: t('GatewayRulesTab.columns.source'), cell: (r: any) => <span className="text-xs font-mono">{r.source_net || r.source || 'any'}{r.source_port ? `:${r.source_port}` : ''}{r.source_invert ? t('GatewayRulesTab.notSuffix') : ''}</span> },
    { id: 'destination', header: t('GatewayRulesTab.columns.destination'), cell: (r: any) => <span className="text-xs font-mono">{r.destination_net || r.destination || 'any'}{r.destination_port ? `:${r.destination_port}` : ''}{r.destination_invert ? t('GatewayRulesTab.notSuffix') : ''}</span> },
    { id: 'interface', header: t('GatewayRulesTab.columns.interface'), accessorFn: (r: any) => r.interface_name || r.interface || '-' },
    { id: 'gateway', header: t('GatewayRulesTab.columns.gateway'), accessorFn: (r: any) => r.gateway || '-' },
    { id: 'description', header: t('GatewayRulesTab.columns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'enabled', header: t('GatewayRulesTab.columns.enabled'), cell: (r: any) => {
      const enabled = r.enabled !== false && r.enabled !== '0';
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'log', header: t('GatewayRulesTab.columns.log'), cell: (r: any) => {
      return r.log ? <CheckCircle className="h-4 w-4 text-blue-500" /> : <XCircle className="h-4 w-4 text-muted-foreground/30" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id || r.tracking_id;
      return vid ? (
        <Button variant="ghost" size="sm" onClick={() => onDeleteRule(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>
      ) : null;
    }},
  ];

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{t('GatewayRulesTab.title')}</CardTitle>
            <CardDescription>{t('GatewayRulesTab.liveRulesFrom', { vendor: vendorLabel })}</CardDescription>
          </div>
          <Button size="sm" onClick={onAddRule}>
            <Plus className="h-4 w-4 mr-1" /> {t('GatewayRulesTab.pushRule')}
          </Button>
        </div>
      </CardHeader>
      <DataTable data={rules} columns={ruleColumns} isLoading={rulesLoading} searchable searchPlaceholder={t('GatewayRulesTab.searchPlaceholder')} embedded />
    </Card>
  );
}
