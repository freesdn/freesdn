// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayAliasesTab · firewall aliases listing for the gateway detail page.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * aliasColumns definition (only used here) and receives data + edit/delete
 * callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { CheckCircle, Pencil, Plus, Trash2, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayAliasesTabProps {
  aliases: any[];
  aliasesLoading: boolean;
  onAddAlias: () => void;
  onEditAlias: (item: any) => void;
  onDeleteAlias: (item: any, vid: string) => void;
}

export function GatewayAliasesTab({
  aliases,
  aliasesLoading,
  onAddAlias,
  onEditAlias,
  onDeleteAlias,
}: GatewayAliasesTabProps) {
  const { t } = useTranslation('firewall');

  const aliasColumns: DataTableColumn<any>[] = [
    { id: 'name', header: t('GatewayAliasesTab.columns.name'), accessorFn: (r: any) => r.name || '-', sortable: true },
    { id: 'type', header: t('GatewayAliasesTab.columns.type'), accessorFn: (r: any) => r.alias_type || r.type || '-' },
    { id: 'content', header: t('GatewayAliasesTab.columns.content'), cell: (r: any) => {
      const items = Array.isArray(r.content) ? r.content : [r.content];
      return <span className="text-xs font-mono">{items.slice(0, 3).join(', ')}{items.length > 3 ? ` +${items.length - 3}` : ''}</span>;
    }},
    { id: 'description', header: t('GatewayAliasesTab.columns.description'), accessorFn: (r: any) => r.description || '-' },
    { id: 'enabled', header: t('GatewayAliasesTab.columns.enabled'), cell: (r: any) => {
      const enabled = r.enabled !== false && r.enabled !== '0';
      return enabled ? <CheckCircle className="h-4 w-4 text-green-600" /> : <XCircle className="h-4 w-4 text-muted-foreground" />;
    }},
    { id: 'actions', header: '', cell: (r: any) => {
      const vid = r.uuid || r.id;
      return (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => onEditAlias(r)}><Pencil className="h-3.5 w-3.5" /></Button>
          {vid && <Button variant="ghost" size="sm" onClick={() => onDeleteAlias(r, vid)}><Trash2 className="h-3.5 w-3.5 text-destructive" /></Button>}
        </div>
      );
    }},
  ];

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{t('GatewayAliasesTab.title')}</CardTitle>
            <CardDescription>{t('GatewayAliasesTab.description')}</CardDescription>
          </div>
          <Button size="sm" onClick={onAddAlias}>
            <Plus className="h-4 w-4 mr-1" /> {t('GatewayAliasesTab.actions.addAlias')}
          </Button>
        </div>
      </CardHeader>
      <DataTable data={aliases} columns={aliasColumns} isLoading={aliasesLoading} searchable searchPlaceholder={t('GatewayAliasesTab.searchPlaceholder')} embedded />
    </Card>
  );
}
