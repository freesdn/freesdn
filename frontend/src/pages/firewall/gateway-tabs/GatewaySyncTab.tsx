// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewaySyncTab · sync history table for the gateway detail page.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Receives all
 * data and the sync mutation via props; owns no state of its own.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Loader2, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewaySyncTabProps {
  syncLogs: any[];
  syncLogsLoading: boolean;
  syncLogColumns: DataTableColumn<any>[];
  onSync: () => void;
  isSyncing: boolean;
}

export function GatewaySyncTab({
  syncLogs,
  syncLogsLoading,
  syncLogColumns,
  onSync,
  isSyncing,
}: GatewaySyncTabProps) {
  const { t } = useTranslation('firewall');
  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{t('GatewaySyncTab.title')}</CardTitle>
            <CardDescription>{t('GatewaySyncTab.description')}</CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={onSync}
            disabled={isSyncing}
          >
            {isSyncing ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <RefreshCw className="h-4 w-4 mr-1" />}
            {t('GatewaySyncTab.actions.syncNow')}
          </Button>
        </div>
      </CardHeader>
      <DataTable data={syncLogs} columns={syncLogColumns} isLoading={syncLogsLoading} embedded />
    </Card>
  );
}
