// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayLogsTab · system & firewall log viewer for the gateway detail page.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Receives all
 * data via props; owns only its (firewall vs. system) sub-tab state.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ScrollText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';

export interface GatewayLogsTabProps {
  fwLogs: any[];
  fwLogLoading: boolean;
  sysLogs: any[];
  sysLogLoading: boolean;
  logColumns: DataTableColumn<any>[];
}

export function GatewayLogsTab({
  fwLogs,
  fwLogLoading,
  sysLogs,
  sysLogLoading,
  logColumns,
}: GatewayLogsTabProps) {
  const { t } = useTranslation('firewall');
  const [logTab, setLogTab] = useState<'system' | 'firewall'>('firewall');

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2"><ScrollText className="h-4 w-4" /> {t('GatewayLogsTab.title')}</CardTitle>
            <CardDescription>{t('GatewayLogsTab.description')}</CardDescription>
          </div>
          <div className="flex gap-1">
            <Button size="sm" variant={logTab === 'firewall' ? 'default' : 'outline'} onClick={() => setLogTab('firewall')}>{t('GatewayLogsTab.tabs.firewall')}</Button>
            <Button size="sm" variant={logTab === 'system' ? 'default' : 'outline'} onClick={() => setLogTab('system')}>{t('GatewayLogsTab.tabs.system')}</Button>
          </div>
        </div>
      </CardHeader>
      {logTab === 'firewall' ? (
        <DataTable data={fwLogs} columns={logColumns} isLoading={fwLogLoading} searchable searchPlaceholder={t('GatewayLogsTab.searchFirewall')} embedded />
      ) : (
        <DataTable data={sysLogs} columns={logColumns} isLoading={sysLogLoading} searchable searchPlaceholder={t('GatewayLogsTab.searchSystem')} embedded />
      )}
    </Card>
  );
}
