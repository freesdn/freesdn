// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Gateway log reads retain distinct loading, unavailable and empty states. */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw, ScrollText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { GatewayLogEntry } from '@/lib/gateway-log-inventory';

export interface GatewayLogsTabProps {
  fwLogs: GatewayLogEntry[] | null;
  fwLogLoading: boolean;
  sysLogs: GatewayLogEntry[] | null;
  sysLogLoading: boolean;
  logColumns: DataTableColumn<GatewayLogEntry>[];
  onRetryFirewallLogs: () => void;
  onRetrySystemLogs: () => void;
}

export function GatewayLogsTab({
  fwLogs,
  fwLogLoading,
  sysLogs,
  sysLogLoading,
  logColumns,
  onRetryFirewallLogs,
  onRetrySystemLogs,
}: GatewayLogsTabProps) {
  const { t } = useTranslation('firewall');
  const [logTab, setLogTab] = useState<'system' | 'firewall'>('firewall');
  const logs = logTab === 'firewall' ? fwLogs : sysLogs;
  const loading = logTab === 'firewall' ? fwLogLoading : sysLogLoading;
  const retry = logTab === 'firewall' ? onRetryFirewallLogs : onRetrySystemLogs;

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
      {loading ? (
        <CardContent><p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayLogsTab.loading')}
        </p></CardContent>
      ) : logs === null ? (
        <CardContent className="space-y-3">
          <p role="status" className="text-sm text-muted-foreground">{t('GatewayLogsTab.unavailable')}</p>
          <Button variant="outline" size="sm" onClick={retry}>
            <RefreshCw className="h-4 w-4 mr-1" /> {t('GatewayLogsTab.retry')}
          </Button>
        </CardContent>
      ) : (
        <DataTable data={logs} columns={logColumns} searchable searchPlaceholder={t(logTab === 'firewall' ? 'GatewayLogsTab.searchFirewall' : 'GatewayLogsTab.searchSystem')} embedded />
      )}
    </Card>
  );
}
