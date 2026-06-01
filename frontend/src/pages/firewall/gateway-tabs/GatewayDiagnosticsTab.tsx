// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayDiagnosticsTab · ping/traceroute/DNS lookup utilities + active PF states.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns its
 * own host-input state but receives the three diagnostic mutations and the
 * connections data via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, Loader2, Route, Search, Terminal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Input } from '@/components/ui/input';

export interface DiagnosticMutation {
  data?: any;
  isPending: boolean;
  mutate: (host: string) => void;
}

export interface GatewayDiagnosticsTabProps {
  ping: DiagnosticMutation;
  traceroute: DiagnosticMutation;
  dnsLookup: DiagnosticMutation;
  connectionsData: any;
  connectionsLoading: boolean;
}

export function GatewayDiagnosticsTab({
  ping,
  traceroute,
  dnsLookup,
  connectionsData,
  connectionsLoading,
}: GatewayDiagnosticsTabProps) {
  const { t } = useTranslation('firewall');
  const [diagHost, setDiagHost] = useState('');

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Terminal className="h-4 w-4" /> {t('GatewayDiagnosticsTab.diagnostics.title')}</CardTitle>
          <CardDescription>{t('GatewayDiagnosticsTab.diagnostics.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 mb-4">
            <Input
              placeholder={t('GatewayDiagnosticsTab.diagnostics.hostPlaceholder')}
              value={diagHost}
              onChange={(e) => setDiagHost(e.target.value)}
              className="flex-1"
            />
            <Button size="sm" onClick={() => ping.mutate(diagHost)} disabled={!diagHost || ping.isPending}>
              {ping.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Activity className="h-4 w-4 mr-1" />}
              {t('GatewayDiagnosticsTab.actions.ping')}
            </Button>
            <Button size="sm" variant="outline" onClick={() => traceroute.mutate(diagHost)} disabled={!diagHost || traceroute.isPending}>
              {traceroute.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Route className="h-4 w-4 mr-1" />}
              {t('GatewayDiagnosticsTab.actions.traceroute')}
            </Button>
            <Button size="sm" variant="outline" onClick={() => dnsLookup.mutate(diagHost)} disabled={!diagHost || dnsLookup.isPending}>
              {dnsLookup.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Search className="h-4 w-4 mr-1" />}
              {t('GatewayDiagnosticsTab.actions.dnsLookup')}
            </Button>
          </div>

          {/* Ping Result */}
          {ping.data && (
            <div className="mb-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayDiagnosticsTab.results.ping')}</p>
              <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-[200px] font-mono">
                {typeof ping.data.data?.result === 'string'
                  ? ping.data.data.result
                  : JSON.stringify(ping.data.data?.result ?? ping.data.data, null, 2)}
              </pre>
            </div>
          )}

          {/* Traceroute Result */}
          {traceroute.data && (
            <div className="mb-3">
              <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayDiagnosticsTab.results.traceroute')}</p>
              <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-[200px] font-mono">
                {typeof traceroute.data.data?.result === 'string'
                  ? traceroute.data.data.result
                  : JSON.stringify(traceroute.data.data?.result ?? traceroute.data.data, null, 2)}
              </pre>
            </div>
          )}

          {/* DNS Lookup Result */}
          {dnsLookup.data && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-1">{t('GatewayDiagnosticsTab.results.dnsLookup')}</p>
              <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-[200px] font-mono">
                {typeof dnsLookup.data.data?.result === 'string'
                  ? dnsLookup.data.data.result
                  : JSON.stringify(dnsLookup.data.data?.result ?? dnsLookup.data.data, null, 2)}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Active Connections */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayDiagnosticsTab.connections.title')}</CardTitle>
          <CardDescription>{t('GatewayDiagnosticsTab.connections.description')}</CardDescription>
        </CardHeader>
        <DataTable
          data={connectionsData?.data?.connections || []}
          isLoading={connectionsLoading}
          columns={[
            { id: 'protocol', header: t('GatewayDiagnosticsTab.connections.columns.protocol'), accessorKey: 'protocol' },
            { id: 'source', header: t('GatewayDiagnosticsTab.connections.columns.source'), accessorKey: 'source' },
            { id: 'destination', header: t('GatewayDiagnosticsTab.connections.columns.destination'), accessorKey: 'destination' },
            { id: 'state', header: t('GatewayDiagnosticsTab.connections.columns.state'), accessorKey: 'state' },
            { id: 'direction', header: t('GatewayDiagnosticsTab.connections.columns.direction'), accessorKey: 'direction' },
            { id: 'bytes', header: t('GatewayDiagnosticsTab.connections.columns.bytes'), accessorKey: 'bytes' },
          ] as DataTableColumn<any>[]}
          searchable
          searchPlaceholder={t('GatewayDiagnosticsTab.connections.searchPlaceholder')}
          embedded
        />
      </Card>
    </>
  );
}
