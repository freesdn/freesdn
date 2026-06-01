// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Diagnostics page, live telemetry for a specific gateway:
 * speed test, session stats and active sessions. The speed-test
 * trigger is a non-mutating measurement (the backend explicitly
 * classifies it as such) so the button does not stage anything.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  Gauge,
  Zap,
  BarChart3,
  Users,
  Play,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { gatewayDiagnosticsApi } from '@/lib/api/gatewayDiagnostics';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

export default function GatewayDiagnosticsPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);
  const [gatewayMacInput, setGatewayMacInput] = useState('');
  const [gatewayMac, setGatewayMac] = useState<string | null>(null);

  const ready = !!(controllerId && siteId);
  const gatewayReady = ready && !!gatewayMac;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-diagnostics', selectedSiteId],
    // Gateway diagnostics methods only exist on the Omada client; a
    // non-Omada controllerId would 4xx at runtime. Constrain the picker.
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined, undefined, 'omada'),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayDiagnosticsPage.title')}
        description={t('GatewayDiagnosticsPage.description')}
        icon={Gauge}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('GatewayDiagnosticsPage.target.title')}</CardTitle>
          <CardDescription>
            {t('GatewayDiagnosticsPage.target.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <GatewayControllerSitePicker
            controllers={
              controllers as Array<{ id: string; name: string; site_id?: string }>
            }
            controllerId={controllerId}
            onControllerChange={setControllerId}
            siteId={siteId}
            onSiteChange={setSiteId}
          />
          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              {t('GatewayDiagnosticsPage.target.gatewayMac')}
            </label>
            <div className="flex gap-2">
              <Input
                placeholder="aa-bb-cc-dd-ee-ff"
                value={gatewayMacInput}
                onChange={(e) => setGatewayMacInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    setGatewayMac(gatewayMacInput.trim() || null);
                  }
                }}
                className="font-mono"
              />
              <Button
                variant="default"
                onClick={() => setGatewayMac(gatewayMacInput.trim() || null)}
                disabled={!ready || !gatewayMacInput.trim()}
              >
                {t('GatewayDiagnosticsPage.target.load')}
              </Button>
            </div>
            {gatewayMac && (
              <p className="mt-2 text-xs text-muted-foreground">
                {t('GatewayDiagnosticsPage.target.loadedFor')}{' '}
                <span className="font-mono">{gatewayMac}</span>
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {!ready && (
        <EmptyState
          icon={Gauge}
          title={t('GatewayDiagnosticsPage.empty.pickTarget.title')}
          description={t('GatewayDiagnosticsPage.empty.pickTarget.description')}
        />
      )}

      {ready && !gatewayMac && (
        <EmptyState
          icon={Gauge}
          title={t('GatewayDiagnosticsPage.empty.enterMac.title')}
          description={t('GatewayDiagnosticsPage.empty.enterMac.description')}
        />
      )}

      {gatewayReady && (
        <Tabs defaultValue="speed" className="w-full">
          <TabsList>
            <TabsTrigger value="speed">
              <Zap className="mr-2 h-4 w-4" /> {t('GatewayDiagnosticsPage.tabs.speed')}
            </TabsTrigger>
            <TabsTrigger value="stats">
              <BarChart3 className="mr-2 h-4 w-4" /> {t('GatewayDiagnosticsPage.tabs.stats')}
            </TabsTrigger>
            <TabsTrigger value="active">
              <Users className="mr-2 h-4 w-4" /> {t('GatewayDiagnosticsPage.tabs.active')}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="speed">
            <SpeedTestCard
              controllerId={controllerId!}
              siteId={siteId!}
              gatewayMac={gatewayMac!}
            />
          </TabsContent>

          <TabsContent value="stats">
            <SessionStatsCard
              controllerId={controllerId!}
              siteId={siteId!}
              gatewayMac={gatewayMac!}
            />
          </TabsContent>

          <TabsContent value="active">
            <ActiveSessionsCard
              controllerId={controllerId!}
              siteId={siteId!}
              gatewayMac={gatewayMac!}
            />
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

function SpeedTestCard({
  controllerId,
  siteId,
  gatewayMac,
}: {
  controllerId: string;
  siteId: string;
  gatewayMac: string;
}) {
  const { t } = useTranslation('gateway');
  const resultQuery = useQuery({
    queryKey: ['gw-diag-speed-result', controllerId, siteId, gatewayMac],
    queryFn: () =>
      gatewayDiagnosticsApi.getSpeedTestResult(controllerId, siteId, gatewayMac),
  });

  const runMutation = useMutation({
    mutationFn: () =>
      gatewayDiagnosticsApi.runSpeedTest(controllerId, siteId, gatewayMac),
    onSettled: () => {
      // After a few seconds the result should be available, re-fetch.
      setTimeout(() => resultQuery.refetch(), 3000);
    },
  });

  const item =
    ((resultQuery.data?.data as { data?: Record<string, unknown> })?.data ??
      {}) as Record<string, unknown>;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-base">{t('GatewayDiagnosticsPage.speedTest.title')}</CardTitle>
          <CardDescription>
            {t('GatewayDiagnosticsPage.speedTest.description')}
          </CardDescription>
        </div>
        <Button
          variant="default"
          size="sm"
          onClick={() => runMutation.mutate()}
          disabled={runMutation.isPending}
        >
          <Play className="mr-2 h-4 w-4" />
          {runMutation.isPending
            ? t('GatewayDiagnosticsPage.speedTest.running')
            : t('GatewayDiagnosticsPage.speedTest.run')}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {runMutation.isError && (
          <ErrorState
            message={t('GatewayDiagnosticsPage.speedTest.triggerError')}
            onRetry={() => runMutation.reset()}
          />
        )}
        {resultQuery.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : resultQuery.isError ? (
          <ErrorState
            message={
              isControllerUnreachable(resultQuery.error)
                ? t('GatewayControllerSitePicker.unreachable')
                : t('GatewayDiagnosticsPage.speedTest.loadError')
            }
            onRetry={() => {
              resultQuery.refetch();
            }}
          />
        ) : Object.keys(item).length === 0 ? (
          <EmptyState
            icon={Zap}
            title={t('GatewayDiagnosticsPage.speedTest.empty.title')}
            description={t('GatewayDiagnosticsPage.speedTest.empty.description')}
          />
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Stat label={t('GatewayDiagnosticsPage.speedTest.download')} value={String(item.download ?? item.downloadMbps ?? '-')} />
            <Stat label={t('GatewayDiagnosticsPage.speedTest.upload')} value={String(item.upload ?? item.uploadMbps ?? '-')} />
            <Stat label={t('GatewayDiagnosticsPage.speedTest.latency')} value={String(item.latency ?? item.latencyMs ?? '-')} />
            <pre className="sm:col-span-3 overflow-x-auto rounded-md bg-muted p-3 text-xs">
              {JSON.stringify(item, null, 2)}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SessionStatsCard({
  controllerId,
  siteId,
  gatewayMac,
}: {
  controllerId: string;
  siteId: string;
  gatewayMac: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-diag-session-stats', controllerId, siteId, gatewayMac],
    queryFn: () =>
      gatewayDiagnosticsApi.getSessionStats(controllerId, siteId, gatewayMac),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('GatewayDiagnosticsPage.sessionStats.title')}</CardTitle>
        <CardDescription className="font-mono text-xs">
          {gatewayMac}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : query.isError ? (
          <ErrorState
            message={
              isControllerUnreachable(query.error)
                ? t('GatewayControllerSitePicker.unreachable')
                : t('GatewayDiagnosticsPage.sessionStats.loadError')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : (
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs max-h-96">
            {JSON.stringify(
              (query.data?.data as { data?: unknown })?.data ?? {},
              null,
              2,
            )}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

function ActiveSessionsCard({
  controllerId,
  siteId,
  gatewayMac,
}: {
  controllerId: string;
  siteId: string;
  gatewayMac: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-diag-active-sessions', controllerId, siteId, gatewayMac],
    queryFn: () =>
      gatewayDiagnosticsApi.listActiveSessions(controllerId, siteId, gatewayMac, {
        limit: 200,
      }),
  });

  const items = ((query.data?.data as { data?: unknown[] })?.data ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('GatewayDiagnosticsPage.activeSessions.title')}</CardTitle>
        <CardDescription className="font-mono text-xs">
          {gatewayMac}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : query.isError ? (
          <ErrorState
            message={
              isControllerUnreachable(query.error)
                ? t('GatewayControllerSitePicker.unreachable')
                : t('GatewayDiagnosticsPage.activeSessions.loadError')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState icon={Users} title={t('GatewayDiagnosticsPage.activeSessions.empty')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('GatewayDiagnosticsPage.activeSessions.columns.client')}</TableHead>
                <TableHead>{t('GatewayDiagnosticsPage.activeSessions.columns.source')}</TableHead>
                <TableHead>{t('GatewayDiagnosticsPage.activeSessions.columns.destination')}</TableHead>
                <TableHead>{t('GatewayDiagnosticsPage.activeSessions.columns.proto')}</TableHead>
                <TableHead>{t('GatewayDiagnosticsPage.activeSessions.columns.bytes')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((it, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">
                    {String(it.clientMac ?? it.client_mac ?? it.client ?? '-')}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {String(it.src ?? it.source ?? '-')}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {String(it.dst ?? it.destination ?? '-')}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {String(it.protocol ?? it.proto ?? '-')}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">
                    {String(it.bytes ?? it.totalBytes ?? '-')}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}
