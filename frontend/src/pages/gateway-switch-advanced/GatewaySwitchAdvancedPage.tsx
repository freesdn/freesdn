// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Switch Advanced page, read surface for sFlow, mirror
 * sessions and MSTP. Switch-advanced features are scoped to a
 * specific switch by MAC, so the user enters a switch MAC alongside
 * the controller + site picker. Edits are staged via Pending Changes.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Network,
  Activity,
  Copy,
  GitBranch,
  Clock,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
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
import {
  gatewaySwitchAdvancedApi,
  type PerSwitchConfig,
} from '@/lib/api/gatewaySwitchAdvanced';
import { controllersApi } from '@/lib/api/controllers';
import { useControllerCapabilities } from '@/hooks/useControllerCapabilities';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

export default function GatewaySwitchAdvancedPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);
  const [switchMacInput, setSwitchMacInput] = useState('');
  const [switchMac, setSwitchMac] = useState<string | null>(null);

  const ready = !!(controllerId && siteId);
  const switchReady = ready && !!switchMac;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-switch-advanced', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  // Adapter capability flags. Hide tabs for features the underlying
  // adapter doesn't advertise, fail-open on first paint so tabs
  // don't flicker. See ``useControllerCapabilities``.
  const caps = useControllerCapabilities(controllerId);
  const showSflow = caps.has('switch.sflow');
  const showMirror = caps.has('switch.port_mirroring');
  const showMstp = caps.has('switch.mstp');

  const pendingQuery = useQuery({
    queryKey: ['gw-switch-advanced-pending', controllerId, siteId],
    queryFn: () =>
      gatewaySwitchAdvancedApi.listPending(controllerId!, siteId!),
    enabled: ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewaySwitchAdvancedPage.header.title')}
        description={t('GatewaySwitchAdvancedPage.header.description')}
        icon={Network}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewaySwitchAdvancedPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewaySwitchAdvancedPage.target.description')}
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
              {t('GatewaySwitchAdvancedPage.target.switchMacLabel')}
            </label>
            <div className="flex gap-2">
              <Input
                placeholder="aa-bb-cc-dd-ee-ff"
                value={switchMacInput}
                onChange={(e) => setSwitchMacInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    setSwitchMac(switchMacInput.trim() || null);
                  }
                }}
                className="font-mono"
              />
              <Button
                variant="default"
                onClick={() => setSwitchMac(switchMacInput.trim() || null)}
                disabled={!ready || !switchMacInput.trim()}
              >
                {t('GatewaySwitchAdvancedPage.target.load')}
              </Button>
            </div>
            {switchMac && (
              <p className="mt-2 text-xs text-muted-foreground">
                {t('GatewaySwitchAdvancedPage.target.loadedFor')}{' '}
                <span className="font-mono">{switchMac}</span>
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {!ready && (
        <EmptyState
          icon={Network}
          title={t('GatewaySwitchAdvancedPage.empty.pickController.title')}
          description={t(
            'GatewaySwitchAdvancedPage.empty.pickController.description',
          )}
        />
      )}

      {ready && !switchMac && (
        <EmptyState
          icon={Network}
          title={t('GatewaySwitchAdvancedPage.empty.enterMac.title')}
          description={t('GatewaySwitchAdvancedPage.empty.enterMac.description')}
        />
      )}

      {switchReady && (
        <Tabs defaultValue="sflow" className="w-full">
          <TabsList className="flex-wrap">
            {showSflow && (
              <TabsTrigger value="sflow">
                <Activity className="mr-2 h-4 w-4" />{' '}
                {t('GatewaySwitchAdvancedPage.tabs.sflow')}
              </TabsTrigger>
            )}
            {showMirror && (
              <TabsTrigger value="mirror">
                <Copy className="mr-2 h-4 w-4" />{' '}
                {t('GatewaySwitchAdvancedPage.tabs.mirror')}
              </TabsTrigger>
            )}
            {showMstp && (
              <TabsTrigger value="mstp">
                <GitBranch className="mr-2 h-4 w-4" />{' '}
                {t('GatewaySwitchAdvancedPage.tabs.mstp')}
              </TabsTrigger>
            )}
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" />{' '}
              {t('GatewaySwitchAdvancedPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="sflow">
            <SwitchConfigCard
              controllerId={controllerId!}
              siteId={siteId!}
              switchMac={switchMac!}
              configName="sflow"
              label={t('GatewaySwitchAdvancedPage.tabs.sflow')}
            />
          </TabsContent>

          <TabsContent value="mirror">
            <MirrorSessionsCard
              controllerId={controllerId!}
              siteId={siteId!}
              switchMac={switchMac!}
            />
          </TabsContent>

          <TabsContent value="mstp">
            <SwitchConfigCard
              controllerId={controllerId!}
              siteId={siteId!}
              switchMac={switchMac!}
              configName="mstp"
              label={t('GatewaySwitchAdvancedPage.tabs.mstp')}
            />
          </TabsContent>

          <TabsContent value="pending">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">
                    {t('GatewaySwitchAdvancedPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewaySwitchAdvancedPage.pending.description')}
                  </CardDescription>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => pendingQuery.refetch()}
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </CardHeader>
              <CardContent>
                {pendingQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : pendingQuery.isError ? (
                  <ErrorState
                    message={t('GatewaySwitchAdvancedPage.pending.loadError')}
                    onRetry={() => {
                      pendingQuery.refetch();
                    }}
                  />
                ) : !pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewaySwitchAdvancedPage.pending.empty')}
                  />
                ) : (
                  <PendingTable
                    items={
                      pendingQuery.data.data as unknown as Array<
                        Record<string, unknown>
                      >
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

function SwitchConfigCard({
  controllerId,
  siteId,
  switchMac,
  configName,
  label,
}: {
  controllerId: string;
  siteId: string;
  switchMac: string;
  configName: PerSwitchConfig;
  label: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-switch-advanced-config', controllerId, siteId, switchMac, configName],
    queryFn: () =>
      gatewaySwitchAdvancedApi.getSwitchConfig(
        controllerId,
        siteId,
        switchMac,
        configName,
      ),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewaySwitchAdvancedPage.config.title', { label })}
        </CardTitle>
        <CardDescription className="font-mono text-xs">
          {switchMac}
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
                : t('GatewaySwitchAdvancedPage.config.loadError', { label })
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : (
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs max-h-96">
            {JSON.stringify(
              (query.data?.data as { item?: unknown })?.item ?? {},
              null,
              2,
            )}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

function MirrorSessionsCard({
  controllerId,
  siteId,
  switchMac,
}: {
  controllerId: string;
  siteId: string;
  switchMac: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-switch-advanced-mirror', controllerId, siteId, switchMac],
    queryFn: () =>
      gatewaySwitchAdvancedApi.listMirrorSessions(
        controllerId,
        siteId,
        switchMac,
      ),
  });

  const items = ((query.data?.data as { items?: unknown[] })?.items ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewaySwitchAdvancedPage.mirror.title')}
        </CardTitle>
        <CardDescription className="font-mono text-xs">
          {switchMac}
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
                : t('GatewaySwitchAdvancedPage.mirror.loadError')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Copy}
            title={t('GatewaySwitchAdvancedPage.mirror.empty')}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>
                  {t('GatewaySwitchAdvancedPage.mirror.columns.session')}
                </TableHead>
                <TableHead>
                  {t('GatewaySwitchAdvancedPage.mirror.columns.source')}
                </TableHead>
                <TableHead>
                  {t('GatewaySwitchAdvancedPage.mirror.columns.destination')}
                </TableHead>
                <TableHead>
                  {t('GatewaySwitchAdvancedPage.mirror.columns.direction')}
                </TableHead>
                <TableHead>
                  {t('GatewaySwitchAdvancedPage.mirror.columns.status')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((it, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">
                    {String(it.id ?? it.sessionId ?? '-')}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {String(it.source ?? it.src ?? '-')}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {String(it.destination ?? it.dst ?? '-')}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {String(it.direction ?? '-')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={it.enable === false ? 'secondary' : 'default'}
                    >
                      {String(
                        it.status ?? (it.enable === false ? 'disabled' : 'enabled'),
                      )}
                    </Badge>
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

function PendingTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>
            {t('GatewaySwitchAdvancedPage.pending.columns.feature')}
          </TableHead>
          <TableHead>
            {t('GatewaySwitchAdvancedPage.pending.columns.operation')}
          </TableHead>
          <TableHead>
            {t('GatewaySwitchAdvancedPage.pending.columns.target')}
          </TableHead>
          <TableHead>
            {t('GatewaySwitchAdvancedPage.pending.columns.created')}
          </TableHead>
          <TableHead>
            {t('GatewaySwitchAdvancedPage.pending.columns.status')}
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-mono text-xs">
              {String(it.feature ?? '-')}
            </TableCell>
            <TableCell>
              <Badge variant="outline" className="capitalize">
                {String(it.operation ?? '-')}
              </Badge>
            </TableCell>
            <TableCell className="font-mono text-xs">
              {String(it.target_id ?? '-')}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {String(it.created_at ?? '-')}
            </TableCell>
            <TableCell>
              <Badge
                variant={
                  it.status === 'failed'
                    ? 'destructive'
                    : it.status === 'applied'
                      ? 'default'
                      : 'secondary'
                }
              >
                {it.status === 'pending' ? (
                  <AlertTriangle className="mr-1 h-3 w-3" />
                ) : null}
                {String(it.status ?? '-')}
              </Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
