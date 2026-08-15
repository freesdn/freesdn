// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Routing page, VRRP, IPv6 static, BGP read surface, plus
 * BGP neighbors and the live routing table. Edits are staged; nothing
 * pushes to the controller without explicit apply with force=true.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Network,
  Route,
  Globe,
  Clock,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
import { gatewayRoutingApi, type RoutingRead } from '@/lib/api/gatewayRouting';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

const READ_TABS: Array<{ key: RoutingRead; labelKey: string }> = [
  { key: 'vrrp', labelKey: 'readTabs.vrrp' },
  { key: 'bgp', labelKey: 'readTabs.bgp' },
  { key: 'bgp_neighbors', labelKey: 'readTabs.bgpNeighbors' },
  { key: 'ipv6_static', labelKey: 'readTabs.ipv6Static' },
  { key: 'routing_table', labelKey: 'readTabs.routingTable' },
];

export default function GatewayRoutingPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-routing', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  const pendingQuery = useQuery({
    queryKey: ['gw-routing-pending', controllerId, siteId],
    queryFn: () => gatewayRoutingApi.listPending(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayRoutingPage.header.title')}
        description={t('GatewayRoutingPage.header.description')}
        icon={Route}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayRoutingPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayRoutingPage.target.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <GatewayControllerSitePicker
            controllers={
              controllers as Array<{ id: string; name: string; site_id?: string }>
            }
            controllerId={controllerId}
            onControllerChange={setControllerId}
            siteId={siteId}
            onSiteChange={setSiteId}
          />
        </CardContent>
      </Card>

      {!ready && (
        <EmptyState
          icon={Network}
          title={t('GatewayRoutingPage.empty.title')}
          description={t('GatewayRoutingPage.empty.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="vrrp" className="w-full">
          <TabsList className="flex-wrap">
            {READ_TABS.map((tab) => (
              <TabsTrigger key={tab.key} value={tab.key}>
                <Globe className="mr-2 h-4 w-4" />{' '}
                {t(`GatewayRoutingPage.${tab.labelKey}`)}
              </TabsTrigger>
            ))}
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" /> {t('GatewayRoutingPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          {READ_TABS.map((tab) => (
            <TabsContent key={tab.key} value={tab.key}>
              <RoutingDataCard
                controllerId={controllerId}
                siteId={siteId}
                what={tab.key}
                labelKey={tab.labelKey}
              />
            </TabsContent>
          ))}

          <TabsContent value="pending">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">
                    {t('GatewayRoutingPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayRoutingPage.pending.description')}
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
                    message={t('GatewayRoutingPage.pending.loadError')}
                    onRetry={() => {
                      pendingQuery.refetch();
                    }}
                  />
                ) : !pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewayRoutingPage.pending.empty')}
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

function RoutingDataCard({
  controllerId,
  siteId,
  what,
  labelKey,
}: {
  controllerId: string;
  siteId: string;
  what: RoutingRead;
  labelKey: string;
}) {
  const { t } = useTranslation('gateway');
  const label = t(`GatewayRoutingPage.${labelKey}`);
  const query = useQuery({
    queryKey: ['gw-routing', controllerId, siteId, what],
    queryFn: () => gatewayRoutingApi.get(controllerId, siteId, what),
  });

  const body = query.data?.data as { data?: unknown } | undefined;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : query.isError ? (
          <ErrorState
            message={
              isControllerUnreachable(query.error)
                ? t('GatewayControllerSitePicker.unreachable')
                : t('GatewayRoutingPage.loadError', { label })
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : (
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
            {JSON.stringify(body?.data ?? {}, null, 2)}
          </pre>
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
          <TableHead>{t('GatewayRoutingPage.table.feature')}</TableHead>
          <TableHead>{t('GatewayRoutingPage.table.operation')}</TableHead>
          <TableHead>{t('GatewayRoutingPage.table.target')}</TableHead>
          <TableHead>{t('GatewayRoutingPage.table.created')}</TableHead>
          <TableHead>{t('GatewayRoutingPage.table.status')}</TableHead>
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
