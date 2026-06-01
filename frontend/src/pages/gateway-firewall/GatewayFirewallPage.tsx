// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Firewall page, read-only surface over firewall
 * configs (DMZ, UPnP, attack defense, ALG, IDS/IPS). Lists pending
 * firewall changes. All writes go through dedicated dialogs / the
 * Pending Changes screen, this page never stages anything.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
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
import {
  gatewayFirewallApi,
  type FirewallConfig,
} from '@/lib/api/gatewayFirewall';
import { controllersApi } from '@/lib/api/controllers';
import { isControllerUnreachable } from '@/lib/api/client';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

const CONFIG_TABS: Array<{ key: FirewallConfig; labelKey: string }> = [
  { key: 'dmz', labelKey: 'configCards.dmz' },
  { key: 'upnp', labelKey: 'configCards.upnp' },
  { key: 'attack_defense', labelKey: 'configCards.attackDefense' },
  { key: 'alg', labelKey: 'configCards.alg' },
  { key: 'ids_ips', labelKey: 'configCards.idsIps' },
];

export default function GatewayFirewallPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-firewall', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  const pendingQuery = useQuery({
    queryKey: ['gw-firewall-pending', controllerId, siteId],
    queryFn: () => gatewayFirewallApi.listPending(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayFirewallPage.header.title')}
        description={t('GatewayFirewallPage.header.description')}
        icon={Shield}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayFirewallPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayFirewallPage.target.description')}
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
          icon={Shield}
          title={t('GatewayFirewallPage.emptyPicker.title')}
          description={t('GatewayFirewallPage.emptyPicker.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="configs" className="w-full">
          <TabsList>
            <TabsTrigger value="configs">
              <ShieldCheck className="mr-2 h-4 w-4" />{' '}
              {t('GatewayFirewallPage.tabs.configs')}
            </TabsTrigger>
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" />{' '}
              {t('GatewayFirewallPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="configs">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {CONFIG_TABS.map((c) => (
                <FirewallConfigCard
                  key={c.key}
                  controllerId={controllerId!}
                  siteId={siteId!}
                  configName={c.key}
                  label={t(`GatewayFirewallPage.${c.labelKey}`)}
                />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="pending">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">
                    {t('GatewayFirewallPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayFirewallPage.pending.description')}
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
                    message={t('GatewayFirewallPage.pending.loadError')}
                    onRetry={() => {
                      pendingQuery.refetch();
                    }}
                  />
                ) : !pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewayFirewallPage.pending.empty')}
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

function FirewallConfigCard({
  controllerId,
  siteId,
  configName,
  label,
}: {
  controllerId: string;
  siteId: string;
  configName: FirewallConfig;
  label: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-firewall-config', controllerId, siteId, configName],
    queryFn: () =>
      gatewayFirewallApi.getConfig(controllerId, siteId, configName),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : query.isError ? (
          <ErrorState
            message={
              isControllerUnreachable(query.error)
                ? t('GatewayControllerSitePicker.unreachable')
                : t('GatewayFirewallPage.configCards.loadError', { label })
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : (
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs max-h-72">
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

function PendingTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayFirewallPage.table.feature')}</TableHead>
          <TableHead>{t('GatewayFirewallPage.table.operation')}</TableHead>
          <TableHead>{t('GatewayFirewallPage.table.target')}</TableHead>
          <TableHead>{t('GatewayFirewallPage.table.created')}</TableHead>
          <TableHead>{t('GatewayFirewallPage.table.status')}</TableHead>
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
