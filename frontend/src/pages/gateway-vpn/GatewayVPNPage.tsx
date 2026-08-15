// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway VPN page, reads live config from the Omada gateway across
 * all 7 protocols (IPsec, OpenVPN, L2TP, PPTP, WireGuard, SSL-VPN, GRE).
 * Writes are staged through the same staging table as firmware; apply
 * happens through the Pending Changes view.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Globe,
  Network,
  Lock,
  Clock,
  RefreshCw,
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
  gatewayVpnApi,
  type VPNProtocol,
} from '@/lib/api/gatewayVpn';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

const PROTOCOLS: { id: VPNProtocol; label: string; hasUsers: boolean }[] = [
  { id: 'ipsec', label: 'IPsec', hasUsers: false },
  { id: 'wireguard', label: 'WireGuard', hasUsers: false },
  { id: 'openvpn', label: 'OpenVPN', hasUsers: true },
  { id: 'l2tp', label: 'L2TP', hasUsers: true },
  { id: 'pptp', label: 'PPTP', hasUsers: true },
  { id: 'sslvpn', label: 'SSL-VPN', hasUsers: true },
  { id: 'gre', label: 'GRE', hasUsers: false },
];

export default function GatewayVPNPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);
  const [activeProtocol, setActiveProtocol] = useState<VPNProtocol>('ipsec');

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-vpn', selectedSiteId],
    // Gateway VPN only supports Omada controllers (backend rejects others
    // with 400). Constrain the picker so non-Omada controllers aren't
    // offered as targets that can never work.
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined, 100, 'omada'),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  const pendingQuery = useQuery({
    queryKey: ['gw-vpn-pending', controllerId, siteId],
    queryFn: () => gatewayVpnApi.listPendingChanges(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayVPNPage.pageTitle')}
        description={t('GatewayVPNPage.pageDescription')}
        icon={Shield}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('GatewayVPNPage.target')}</CardTitle>
        </CardHeader>
        <CardContent>
          <GatewayControllerSitePicker
            controllers={controllers as Array<{ id: string; name: string; site_id?: string }>}
            controllerId={controllerId}
            onControllerChange={setControllerId}
            siteId={siteId}
            onSiteChange={setSiteId}
          />
        </CardContent>
      </Card>

      {!ready && (
        <EmptyState
          icon={Globe}
          title={t('GatewayVPNPage.pickControllerAndSite')}
        />
      )}

      {ready && (
        <Tabs
          value={activeProtocol}
          onValueChange={(v) => setActiveProtocol(v as VPNProtocol)}
          className="w-full"
        >
          <TabsList className="flex-wrap">
            {PROTOCOLS.map((p) => (
              <TabsTrigger key={p.id} value={p.id}>
                {p.label}
              </TabsTrigger>
            ))}
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" /> {t('GatewayVPNPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          {PROTOCOLS.map((p) => (
            <TabsContent key={p.id} value={p.id}>
              <ProtocolView
                controllerId={controllerId!}
                siteId={siteId!}
                protocol={p.id}
                hasUsers={p.hasUsers}
              />
            </TabsContent>
          ))}

          <TabsContent value="pending">
            <PendingPanel
              loading={pendingQuery.isLoading}
              isError={pendingQuery.isError}
              items={pendingQuery.data?.data ?? []}
              onRefresh={() => pendingQuery.refetch()}
            />
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

interface ProtocolViewProps {
  controllerId: string;
  siteId: string;
  protocol: VPNProtocol;
  hasUsers: boolean;
}

function ProtocolView({
  controllerId,
  siteId,
  protocol,
  hasUsers,
}: ProtocolViewProps) {
  const { t } = useTranslation('gateway');
  const configQuery = useQuery({
    queryKey: ['gw-vpn-config', controllerId, siteId, protocol],
    queryFn: () =>
      gatewayVpnApi.getProtocolConfig(controllerId, siteId, protocol),
    enabled: protocol !== 'gre',
  });

  const statusQuery = useQuery({
    queryKey: ['gw-vpn-status', controllerId, siteId, protocol],
    queryFn: () =>
      gatewayVpnApi.getProtocolStatus(controllerId, siteId, protocol),
  });

  // Per-protocol list (peers / policies / tunnels / users)
  const listQuery = useQuery({
    queryKey: ['gw-vpn-list', controllerId, siteId, protocol],
    queryFn: async () => {
      if (protocol === 'ipsec')
        return gatewayVpnApi.listIPsecPolicies(controllerId, siteId);
      if (protocol === 'wireguard')
        return gatewayVpnApi.listWireguardPeers(controllerId, siteId);
      if (protocol === 'gre')
        return gatewayVpnApi.listGreTunnels(controllerId, siteId);
      if (hasUsers)
        return gatewayVpnApi.listProtocolUsers(
          controllerId,
          siteId,
          protocol as 'openvpn' | 'l2tp' | 'pptp' | 'sslvpn',
        );
      // Synthesize an empty AxiosResponse-shaped object for protocols
      // that don't have a list endpoint.
      return { data: { items: [] } } as unknown as Awaited<
        ReturnType<typeof gatewayVpnApi.listIPsecPolicies>
      >;
    },
  });

  const items =
    ((listQuery.data?.data as { items?: unknown[] })?.items ?? []) as Array<
      Record<string, unknown>
    >;
  const status =
    ((statusQuery.data?.data as { items?: unknown[] })?.items ?? []) as Array<
      Record<string, unknown>
    >;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base capitalize">
            {t('GatewayVPNPage.protocolConfiguration', { protocol })}
          </CardTitle>
          <CardDescription>
            {t('GatewayVPNPage.protocolConfigDescription')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {configQuery.isLoading || listQuery.isLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : configQuery.isError || listQuery.isError ? (
            <ErrorState
              message={
                isControllerUnreachable(configQuery.error ?? listQuery.error)
                  ? t('GatewayControllerSitePicker.unreachable')
                  : t('GatewayVPNPage.configLoadError', { protocol })
              }
              onRetry={() => {
                configQuery.refetch();
                listQuery.refetch();
              }}
            />
          ) : items.length === 0 ? (
            <EmptyState
              icon={Lock}
              title={t('GatewayVPNPage.nothingConfigured')}
              description={t('GatewayVPNPage.nothingConfiguredDescription', {
                protocol,
                entryType: hasUsers
                  ? t('GatewayVPNPage.entryType.users')
                  : t('GatewayVPNPage.entryType.entries'),
              })}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('GatewayVPNPage.columns.nameId')}</TableHead>
                  <TableHead>{t('GatewayVPNPage.columns.detail')}</TableHead>
                  <TableHead>{t('GatewayVPNPage.columns.enabled')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((it, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium">
                      {String(it.name ?? it.username ?? it.id ?? '-')}
                    </TableCell>
                    <TableCell className="max-w-md truncate text-xs text-muted-foreground">
                      {summariseEntry(it, protocol, t)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={it.enabled ? 'default' : 'secondary'}>
                        {it.enabled === undefined
                          ? '-'
                          : it.enabled
                            ? t('GatewayVPNPage.enabledState.on')
                            : t('GatewayVPNPage.enabledState.off')}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('GatewayVPNPage.activeConnections')}</CardTitle>
        </CardHeader>
        <CardContent>
          {statusQuery.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : statusQuery.isError ? (
            <ErrorState
              message={
                isControllerUnreachable(statusQuery.error)
                  ? t('GatewayControllerSitePicker.unreachable')
                  : t('GatewayVPNPage.statusLoadError', { protocol })
              }
              onRetry={() => {
                statusQuery.refetch();
              }}
            />
          ) : status.length === 0 ? (
            <EmptyState
              icon={Network}
              title={t('GatewayVPNPage.noActiveSessions')}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('GatewayVPNPage.columns.peer')}</TableHead>
                  <TableHead>{t('GatewayVPNPage.columns.state')}</TableHead>
                  <TableHead>{t('GatewayVPNPage.columns.rxTx')}</TableHead>
                  <TableHead>{t('GatewayVPNPage.columns.lastHandshake')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {status.map((s, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">
                      {String(s.peer ?? s.name ?? '-')}
                    </TableCell>
                    <TableCell>{String(s.state ?? '-')}</TableCell>
                    <TableCell className="text-xs">
                      {String(s.bytes_rx ?? 0)} /{' '}
                      {String(s.bytes_tx ?? 0)}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {String(s.last_handshake ?? '-')}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function summariseEntry(
  it: Record<string, unknown>,
  protocol: VPNProtocol,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  if (protocol === 'ipsec') {
    return t('GatewayVPNPage.summary.ipsec', {
      local: String(it.localSubnet ?? '?'),
      remote: String(it.remoteSubnet ?? '?'),
      gateway: String(it.remoteGateway ?? '?'),
    });
  }
  if (protocol === 'wireguard') {
    const ips = Array.isArray(it.allowedIps)
      ? (it.allowedIps as unknown[]).join(', ')
      : String(it.allowedIps ?? '');
    return `${ips}${it.endpoint ? ` → ${String(it.endpoint)}` : ''}`;
  }
  if (protocol === 'gre') {
    return `${String(it.localAddress ?? '?')} → ${String(it.remoteAddress ?? '?')}`;
  }
  // user-style protocols
  return String(it.allowedSubnets ?? it.username ?? '');
}

function PendingPanel({
  loading,
  isError,
  items,
  onRefresh,
}: {
  loading: boolean;
  isError: boolean;
  items: unknown;
  onRefresh: () => void;
}) {
  const { t } = useTranslation('gateway');
  const list = (Array.isArray(items) ? items : []) as Array<
    Record<string, unknown>
  >;
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-base">{t('GatewayVPNPage.pendingChanges')}</CardTitle>
          <CardDescription>
            {t('GatewayVPNPage.pendingChangesDescription')}
          </CardDescription>
        </div>
        <Button variant="ghost" size="sm" onClick={onRefresh}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-24 w-full" />
        ) : isError ? (
          <ErrorState
            message={t('GatewayVPNPage.pendingLoadError')}
            onRetry={onRefresh}
          />
        ) : list.length === 0 ? (
          <EmptyState
            icon={CheckCircle}
            title={t('GatewayVPNPage.noPendingChanges')}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('GatewayVPNPage.columns.feature')}</TableHead>
                <TableHead>{t('GatewayVPNPage.columns.op')}</TableHead>
                <TableHead>{t('GatewayVPNPage.columns.target')}</TableHead>
                <TableHead>{t('GatewayVPNPage.columns.created')}</TableHead>
                <TableHead>{t('GatewayVPNPage.columns.status')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((it, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono text-xs">
                    {String(it.feature ?? '-')}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{String(it.operation ?? '-')}</Badge>
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
                      {String(it.status ?? '-')}
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
