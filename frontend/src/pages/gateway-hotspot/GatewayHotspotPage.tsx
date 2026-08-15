// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Hotspot page, read-only surface over hotspot operators,
 * SMS gateway config and free-auth policies. All edits are staged
 * via the Pending Changes screen, this page never stages anything.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Wifi,
  Users,
  MessageSquare,
  KeyRound,
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
import { gatewayHotspotApi } from '@/lib/api/gatewayHotspot';
import { controllersApi } from '@/lib/api/controllers';
import { useControllerCapabilities } from '@/hooks/useControllerCapabilities';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

export default function GatewayHotspotPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-hotspot', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  // Hide hotspot sub-tabs the adapter doesn't advertise. Fail-open
  // on first paint (the hook returns ``true`` from ``has`` until
  // the manifest has loaded) so navigation doesn't flicker.
  const caps = useControllerCapabilities(controllerId);
  const showOperators = caps.has('hotspot.operators');
  const showSms = caps.has('hotspot.sms_gateway');
  const showFreeAuth = caps.has('hotspot.free_auth');

  const operatorsQuery = useQuery({
    queryKey: ['gw-hotspot-operators', controllerId, siteId],
    queryFn: () => gatewayHotspotApi.listOperators(controllerId!, siteId!),
    enabled: !!ready,
  });

  const smsQuery = useQuery({
    queryKey: ['gw-hotspot-sms', controllerId, siteId],
    queryFn: () => gatewayHotspotApi.getSmsGateway(controllerId!, siteId!),
    enabled: !!ready,
  });

  const freeAuthQuery = useQuery({
    queryKey: ['gw-hotspot-free-auth', controllerId, siteId],
    queryFn: () =>
      gatewayHotspotApi.listFreeAuthPolicies(controllerId!, siteId!),
    enabled: !!ready,
  });

  const pendingQuery = useQuery({
    queryKey: ['gw-hotspot-pending', controllerId, siteId],
    queryFn: () => gatewayHotspotApi.listPending(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayHotspotPage.header.title')}
        description={t('GatewayHotspotPage.header.description')}
        icon={Wifi}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayHotspotPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayHotspotPage.target.description')}
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
          icon={Wifi}
          title={t('GatewayHotspotPage.picker.title')}
          description={t('GatewayHotspotPage.picker.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="operators" className="w-full">
          <TabsList className="flex-wrap">
            {showOperators && (
              <TabsTrigger value="operators">
                <Users className="mr-2 h-4 w-4" /> {t('GatewayHotspotPage.tabs.operators')}
              </TabsTrigger>
            )}
            {showSms && (
              <TabsTrigger value="sms">
                <MessageSquare className="mr-2 h-4 w-4" /> {t('GatewayHotspotPage.tabs.sms')}
              </TabsTrigger>
            )}
            {showFreeAuth && (
              <TabsTrigger value="free-auth">
                <KeyRound className="mr-2 h-4 w-4" /> {t('GatewayHotspotPage.tabs.freeAuth')}
              </TabsTrigger>
            )}
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" /> {t('GatewayHotspotPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="operators">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayHotspotPage.operators.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewayHotspotPage.operators.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {operatorsQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : operatorsQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(operatorsQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayHotspotPage.operators.error')
                  }
                    onRetry={() => {
                      operatorsQuery.refetch();
                    }}
                  />
                ) : (
                  <OperatorsTable
                    items={
                      ((operatorsQuery.data?.data as { items?: unknown[] })
                        ?.items ?? []) as Array<Record<string, unknown>>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="sms">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayHotspotPage.sms.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewayHotspotPage.sms.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {smsQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : smsQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(smsQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayHotspotPage.sms.error')
                  }
                    onRetry={() => {
                      smsQuery.refetch();
                    }}
                  />
                ) : (
                  <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
                    {JSON.stringify(
                      (smsQuery.data?.data as { item?: unknown })?.item ?? {},
                      null,
                      2,
                    )}
                  </pre>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="free-auth">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayHotspotPage.freeAuth.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewayHotspotPage.freeAuth.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {freeAuthQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : freeAuthQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(freeAuthQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayHotspotPage.freeAuth.error')
                  }
                    onRetry={() => {
                      freeAuthQuery.refetch();
                    }}
                  />
                ) : (
                  <FreeAuthTable
                    items={
                      ((freeAuthQuery.data?.data as { items?: unknown[] })
                        ?.items ?? []) as Array<Record<string, unknown>>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="pending">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">
                    {t('GatewayHotspotPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayHotspotPage.pending.description')}
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
                {!pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewayHotspotPage.pending.empty')}
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

function OperatorsTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState icon={Users} title={t('GatewayHotspotPage.operators.empty')} />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayHotspotPage.operators.columns.username')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.operators.columns.role')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.operators.columns.portal')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.operators.columns.notes')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">
              {String(it.username ?? it.name ?? '-')}
            </TableCell>
            <TableCell>
              <Badge variant="outline">
                {String(it.role ?? it.type ?? '-')}
              </Badge>
            </TableCell>
            <TableCell className="font-mono text-xs">
              {String(it.portalId ?? it.portal_id ?? '-')}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {String(it.note ?? it.notes ?? '')}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function FreeAuthTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={KeyRound}
        title={t('GatewayHotspotPage.freeAuth.empty')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayHotspotPage.freeAuth.columns.name')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.freeAuth.columns.status')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.freeAuth.columns.match')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.freeAuth.columns.id')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">
              {String(it.name ?? '-')}
            </TableCell>
            <TableCell>
              <Badge variant={it.status === 'enabled' ? 'default' : 'secondary'}>
                {String(it.status ?? (it.enable ? 'enabled' : 'disabled'))}
              </Badge>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground max-w-md truncate">
              {String(it.matchType ?? it.match ?? '-')}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {String(it.id ?? '-')}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function PendingTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayHotspotPage.pending.columns.feature')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.pending.columns.operation')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.pending.columns.target')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.pending.columns.created')}</TableHead>
          <TableHead>{t('GatewayHotspotPage.pending.columns.status')}</TableHead>
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
