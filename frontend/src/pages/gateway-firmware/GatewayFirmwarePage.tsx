// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Firmware page, controller-side firmware management for the
 * managed gateway (Omada today). Distinct from FreeSDN's own
 * /firmware page which tracks locally-stored firmware images for our
 * device inventory.
 *
 * Read paths run live against the controller. Writes (upgrade now,
 * batch upgrade, schedule CRUD) are STAGED, they show up in the
 * "Pending Changes" panel and only push to the controller if an
 * operator explicitly applies with force=true AND OMADA_READ_ONLY is
 * off. Default-safe in production.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  HardDrive,
  Calendar,
  History,
  Package,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
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
import { gatewayFirmwareApi } from '@/lib/api/gatewayFirmware';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from './GatewayControllerSitePicker';

export default function GatewayFirmwarePage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  // Fetch controllers (for picker)
  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-firmware', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  // Live: available firmware images
  const availableQuery = useQuery({
    queryKey: ['gw-firmware-available', controllerId, siteId],
    queryFn: () => gatewayFirmwareApi.getAvailable(controllerId!, siteId!),
    enabled: !!ready,
  });

  // Live: schedules
  const schedulesQuery = useQuery({
    queryKey: ['gw-firmware-schedules', controllerId, siteId],
    queryFn: () => gatewayFirmwareApi.listSchedules(controllerId!, siteId!),
    enabled: !!ready,
  });

  // Live: history
  const historyQuery = useQuery({
    queryKey: ['gw-firmware-history', controllerId, siteId],
    queryFn: () =>
      gatewayFirmwareApi.getHistory(controllerId!, siteId!, { limit: 50 }),
    enabled: !!ready,
  });

  // Pending changes
  const pendingQuery = useQuery({
    queryKey: ['gw-firmware-pending', controllerId, siteId],
    queryFn: () =>
      gatewayFirmwareApi.listPendingChanges(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayFirmwarePage.header.title')}
        description={t('GatewayFirmwarePage.header.description')}
        icon={HardDrive}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayFirmwarePage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayFirmwarePage.target.description')}
          </CardDescription>
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
          icon={HardDrive}
          title={t('GatewayFirmwarePage.notReady.title')}
          description={t('GatewayFirmwarePage.notReady.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="available" className="w-full">
          <TabsList>
            <TabsTrigger value="available">
              <Package className="mr-2 h-4 w-4" /> {t('GatewayFirmwarePage.tabs.available')}
            </TabsTrigger>
            <TabsTrigger value="schedules">
              <Calendar className="mr-2 h-4 w-4" /> {t('GatewayFirmwarePage.tabs.schedules')}
            </TabsTrigger>
            <TabsTrigger value="history">
              <History className="mr-2 h-4 w-4" /> {t('GatewayFirmwarePage.tabs.history')}
            </TabsTrigger>
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" /> {t('GatewayFirmwarePage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="available">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayFirmwarePage.available.title')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {availableQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : availableQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(availableQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayFirmwarePage.available.loadError')
                  }
                    onRetry={() => {
                      availableQuery.refetch();
                    }}
                  />
                ) : (
                  <FirmwareTable
                    items={
                      ((availableQuery.data?.data as { items?: unknown[] })
                        ?.items ?? []) as Array<Record<string, unknown>>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="schedules">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayFirmwarePage.schedules.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewayFirmwarePage.schedules.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {schedulesQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : schedulesQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(schedulesQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayFirmwarePage.schedules.loadError')
                  }
                    onRetry={() => {
                      schedulesQuery.refetch();
                    }}
                  />
                ) : (
                  <SchedulesTable
                    items={
                      ((schedulesQuery.data?.data as { items?: unknown[] })
                        ?.items ?? []) as Array<Record<string, unknown>>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="history">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayFirmwarePage.history.title')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {historyQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : historyQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(historyQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayFirmwarePage.history.loadError')
                  }
                    onRetry={() => {
                      historyQuery.refetch();
                    }}
                  />
                ) : (
                  <HistoryTable
                    items={
                      ((historyQuery.data?.data as { items?: unknown[] })
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
                    {t('GatewayFirmwarePage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayFirmwarePage.pending.description')}
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
                    title={t('GatewayFirmwarePage.pending.emptyTitle')}
                    description={t('GatewayFirmwarePage.pending.emptyDescription')}
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

// ── Helper tables ─────────────────────────────────────────────────────

function FirmwareTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Package}
        title={t('GatewayFirmwarePage.firmwareTable.emptyTitle')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayFirmwarePage.firmwareTable.model')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.firmwareTable.version')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.firmwareTable.released')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.firmwareTable.notes')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">{String(it.model ?? '-')}</TableCell>
            <TableCell>
              <Badge variant="outline">{String(it.version ?? '-')}</Badge>
            </TableCell>
            <TableCell>{String(it.releaseDate ?? '-')}</TableCell>
            <TableCell className="max-w-md truncate">
              {String(it.releaseNotes ?? '')}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function SchedulesTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Calendar}
        title={t('GatewayFirmwarePage.schedulesTable.emptyTitle')}
        description={t('GatewayFirmwarePage.schedulesTable.emptyDescription')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayFirmwarePage.schedulesTable.name')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.schedulesTable.models')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.schedulesTable.when')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.schedulesTable.stableOnly')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">{String(it.name ?? '-')}</TableCell>
            <TableCell>
              {Array.isArray(it.deviceModels)
                ? (it.deviceModels as unknown[]).join(', ')
                : '-'}
            </TableCell>
            <TableCell>
              {String(it.cron ?? it.timeOfDay ?? '-')}
            </TableCell>
            <TableCell>
              {it.stableOnly
                ? t('GatewayFirmwarePage.common.yes')
                : t('GatewayFirmwarePage.common.no')}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function HistoryTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={History}
        title={t('GatewayFirmwarePage.historyTable.emptyTitle')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayFirmwarePage.historyTable.device')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.historyTable.fromTo')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.historyTable.status')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.historyTable.when')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => {
          const ok = String(it.status ?? '').toLowerCase() === 'success';
          return (
            <TableRow key={i}>
              <TableCell className="font-mono text-xs">
                {String(it.deviceMac ?? '-')}
              </TableCell>
              <TableCell>
                <span className="text-muted-foreground">
                  {String(it.fromVersion ?? '?')}
                </span>{' '}
                → <span>{String(it.toVersion ?? '?')}</span>
              </TableCell>
              <TableCell>
                <Badge
                  variant={ok ? 'default' : 'destructive'}
                  className="capitalize"
                >
                  {String(it.status ?? '-')}
                </Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {String(it.completedAt ?? it.startedAt ?? '-')}
              </TableCell>
            </TableRow>
          );
        })}
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
          <TableHead>{t('GatewayFirmwarePage.pendingTable.feature')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.pendingTable.operation')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.pendingTable.target')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.pendingTable.created')}</TableHead>
          <TableHead>{t('GatewayFirmwarePage.pendingTable.status')}</TableHead>
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
