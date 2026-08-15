// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Bulk Ops + Templates page.
 *
 * Read paths run live against the Omada controller. Writes (bulk
 * device/SSID/client ops, site clone, templates) are STAGED, they
 * never push to the controller unless an operator applies with
 * force=true AND OMADA_READ_ONLY is off.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Layers,
  ClipboardCopy,
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
import { gatewayBulkApi } from '@/lib/api/gatewayBulk';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

export default function GatewayBulkPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-bulk', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  const templatesQuery = useQuery({
    queryKey: ['gw-bulk-templates', controllerId, siteId],
    queryFn: () => gatewayBulkApi.listTemplates(controllerId!, siteId!),
    enabled: !!ready,
  });

  const pendingQuery = useQuery({
    queryKey: ['gw-bulk-pending', controllerId, siteId],
    // Backend returns bulk.* + site.* by default for the bulk page,
    // do NOT send a feature_prefix override (an empty string used to
    // be turned into ``LIKE %`` and showed every feature domain).
    queryFn: () => gatewayBulkApi.listPending(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayBulkPage.header.title')}
        description={t('GatewayBulkPage.header.description')}
        icon={Layers}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayBulkPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayBulkPage.target.description')}
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
          icon={Layers}
          title={t('GatewayBulkPage.notReady.title')}
          description={t('GatewayBulkPage.notReady.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="templates" className="w-full">
          <TabsList>
            <TabsTrigger value="templates">
              <ClipboardCopy className="mr-2 h-4 w-4" />{' '}
              {t('GatewayBulkPage.tabs.templates')}
            </TabsTrigger>
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" />{' '}
              {t('GatewayBulkPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="templates">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewayBulkPage.templates.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewayBulkPage.templates.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {templatesQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : templatesQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(templatesQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewayBulkPage.templates.loadError')
                  }
                    onRetry={() => {
                      templatesQuery.refetch();
                    }}
                  />
                ) : (
                  <TemplatesTable
                    items={
                      ((templatesQuery.data?.data as { items?: unknown[] })
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
                    {t('GatewayBulkPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayBulkPage.pending.description')}
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
                    message={t('GatewayBulkPage.pending.loadError')}
                    onRetry={() => {
                      pendingQuery.refetch();
                    }}
                  />
                ) : !pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewayBulkPage.pending.empty')}
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

function TemplatesTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={ClipboardCopy}
        title={t('GatewayBulkPage.templatesTable.empty')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewayBulkPage.templatesTable.name')}</TableHead>
          <TableHead>{t('GatewayBulkPage.templatesTable.id')}</TableHead>
          <TableHead>
            {t('GatewayBulkPage.templatesTable.description')}
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">
              {String(it.name ?? '-')}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {String(it.id ?? '-')}
            </TableCell>
            <TableCell className="max-w-md truncate">
              {String(it.description ?? '')}
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
          <TableHead>{t('GatewayBulkPage.pendingTable.feature')}</TableHead>
          <TableHead>{t('GatewayBulkPage.pendingTable.operation')}</TableHead>
          <TableHead>{t('GatewayBulkPage.pendingTable.target')}</TableHead>
          <TableHead>{t('GatewayBulkPage.pendingTable.created')}</TableHead>
          <TableHead>{t('GatewayBulkPage.pendingTable.status')}</TableHead>
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
