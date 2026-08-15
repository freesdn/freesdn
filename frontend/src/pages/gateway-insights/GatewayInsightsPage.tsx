// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Insights page, pure read-only telemetry: top-talkers,
 * anomalies, AI suggestions, mesh topology. No staging, no writes.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  TrendingUp,
  AlertTriangle,
  Sparkles,
  GitMerge,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
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
import { gatewayInsightsApi } from '@/lib/api/gatewayInsights';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

export default function GatewayInsightsPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = !!(controllerId && siteId);

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-insights', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayInsightsPage.header.title')}
        description={t('GatewayInsightsPage.header.description')}
        icon={TrendingUp}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayInsightsPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayInsightsPage.target.description')}
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
          icon={TrendingUp}
          title={t('GatewayInsightsPage.empty.pickTarget.title')}
          description={t('GatewayInsightsPage.empty.pickTarget.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue="top-talkers" className="w-full">
          <TabsList className="flex-wrap">
            <TabsTrigger value="top-talkers">
              <TrendingUp className="mr-2 h-4 w-4" /> {t('GatewayInsightsPage.tabs.topTalkers')}
            </TabsTrigger>
            <TabsTrigger value="anomalies">
              <AlertTriangle className="mr-2 h-4 w-4" /> {t('GatewayInsightsPage.tabs.anomalies')}
            </TabsTrigger>
            <TabsTrigger value="ai">
              <Sparkles className="mr-2 h-4 w-4" /> {t('GatewayInsightsPage.tabs.aiSuggestions')}
            </TabsTrigger>
            <TabsTrigger value="mesh">
              <GitMerge className="mr-2 h-4 w-4" /> {t('GatewayInsightsPage.tabs.meshTopology')}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="top-talkers">
            <TopTalkersCard controllerId={controllerId!} siteId={siteId!} />
          </TabsContent>

          <TabsContent value="anomalies">
            <AnomaliesCard controllerId={controllerId!} siteId={siteId!} />
          </TabsContent>

          <TabsContent value="ai">
            <AiSuggestionsCard controllerId={controllerId!} siteId={siteId!} />
          </TabsContent>

          <TabsContent value="mesh">
            <MeshTopologyCard controllerId={controllerId!} siteId={siteId!} />
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

function TopTalkersCard({
  controllerId,
  siteId,
}: {
  controllerId: string;
  siteId: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-insights-top-talkers', controllerId, siteId],
    queryFn: () =>
      gatewayInsightsApi.topTalkers(controllerId, siteId, {
        period: '1d',
        top_n: 25,
      }),
  });

  const items = ((query.data?.data as { data?: unknown[] })?.data ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewayInsightsPage.topTalkers.title')}
        </CardTitle>
        <CardDescription>
          {t('GatewayInsightsPage.topTalkers.description')}
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
                : t('GatewayInsightsPage.topTalkers.error')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={TrendingUp}
            title={t('GatewayInsightsPage.topTalkers.empty')}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('GatewayInsightsPage.topTalkers.columns.identity')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.topTalkers.columns.kind')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.topTalkers.columns.rx')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.topTalkers.columns.tx')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.topTalkers.columns.total')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((it, i) => (
                <TableRow key={i}>
                  <TableCell className="font-medium">
                    {String(it.name ?? it.identity ?? it.id ?? '-')}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {String(it.kind ?? it.type ?? '-')}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">
                    {String(it.rx ?? it.rxBytes ?? '-')}
                  </TableCell>
                  <TableCell className="text-xs">
                    {String(it.tx ?? it.txBytes ?? '-')}
                  </TableCell>
                  <TableCell className="text-xs">
                    {String(it.total ?? it.totalBytes ?? it.bytes ?? '-')}
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

function AnomaliesCard({
  controllerId,
  siteId,
}: {
  controllerId: string;
  siteId: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-insights-anomalies', controllerId, siteId],
    queryFn: () =>
      gatewayInsightsApi.anomalies(controllerId, siteId, { period: '1d' }),
  });

  const items = ((query.data?.data as { data?: unknown[] })?.data ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewayInsightsPage.anomalies.title')}
        </CardTitle>
        <CardDescription>
          {t('GatewayInsightsPage.anomalies.description')}
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
                : t('GatewayInsightsPage.anomalies.error')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={AlertTriangle}
            title={t('GatewayInsightsPage.anomalies.empty')}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('GatewayInsightsPage.anomalies.columns.when')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.anomalies.columns.severity')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.anomalies.columns.type')}</TableHead>
                <TableHead>{t('GatewayInsightsPage.anomalies.columns.description')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((it, i) => (
                <TableRow key={i}>
                  <TableCell className="text-xs text-muted-foreground">
                    {String(it.timestamp ?? it.detectedAt ?? '-')}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        it.severity === 'critical' || it.severity === 'high'
                          ? 'destructive'
                          : it.severity === 'medium'
                            ? 'default'
                            : 'secondary'
                      }
                    >
                      {String(it.severity ?? '-')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{String(it.type ?? '-')}</Badge>
                  </TableCell>
                  <TableCell className="max-w-xl truncate text-xs">
                    {String(it.description ?? it.message ?? '')}
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

function AiSuggestionsCard({
  controllerId,
  siteId,
}: {
  controllerId: string;
  siteId: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-insights-ai', controllerId, siteId],
    queryFn: () => gatewayInsightsApi.aiSuggestions(controllerId, siteId),
  });

  const items = ((query.data?.data as { data?: unknown[] })?.data ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewayInsightsPage.aiSuggestions.title')}
        </CardTitle>
        <CardDescription>
          {t('GatewayInsightsPage.aiSuggestions.description')}
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
                : t('GatewayInsightsPage.aiSuggestions.error')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Sparkles}
            title={t('GatewayInsightsPage.aiSuggestions.empty')}
          />
        ) : (
          <div className="space-y-3">
            {items.map((it, i) => (
              <div key={i} className="rounded-md border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm">
                      {String(it.title ?? it.summary ?? '-')}
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {String(it.description ?? it.detail ?? '')}
                    </p>
                  </div>
                  {it.severity ? (
                    <Badge variant="outline">{String(it.severity)}</Badge>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MeshTopologyCard({
  controllerId,
  siteId,
}: {
  controllerId: string;
  siteId: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-insights-mesh', controllerId, siteId],
    queryFn: () => gatewayInsightsApi.meshTopology(controllerId, siteId),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewayInsightsPage.meshTopology.title')}
        </CardTitle>
        <CardDescription>
          {t('GatewayInsightsPage.meshTopology.description')}
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
                : t('GatewayInsightsPage.meshTopology.error')
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
