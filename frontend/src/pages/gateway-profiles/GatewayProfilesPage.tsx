// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway Profiles page, read-only catalog of reusable objects:
 * MAC groups, domain groups, OUI profiles, time ranges, rate-limit
 * profiles, PPSK, RADIUS, LDAP. Edits are staged via the Pending
 * Changes screen.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  FileCode2,
  Layers,
  Clock as ClockIcon,
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
  gatewayProfilesApi,
  type ProfileType,
} from '@/lib/api/gatewayProfiles';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';
import { GatewayControllerSitePicker } from '../gateway-firmware/GatewayControllerSitePicker';

const PROFILE_TABS: Array<{ key: ProfileType; labelKey: string }> = [
  { key: 'mac_groups', labelKey: 'macGroups' },
  { key: 'domain_groups', labelKey: 'domainGroups' },
  { key: 'oui_profiles', labelKey: 'ouiProfiles' },
  { key: 'time_ranges', labelKey: 'timeRanges' },
  { key: 'rate_limit_profiles', labelKey: 'rateLimits' },
  { key: 'ppsk_profiles', labelKey: 'ppsk' },
  { key: 'radius_profiles', labelKey: 'radius' },
  { key: 'ldap_profiles', labelKey: 'ldap' },
];

export default function GatewayProfilesPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-profiles', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  const pendingQuery = useQuery({
    queryKey: ['gw-profiles-pending', controllerId, siteId],
    queryFn: () => gatewayProfilesApi.listPending(controllerId!, siteId!),
    enabled: !!ready,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewayProfilesPage.header.title')}
        description={t('GatewayProfilesPage.header.description')}
        icon={FileCode2}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewayProfilesPage.target.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewayProfilesPage.target.description')}
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
          icon={FileCode2}
          title={t('GatewayProfilesPage.notReady.title')}
          description={t('GatewayProfilesPage.notReady.description')}
        />
      )}

      {ready && (
        <Tabs defaultValue={PROFILE_TABS[0].key} className="w-full">
          <TabsList className="flex-wrap">
            {PROFILE_TABS.map((tab) => (
              <TabsTrigger key={tab.key} value={tab.key}>
                <Layers className="mr-2 h-4 w-4" />{' '}
                {t(`GatewayProfilesPage.tabs.${tab.labelKey}`)}
              </TabsTrigger>
            ))}
            <TabsTrigger value="pending">
              <ClockIcon className="mr-2 h-4 w-4" />{' '}
              {t('GatewayProfilesPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          {PROFILE_TABS.map((tab) => (
            <TabsContent key={tab.key} value={tab.key}>
              <ProfileListCard
                controllerId={controllerId!}
                siteId={siteId!}
                profileType={tab.key}
                label={t(`GatewayProfilesPage.tabs.${tab.labelKey}`)}
              />
            </TabsContent>
          ))}

          <TabsContent value="pending">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">
                    {t('GatewayProfilesPage.pending.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewayProfilesPage.pending.description')}
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
                    message={t('GatewayProfilesPage.pending.loadError')}
                    onRetry={() => {
                      pendingQuery.refetch();
                    }}
                  />
                ) : !pendingQuery.data?.data?.length ? (
                  <EmptyState
                    icon={CheckCircle}
                    title={t('GatewayProfilesPage.pending.empty')}
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

function ProfileListCard({
  controllerId,
  siteId,
  profileType,
  label,
}: {
  controllerId: string;
  siteId: string;
  profileType: ProfileType;
  label: string;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-profiles-list', controllerId, siteId, profileType],
    queryFn: () => gatewayProfilesApi.list(controllerId, siteId, profileType),
  });

  const items = ((query.data?.data as { items?: unknown[] })?.items ?? []) as Array<
    Record<string, unknown>
  >;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{label}</CardTitle>
        <CardDescription>
          {items.length === 1
            ? t('GatewayProfilesPage.list.itemCountOne', { count: items.length })
            : t('GatewayProfilesPage.list.itemCountOther', {
                count: items.length,
              })}
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
                : t('GatewayProfilesPage.list.loadError', { label })
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={Layers}
            title={t('GatewayProfilesPage.list.empty', {
              label: label.toLowerCase(),
            })}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('GatewayProfilesPage.list.columns.name')}</TableHead>
                <TableHead>{t('GatewayProfilesPage.list.columns.id')}</TableHead>
                <TableHead>{t('GatewayProfilesPage.list.columns.type')}</TableHead>
                <TableHead>
                  {t('GatewayProfilesPage.list.columns.description')}
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
                  <TableCell>
                    <Badge variant="outline">
                      {String(it.type ?? it.profileType ?? '-')}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-md truncate text-xs text-muted-foreground">
                    {String(it.description ?? it.desc ?? '')}
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
          <TableHead>{t('GatewayProfilesPage.pending.columns.feature')}</TableHead>
          <TableHead>
            {t('GatewayProfilesPage.pending.columns.operation')}
          </TableHead>
          <TableHead>{t('GatewayProfilesPage.pending.columns.target')}</TableHead>
          <TableHead>{t('GatewayProfilesPage.pending.columns.created')}</TableHead>
          <TableHead>{t('GatewayProfilesPage.pending.columns.status')}</TableHead>
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
