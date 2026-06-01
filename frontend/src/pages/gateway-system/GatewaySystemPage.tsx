// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Gateway System page, controller-level system + monitoring read
 * surface. Inspect SMTP, notifications, SSL cert, global / maintenance
 * settings, cloud-access, controller backups and admin accounts. Site
 * NTP / LED / reboot schedules and SNMP/syslog are exposed via the
 * site config view.
 *
 * All writes here are staged. Backup *download* streams raw bytes from
 * the controller (read-only, no staging).
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isControllerUnreachable } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import {
  Server,
  ShieldCheck,
  Mail,
  Cloud,
  Users,
  Database,
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
  gatewaySystemApi,
  type ControllerConfigName,
} from '@/lib/api/gatewaySystem';
import { controllersApi } from '@/lib/api/controllers';
import { useSiteStore } from '@/stores/siteStore';

type ControllerLite = { id: string; name: string };

const CONFIG_TABS: ControllerConfigName[] = [
  'smtp',
  'notifications',
  'ssl_cert',
  'global',
  'maintenance',
  'cloud_access',
];

const CONFIG_LABEL_KEY: Record<ControllerConfigName, string> = {
  smtp: 'configLabels.smtp',
  notifications: 'configLabels.notifications',
  ssl_cert: 'configLabels.sslCert',
  global: 'configLabels.global',
  maintenance: 'configLabels.maintenance',
  cloud_access: 'configLabels.cloudAccess',
};

export default function GatewaySystemPage() {
  const { t } = useTranslation('gateway');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-system', selectedSiteId],
    // The page's reads are all bound to the Omada adapter; selecting a
    // non-Omada controller 400s every tab. Filter the picker to Omada only.
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined, undefined, 'omada'),
  });
  const controllers =
    ((controllersResp?.data as { items?: ControllerLite[] })?.items ?? []);

  const backupsQuery = useQuery({
    queryKey: ['gw-system-backups', controllerId],
    queryFn: () => gatewaySystemApi.listBackups(controllerId!),
    enabled: !!controllerId,
  });

  const adminsQuery = useQuery({
    queryKey: ['gw-system-admins', controllerId],
    queryFn: () => gatewaySystemApi.listAdmins(controllerId!),
    enabled: !!controllerId,
  });

  const pendingQuery = useQuery({
    queryKey: ['gw-system-pending', controllerId],
    queryFn: () =>
      gatewaySystemApi.listPending(controllerId!, { feature_prefix: 'system.' }),
    enabled: !!controllerId,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('GatewaySystemPage.pageTitle')}
        description={t('GatewaySystemPage.pageDescription')}
        icon={Server}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('GatewaySystemPage.controllerCard.title')}
          </CardTitle>
          <CardDescription>
            {t('GatewaySystemPage.controllerCard.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ControllerPicker
            controllers={controllers}
            controllerId={controllerId}
            onChange={setControllerId}
          />
        </CardContent>
      </Card>

      {!controllerId && (
        <EmptyState
          icon={Server}
          title={t('GatewaySystemPage.emptyPickController.title')}
          description={t('GatewaySystemPage.emptyPickController.description')}
        />
      )}

      {controllerId && (
        <Tabs defaultValue="smtp" className="w-full">
          <TabsList className="flex-wrap">
            {CONFIG_TABS.map((name) => (
              <TabsTrigger key={name} value={name}>
                {iconFor(name)}
                {t(`GatewaySystemPage.${CONFIG_LABEL_KEY[name]}`)}
              </TabsTrigger>
            ))}
            <TabsTrigger value="backups">
              <Database className="mr-2 h-4 w-4" />{' '}
              {t('GatewaySystemPage.tabs.backups')}
            </TabsTrigger>
            <TabsTrigger value="admins">
              <Users className="mr-2 h-4 w-4" />{' '}
              {t('GatewaySystemPage.tabs.admins')}
            </TabsTrigger>
            <TabsTrigger value="pending">
              <Clock className="mr-2 h-4 w-4" />{' '}
              {t('GatewaySystemPage.tabs.pending')}
              {pendingQuery.data?.data?.length ? (
                <Badge variant="secondary" className="ml-2">
                  {pendingQuery.data.data.length}
                </Badge>
              ) : null}
            </TabsTrigger>
          </TabsList>

          {CONFIG_TABS.map((name) => (
            <TabsContent key={name} value={name}>
              <ConfigCard controllerId={controllerId} configName={name} />
            </TabsContent>
          ))}

          <TabsContent value="backups">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewaySystemPage.backupsCard.title')}
                </CardTitle>
                <CardDescription>
                  {t('GatewaySystemPage.backupsCard.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {backupsQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : backupsQuery.isError ? (
                  <ErrorState
                    message={
                    isControllerUnreachable(backupsQuery.error)
                      ? t('GatewayControllerSitePicker.unreachable')
                      : t('GatewaySystemPage.backupsCard.loadError')
                  }
                    onRetry={() => {
                      backupsQuery.refetch();
                    }}
                  />
                ) : (
                  <BackupsTable
                    controllerId={controllerId}
                    items={
                      ((backupsQuery.data?.data as { items?: unknown[] })
                        ?.items ?? []) as Array<Record<string, unknown>>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="admins">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('GatewaySystemPage.adminsCard.title')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {adminsQuery.isLoading ? (
                  <Skeleton className="h-32 w-full" />
                ) : (
                  <AdminsTable
                    items={
                      ((adminsQuery.data?.data as { items?: unknown[] })
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
                    {t('GatewaySystemPage.pendingCard.title')}
                  </CardTitle>
                  <CardDescription>
                    {t('GatewaySystemPage.pendingCard.description')}
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
                    title={t('GatewaySystemPage.pendingCard.empty')}
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

function iconFor(name: ControllerConfigName) {
  if (name === 'smtp') return <Mail className="mr-2 h-4 w-4" />;
  if (name === 'ssl_cert') return <ShieldCheck className="mr-2 h-4 w-4" />;
  if (name === 'cloud_access') return <Cloud className="mr-2 h-4 w-4" />;
  return <Server className="mr-2 h-4 w-4" />;
}

function ControllerPicker({
  controllers,
  controllerId,
  onChange,
}: {
  controllers: ControllerLite[];
  controllerId: string | null;
  onChange: (id: string | null) => void;
}) {
  const { t } = useTranslation('gateway');
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">
          {t('GatewaySystemPage.picker.label')}
        </label>
        <select
          className="h-9 w-full rounded-md border bg-background px-3 text-sm"
          value={controllerId ?? ''}
          onChange={(e) => onChange(e.target.value || null)}
        >
          <option value="">{t('GatewaySystemPage.picker.placeholder')}</option>
          {controllers.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function ConfigCard({
  controllerId,
  configName,
}: {
  controllerId: string;
  configName: ControllerConfigName;
}) {
  const { t } = useTranslation('gateway');
  const query = useQuery({
    queryKey: ['gw-system-config', controllerId, configName],
    queryFn: () =>
      gatewaySystemApi.getControllerConfig(controllerId, configName),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('GatewaySystemPage.configCard.title', {
            name: t(`GatewaySystemPage.${CONFIG_LABEL_KEY[configName]}`),
          })}
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
                : t('GatewaySystemPage.configCard.loadError')
            }
            onRetry={() => {
              query.refetch();
            }}
          />
        ) : (
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
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

function BackupsTable({
  controllerId,
  items,
}: {
  controllerId: string;
  items: Array<Record<string, unknown>>;
}) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title={t('GatewaySystemPage.backupsTable.empty')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewaySystemPage.backupsTable.id')}</TableHead>
          <TableHead>{t('GatewaySystemPage.backupsTable.created')}</TableHead>
          <TableHead>{t('GatewaySystemPage.backupsTable.size')}</TableHead>
          <TableHead>{t('GatewaySystemPage.backupsTable.action')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => {
          const id = String(it.id ?? it.backupId ?? '');
          return (
            <TableRow key={i}>
              <TableCell className="font-mono text-xs">{id || '-'}</TableCell>
              <TableCell className="text-xs">
                {String(it.createdAt ?? it.created_at ?? '-')}
              </TableCell>
              <TableCell className="text-xs">
                {String(it.size ?? '-')}
              </TableCell>
              <TableCell>
                {id ? (
                  <a
                    className="text-sm font-medium text-primary hover:underline"
                    href={gatewaySystemApi.backupDownloadUrl(controllerId, id)}
                  >
                    {t('GatewaySystemPage.backupsTable.download')}
                  </a>
                ) : null}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function AdminsTable({ items }: { items: Array<Record<string, unknown>> }) {
  const { t } = useTranslation('gateway');
  if (items.length === 0) {
    return (
      <EmptyState
        icon={Users}
        title={t('GatewaySystemPage.adminsTable.empty')}
      />
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t('GatewaySystemPage.adminsTable.username')}</TableHead>
          <TableHead>{t('GatewaySystemPage.adminsTable.role')}</TableHead>
          <TableHead>{t('GatewaySystemPage.adminsTable.email')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it, i) => (
          <TableRow key={i}>
            <TableCell className="font-medium">
              {String(it.username ?? it.name ?? '-')}
            </TableCell>
            <TableCell>
              <Badge variant="outline">{String(it.role ?? '-')}</Badge>
            </TableCell>
            <TableCell className="text-xs">{String(it.email ?? '-')}</TableCell>
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
          <TableHead>{t('GatewaySystemPage.pendingTable.feature')}</TableHead>
          <TableHead>{t('GatewaySystemPage.pendingTable.operation')}</TableHead>
          <TableHead>{t('GatewaySystemPage.pendingTable.target')}</TableHead>
          <TableHead>{t('GatewaySystemPage.pendingTable.created')}</TableHead>
          <TableHead>{t('GatewaySystemPage.pendingTable.status')}</TableHead>
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
