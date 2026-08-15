// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikSystemTab · RouterOS identity, time/NTP, and resource usage.
 *
 * Mirrors the GatewaySystemTab structure (self-contained queries, shadcn
 * cards). Reads aggregate via the single ``/system/info`` endpoint;
 * identity-name and NTP edits stage a ``mikrotik.system.identity``
 * / ``mikrotik.system.ntp`` change (apply requires adapter wiring,
 * stage is the canonical UI contract here).
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Cpu,
  HardDrive,
  Loader2,
  Pencil,
  RefreshCw,
  Server,
  Timer,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import { getApiErrorMessage, mikrotikApi } from '@/lib/api';

export interface MikroTikSystemTabProps {
  controllerId: string;
  isActive: boolean;
  /**
   * Display name of the controller (e.g. "edge-rtr-1"). Surfaced in
   * error/success toasts so operators managing multi-router fleets know
   * which router an error came from. Optional for backward-compat with
   * older test callers; falls back to "controller" when omitted.
   */
  gatewayName?: string;
}

const SYSTEM_INFO_KEY = (cid: string) => ['mikrotik', cid, 'system-info'];

function fmtBytes(value: unknown): string {
  if (value === undefined || value === null || value === '') return '-';
  const num = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(num) || num <= 0) return String(value);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = num;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function fmtUptime(value: unknown): string {
  // RouterOS uptime is already a friendly string like "1w2d3h4m5s".
  if (typeof value === 'string' && value.length > 0) return value;
  return '-';
}

function asString(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

export function MikroTikSystemTab({
  controllerId,
  isActive,
  gatewayName,
}: MikroTikSystemTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';
  const [identityOpen, setIdentityOpen] = useState(false);
  const [ntpOpen, setNtpOpen] = useState(false);
  const [identityName, setIdentityName] = useState('');
  const [ntpPrimary, setNtpPrimary] = useState('');
  const [ntpSecondary, setNtpSecondary] = useState('');

  const {
    data: infoResp,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: SYSTEM_INFO_KEY(controllerId),
    queryFn: () => mikrotikApi.getSystemInfo(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 30_000,
  });

  const info = infoResp?.data;
  const identity = info?.identity ?? {};
  const resource = info?.resource ?? {};
  const routerboard = info?.routerboard ?? {};
  const clock = info?.clock ?? {};
  const health = info?.health ?? [];

  // Seed the dialog inputs from the live data the first time we have
  // it. Re-runs only if controller changes or info reloads.
  useEffect(() => {
    if (identity.name !== undefined) {
      setIdentityName(typeof identity.name === 'string' ? identity.name : '');
    }
  }, [identity.name]);

  const identityMutation = useMutation({
    mutationFn: (name: string) => mikrotikApi.stageIdentityUpdate(controllerId, name),
    onSuccess: () => {
      toast({
        title: t('MikroTikSystemTab.toasts.identityStaged.title'),
        description: t('MikroTikSystemTab.toasts.identityStaged.description'),
      });
      setIdentityOpen(false);
      queryClient.invalidateQueries({ queryKey: SYSTEM_INFO_KEY(controllerId) });
    },
    onError: (err) => {
      toast({
        title: `${ctx}${t('MikroTikSystemTab.toasts.identityFailed.title')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const ntpMutation = useMutation({
    mutationFn: ({ primary, secondary }: { primary: string; secondary: string }) =>
      mikrotikApi.stageNtpUpdate(
        controllerId,
        primary.trim() || null,
        secondary.trim() || null,
      ),
    onSuccess: () => {
      toast({
        title: t('MikroTikSystemTab.toasts.ntpStaged.title'),
        description: t('MikroTikSystemTab.toasts.ntpStaged.description'),
      });
      setNtpOpen(false);
      queryClient.invalidateQueries({ queryKey: SYSTEM_INFO_KEY(controllerId) });
    },
    onError: (err) => {
      toast({
        title: `${ctx}${t('MikroTikSystemTab.toasts.ntpFailed.title')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikSystemTab.loading')}
      </div>
    );
  }

  if (isError || !info) {
    return (
      <ErrorState
        message={
          error
            ? getApiErrorMessage(error, t('MikroTikSystemTab.error.loadFailed'))
            : t('MikroTikSystemTab.error.noInfo')
        }
        onRetry={() => refetch()}
      />
    );
  }

  const memUsed =
    typeof resource['total-memory'] === 'number' &&
    typeof resource['free-memory'] === 'number'
      ? (resource['total-memory'] as number) - (resource['free-memory'] as number)
      : undefined;

  const cpuLoad = resource['cpu-load'];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {t('MikroTikSystemTab.liveState')}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          {isFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikSystemTab.actions.refresh')}
        </Button>
      </div>

      {/* Identity */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-4 w-4" /> {t('MikroTikSystemTab.identity.title')}
              </CardTitle>
              <CardDescription>{t('MikroTikSystemTab.identity.description')}</CardDescription>
            </div>
            <Button size="sm" variant="outline" onClick={() => setIdentityOpen(true)}>
              <Pencil className="h-3.5 w-3.5 mr-1" aria-hidden="true" /> {t('MikroTikSystemTab.actions.editName')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.name')}</dt>
              <dd className="font-medium">{asString(identity.name)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.board')}</dt>
              <dd className="font-medium">
                {asString(resource['board-name'] ?? routerboard.model)}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.version')}</dt>
              <dd className="font-medium">{asString(resource.version)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.architecture')}</dt>
              <dd className="font-medium">
                {asString(resource['architecture-name'])}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.serial')}</dt>
              <dd className="font-mono text-xs">
                {asString(routerboard['serial-number'])}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.factoryFirmware')}</dt>
              <dd className="font-medium">
                {asString(routerboard['factory-firmware'])}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.currentFirmware')}</dt>
              <dd className="font-medium">
                {asString(routerboard['current-firmware'])}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.identity.fields.upgradeAvailable')}</dt>
              <dd className="font-medium">
                {asString(routerboard['upgrade-firmware'])}
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Time + NTP */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Timer className="h-4 w-4" /> {t('MikroTikSystemTab.time.title')}
              </CardTitle>
              <CardDescription>{t('MikroTikSystemTab.time.description')}</CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setNtpPrimary('');
                setNtpSecondary('');
                setNtpOpen(true);
              }}
            >
              <Pencil className="h-3.5 w-3.5 mr-1" aria-hidden="true" /> {t('MikroTikSystemTab.actions.editNtp')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.time.fields.date')}</dt>
              <dd className="font-mono">{asString(clock.date)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.time.fields.time')}</dt>
              <dd className="font-mono">{asString(clock.time)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.time.fields.timezone')}</dt>
              <dd className="font-medium">{asString(clock['time-zone-name'])}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t('MikroTikSystemTab.time.fields.dst')}</dt>
              <dd>
                <Badge variant={clock['dst-active'] ? 'default' : 'secondary'}>
                  {clock['dst-active'] === undefined || clock['dst-active'] === null
                    ? t('MikroTikSystemTab.time.dstUnknown')
                    : String(clock['dst-active'])}
                </Badge>
              </dd>
            </div>
          </dl>
          <div className="mt-3 flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/5 p-3 text-xs">
            <AlertTriangle className="h-4 w-4 text-yellow-600 flex-shrink-0 mt-0.5" />
            <p>
              {t('MikroTikSystemTab.time.ntpNotice')}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Resource usage */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-4 w-4" /> {t('MikroTikSystemTab.resource.title')}
          </CardTitle>
          <CardDescription>{t('MikroTikSystemTab.resource.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-muted-foreground text-xs">
                <Cpu className="h-3.5 w-3.5" /> {t('MikroTikSystemTab.resource.cpuLoad')}
              </div>
              <div className="text-2xl font-semibold mt-1">
                {cpuLoad !== undefined && cpuLoad !== null ? `${String(cpuLoad)}%` : '-'}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {t('MikroTikSystemTab.resource.cpuDetail', {
                  cpu: asString(resource.cpu),
                  count: asString(resource['cpu-count']),
                  freq: asString(resource['cpu-frequency']),
                })}
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-muted-foreground text-xs">
                <HardDrive className="h-3.5 w-3.5" /> {t('MikroTikSystemTab.resource.ramUsed')}
              </div>
              <div className="text-2xl font-semibold mt-1">
                {memUsed !== undefined ? fmtBytes(memUsed) : '-'}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {t('MikroTikSystemTab.resource.ofTotal', {
                  total: fmtBytes(resource['total-memory']),
                })}
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-muted-foreground text-xs">
                <HardDrive className="h-3.5 w-3.5" /> {t('MikroTikSystemTab.resource.diskFree')}
              </div>
              <div className="text-2xl font-semibold mt-1">
                {fmtBytes(resource['free-hdd-space'])}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {t('MikroTikSystemTab.resource.ofTotal', {
                  total: fmtBytes(resource['total-hdd-space']),
                })}
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-muted-foreground text-xs">
                <Timer className="h-3.5 w-3.5" /> {t('MikroTikSystemTab.resource.uptime')}
              </div>
              <div className="text-2xl font-semibold mt-1">
                {fmtUptime(resource.uptime)}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {t('MikroTikSystemTab.resource.build', {
                  build: asString(resource['build-time']),
                })}
              </div>
            </div>
          </div>

          {health.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">{t('MikroTikSystemTab.health.title')}</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('MikroTikSystemTab.health.columns.sensor')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikSystemTab.health.columns.value')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikSystemTab.health.columns.type')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {health.map((row, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asString(row.name)}</td>
                        <td className="px-3 py-2 font-mono">{asString(row.value)}</td>
                        <td className="px-3 py-2">{asString(row.type)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Identity edit dialog */}
      <Dialog open={identityOpen} onOpenChange={setIdentityOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikSystemTab.identityDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikSystemTab.identityDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="mikrotik-identity-name">{t('MikroTikSystemTab.identityDialog.nameLabel')}</Label>
            <Input
              id="mikrotik-identity-name"
              value={identityName}
              onChange={(e) => setIdentityName(e.target.value)}
              placeholder="MyRouter"
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIdentityOpen(false)}>
              {t('MikroTikSystemTab.actions.cancel')}
            </Button>
            <Button
              onClick={() => identityMutation.mutate(identityName.trim())}
              disabled={identityMutation.isPending || identityName.trim().length === 0}
            >
              {identityMutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikSystemTab.actions.stageChange')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* NTP edit dialog */}
      <Dialog open={ntpOpen} onOpenChange={setNtpOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikSystemTab.ntpDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikSystemTab.ntpDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-ntp-primary">{t('MikroTikSystemTab.ntpDialog.primaryLabel')}</Label>
              <Input
                id="mikrotik-ntp-primary"
                value={ntpPrimary}
                onChange={(e) => setNtpPrimary(e.target.value)}
                placeholder="0.pool.ntp.org"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-ntp-secondary">{t('MikroTikSystemTab.ntpDialog.secondaryLabel')}</Label>
              <Input
                id="mikrotik-ntp-secondary"
                value={ntpSecondary}
                onChange={(e) => setNtpSecondary(e.target.value)}
                placeholder="1.pool.ntp.org"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNtpOpen(false)}>
              {t('MikroTikSystemTab.actions.cancel')}
            </Button>
            <Button
              onClick={() =>
                ntpMutation.mutate({ primary: ntpPrimary, secondary: ntpSecondary })
              }
              disabled={ntpMutation.isPending || ntpPrimary.trim().length === 0}
            >
              {ntpMutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikSystemTab.actions.stageChange')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
