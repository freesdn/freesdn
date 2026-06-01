// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikFirmwareTab · RouterOS firmware lifecycle.
 *
 * The most destructive surface in the stack, installing a firmware
 * update reboots the device. Triple-gate:
 *
 *   1. Check for updates → non-destructive (stages a check).
 *   2. Download update    → non-destructive (just stages).
 *   3. Install update     → destructive, requires the operator to type
 *      the literal string ``ROUTEROS`` to proceed AND shows a live
 *      progress poll of get_update_status while the install runs.
 *
 * Four cards:
 *   - Current state (installed version, current channel, last-checked).
 *   - Available update (latest version on the selected channel, action
 *     buttons: Check / Download / Install + Cancel-download).
 *   - Channel selector (stable / testing / development / long-term-stable).
 *   - Installed packages (name / version / scheduled-action) with
 *     per-package enable-disable-uninstall actions.
 *
 * All writes go through stageChange, operators apply via the shared
 * pending-changes endpoint. The install action is the only one that
 * additionally requires typed confirmation client-side; everything
 * else is just the standard stage flow.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  HardDrive,
  Loader2,
  PackageX,
  Power,
  PowerOff,
  RefreshCw,
  Rocket,
  XCircle,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikPackage,
} from '@/lib/api';

export interface MikroTikFirmwareTabProps {
  controllerId: string;
  isActive: boolean;
}

const STATUS_KEY = (cid: string) => ['mikrotik', cid, 'firmware-status'];
const PACKAGES_KEY = (cid: string) => ['mikrotik', cid, 'firmware-packages'];

const CHANNELS = [
  { value: 'stable', labelKey: 'channels.stable' },
  { value: 'long-term', labelKey: 'channels.longTerm' },
  { value: 'testing', labelKey: 'channels.testing' },
  { value: 'development', labelKey: 'channels.development' },
];

const CONFIRM_INSTALL_TOKEN = 'ROUTEROS';

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true' || value === 'yes';
  return false;
}

export function MikroTikFirmwareTab({
  controllerId,
  isActive,
}: MikroTikFirmwareTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [pendingChannel, setPendingChannel] = useState<string>('');
  const [installDialogOpen, setInstallDialogOpen] = useState(false);
  const [installConfirmText, setInstallConfirmText] = useState('');
  // While an install is staged + applied, we poll status more aggressively
  // to surface the RouterOS state machine to the operator.
  const [installInFlight, setInstallInFlight] = useState(false);

  const statusQuery = useQuery({
    queryKey: STATUS_KEY(controllerId),
    queryFn: () => mikrotikApi.getFirmwareStatus(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: installInFlight ? 5_000 : 60_000,
  });

  const packagesQuery = useQuery({
    queryKey: PACKAGES_KEY(controllerId),
    queryFn: () => mikrotikApi.getInstalledPackages(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  // Backend returns a bare status dict (not a {item} envelope).
  const status = statusQuery.data?.data;
  // Backend returns a bare packages array (not an {items} envelope).
  const packages = packagesQuery.data?.data ?? [];

  // Seed the channel selector from the live status the first time it
  // arrives. After that the operator owns the selection until they hit
  // "Switch channel".
  useEffect(() => {
    if (status?.channel && !pendingChannel) {
      setPendingChannel(asStr(status.channel));
    }
  }, [status?.channel, pendingChannel]);

  const checkMut = useMutation({
    mutationFn: () => mikrotikApi.checkFirmwareUpdates(controllerId),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.checkStaged') });
      queryClient.invalidateQueries({ queryKey: STATUS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.checkFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const channelMut = useMutation({
    mutationFn: (channel: string) =>
      mikrotikApi.setFirmwareChannel(controllerId, channel),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.channelStaged') });
      queryClient.invalidateQueries({ queryKey: STATUS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.channelFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const downloadMut = useMutation({
    mutationFn: () => mikrotikApi.downloadFirmwareUpdate(controllerId),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.downloadStaged') });
      queryClient.invalidateQueries({ queryKey: STATUS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.downloadFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const cancelMut = useMutation({
    mutationFn: () => mikrotikApi.cancelFirmwareDownload(controllerId),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.cancelStaged') });
      queryClient.invalidateQueries({ queryKey: STATUS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.cancelFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const installMut = useMutation({
    mutationFn: () => mikrotikApi.installFirmwareUpdate(controllerId),
    onSuccess: () => {
      setInstallDialogOpen(false);
      setInstallConfirmText('');
      setInstallInFlight(true);
      toast({
        title: t('MikroTikFirmwareTab.toasts.installStaged'),
        description: t('MikroTikFirmwareTab.toasts.installStagedDescription'),
      });
      queryClient.invalidateQueries({ queryKey: STATUS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.installFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const enablePkgMut = useMutation({
    mutationFn: (name: string) =>
      mikrotikApi.enablePackage(controllerId, name),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.enableStaged') });
      queryClient.invalidateQueries({ queryKey: PACKAGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.enableFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const disablePkgMut = useMutation({
    mutationFn: (name: string) =>
      mikrotikApi.disablePackage(controllerId, name),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.disableStaged') });
      queryClient.invalidateQueries({ queryKey: PACKAGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.disableFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const uninstallPkgMut = useMutation({
    mutationFn: (name: string) =>
      mikrotikApi.uninstallPackage(controllerId, name),
    onSuccess: () => {
      toast({ title: t('MikroTikFirmwareTab.toasts.uninstallStaged') });
      queryClient.invalidateQueries({ queryKey: PACKAGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirmwareTab.toasts.uninstallFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  if (statusQuery.isLoading && packagesQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikFirmwareTab.loading')}
      </div>
    );
  }

  const installedVersion = asStr(status?.['installed-version']);
  const latestVersion = asStr(status?.['latest-version']);
  const hasUpdate =
    installedVersion !== '-' &&
    latestVersion !== '-' &&
    installedVersion !== latestVersion;
  const currentChannel = asStr(status?.channel);
  const updateStatus = asStr(status?.status);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            statusQuery.refetch();
            packagesQuery.refetch();
          }}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> {t('MikroTikFirmwareTab.actions.refresh')}
        </Button>
      </div>

      {/* Card 1: Current state */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <HardDrive className="h-4 w-4" /> {t('MikroTikFirmwareTab.currentState.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikFirmwareTab.currentState.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {statusQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                statusQuery.error,
                t('MikroTikFirmwareTab.currentState.loadError'),
              )}
              onRetry={() => statusQuery.refetch()}
            />
          ) : !status ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikFirmwareTab.currentState.empty.title')}
              description={t('MikroTikFirmwareTab.currentState.empty.description')}
            />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.currentState.installedVersion')}</dt>
              <dd className="font-mono text-xs">{installedVersion}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.currentState.currentChannel')}</dt>
              <dd>
                <Badge variant="secondary">{currentChannel}</Badge>
              </dd>
              <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.currentState.lastChecked')}</dt>
              <dd className="font-mono text-xs">
                {asStr(status['last-checked'])}
              </dd>
              <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.currentState.status')}</dt>
              <dd>
                <Badge variant={hasUpdate ? 'default' : 'secondary'}>
                  {updateStatus}
                </Badge>
              </dd>
            </dl>
          )}
        </CardContent>
      </Card>

      {/* Card 2: Available update */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Rocket className="h-4 w-4" /> {t('MikroTikFirmwareTab.availableUpdate.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikFirmwareTab.availableUpdate.description')}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => checkMut.mutate()}
                disabled={checkMut.isPending}
              >
                {checkMut.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <RefreshCw className="h-4 w-4 mr-1" />
                )}
                {t('MikroTikFirmwareTab.actions.checkForUpdates')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.availableUpdate.latestAvailable')}</dt>
            <dd className="font-mono text-xs">
              {latestVersion}
              {hasUpdate && (
                <Badge variant="default" className="ml-2">
                  {t('MikroTikFirmwareTab.availableUpdate.updateAvailable')}
                </Badge>
              )}
            </dd>
            <dt className="text-muted-foreground">{t('MikroTikFirmwareTab.availableUpdate.lastError')}</dt>
            <dd className="font-mono text-xs">
              {asStr(status?.['last-error'])}
            </dd>
          </dl>
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border/50">
            <Button
              size="sm"
              variant="outline"
              onClick={() => downloadMut.mutate()}
              disabled={!hasUpdate || downloadMut.isPending}
            >
              {downloadMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Download className="h-4 w-4 mr-1" />
              )}
              {t('MikroTikFirmwareTab.actions.download')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => cancelMut.mutate()}
              disabled={cancelMut.isPending}
            >
              <XCircle className="h-4 w-4 mr-1" />
              {t('MikroTikFirmwareTab.actions.cancelDownload')}
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setInstallDialogOpen(true)}
              disabled={!hasUpdate || installMut.isPending || installInFlight}
            >
              <AlertTriangle className="h-4 w-4 mr-1" />
              {t('MikroTikFirmwareTab.actions.installReboot')}
            </Button>
            {installInFlight && (
              <Badge variant="default" className="ml-2">
                <Loader2 className="h-3 w-3 animate-spin mr-1" /> {t('MikroTikFirmwareTab.availableUpdate.installInFlight')}
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Card 3: Channel selector */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4" /> {t('MikroTikFirmwareTab.channel.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikFirmwareTab.channel.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-3">
            <div className="space-y-2 flex-1 max-w-xs">
              <Label htmlFor="mtk-firmware-channel">{t('MikroTikFirmwareTab.channel.label')}</Label>
              <Select
                value={pendingChannel || currentChannel}
                onValueChange={setPendingChannel}
              >
                <SelectTrigger id="mtk-firmware-channel">
                  <SelectValue placeholder={t('MikroTikFirmwareTab.channel.placeholder')} />
                </SelectTrigger>
                <SelectContent>
                  {CHANNELS.map((c) => (
                    <SelectItem key={c.value} value={c.value}>
                      {t(`MikroTikFirmwareTab.${c.labelKey}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              onClick={() => channelMut.mutate(pendingChannel)}
              disabled={
                !pendingChannel ||
                pendingChannel === currentChannel ||
                channelMut.isPending
              }
            >
              {channelMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikFirmwareTab.actions.switchChannel')}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Card 4: Installed packages */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <PackageX className="h-4 w-4" /> {t('MikroTikFirmwareTab.packages.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikFirmwareTab.packages.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {packagesQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                packagesQuery.error,
                t('MikroTikFirmwareTab.packages.loadError'),
              )}
              onRetry={() => packagesQuery.refetch()}
            />
          ) : packages.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikFirmwareTab.packages.empty.title')}
              description={t('MikroTikFirmwareTab.packages.empty.description')}
            />
          ) : (
            <div className="border rounded-md overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('MikroTikFirmwareTab.packages.columns.name')}</TableHead>
                    <TableHead>{t('MikroTikFirmwareTab.packages.columns.version')}</TableHead>
                    <TableHead>{t('MikroTikFirmwareTab.packages.columns.scheduled')}</TableHead>
                    <TableHead>{t('MikroTikFirmwareTab.packages.columns.state')}</TableHead>
                    <TableHead className="text-right">{t('MikroTikFirmwareTab.packages.columns.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {packages.map((p: MikroTikPackage) => {
                    const name = asStr(p.name);
                    const disabled = asBool(p.disabled);
                    return (
                      <TableRow key={p['.id'] ?? name}>
                        <TableCell className="font-mono text-xs">
                          {name}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {asStr(p.version)}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {asStr(p['scheduled-action'] ?? p.scheduled)}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={disabled ? 'secondary' : 'default'}
                          >
                            {disabled
                              ? t('MikroTikFirmwareTab.packages.state.disabled')
                              : t('MikroTikFirmwareTab.packages.state.enabled')}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            {disabled ? (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => enablePkgMut.mutate(name)}
                                disabled={
                                  enablePkgMut.isPending || name === '-'
                                }
                              >
                                <Power className="h-3 w-3 mr-1" />
                                {t('MikroTikFirmwareTab.actions.enable')}
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => disablePkgMut.mutate(name)}
                                disabled={
                                  disablePkgMut.isPending || name === '-'
                                }
                              >
                                <PowerOff className="h-3 w-3 mr-1" />
                                {t('MikroTikFirmwareTab.actions.disable')}
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => uninstallPkgMut.mutate(name)}
                              disabled={
                                uninstallPkgMut.isPending || name === '-'
                              }
                            >
                              <PackageX className="h-3 w-3 mr-1" />
                              {t('MikroTikFirmwareTab.actions.uninstall')}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Install confirm dialog · type ROUTEROS to proceed */}
      <Dialog
        open={installDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setInstallDialogOpen(false);
            setInstallConfirmText('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" /> {t('MikroTikFirmwareTab.installDialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikFirmwareTab.installDialog.descriptionBefore')}{' '}
              <span className="font-mono font-semibold">
                {CONFIRM_INSTALL_TOKEN}
              </span>{' '}
              {t('MikroTikFirmwareTab.installDialog.descriptionAfter')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-firmware-confirm">{t('MikroTikFirmwareTab.installDialog.tokenLabel')}</Label>
              <Input
                id="mtk-firmware-confirm"
                autoComplete="off"
                spellCheck={false}
                value={installConfirmText}
                onChange={(e) => setInstallConfirmText(e.target.value)}
                placeholder={CONFIRM_INSTALL_TOKEN}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              {t('MikroTikFirmwareTab.installDialog.targetVersion')}{' '}
              <span className="font-mono">{latestVersion}</span>
              {' · '}
              {t('MikroTikFirmwareTab.installDialog.from')}{' '}
              <span className="font-mono">{installedVersion}</span>
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setInstallDialogOpen(false);
                setInstallConfirmText('');
              }}
            >
              {t('MikroTikFirmwareTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => installMut.mutate()}
              disabled={
                installConfirmText !== CONFIRM_INSTALL_TOKEN ||
                installMut.isPending
              }
            >
              {installMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikFirmwareTab.actions.stageInstall')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
