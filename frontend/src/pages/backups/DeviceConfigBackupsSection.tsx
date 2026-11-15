// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DeviceConfigBackupsSection · scheduled, versioned config history of network
 * devices (OPNsense config.xml, OpenWrt sysupgrade), exported READ-ONLY once a
 * day by default and stored encrypted. Everything shown here is REDACTED by the
 * server: a changed password appears as a changed `[redacted:…]` fingerprint,
 * never as its value. There is no restore button: restore goes through the
 * vendor's own UI from the audited super-admin download.
 *
 * Changing a device's schedule (on/off, every 6 to 168 hours) and "Back up
 * now" need `firewall.manage_rules`, as the backend enforces; without it the
 * controls are disabled with the reason.
 */
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { CalendarClock, History, Loader2, Network, RefreshCw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { DisabledReason } from '@/components/ui/disabled-reason';
import { getApiErrorMessage } from '@/lib/api';
import {
  configBackupApi,
  type ConfigBackupTarget,
  type ConfigBackupTargetUpdate,
  type ConfigDiff,
  type ConfigSnapshot,
} from '@/lib/api/configBackups';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuthStore } from '@/stores/authStore';

type BadgeVariant = 'success' | 'destructive' | 'warning' | 'muted' | 'secondary';

const STATUS_VARIANT: Record<string, BadgeVariant> = {
  changed: 'success',
  unchanged: 'success',
  failed: 'destructive',
  paused: 'warning',
  never: 'muted',
  unsupported: 'muted',
  source_removed: 'secondary',
};

function when(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '-';
}

/** The backend's INTERVAL_HOURS_RANGE (app/services/device_config_backup.py). */
export const INTERVAL_HOURS_MIN = 6;
export const INTERVAL_HOURS_MAX = 168;
const INTERVAL_PRESETS = [6, 12, 24, 48, 72, 168];

/** Statuses for which a schedule can no longer run (the backend never queues them). */
const UNSCHEDULABLE = new Set(['source_removed', 'unsupported']);

function intervalLabel(t: TFunction, hours: number): string {
  if (hours === 24) return t('DeviceConfigBackups.schedule.daily');
  if (hours === 168) return t('DeviceConfigBackups.schedule.weekly');
  return t('DeviceConfigBackups.schedule.everyHours', { hours });
}

function ScheduleDialog({ target, onClose }: { target: ConfigBackupTarget; onClose: () => void }) {
  const { t } = useTranslation('backup');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [enabled, setEnabled] = useState(target.enabled);
  const [hours, setHours] = useState(target.interval_hours);
  const options = INTERVAL_PRESETS.includes(target.interval_hours)
    ? INTERVAL_PRESETS
    : [...INTERVAL_PRESETS, target.interval_hours].sort((a, b) => a - b);
  const change: ConfigBackupTargetUpdate = {};
  if (enabled !== target.enabled) change.enabled = enabled;
  if (hours !== target.interval_hours) change.interval_hours = hours;
  const dirty = Object.keys(change).length > 0;
  const valid = hours >= INTERVAL_HOURS_MIN && hours <= INTERVAL_HOURS_MAX;

  const save = useMutation({
    mutationFn: () => configBackupApi.update(target.id, change),
    onSuccess: () => {
      toast({ title: t('DeviceConfigBackups.schedule.saved', { name: target.display_name }) });
      void queryClient.invalidateQueries({ queryKey: ['config-backup-targets'] });
      onClose();
    },
    onError: (error) => {
      toast({
        title: t('DeviceConfigBackups.schedule.failed'),
        description: getApiErrorMessage(error),
        variant: 'destructive',
      });
    },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('DeviceConfigBackups.schedule.title', { name: target.display_name })}</DialogTitle>
          <DialogDescription>{t('DeviceConfigBackups.schedule.description')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-4 rounded-md border border-border p-3">
            <div className="space-y-0.5">
              <Label htmlFor={`config-schedule-enabled-${target.id}`}>
                {t('DeviceConfigBackups.schedule.enabled')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {enabled ? t('DeviceConfigBackups.schedule.enabledOn') : t('DeviceConfigBackups.schedule.enabledOff')}
              </p>
            </div>
            <Switch
              id={`config-schedule-enabled-${target.id}`}
              checked={enabled}
              onCheckedChange={setEnabled}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={`config-schedule-interval-${target.id}`}>{t('DeviceConfigBackups.schedule.interval')}</Label>
            <Select value={String(hours)} onValueChange={(value) => setHours(Number(value))} disabled={!enabled}>
              <SelectTrigger id={`config-schedule-interval-${target.id}`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {options.map((option) => (
                  <SelectItem key={option} value={String(option)}>
                    {intervalLabel(t, option)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {t('DeviceConfigBackups.schedule.intervalHelp', { min: INTERVAL_HOURS_MIN, max: INTERVAL_HOURS_MAX })}
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('DeviceConfigBackups.schedule.cancel')}
          </Button>
          <Button disabled={!dirty || !valid || save.isPending} onClick={() => save.mutate()}>
            {save.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('DeviceConfigBackups.schedule.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DiffView({ diff }: { diff: ConfigDiff }) {
  const { t } = useTranslation('backup');
  if (diff.lines.length === 0) {
    return <p className="text-sm text-muted-foreground">{t('DeviceConfigBackups.history.noChanges')}</p>;
  }
  return (
    <div className="space-y-1">
      <p className="text-xs text-muted-foreground">
        {t('DeviceConfigBackups.history.summary', { added: diff.added, removed: diff.removed })}
        {diff.truncated ? ` ${t('DeviceConfigBackups.history.truncated')}` : ''}
      </p>
      <pre
        data-testid="config-diff"
        className="max-h-[50vh] overflow-auto rounded-md border border-border bg-muted p-2 text-xs leading-5"
      >
        {diff.lines.map((line, index) => (
          <div
            key={index}
            className={cn(
              line.startsWith('+') && !line.startsWith('+++') && 'text-green-600 dark:text-green-400',
              line.startsWith('-') && !line.startsWith('---') && 'text-destructive',
              line.startsWith('@@') && 'text-muted-foreground',
            )}
          >
            {line || ' '}
          </div>
        ))}
      </pre>
    </div>
  );
}

function HistoryDialog({ target, onClose }: { target: ConfigBackupTarget; onClose: () => void }) {
  const { t } = useTranslation('backup');
  const [selected, setSelected] = useState<number | null>(target.latest_version);
  const versions = useQuery<ConfigSnapshot[]>({
    queryKey: ['config-backup-versions', target.id],
    queryFn: () => configBackupApi.versions(target.id),
  });
  const diff = useQuery<ConfigDiff>({
    queryKey: ['config-backup-diff', target.id, selected],
    queryFn: () => configBackupApi.diff(target.id, selected as number),
    enabled: selected !== null,
  });
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>{t('DeviceConfigBackups.history.title', { name: target.display_name })}</DialogTitle>
          <DialogDescription>{t('DeviceConfigBackups.history.redactedNote')}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 md:grid-cols-[12rem_1fr]">
          <ul className="space-y-1" aria-label={t('DeviceConfigBackups.history.versions')}>
            {(versions.data ?? []).map((version) => (
              <li key={version.id}>
                <button
                  type="button"
                  onClick={() => setSelected(version.version)}
                  className={cn(
                    'w-full rounded-md px-2 py-1 text-left text-xs hover:bg-muted',
                    selected === version.version && 'bg-muted font-medium text-foreground',
                  )}
                >
                  v{version.version} · {when(version.captured_at)}
                  {version.summary && (
                    <span className="ml-1 text-muted-foreground">
                      +{version.summary.added}/-{version.summary.removed}
                    </span>
                  )}
                </button>
              </li>
            ))}
            {versions.isSuccess && versions.data.length === 0 && (
              <li className="text-xs text-muted-foreground">{t('DeviceConfigBackups.history.none')}</li>
            )}
          </ul>
          <div>
            {diff.isLoading && selected !== null && <Loader2 className="h-4 w-4 animate-spin" />}
            {diff.isError && (
              <p className="text-sm text-destructive">{getApiErrorMessage(diff.error)}</p>
            )}
            {diff.data && <DiffView diff={diff.data} />}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function DeviceConfigBackupsSection() {
  const { t } = useTranslation('backup');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const canManage = useAuthStore((s) => s.hasPermission('firewall.manage_rules'));
  const manageReason = canManage ? undefined : t('DeviceConfigBackups.permission.manage');
  const [historyFor, setHistoryFor] = useState<ConfigBackupTarget | null>(null);
  const [scheduleFor, setScheduleFor] = useState<ConfigBackupTarget | null>(null);
  const targets = useQuery<ConfigBackupTarget[]>({
    queryKey: ['config-backup-targets'],
    queryFn: configBackupApi.list,
    retry: false,
  });
  const capture = useMutation({
    mutationFn: (target: ConfigBackupTarget) => configBackupApi.capture(target.id),
    onSuccess: () => {
      toast({ title: t('DeviceConfigBackups.capture.queued') });
      void queryClient.invalidateQueries({ queryKey: ['config-backup-targets'] });
    },
    onError: (error) => {
      toast({
        title: t('DeviceConfigBackups.capture.refused'),
        description: getApiErrorMessage(error),
        variant: 'destructive',
      });
    },
  });

  // Users without firewall.view get a 403: show nothing rather than an error.
  if (targets.isError) return null;

  return (
    <Card data-testid="device-config-backups">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4 text-primary" />
          {t('DeviceConfigBackups.title')}
        </CardTitle>
        <CardDescription>{t('DeviceConfigBackups.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        {targets.isLoading && <Loader2 className="h-4 w-4 animate-spin" />}
        {targets.isSuccess && targets.data.length === 0 && (
          <p className="text-sm text-muted-foreground">{t('DeviceConfigBackups.empty')}</p>
        )}
        {targets.isSuccess && targets.data.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.device')}</th>
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.status')}</th>
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.lastSuccess')}</th>
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.versions')}</th>
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.schedule')}</th>
                  <th className="py-2 pr-3 font-medium">{t('DeviceConfigBackups.columns.nextRun')}</th>
                  <th className="py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {targets.data.map((target) => (
                  <tr key={target.id} className="border-b border-border last:border-0">
                    <td className="py-2 pr-3 text-foreground">
                      {target.display_name}
                      <span className="ml-2 text-xs text-muted-foreground">{target.vendor}</span>
                    </td>
                    <td className="py-2 pr-3">
                      <Badge variant={STATUS_VARIANT[target.last_status] ?? 'muted'}>
                        {t(`DeviceConfigBackups.status.${target.last_status}`, {
                          defaultValue: target.last_status,
                        })}
                      </Badge>
                      {target.last_error_code && (
                        <span className="ml-2 text-xs text-muted-foreground">
                          {t(`DeviceConfigBackups.error.${target.last_error_code}`, {
                            defaultValue: target.last_error_code,
                          })}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-muted-foreground">{when(target.last_success_at)}</td>
                    <td className="py-2 pr-3 text-muted-foreground">{target.latest_version ?? '-'}</td>
                    <td className="py-2 pr-3 text-muted-foreground" data-testid={`config-schedule-${target.id}`}>
                      {target.enabled ? intervalLabel(t, target.interval_hours) : t('DeviceConfigBackups.disabled')}
                    </td>
                    <td className="py-2 pr-3 text-muted-foreground">
                      {target.enabled ? when(target.next_due_at) : t('DeviceConfigBackups.disabled')}
                    </td>
                    <td className="py-2 text-right whitespace-nowrap">
                      <DisabledReason
                        reason={
                          manageReason ??
                          (UNSCHEDULABLE.has(target.last_status)
                            ? t('DeviceConfigBackups.permission.unschedulable')
                            : undefined)
                        }
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          className="gap-1"
                          disabled={!canManage || UNSCHEDULABLE.has(target.last_status)}
                          onClick={() => setScheduleFor(target)}
                        >
                          <CalendarClock className="h-4 w-4" />
                          {t('DeviceConfigBackups.actions.schedule')}
                        </Button>
                      </DisabledReason>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="gap-1"
                        disabled={target.latest_version === null}
                        onClick={() => setHistoryFor(target)}
                      >
                        <History className="h-4 w-4" />
                        {t('DeviceConfigBackups.actions.history')}
                      </Button>
                      <DisabledReason reason={manageReason}>
                        <Button
                          variant="outline"
                          size="sm"
                          className="ml-1 gap-1"
                          disabled={!canManage || target.capture_running || capture.isPending}
                          onClick={() => capture.mutate(target)}
                        >
                          <RefreshCw className={cn('h-4 w-4', target.capture_running && 'animate-spin')} />
                          {t('DeviceConfigBackups.actions.capture')}
                        </Button>
                      </DisabledReason>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
      {historyFor && <HistoryDialog target={historyFor} onClose={() => setHistoryFor(null)} />}
      {scheduleFor && <ScheduleDialog target={scheduleFor} onClose={() => setScheduleFor(null)} />}
    </Card>
  );
}

export default DeviceConfigBackupsSection;
