// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Settings > Read-only / Write access.
 *
 * The platform-wide ADAPTER_READ_ONLY switch. This is the most safety-critical
 * control in the UI, so it only ever states what the SERVER reported:
 *
 *  - The mode is read from the server on mount, not from the UI store. The
 *    store defaults to `false` (read-write) and is only seeded by a fire-and-
 *    forget fetch in App.tsx that swallows errors, so reading the store alone
 *    told an operator "Write access is ON" whenever that fetch had not landed
 *    or had failed. Unknown is now shown as unknown, with the switch disabled.
 *  - Turning writes ON asks first. Turning them OFF (the safe direction) does
 *    not.
 *  - After a change, the toast reports the mode the server APPLIED. If that is
 *    not the mode that was asked for, it says so instead of claiming success.
 *  - The mode has two sources, and the more restrictive wins: ADAPTER_READ_ONLY
 *    in the server environment and this switch (stored in the database). Both
 *    are shown, with the one in force. When the environment enforces read-only
 *    the switch cannot turn it off (the server refuses), so it is disabled and
 *    the page says where to change it.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Eye, HelpCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { useToastHelpers } from '@/components/ui/toast';
import { systemApi, getApiErrorMessage } from '@/lib/api';
import type { AdapterReadOnly, AdapterReadOnlyEnforcedBy } from '@/lib/api/system';
import { useUIStore } from '@/stores';
import { cn } from '@/lib/utils';

export const ADAPTER_READ_ONLY_QUERY_KEY = ['system', 'adapter-read-only'] as const;

/** The server's answer, or null when the body does not carry a boolean. */
function readOnlyFrom(data: unknown): boolean | null {
  if (data && typeof data === 'object' && typeof (data as { read_only?: unknown }).read_only === 'boolean') {
    return (data as { read_only: boolean }).read_only;
  }
  return null;
}

const ENFORCED_BY: readonly AdapterReadOnlyEnforcedBy[] = [
  'environment',
  'setting',
  'environment_and_setting',
  'unverified',
  'none',
];

/** The source detail, when the server sends it (older servers do not). */
function sourcesFrom(data: unknown): {
  env: boolean | null;
  setting: boolean | null | undefined;
  enforcedBy: AdapterReadOnlyEnforcedBy | null;
  canDisable: boolean;
} {
  const d = (data && typeof data === 'object' ? data : {}) as Partial<AdapterReadOnly>;
  const env = typeof d.env_read_only === 'boolean' ? d.env_read_only : null;
  const setting =
    typeof d.setting_read_only === 'boolean' || d.setting_read_only === null
      ? d.setting_read_only
      : undefined;
  const enforcedBy =
    typeof d.enforced_by === 'string' && ENFORCED_BY.includes(d.enforced_by) ? d.enforced_by : null;
  const canDisable = typeof d.can_disable === 'boolean' ? d.can_disable : env !== true;
  return { env, setting, enforcedBy, canDisable };
}

export function AccessSettingsTab() {
  const { t } = useTranslation('settings');
  const toast = useToastHelpers();
  const queryClient = useQueryClient();
  const setReadOnlyMode = useUIStore((state) => state.setReadOnlyMode);
  const [confirmWriteOpen, setConfirmWriteOpen] = useState(false);

  const modeQuery = useQuery({
    queryKey: ADAPTER_READ_ONLY_QUERY_KEY,
    queryFn: async () => (await systemApi.getAdapterReadOnly()).data,
    staleTime: 0,
  });
  const serverReadOnly = modeQuery.isSuccess ? readOnlyFrom(modeQuery.data) : null;
  const known = serverReadOnly !== null;
  const sources = sourcesFrom(modeQuery.isSuccess ? modeQuery.data : null);
  // The environment enforces read-only: the switch cannot turn it off.
  const envLocked = known && serverReadOnly === true && !sources.canDisable;

  // Keep the global store (header badge, read-only-aware dialogs) in step with
  // what the server just told us.
  useEffect(() => {
    if (serverReadOnly !== null) setReadOnlyMode(serverReadOnly);
  }, [serverReadOnly, setReadOnlyMode]);

  const mutation = useMutation({
    mutationFn: async (nextReadOnly: boolean) =>
      (await systemApi.setAdapterReadOnly(nextReadOnly)).data,
    onSuccess: (data, requested) => {
      const applied = readOnlyFrom(data);
      if (applied === null) {
        // The write was accepted but the body does not say which mode is in
        // force. Do not guess: re-read it.
        void queryClient.invalidateQueries({ queryKey: ADAPTER_READ_ONLY_QUERY_KEY });
        return;
      }
      queryClient.setQueryData(ADAPTER_READ_ONLY_QUERY_KEY, data);
      setReadOnlyMode(applied);
      if (applied !== requested) {
        toast.warning(
          t('SettingsPage.access.toast.mismatchTitle', 'Mode not changed'),
          applied
            ? t('SettingsPage.access.toast.mismatchStillReadOnly', 'The server kept read-only mode on. No device writes are possible.')
            : t('SettingsPage.access.toast.mismatchStillWrite', 'The server kept write access on.'),
        );
        return;
      }
      if ((data as Partial<AdapterReadOnly>).propagated === false) {
        toast.warning(
          t('SettingsPage.access.toast.notPropagatedTitle', 'Saved'),
          t('SettingsPage.access.toast.notPropagatedDesc', 'The change is saved. Some FreeSDN processes may take up to 30 seconds to apply it.'),
        );
        return;
      }
      if (applied) {
        toast.success(
          t('SettingsPage.access.toast.readOnlyTitle', 'Read-only mode enabled'),
          t('SettingsPage.access.toast.readOnlyDesc', 'Device writes are now disabled platform-wide.'),
        );
      } else {
        toast.success(
          t('SettingsPage.access.toast.writeTitle', 'Write access enabled'),
          t('SettingsPage.access.toast.writeDesc', 'Devices can now be managed and configured.'),
        );
      }
    },
    onError: (err) => {
      toast.error(
        t('SettingsPage.access.toast.errorTitle', 'Failed to update mode'),
        getApiErrorMessage(err, t('messages.saveFailed')),
      );
    },
  });

  const requestChange = (nextReadOnly: boolean) => {
    if (!nextReadOnly) {
      setConfirmWriteOpen(true);
      return;
    }
    mutation.mutate(true);
  };

  let label: string;
  let description: string;
  if (!known) {
    label = t('SettingsPage.access.row.labelUnknown', 'Current mode unknown');
    description = modeQuery.isError
      ? t('SettingsPage.access.row.descError', 'The server did not report the current mode, so it is not shown here. The switch stays disabled until it can be read.')
      : t('SettingsPage.access.row.descLoading', 'Reading the current mode from the server.');
  } else if (envLocked) {
    label = t('SettingsPage.access.row.labelReadOnly', 'Read-only mode (monitor only)');
    description = t('SettingsPage.access.row.descEnvEnforced', "Read-only mode is set by ADAPTER_READ_ONLY=true in the server environment, so it cannot be turned off here. Set ADAPTER_READ_ONLY=false in the server's .env file and restart FreeSDN to allow device writes.");
  } else if (serverReadOnly && sources.enforcedBy === 'unverified') {
    label = t('SettingsPage.access.row.labelReadOnly', 'Read-only mode (monitor only)');
    description = t('SettingsPage.access.row.descUnverified', 'The stored switch could not be read, so device writes are refused until it can be. Retry in a moment.');
  } else if (serverReadOnly) {
    label = t('SettingsPage.access.row.labelReadOnly', 'Read-only mode (monitor only)');
    description = t('SettingsPage.access.row.descReadOnly', 'Device writes are disabled. Turn this off to manage and configure devices.');
  } else {
    label = t('SettingsPage.access.row.labelWrite', 'Read-write mode (manage)');
    description = t('SettingsPage.access.row.descWrite', 'Device writes are enabled. Turn this on to lock the platform to monitor-only.');
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
        <div className="min-w-0 space-y-0.5">
          <Label htmlFor="adapter-read-only-switch" className="text-base">
            {label}
          </Label>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {(modeQuery.isError || sources.enforcedBy === 'unverified') && (
            <Button variant="outline" size="sm" onClick={() => void modeQuery.refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {t('SettingsPage.access.row.retry', 'Retry')}
            </Button>
          )}
          {modeQuery.isPending ? (
            <Skeleton className="h-6 w-11 rounded-full" />
          ) : (
            <Switch
              id="adapter-read-only-switch"
              checked={serverReadOnly === true}
              onCheckedChange={requestChange}
              disabled={!known || envLocked || mutation.isPending}
              aria-label={t('SettingsPage.access.row.toggleAria', 'Toggle read-only mode')}
            />
          )}
        </div>
      </div>

      <div
        role="status"
        className={cn(
          'flex items-start gap-3 rounded-lg border p-4 text-sm',
          !known
            ? 'border-border bg-muted/40 text-muted-foreground'
            : serverReadOnly
              ? 'border-warning/30 bg-warning/10 text-warning'
              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
        )}
      >
        {!known ? (
          <HelpCircle className="mt-0.5 h-4 w-4 shrink-0" />
        ) : serverReadOnly ? (
          <Eye className="mt-0.5 h-4 w-4 shrink-0" />
        ) : (
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
        )}
        <span>
          {!known
            ? t('SettingsPage.access.status.unknown', 'The current mode has not been confirmed by the server.')
            : serverReadOnly
              ? t('SettingsPage.access.status.readOnly', 'Read-only mode is ON. FreeSDN will not write to any device.')
              : t('SettingsPage.access.status.write', 'Write access is ON. FreeSDN can apply changes to managed devices.')}
        </span>
      </div>

      {known && sources.env !== null && (
        <div className="rounded-lg border p-4 text-sm">
          <p className="mb-2 font-medium">
            {t('SettingsPage.access.sources.title', 'Where the mode comes from')}
          </p>
          <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[auto_1fr]">
            <dt className="text-muted-foreground">
              {t('SettingsPage.access.sources.env', 'Server environment (ADAPTER_READ_ONLY)')}
            </dt>
            <dd data-testid="read-only-source-env">
              {sources.env
                ? t('SettingsPage.access.sources.readOnly', 'Read-only')
                : t('SettingsPage.access.sources.envOff', 'Not enforced')}
            </dd>
            <dt className="text-muted-foreground">
              {t('SettingsPage.access.sources.setting', 'Settings switch')}
            </dt>
            <dd data-testid="read-only-source-setting">
              {sources.setting === null
                ? t('SettingsPage.access.sources.settingUnknown', 'Could not be read')
                : sources.setting
                  ? t('SettingsPage.access.sources.readOnly', 'Read-only')
                  : t('SettingsPage.access.sources.settingOff', 'Off')}
            </dd>
            {sources.enforcedBy && (
              <>
                <dt className="text-muted-foreground">
                  {t('SettingsPage.access.sources.inForce', 'In force')}
                </dt>
                <dd data-testid="read-only-enforced-by">
                  {t(`SettingsPage.access.enforcedBy.${sources.enforcedBy}`)}
                </dd>
              </>
            )}
          </dl>
        </div>
      )}

      <AlertDialog open={confirmWriteOpen} onOpenChange={setConfirmWriteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              {t('SettingsPage.access.confirm.title', 'Allow FreeSDN to write to devices?')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'SettingsPage.access.confirm.description',
                'This turns read-only mode off for the whole platform. Staged changes can then be applied to switches, firewalls, cameras, phones and hypervisors by anyone with write permission. Each apply still needs its own confirmation.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('SettingsPage.access.confirm.cancel', 'Keep read-only')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => mutation.mutate(false)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('SettingsPage.access.confirm.confirm', 'Enable write access')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
