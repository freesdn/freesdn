// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DatabaseBackupStatusCard · the state of the encrypted pg-backup dumps.
 *
 * A fresh install has NO database backups until an operator installs a GPG
 * public key (pg-backup refuses plaintext). That used to be visible only in the
 * container log. Admins only (the endpoint 403s everyone else, and so does this).
 * The key cannot be installed from here, by design: a web session must never be
 * able to choose where the instance's backups are encrypted to.
 */
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle2, Database, HelpCircle } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { databaseBackupApi, type DatabaseBackupState, type DatabaseBackupStatus } from '@/lib/api/configBackups';
import { useAuthStore } from '@/stores/authStore';

function formatWhen(value: string | null): string | null {
  return value ? new Date(value).toLocaleString() : null;
}

const KNOWN_STATES = new Set<DatabaseBackupState>([
  'healthy',
  'unencrypted',
  'pending',
  'unknown',
  'disabled',
  'failing',
  'stale',
]);

export function DatabaseBackupStatusCard() {
  const { t } = useTranslation('backup');
  const user = useAuthStore((state) => state.user);
  const isAdmin = Boolean(user?.is_active && (user.is_superuser || user.is_org_admin));
  const { data, isError } = useQuery<DatabaseBackupStatus>({
    queryKey: ['database-backup-status'],
    queryFn: databaseBackupApi.status,
    enabled: isAdmin,
    staleTime: 60_000,
    retry: false,
  });

  if (!isAdmin || isError || !data) return null;

  // A body without a state this card knows (an older backend, a proxy page
  // parsed as JSON) used to print raw keys such as
  // "DatabaseBackupStatus.title.undefined". It is an unknown status, said so.
  const state: DatabaseBackupState = KNOWN_STATES.has(data.state) ? data.state : 'unknown';
  const last = formatWhen(typeof data.last_success_at === 'string' ? data.last_success_at : null);
  const critical = state !== 'unknown' && data.severity === 'critical';
  const healthy = state === 'healthy';
  const Icon = critical ? AlertTriangle : healthy ? CheckCircle2 : state === 'unknown' ? HelpCircle : Database;
  const reasonKey = `DatabaseBackupStatus.reason.${data.reason ?? 'none'}`;

  return (
    <Alert variant={critical ? 'destructive' : 'default'} data-testid="database-backup-status" data-state={state}>
      <Icon className="h-4 w-4" />
      <AlertTitle>{t(`DatabaseBackupStatus.title.${state}`)}</AlertTitle>
      <AlertDescription>
        <p>{t(`DatabaseBackupStatus.body.${state}`)}</p>
        {state === 'disabled' && data.reason && (
          <p className="mt-1">{t(reasonKey, { defaultValue: '' })}</p>
        )}
        {last && (
          <p className="mt-1 text-xs text-muted-foreground">
            {t('DatabaseBackupStatus.lastSuccess', { when: last })}
          </p>
        )}
        {typeof data.setup_command === 'string' && data.setup_command && (
          <div className="mt-2 space-y-1">
            <p className="text-xs">{t('DatabaseBackupStatus.setupHint')}</p>
            <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 text-xs text-foreground">
              <code>{data.setup_command}</code>
            </pre>
            <p className="text-xs text-muted-foreground">{t('DatabaseBackupStatus.privateKeyWarning')}</p>
          </div>
        )}
      </AlertDescription>
    </Alert>
  );
}

export default DatabaseBackupStatusCard;
