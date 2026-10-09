// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayBackupsTab · gateway configuration backups + running-vs-backup diff.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns the
 * backupColumns definition (only used here) and receives all data + the
 * create/revert/delete/download callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, Archive, Download, RefreshCw, RotateCcw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import type { GatewayBackupMetadata } from '@/lib/gateway-backup-inventory';
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

export interface GatewayBackupsTabProps {
  backups: GatewayBackupMetadata[] | null;
  backupsLoading: boolean;
  onRetryBackups?: () => void;
  onRevertBackup: (filename: string) => void;
  onDeleteBackup: (filename: string) => void;
  onDownloadConfig: () => void;
  isDownloadingConfig?: boolean;
  configDiffData: any;
  configDiffLoading: boolean;
  configDiffError?: boolean;
  onRetryConfigDiff?: () => void;
}

export function GatewayBackupsTab({
  backups,
  backupsLoading,
  onRetryBackups,
  onRevertBackup,
  onDeleteBackup,
  onDownloadConfig,
  isDownloadingConfig = false,
  configDiffData,
  configDiffLoading,
  configDiffError = false,
  onRetryConfigDiff,
}: GatewayBackupsTabProps) {
  const { t } = useTranslation('firewall');
  // Revert confirmation, destructive overwrite of running config.
  const [pendingRevert, setPendingRevert] = useState<{ filename: string; inventory: GatewayBackupMetadata[] } | null>(null);
  const canRevert = !backupsLoading && backups !== null && pendingRevert?.inventory === backups
    && backups.some((backup) => backup.filename === pendingRevert.filename);
  useEffect(() => { setPendingRevert(null); }, [backups, backupsLoading]);

  const backupColumns: DataTableColumn<GatewayBackupMetadata>[] = [
    { id: 'filename', header: t('GatewayBackupsTab.columns.filename'), accessorFn: (r) => r.filename, sortable: true },
    { id: 'date', header: t('GatewayBackupsTab.columns.date'), accessorFn: (r) => r.timestamp, cell: (r) => (
      <span className="text-sm">{r.timestamp || '-'}</span>
    )},
    { id: 'size', header: t('GatewayBackupsTab.columns.size'), accessorFn: (r) => r.size_bytes, cell: (r) => `${r.size_bytes.toLocaleString()} B` },
    { id: 'actions', header: '', cell: (r) => (
      <div className="flex gap-1">
        <Button variant="ghost" size="sm" onClick={() => { if (backups && !backupsLoading) setPendingRevert({ filename: r.filename, inventory: backups }); }}>
          <RotateCcw className="h-3.5 w-3.5 mr-1" /> {t('GatewayBackupsTab.actions.revert')}
        </Button>
        <Button variant="ghost" size="sm" aria-label={t('GatewayBackupsTab.actions.deleteBackup', { filename: r.filename })} onClick={() => { if (backups && !backupsLoading) onDeleteBackup(r.filename); }}>
          <Trash2 className="h-3.5 w-3.5 text-destructive" />
        </Button>

      </div>
    )},
  ];

  return (
    <>
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Archive className="h-4 w-4" /> {t('GatewayBackupsTab.backups.title')}</CardTitle>
              <CardDescription>{t('GatewayBackupsTab.backups.description')}</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={onDownloadConfig} disabled={isDownloadingConfig} aria-busy={isDownloadingConfig}>
                <Download className="h-4 w-4 mr-1" />
                {t('GatewayBackupsTab.actions.exportConfig', { defaultValue: 'Export configuration' })}
              </Button>
            </div>
          </div>
          <p role="status" className="text-sm text-muted-foreground">
            {t('GatewayBackupsTab.backups.creationUnsupported')}
          </p>
        </CardHeader>
        {backupsLoading ? (
          <CardContent><p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayBackupsTab.backups.loading')}
          </p></CardContent>
        ) : backups === null ? (
          <CardContent className="space-y-3">
            <p role="status" className="text-sm text-muted-foreground">{t('GatewayBackupsTab.backups.unavailable')}</p>
            {onRetryBackups && <Button variant="outline" size="sm" onClick={onRetryBackups}>
              <RefreshCw className="h-4 w-4 mr-1" /> {t('GatewayBackupsTab.backups.retry')}
            </Button>}
          </CardContent>
        ) : <DataTable data={backups} columns={backupColumns} embedded />}
      </Card>

      {/* ─── Config Diff ──────────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" /> {t('GatewayBackupsTab.diff.title')}</CardTitle>
          <CardDescription>{t('GatewayBackupsTab.diff.description')}</CardDescription>
        </CardHeader>
        {configDiffLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayBackupsTab.diff.generating')}</div></CardContent>
        ) : (() => {
          const diff = configDiffData?.data;
          const comparable = !configDiffError
            && diff?.comparison_available === true
            && typeof diff.has_changes === 'boolean'
            && Array.isArray(diff.diff_lines)
            && diff.diff_lines.every((line: unknown) => typeof line === 'string')
            && diff.has_changes === (diff.diff_lines.length > 0)
            && Number.isInteger(diff.current_size) && diff.current_size > 0
            && Number.isInteger(diff.backup_size) && diff.backup_size > 0;
          if (!comparable) {
            return (
              <CardContent className="space-y-3">
                <p role="status" className="text-sm text-muted-foreground">
                  {t('GatewayBackupsTab.diff.unavailable', {
                    defaultValue: 'Comparison unavailable. Both configuration documents must be retrieved successfully; no conclusion about changes can be made.',
                  })}
                </p>
                {onRetryConfigDiff && (
                  <Button variant="outline" size="sm" onClick={onRetryConfigDiff}>
                    <RefreshCw className="h-4 w-4 mr-1" />
                    {t('GatewayBackupsTab.diff.retry', { defaultValue: 'Retry comparison' })}
                  </Button>
                )}
              </CardContent>
            );
          }
          return (
            <CardContent className="space-y-3">
              <div className="flex items-center gap-4 text-sm">
                <Badge variant={diff.has_changes ? 'destructive' : 'default'}>{diff.has_changes ? t('GatewayBackupsTab.diff.changesDetected') : t('GatewayBackupsTab.diff.noChanges')}</Badge>
                {diff.summary && <span className="text-muted-foreground">{diff.summary}</span>}
              </div>
              {diff.diff_lines && diff.diff_lines.length > 0 && (
                <pre className="text-xs bg-muted p-3 rounded-lg overflow-auto max-h-[400px] font-mono">
                  {diff.diff_lines.map((line: string, i: number) => (
                    <div key={i} className={
                      line.startsWith('+') && !line.startsWith('+++') ? 'text-green-600 dark:text-green-400' :
                      line.startsWith('-') && !line.startsWith('---') ? 'text-red-600 dark:text-red-400' :
                      line.startsWith('@@') ? 'text-blue-600 dark:text-blue-400' :
                      'text-muted-foreground'
                    }>{line}</div>
                  ))}
                </pre>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* Revert Backup Confirmation */}
      <AlertDialog open={canRevert} onOpenChange={(o) => { if (!o) setPendingRevert(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayBackupsTab.revertDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayBackupsTab.revertDialog.prefix')} <strong>{pendingRevert?.filename}</strong>{t('GatewayBackupsTab.revertDialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayBackupsTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (canRevert && pendingRevert) onRevertBackup(pendingRevert.filename);
                setPendingRevert(null);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('GatewayBackupsTab.actions.revert')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
