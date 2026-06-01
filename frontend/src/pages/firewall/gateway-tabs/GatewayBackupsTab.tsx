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
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, Archive, Download, Loader2, Plus, RefreshCw, RotateCcw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
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
  backups: any[];
  backupsLoading: boolean;
  onCreateBackup: () => void;
  isCreating: boolean;
  onRevertBackup: (filename: string) => void;
  onDeleteBackup: (filename: string) => void;
  onDownloadConfig: () => void;
  configDiffData: any;
  configDiffLoading: boolean;
}

export function GatewayBackupsTab({
  backups,
  backupsLoading,
  onCreateBackup,
  isCreating,
  onRevertBackup,
  onDeleteBackup,
  onDownloadConfig,
  configDiffData,
  configDiffLoading,
}: GatewayBackupsTabProps) {
  const { t } = useTranslation('firewall');
  // Revert confirmation, destructive overwrite of running config.
  const [pendingRevert, setPendingRevert] = useState<string | null>(null);

  const backupColumns: DataTableColumn<any>[] = [
    { id: 'filename', header: t('GatewayBackupsTab.columns.filename'), accessorFn: (r: any) => r.filename || r.name || '-', sortable: true },
    { id: 'date', header: t('GatewayBackupsTab.columns.date'), accessorFn: (r: any) => r.date || r.timestamp || '-', cell: (r: any) => (
      <span className="text-sm">{r.date ? new Date(r.date).toLocaleString() : r.timestamp || '-'}</span>
    )},
    { id: 'size', header: t('GatewayBackupsTab.columns.size'), accessorFn: (r: any) => r.size || '-' },
    { id: 'actions', header: '', cell: (r: any) => (
      <div className="flex gap-1">
        <Button variant="ghost" size="sm" onClick={() => setPendingRevert(r.filename || r.name)}>
          <RotateCcw className="h-3.5 w-3.5 mr-1" /> {t('GatewayBackupsTab.actions.revert')}
        </Button>
        <Button variant="ghost" size="sm" onClick={() => onDeleteBackup(r.filename || r.name)}>
          <Trash2 className="h-3.5 w-3.5 text-destructive" />
        </Button>
        <Button variant="ghost" size="sm" onClick={onDownloadConfig}>
          <Download className="h-3.5 w-3.5" />
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
            <Button size="sm" onClick={onCreateBackup} disabled={isCreating}>
              {isCreating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Plus className="h-4 w-4 mr-1" />}
              {t('GatewayBackupsTab.actions.createBackup')}
            </Button>
          </div>
        </CardHeader>
        <DataTable data={backups} columns={backupColumns} isLoading={backupsLoading} embedded />
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
          const diff = configDiffData?.data || {};
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
      <AlertDialog open={!!pendingRevert} onOpenChange={(o) => { if (!o) setPendingRevert(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayBackupsTab.revertDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayBackupsTab.revertDialog.prefix')} <strong>{pendingRevert}</strong>{t('GatewayBackupsTab.revertDialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayBackupsTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingRevert) onRevertBackup(pendingRevert);
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
