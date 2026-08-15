// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikBackupTab · RouterOS config backup / restore.
 *
 * RouterOS exposes two backup formats:
 *
 *   - Binary `.backup` files: full system state, password-protectable,
 *     restored with `/system/backup/load`. The restore reboots the
 *     device into the saved config.
 *   - Text `.rsc` exports: human-readable RouterOS script form, run
 *     via `/import` (deferred; this tab only surfaces the
 *     export-to-file action, since import has its own gotchas around
 *     state ordering).
 *
 * Surface:
 *   - Action bar: "Create binary backup" + "Export config (.rsc)" +
 *     "Upload backup" (file picker).
 *   - Backups table: filename / size / type / created / download /
 *     delete / restore. Restore is destructive, requires the operator
 *     to type the exact filename (matching the row's `name` field) AND
 *     warns that the device will reboot.
 *
 * Critical: NEVER show binary content inline, `downloadBackupContent`
 * returns a base64 blob; we save it via the browser download API.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Archive,
  Download,
  FileCode,
  Loader2,
  RefreshCw,
  RotateCcw,
  Trash2,
  Upload,
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
  type MikroTikBackupFile,
} from '@/lib/api';

export interface MikroTikBackupTabProps {
  controllerId: string;
  isActive: boolean;
}

const BACKUPS_KEY = (cid: string) => ['mikrotik', cid, 'backups'];

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

function formatSize(bytes: unknown): string {
  if (typeof bytes !== 'string' && typeof bytes !== 'number') return '-';
  const n = typeof bytes === 'number' ? bytes : Number.parseInt(bytes, 10);
  if (!Number.isFinite(n)) return asStr(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function backupKind(name: string): 'binary' | 'text' | 'other' {
  if (name.endsWith('.backup')) return 'binary';
  if (name.endsWith('.rsc')) return 'text';
  return 'other';
}

export function MikroTikBackupTab({
  controllerId,
  isActive,
}: MikroTikBackupTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportComment, setExportComment] = useState('');
  const [exportEncrypted, setExportEncrypted] = useState(false);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [uploadName, setUploadName] = useState('');
  const [uploadContent, setUploadContent] = useState('');

  const [restoreTarget, setRestoreTarget] = useState<MikroTikBackupFile | null>(
    null,
  );
  const [restoreConfirmText, setRestoreConfirmText] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<MikroTikBackupFile | null>(
    null,
  );

  const backupsQuery = useQuery({
    queryKey: BACKUPS_KEY(controllerId),
    queryFn: () => mikrotikApi.listMikrotikBackups(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  // Backend returns a bare backups array (not an {items} envelope).
  const backups = backupsQuery.data?.data ?? [];

  const createMut = useMutation({
    mutationFn: (vars: { name: string; password?: string }) =>
      mikrotikApi.createBinaryBackup(controllerId, vars.name, vars.password),
    onSuccess: () => {
      toast({ title: t('MikroTikBackupTab.toasts.createSuccess') });
      setCreateDialogOpen(false);
      setCreateName('');
      setCreatePassword('');
      queryClient.invalidateQueries({ queryKey: BACKUPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikBackupTab.toasts.createError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const exportMut = useMutation({
    mutationFn: (vars: { comment: string; encrypted: boolean }) =>
      mikrotikApi.exportTextConfig(controllerId, vars.comment, vars.encrypted),
    onSuccess: () => {
      toast({ title: t('MikroTikBackupTab.toasts.exportSuccess') });
      setExportDialogOpen(false);
      setExportComment('');
      setExportEncrypted(false);
      queryClient.invalidateQueries({ queryKey: BACKUPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikBackupTab.toasts.exportError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const uploadMut = useMutation({
    mutationFn: (vars: { name: string; content: string }) =>
      mikrotikApi.uploadBackupContent(controllerId, vars.name, vars.content),
    onSuccess: () => {
      toast({ title: t('MikroTikBackupTab.toasts.uploadSuccess') });
      setUploadDialogOpen(false);
      setUploadName('');
      setUploadContent('');
      queryClient.invalidateQueries({ queryKey: BACKUPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikBackupTab.toasts.uploadError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteMut = useMutation({
    mutationFn: (name: string) =>
      mikrotikApi.deleteMikrotikBackup(controllerId, name),
    onSuccess: () => {
      toast({ title: t('MikroTikBackupTab.toasts.deleteSuccess') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: BACKUPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikBackupTab.toasts.deleteError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const restoreMut = useMutation({
    mutationFn: (vars: { name: string; password?: string }) =>
      mikrotikApi.restoreMikrotikBackup(
        controllerId,
        vars.name,
        vars.password,
      ),
    onSuccess: () => {
      toast({
        title: t('MikroTikBackupTab.toasts.restoreSuccess'),
        description: t('MikroTikBackupTab.toasts.restoreSuccessDescription'),
      });
      setRestoreTarget(null);
      setRestoreConfirmText('');
      setRestorePassword('');
      queryClient.invalidateQueries({ queryKey: BACKUPS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikBackupTab.toasts.restoreError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  async function handleDownload(name: string) {
    try {
      const resp = await mikrotikApi.downloadBackupContent(controllerId, name);
      // Backend streams the raw backup bytes; resp.data is already a Blob
      // (the request runs with responseType:'blob'), so save it directly.
      const blob = resp.data;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: t('MikroTikBackupTab.toasts.downloadSuccess', { name }) });
    } catch (err) {
      toast({
        title: t('MikroTikBackupTab.toasts.downloadError'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    }
  }

  async function handleFilePick(file: File) {
    const text = await file.text();
    setUploadName(file.name);
    setUploadContent(text);
  }

  if (backupsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikBackupTab.loading')}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            onClick={() => setCreateDialogOpen(true)}
            disabled={createMut.isPending}
          >
            <Archive className="h-4 w-4 mr-1" /> {t('MikroTikBackupTab.actions.createBinary')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setExportDialogOpen(true)}
            disabled={exportMut.isPending}
          >
            <FileCode className="h-4 w-4 mr-1" /> {t('MikroTikBackupTab.actions.exportConfig')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setUploadDialogOpen(true)}
            disabled={uploadMut.isPending}
          >
            <Upload className="h-4 w-4 mr-1" /> {t('MikroTikBackupTab.actions.uploadBackup')}
          </Button>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => backupsQuery.refetch()}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> {t('MikroTikBackupTab.actions.refresh')}
        </Button>
      </div>

      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Archive className="h-4 w-4" /> {t('MikroTikBackupTab.savedBackups.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikBackupTab.savedBackups.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {backupsQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                backupsQuery.error,
                t('MikroTikBackupTab.errors.loadBackups'),
              )}
              onRetry={() => backupsQuery.refetch()}
            />
          ) : backups.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikBackupTab.empty.title')}
              description={t('MikroTikBackupTab.empty.description')}
            />
          ) : (
            <div className="border rounded-md overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('MikroTikBackupTab.table.filename')}</TableHead>
                    <TableHead>{t('MikroTikBackupTab.table.type')}</TableHead>
                    <TableHead>{t('MikroTikBackupTab.table.size')}</TableHead>
                    <TableHead>{t('MikroTikBackupTab.table.created')}</TableHead>
                    <TableHead className="text-right">{t('MikroTikBackupTab.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {backups.map((b: MikroTikBackupFile) => {
                    const name = asStr(b.name);
                    const kind = backupKind(name);
                    return (
                      <TableRow key={b['.id'] ?? name}>
                        <TableCell className="font-mono text-xs">
                          {name}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={kind === 'binary' ? 'default' : 'secondary'}
                          >
                            {kind === 'binary'
                              ? '.backup'
                              : kind === 'text'
                                ? '.rsc'
                                : t('MikroTikBackupTab.table.kindOther')}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {formatSize(b.size)}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {asStr(b['creation-time'])}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleDownload(name)}
                              disabled={name === '-'}
                            >
                              <Download className="h-3 w-3 mr-1" aria-hidden="true" />
                              {t('MikroTikBackupTab.rowActions.download')}
                            </Button>
                            {kind === 'binary' && (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setRestoreTarget(b)}
                                disabled={name === '-'}
                              >
                                <RotateCcw className="h-3 w-3 mr-1" aria-hidden="true" />
                                {t('MikroTikBackupTab.rowActions.restore')}
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => setDeleteTarget(b)}
                              disabled={name === '-'}
                            >
                              <Trash2 className="h-3 w-3 mr-1" aria-hidden="true" />
                              {t('MikroTikBackupTab.rowActions.delete')}
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

      {/* Create binary backup */}
      <Dialog
        open={createDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setCreateDialogOpen(false);
            setCreateName('');
            setCreatePassword('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikBackupTab.createDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikBackupTab.createDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-backup-name">{t('MikroTikBackupTab.createDialog.nameLabel')}</Label>
              <Input
                id="mtk-backup-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder={t('MikroTikBackupTab.createDialog.namePlaceholder')}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-backup-password">
                {t('MikroTikBackupTab.createDialog.passwordLabel')}
              </Label>
              <Input
                id="mtk-backup-password"
                type="password"
                autoComplete="new-password"
                value={createPassword}
                onChange={(e) => setCreatePassword(e.target.value)}
                placeholder={t('MikroTikBackupTab.createDialog.passwordPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setCreateDialogOpen(false)}
            >
              {t('MikroTikBackupTab.common.cancel')}
            </Button>
            <Button
              onClick={() =>
                createMut.mutate({
                  name: createName.trim(),
                  password: createPassword.trim() || undefined,
                })
              }
              disabled={!createName.trim() || createMut.isPending}
            >
              {createMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikBackupTab.createDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Export config (.rsc) */}
      <Dialog
        open={exportDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setExportDialogOpen(false);
            setExportComment('');
            setExportEncrypted(false);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikBackupTab.exportDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikBackupTab.exportDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-export-comment">{t('MikroTikBackupTab.exportDialog.commentLabel')}</Label>
              <Input
                id="mtk-export-comment"
                value={exportComment}
                onChange={(e) => setExportComment(e.target.value)}
                placeholder={t('MikroTikBackupTab.exportDialog.commentPlaceholder')}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={exportEncrypted}
                onChange={(e) => setExportEncrypted(e.target.checked)}
              />
              {t('MikroTikBackupTab.exportDialog.encryptedLabel')}
            </label>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setExportDialogOpen(false)}
            >
              {t('MikroTikBackupTab.common.cancel')}
            </Button>
            <Button
              onClick={() =>
                exportMut.mutate({
                  comment: exportComment.trim(),
                  encrypted: exportEncrypted,
                })
              }
              disabled={exportMut.isPending}
            >
              {exportMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikBackupTab.exportDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Upload backup */}
      <Dialog
        open={uploadDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setUploadDialogOpen(false);
            setUploadName('');
            setUploadContent('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikBackupTab.uploadDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikBackupTab.uploadDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-upload-file">{t('MikroTikBackupTab.uploadDialog.chooseFileLabel')}</Label>
              <Input
                id="mtk-upload-file"
                type="file"
                accept=".rsc,.txt"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void handleFilePick(file);
                }}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-upload-name">{t('MikroTikBackupTab.uploadDialog.nameLabel')}</Label>
              <Input
                id="mtk-upload-name"
                value={uploadName}
                onChange={(e) => setUploadName(e.target.value)}
                placeholder={t('MikroTikBackupTab.uploadDialog.namePlaceholder')}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              {uploadContent
                ? t('MikroTikBackupTab.uploadDialog.charsLoaded', {
                    count: uploadContent.length,
                  })
                : t('MikroTikBackupTab.uploadDialog.noFileSelected')}
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setUploadDialogOpen(false)}
            >
              {t('MikroTikBackupTab.common.cancel')}
            </Button>
            <Button
              onClick={() =>
                uploadMut.mutate({
                  name: uploadName.trim(),
                  content: uploadContent,
                })
              }
              disabled={
                !uploadName.trim() ||
                !uploadContent ||
                uploadMut.isPending
              }
            >
              {uploadMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikBackupTab.uploadDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikBackupTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikBackupTab.deleteDialog.descriptionPrefix')}{' '}
              <span className="font-mono">
                {deleteTarget ? asStr(deleteTarget.name) : ''}
              </span>{' '}
              {t('MikroTikBackupTab.deleteDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikBackupTab.common.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteTarget &&
                deleteMut.mutate(asStr(deleteTarget.name))
              }
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikBackupTab.deleteDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Restore confirmation, type filename to confirm */}
      <Dialog
        open={restoreTarget !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRestoreTarget(null);
            setRestoreConfirmText('');
            setRestorePassword('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" /> {t('MikroTikBackupTab.restoreDialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikBackupTab.restoreDialog.descriptionPrefix')}{' '}
              <span className="font-mono">
                {restoreTarget ? asStr(restoreTarget.name) : ''}
              </span>{' '}
              {t('MikroTikBackupTab.restoreDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-restore-confirm">
                {t('MikroTikBackupTab.restoreDialog.confirmLabel')}
              </Label>
              <Input
                id="mtk-restore-confirm"
                autoComplete="off"
                spellCheck={false}
                value={restoreConfirmText}
                onChange={(e) => setRestoreConfirmText(e.target.value)}
                placeholder={restoreTarget ? asStr(restoreTarget.name) : ''}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-restore-password">
                {t('MikroTikBackupTab.restoreDialog.passwordLabel')}
              </Label>
              <Input
                id="mtk-restore-password"
                type="password"
                autoComplete="new-password"
                value={restorePassword}
                onChange={(e) => setRestorePassword(e.target.value)}
                placeholder={t('MikroTikBackupTab.restoreDialog.passwordPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRestoreTarget(null)}
            >
              {t('MikroTikBackupTab.common.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                restoreTarget &&
                restoreMut.mutate({
                  name: asStr(restoreTarget.name),
                  password: restorePassword.trim() || undefined,
                })
              }
              disabled={
                !restoreTarget ||
                restoreConfirmText !== asStr(restoreTarget.name) ||
                restoreMut.isPending
              }
            >
              {restoreMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikBackupTab.restoreDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
