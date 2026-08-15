// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AgentReleasesPage, admin UI for managing agent binary releases.
 *
 * Uploads land in the backend's release directory. The frontend
 * deliberately does NOT compute SHA-256 itself, the backend does that
 * during the streaming upload so the checksum can't drift from the
 * served bytes.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getApiErrorMessage } from '@/lib/api';
import { safeOpen } from '@/lib/utils';
import {
  Download,
  Upload,
  Star,
  Trash2,
  RefreshCw,
  Package,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { agentReleasesApi, type AgentReleaseDetail } from '@/lib/api/agents';
import { useToast } from '@/hooks/use-toast';

function _formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

interface UploadForm {
  file: File | null;
  version: string;
  platform: string;
  agent_type: string;
  release_notes: string;
  is_prerelease: boolean;
}

const EMPTY_UPLOAD: UploadForm = {
  file: null,
  version: '',
  platform: 'windows',
  agent_type: 'daemon',
  release_notes: '',
  is_prerelease: false,
};

export function AgentReleasesPage() {
  const { t } = useTranslation('agents');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState<UploadForm>(EMPTY_UPLOAD);
  const [uploadProgress, setUploadProgress] = useState(0);

  const { data: releases = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['agent-releases'],
    queryFn: async () => {
      const resp = await agentReleasesApi.list();
      return resp.data;
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: UploadForm) => {
      if (!data.file) throw new Error('No file selected');
      const fd = new FormData();
      fd.append('file', data.file);
      fd.append('version', data.version);
      fd.append('platform', data.platform);
      fd.append('agent_type', data.agent_type);
      fd.append('release_notes', data.release_notes);
      fd.append('is_prerelease', data.is_prerelease ? 'true' : 'false');
      fd.append('is_latest', 'true');
      return agentReleasesApi.upload(fd, (e: any) => {
        if (e?.total) setUploadProgress(Math.round((e.loaded / e.total) * 100));
      });
    },
    onSuccess: (resp) => {
      toast({
        title: t('AgentReleasesPage.toasts.uploaded.title'),
        description: t('AgentReleasesPage.toasts.uploaded.description', {
          version: resp.data.version,
          platform: resp.data.platform,
          type: resp.data.agent_type,
        }),
      });
      setDialogOpen(false);
      setForm(EMPTY_UPLOAD);
      setUploadProgress(0);
      queryClient.invalidateQueries({ queryKey: ['agent-releases'] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('AgentReleasesPage.toasts.uploadFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
      setUploadProgress(0);
    },
  });

  const promoteMutation = useMutation({
    mutationFn: (id: string) => agentReleasesApi.promote(id),
    onSuccess: (resp) => {
      toast({
        title: t('AgentReleasesPage.toasts.promoted.title'),
        description: t('AgentReleasesPage.toasts.promoted.description', {
          version: resp.data.version,
          platform: resp.data.platform,
          type: resp.data.agent_type,
        }),
      });
      queryClient.invalidateQueries({ queryKey: ['agent-releases'] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => agentReleasesApi.remove(id),
    onSuccess: () => {
      toast({ title: t('AgentReleasesPage.toasts.deleted.title') });
      queryClient.invalidateQueries({ queryKey: ['agent-releases'] });
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('AgentReleasesPage.header.title')}
        description={t('AgentReleasesPage.header.description')}
        icon={Package}
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              {t('AgentReleasesPage.card.title')}
              <Badge variant="secondary">{releases.length}</Badge>
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                <RefreshCw className="h-4 w-4" />
              </Button>
              <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                <DialogTrigger asChild>
                  <Button size="sm">
                    <Upload className="h-4 w-4 mr-1" />
                    {t('AgentReleasesPage.actions.uploadRelease')}
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>{t('AgentReleasesPage.dialog.title')}</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-3 pt-2">
                    <div>
                      <Label>{t('AgentReleasesPage.form.binaryFile')}</Label>
                      <Input
                        type="file"
                        onChange={(e) =>
                          setForm({
                            ...form,
                            file: e.target.files?.[0] ?? null,
                          })
                        }
                      />
                      {form.file ? (
                        <div className="text-xs text-muted-foreground mt-1">
                          {form.file.name} ({_formatBytes(form.file.size)})
                        </div>
                      ) : null}
                    </div>
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <Label>{t('AgentReleasesPage.form.version')}</Label>
                        <Input
                          placeholder="1.0.1"
                          value={form.version}
                          onChange={(e) =>
                            setForm({ ...form, version: e.target.value })
                          }
                        />
                      </div>
                      <div>
                        <Label>{t('AgentReleasesPage.form.platform')}</Label>
                        <Select
                          value={form.platform}
                          onValueChange={(v) =>
                            setForm({ ...form, platform: v })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="windows">windows</SelectItem>
                            <SelectItem value="linux">linux</SelectItem>
                            <SelectItem value="macos">macos</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label>{t('AgentReleasesPage.form.type')}</Label>
                        <Select
                          value={form.agent_type}
                          onValueChange={(v) =>
                            setForm({ ...form, agent_type: v })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="daemon">daemon</SelectItem>
                            <SelectItem value="desktop">desktop</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div>
                      <Label>{t('AgentReleasesPage.form.releaseNotes')}</Label>
                      <Textarea
                        rows={4}
                        placeholder={t('AgentReleasesPage.form.releaseNotesPlaceholder')}
                        value={form.release_notes}
                        onChange={(e) =>
                          setForm({ ...form, release_notes: e.target.value })
                        }
                      />
                    </div>
                    <label className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={form.is_prerelease}
                        onChange={(e) =>
                          setForm({ ...form, is_prerelease: e.target.checked })
                        }
                      />
                      {t('AgentReleasesPage.form.markPrerelease')}
                    </label>
                    {uploadProgress > 0 ? (
                      <div className="text-xs text-muted-foreground">
                        {t('AgentReleasesPage.form.uploadingProgress', { percent: uploadProgress })}
                      </div>
                    ) : null}
                  </div>
                  <DialogFooter>
                    <Button
                      variant="outline"
                      onClick={() => setDialogOpen(false)}
                    >
                      {t('AgentReleasesPage.actions.cancel')}
                    </Button>
                    <Button
                      onClick={() => uploadMutation.mutate(form)}
                      disabled={
                        !form.file ||
                        !form.version.trim() ||
                        uploadMutation.isPending
                      }
                    >
                      {uploadMutation.isPending
                        ? t('AgentReleasesPage.actions.uploading')
                        : t('AgentReleasesPage.actions.uploadPublish')}
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isError ? (
            <div className="text-sm text-destructive p-4">
              {t('AgentReleasesPage.states.error')}
            </div>
          ) : isLoading ? (
            <div className="text-sm text-muted-foreground p-4">{t('AgentReleasesPage.states.loading')}</div>
          ) : releases.length === 0 ? (
            <div className="text-sm text-muted-foreground p-4">
              {t('AgentReleasesPage.states.empty')}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('AgentReleasesPage.table.version')}</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.platform')}</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.type')}</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.size')}</TableHead>
                  <TableHead>SHA-256</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.downloads')}</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.status')}</TableHead>
                  <TableHead>{t('AgentReleasesPage.table.published')}</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {releases.map((r: AgentReleaseDetail) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-mono font-medium">
                      {r.version}
                    </TableCell>
                    <TableCell>{r.platform}</TableCell>
                    <TableCell>{r.agent_type}</TableCell>
                    <TableCell className="text-xs tabular-nums">
                      {_formatBytes(r.file_size)}
                    </TableCell>
                    <TableCell
                      className="font-mono text-xs"
                      title={r.checksum_sha256}
                    >
                      {r.checksum_sha256.slice(0, 12)}…
                    </TableCell>
                    <TableCell className="text-xs tabular-nums">
                      {r.download_count}
                    </TableCell>
                    <TableCell>
                      {r.is_latest ? (
                        <Badge variant="secondary" className="text-xs">
                          <Star className="h-3 w-3 mr-1" />
                          {t('AgentReleasesPage.badges.latest')}
                        </Badge>
                      ) : null}
                      {r.is_prerelease ? (
                        <Badge variant="outline" className="text-xs ml-1">
                          {t('AgentReleasesPage.badges.prerelease')}
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(r.published_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        title={t('AgentReleasesPage.rowActions.download')}
                        onClick={() => {
                          safeOpen(r.download_url);
                        }}
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                      {!r.is_latest ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          title={t('AgentReleasesPage.rowActions.markLatest')}
                          onClick={() => promoteMutation.mutate(r.id)}
                        >
                          <Star className="h-4 w-4" />
                        </Button>
                      ) : null}
                      <Button
                        variant="ghost"
                        size="icon"
                        title={t('AgentReleasesPage.rowActions.delete')}
                        onClick={() => {
                          if (
                            confirm(
                              t('AgentReleasesPage.confirm.delete', {
                                version: r.version,
                                platform: r.platform,
                                type: r.agent_type,
                              })
                            )
                          ) {
                            deleteMutation.mutate(r.id);
                          }
                        }}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default AgentReleasesPage;
