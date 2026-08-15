// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Voicemail Inbox Page
 *
 * Voicemail list with read/unread, play, download, delete.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSiteStore } from '@/stores/siteStore';
import {
  Voicemail, Download, Trash2, CheckCircle, Mail,
  MailOpen, Clock, AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { voipApi } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { formatDuration, formatTimeAgo } from './components';
import type { VoicemailMessage } from './types';

export default function VoicemailPage() {
  const { t } = useTranslation('voip');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries ──

  const { data: vmRes, isLoading, isError: vmError, refetch } = useQuery({
    queryKey: ['voip-voicemails', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getVoicemails({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
  });

  const voicemails: VoicemailMessage[] = vmRes?.data?.items ?? vmRes?.data ?? [];

  const { data: statsRes, isError: statsError } = useQuery({
    queryKey: ['voip-voicemail-stats', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getVoicemailStats(selectedSiteId ? { site_id: selectedSiteId } : undefined),
    refetchInterval: 30_000,
  });

  const stats = statsRes?.data ?? {
    total: voicemails.length,
    unread: voicemails.filter((v) => !v.is_read).length,
    urgent: 0,
  };

  // ── Mutations ──

  const markReadMutation = useMutation({
    mutationFn: (id: string) => voipApi.markVoicemailRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-voicemails'] });
      queryClient.invalidateQueries({ queryKey: ['voip-voicemail-stats'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.markReadFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => voipApi.deleteVoicemail(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-voicemails'] });
      queryClient.invalidateQueries({ queryKey: ['voip-voicemail-stats'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => toast({ title: t('VoIPPage.toasts.deleteVoicemailFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // NOTE: playable audio is not available yet. The backend only stores the
  // voicemail's spool PATH on the remote PBX (VoicemailMessage.file_path),
  // a string on the PBX host's filesystem that FreeSDN can neither read nor
  // serve. No FreePBX/Asterisk adapter method exposes the recording bytes
  // over its API. Rather than hand the user a broken filesystem path that
  // resolves to a same-origin 404, the Download button is disabled with an
  // explanatory tooltip until a real retrieval path lands (see below). When
  // an adapter download method + a streaming GET /voicemails/{id}/audio
  // endpoint exist, re-enable the button and point it at that endpoint.

  // ── Columns ──

  const columns: DataTableColumn<VoicemailMessage>[] = [
    {
      id: 'status',
      header: '',
      cell: (row) => row.is_read
        ? <MailOpen className="h-4 w-4 text-muted-foreground" />
        : <Mail className="h-4 w-4 text-blue-500" />,
    },
    {
      id: 'caller',
      header: t('VoicemailPage.columns.from'),
      cell: (row) => (
        <div>
          <p className={`text-sm ${!row.is_read ? 'font-semibold' : 'font-medium'}`}>
            {row.caller_name || row.caller_id || t('VoicemailPage.unknown')}
          </p>
          {row.caller_name && row.caller_id && (
            <p className="text-xs text-muted-foreground font-mono">{row.caller_id}</p>
          )}
        </div>
      ),
    },
    {
      id: 'mailbox',
      header: t('VoicemailPage.columns.mailbox'),
      cell: (row) => <span className="text-sm font-mono">{row.extension_number || row.mailbox || row.extension || '-'}</span>,
    },
    {
      id: 'duration',
      header: t('VoicemailPage.columns.duration'),
      cell: (row) => <span className="text-sm font-mono">{formatDuration(row.duration)}</span>,
    },
    {
      id: 'date',
      header: t('VoicemailPage.columns.date'),
      cell: (row) => {
        const ts = row.message_date || row.created_at;
        return (
          <div className="text-xs">
            <p>{ts ? new Date(ts).toLocaleDateString() : '-'}</p>
            <p className="text-muted-foreground">{formatTimeAgo(ts)}</p>
          </div>
        );
      },
    },
    {
      id: 'urgent',
      header: '',
      cell: (row) => row.is_urgent
        ? <Badge className="bg-red-500/20 text-red-600 border-red-500/30 text-xs">{t('VoicemailPage.urgent')}</Badge>
        : null,
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <div className="flex items-center gap-1">
          {!row.is_read && (
            <Button variant="ghost" size="icon" className="h-7 w-7" title={t('VoicemailPage.actions.markRead')}
              onClick={() => markReadMutation.mutate(row.id)}>
              <CheckCircle className="h-3.5 w-3.5" />
            </Button>
          )}
          {/* Audio retrieval is not yet wired, the recording lives only on
              the remote PBX spool, which FreeSDN cannot read or serve. Keep
              the affordance visible but disabled + explained so we never hand
              the user a broken path. */}
          <Button variant="ghost" size="icon" className="h-7 w-7" disabled
            title={t('VoicemailPage.actions.downloadUnavailable')}>
            <Download className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" title={t('VoicemailPage.actions.delete')}
            onClick={() => {
              if (window.confirm(t('VoIPPage.confirm.deleteVoicemail'))) {
                deleteMutation.mutate(row.id);
              }
            }}>
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Voicemail}
        title={t('VoicemailPage.title')}
        subtitle={t('VoicemailPage.subtitle', { total: stats.total, unread: stats.unread })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
      />

      {(vmError || statsError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('VoicemailPage.dataLoadError')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg"><Voicemail className="h-5 w-5 text-primary" /></div>
              <div>
                <p className="text-2xl font-bold">{stats.total}</p>
                <p className="text-xs text-muted-foreground">{t('VoicemailPage.stats.totalMessages')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/10 rounded-lg"><Mail className="h-5 w-5 text-blue-500" /></div>
              <div>
                <p className="text-2xl font-bold">{stats.unread}</p>
                <p className="text-xs text-muted-foreground">{t('VoicemailPage.stats.unread')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/10 rounded-lg"><Clock className="h-5 w-5 text-red-500" /></div>
              <div>
                <p className="text-2xl font-bold">{stats.urgent ?? 0}</p>
                <p className="text-xs text-muted-foreground">{t('VoicemailPage.stats.urgent')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Table */}
      <DataTable
        data={voicemails}
        columns={columns}
        isLoading={isLoading}
        searchable
        itemName={t('VoicemailPage.itemName')}
        paginated
        defaultPageSize={20}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Voicemail className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('VoicemailPage.empty')}</p>
          </div>
        }
      />
    </div>
  );
}
