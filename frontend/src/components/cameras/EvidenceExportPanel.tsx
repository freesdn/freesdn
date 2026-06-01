// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Download,
  FileArchive,
  Loader2,
  ShieldCheck,
  Trash2,
} from 'lucide-react';

import { evidenceApi, getApiErrorMessage, type EvidenceArchive } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';

const DURATIONS = [
  { v: 30, label: '30s' },
  { v: 60, label: '1m' },
  { v: 300, label: '5m' },
  { v: 900, label: '15m' },
  { v: 1800, label: '30m' },
  { v: 3600, label: '1h' },
];

/** Format an epoch-ms instant for a <input type="datetime-local"> (local clock). */
function toLocalInput(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}`;
}

/**
 * Batch evidence export for the multi-playback grid: place the SAME recorded
 * window on legal hold for every camera in the grid at once. Each camera gets
 * its own sealed, SHA-256-hashed clip (chain-of-custody); ready clips can be
 * pulled individually or as one ZIP bundle with a manifest.
 */
export function EvidenceExportPanel({
  cameraIds,
  playheadMs,
}: {
  cameraIds: string[];
  playheadMs: number;
}) {
  const { t } = useTranslation('cameras');
  const qc = useQueryClient();
  const { toast } = useToast();

  const [open, setOpen] = useState(false);
  const [startInput, setStartInput] = useState('');
  const [durationSec, setDurationSec] = useState(60);
  const [watermark, setWatermark] = useState(true);

  // Seed the start field from the playhead the first time the panel opens.
  useEffect(() => {
    if (open && !startInput && playheadMs) setStartInput(toLocalInput(playheadMs));
  }, [open, playheadMs, startInput]);

  const { data: holds } = useQuery({
    queryKey: ['evidence', 'all'],
    queryFn: () => evidenceApi.list().then((r) => r.data.items),
    refetchInterval: 10_000,
    enabled: open,
  });
  const gridHolds = (holds ?? []).filter((h) => cameraIds.includes(h.camera_id));
  const readyIds = gridHolds.filter((h) => h.status === 'ready').map((h) => h.id);

  const startMs = startInput ? new Date(startInput).getTime() : 0;
  const endMs = startMs + durationSec * 1000;
  const valid = cameraIds.length > 0 && startMs > 0 && durationSec > 0;

  const batchMut = useMutation({
    mutationFn: () =>
      evidenceApi.createBatch({
        camera_ids: cameraIds,
        start_time: new Date(startMs).toISOString(),
        end_time: new Date(endMs).toISOString(),
        watermark,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['evidence'] });
      toast({ title: t('MultiPlaybackPage.evidence.held', { count: res.data.items.length }) });
    },
    onError: (err) =>
      toast({
        title: t('MultiPlaybackPage.evidence.failed'),
        description: getApiErrorMessage(err, ''),
        variant: 'destructive',
      }),
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => evidenceApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['evidence'] }),
    // Surface 409 (still archiving) / 403 (role downgraded) instead of a
    // silent no-op, mirrors batchMut's onError.
    onError: (err) =>
      toast({
        title: t('MultiPlaybackPage.evidence.releaseFailed'),
        description: getApiErrorMessage(err, ''),
        variant: 'destructive',
      }),
  });

  return (
    <div className="rounded-lg border bg-card">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-sm font-medium"
      >
        <ShieldCheck className="h-4 w-4 text-primary" />
        {t('MultiPlaybackPage.evidence.title')}
        <span className="ml-auto text-xs text-muted-foreground">
          {cameraIds.length} {t('MultiPlaybackPage.evidence.camerasInGrid')}
        </span>
      </button>

      {open && (
        <div className="space-y-3 border-t px-3 py-3">
          {/* Window controls */}
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-medium text-muted-foreground">
                {t('MultiPlaybackPage.evidence.start')}
              </label>
              <Input
                type="datetime-local"
                value={startInput}
                onChange={(e) => setStartInput(e.target.value)}
                className="h-8 w-52 text-xs"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-medium text-muted-foreground">
                {t('MultiPlaybackPage.evidence.duration')}
              </label>
              <select
                value={durationSec}
                onChange={(e) => setDurationSec(Number(e.target.value))}
                className="h-8 rounded-md border bg-background px-2 text-xs"
              >
                {DURATIONS.map((d) => (
                  <option key={d.v} value={d.v}>
                    {d.label}
                  </option>
                ))}
              </select>
            </div>
            <label className="flex items-center gap-1.5 pb-1.5 text-xs text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={watermark}
                onChange={(e) => setWatermark(e.target.checked)}
                className="h-3.5 w-3.5 accent-primary"
              />
              {t('MultiPlaybackPage.evidence.watermark')}
            </label>
            <Button
              size="sm"
              disabled={!valid || batchMut.isPending}
              onClick={() => batchMut.mutate()}
              className="gap-1.5"
            >
              {batchMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
              {t('MultiPlaybackPage.evidence.holdN', { count: cameraIds.length })}
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground">
            {t('MultiPlaybackPage.evidence.hint')}
          </p>

          {/* Holds for the cameras in this grid */}
          {gridHolds.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium">
                  {t('MultiPlaybackPage.evidence.holdsTitle')}
                </span>
                {readyIds.length > 1 && (
                  <a href={evidenceApi.bundleUrl(readyIds)}>
                    <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs">
                      <FileArchive className="h-3.5 w-3.5" />
                      {t('MultiPlaybackPage.evidence.downloadBundle', { count: readyIds.length })}
                    </Button>
                  </a>
                )}
              </div>
              <div className="divide-y rounded-md border">
                {gridHolds.map((h: EvidenceArchive) => (
                  <div key={h.id} className="flex items-center justify-between gap-2 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-xs font-medium">{h.camera_name}</div>
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                        {h.status === 'ready' ? (
                          <span className="inline-flex items-center gap-1 text-green-600">
                            <ShieldCheck className="h-3 w-3" />
                            {t('CameraDetailPage.recordings.evidence.statusReady')}
                          </span>
                        ) : h.status === 'failed' ? (
                          <span className="text-destructive">
                            {t('CameraDetailPage.recordings.evidence.statusFailed')}
                            {h.error ? `: ${h.error}` : ''}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            {t('CameraDetailPage.recordings.evidence.statusArchiving')}
                          </span>
                        )}
                        {h.file_size ? <span>· {(h.file_size / 1024 / 1024).toFixed(1)} MB</span> : null}
                      </div>
                      {h.sha256 && (
                        <div className="truncate font-mono text-[10px] text-muted-foreground" title={h.sha256}>
                          SHA-256 {h.sha256}
                        </div>
                      )}
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      {h.status === 'ready' && (
                        <a
                          href={evidenceApi.downloadUrl(h.id)}
                          title={t('CameraDetailPage.recordings.evidence.download')}
                        >
                          <Button variant="ghost" size="icon" className="h-7 w-7">
                            <Download className="h-3.5 w-3.5" />
                          </Button>
                        </a>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive"
                        title={t('CameraDetailPage.recordings.evidence.release')}
                        disabled={deleteMut.isPending}
                        onClick={() => {
                          if (window.confirm(t('CameraDetailPage.recordings.evidence.confirmRelease'))) {
                            deleteMut.mutate(h.id);
                          }
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
