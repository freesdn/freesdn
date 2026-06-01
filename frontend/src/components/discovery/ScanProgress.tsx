// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ScanProgress - Live scan progress display with phase indicators.
 */

import { useState, useEffect } from 'react';
import {
  Radar,
  CheckCircle,
  XCircle,
  StopCircle,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import type { ScanProgress as ScanProgressType } from '@/lib/api';

interface ScanProgressProps {
  progress: ScanProgressType;
  onCancel: () => void;
  onViewResults?: () => void;
}

const PHASE_LABEL_KEYS: Record<string, string> = {
  protocol_discovery: 'protocolDiscovery',
  port_scanning: 'portScanning',
  service_probing: 'serviceProbing',
  hostname_resolution: 'hostnameResolution',
};

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, '0')}`;
}

export default function ScanProgress({ progress, onCancel, onViewResults }: ScanProgressProps) {
  const { t } = useTranslation('common');
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (progress.status !== 'running') return;
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, [progress.status]);

  // Reset elapsed when a new scan starts
  useEffect(() => {
    if (progress.status === 'running') {
      setElapsed(progress.elapsed_seconds ?? 0);
    }
  }, [progress.scan_id, progress.status, progress.elapsed_seconds]);

  const getStatusIcon = () => {
    switch (progress.status) {
      case 'running':
        return <Radar className="h-5 w-5 text-primary animate-pulse" />;
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-emerald-500" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'cancelled':
        return <StopCircle className="h-5 w-5 text-amber-500" />;
      default:
        return <Loader2 className="h-5 w-5 animate-spin" />;
    }
  };

  const getStatusBadge = () => {
    const variants: Record<string, string> = {
      running: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      completed: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
      failed: 'bg-red-500/10 text-red-500 border-red-500/20',
      cancelled: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    };
    const statusLabels: Record<string, string> = {
      running: t('ScanProgress.status.running'),
      completed: t('ScanProgress.status.completed'),
      failed: t('ScanProgress.status.failed'),
      cancelled: t('ScanProgress.status.cancelled'),
    };
    return (
      <Badge
        variant="outline"
        className={cn('capitalize', variants[progress.status] || '')}
      >
        {statusLabels[progress.status] || progress.status}
      </Badge>
    );
  };

  const pct = progress.progress ?? progress.phase_progress ?? 0;
  const totalHosts = progress.total_hosts ?? 0;
  const scannedHosts = progress.hosts_scanned ?? progress.scanned_hosts ?? 0;
  const devicesFound = progress.devices_found ?? progress.discovered_hosts ?? 0;
  const devicesIdentified = progress.devices_identified ?? 0;

  return (
    <Card className="border-primary/30">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <CardTitle className="text-base">{t('ScanProgress.title')}</CardTitle>
          </div>
          {getStatusBadge()}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress bar */}
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {(PHASE_LABEL_KEYS[progress.current_phase || '']
                ? t(`ScanProgress.phases.${PHASE_LABEL_KEYS[progress.current_phase || '']}`)
                : progress.current_activity) || t('ScanProgress.scanning')}
            </span>
            <span>{Math.round(pct)}%</span>
          </div>
          <Progress value={pct} className="h-2" />
        </div>

        {/* Current activity */}
        {progress.current_activity && progress.status === 'running' && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>{progress.current_activity}</span>
          </div>
        )}

        {/* Stats grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <p className="text-2xl font-bold">{scannedHosts}</p>
            <p className="text-xs text-muted-foreground">
              {totalHosts > 0
                ? t('ScanProgress.stats.scannedOf', { total: totalHosts })
                : t('ScanProgress.stats.scanned')}
            </p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-emerald-500">{devicesFound}</p>
            <p className="text-xs text-muted-foreground">{t('ScanProgress.stats.found')}</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-500">{devicesIdentified}</p>
            <p className="text-xs text-muted-foreground">{t('ScanProgress.stats.identified')}</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold">{formatDuration(elapsed)}</p>
            <p className="text-xs text-muted-foreground">{t('ScanProgress.stats.elapsed')}</p>
          </div>
        </div>

        {/* Errors */}
        {progress.errors && progress.errors.length > 0 && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
            <p className="text-sm font-medium text-red-500 mb-1">
              {t('ScanProgress.errors.heading', { count: progress.errors.length })}
            </p>
            {progress.errors.slice(0, 5).map((err, i) => (
              <p key={i} className="text-xs text-red-400">{err}</p>
            ))}
            {progress.errors.length > 5 && (
              <p className="text-xs text-red-400">{t('ScanProgress.errors.more', { count: progress.errors.length - 5 })}</p>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3 pt-2">
          {progress.status === 'running' && (
            <Button variant="destructive" size="sm" onClick={onCancel}>
              {t('ScanProgress.actions.cancelScan')}
            </Button>
          )}
          {(progress.status === 'completed' || progress.status === 'cancelled') && onViewResults && (
            <Button size="sm" onClick={onViewResults}>
              {t('ScanProgress.actions.viewResults', { count: devicesFound })}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
