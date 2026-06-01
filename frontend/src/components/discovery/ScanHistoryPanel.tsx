// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ScanHistoryPanel - List of recent scans with status and statistics.
 */

import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import {
  History,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  Radar,
  ChevronRight,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { discoveryApi, type ScanHistoryItem } from '@/lib/api';

interface ScanHistoryPanelProps {
  onViewScan?: (scanId: string) => void;
}

const STATUS_CONFIG: Record<string, { icon: React.ElementType; color: string; labelKey: string }> = {
  completed: { icon: CheckCircle2, color: 'text-green-500', labelKey: 'status.completed' },
  running: { icon: Loader2, color: 'text-blue-500', labelKey: 'status.running' },
  failed: { icon: XCircle, color: 'text-destructive', labelKey: 'status.failed' },
  cancelled: { icon: XCircle, color: 'text-muted-foreground', labelKey: 'status.cancelled' },
  pending: { icon: Clock, color: 'text-yellow-500', labelKey: 'status.pending' },
};

function formatRelativeTime(dateStr: string, t: TFunction): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return t('ScanHistoryPanel.time.justNow');
  if (mins < 60) return t('ScanHistoryPanel.time.minutesAgo', { count: mins });
  const hours = Math.floor(mins / 60);
  if (hours < 24) return t('ScanHistoryPanel.time.hoursAgo', { count: hours });
  const days = Math.floor(hours / 24);
  return t('ScanHistoryPanel.time.daysAgo', { count: days });
}

export default function ScanHistoryPanel({ onViewScan }: ScanHistoryPanelProps) {
  const { t } = useTranslation('common');
  const { data: history = [], isLoading } = useQuery({
    queryKey: ['discovery', 'scan-history'],
    queryFn: async () => {
      const res = await discoveryApi.getScanHistory();
      return res.data;
    },
    refetchInterval: 10000,
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <History className="h-4 w-4 text-primary" />
          {t('ScanHistoryPanel.title')}
          {history.length > 0 && (
            <Badge variant="secondary" className="text-[10px] ml-auto">{history.length}</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <Radar className="h-8 w-8 mb-2 opacity-50" />
            <p className="text-sm">{t('ScanHistoryPanel.empty.title')}</p>
            <p className="text-xs">{t('ScanHistoryPanel.empty.description')}</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {history.map((scan: ScanHistoryItem) => {
              const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
              const StatusIcon = cfg.icon;

              return (
                <div
                  key={scan.scan_id || scan.id}
                  className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted/30 transition-colors cursor-pointer"
                  onClick={() => onViewScan?.(scan.scan_id || scan.id || '')}
                >
                  <StatusIcon
                    className={cn(
                      'h-4 w-4 shrink-0',
                      cfg.color,
                      scan.status === 'running' && 'animate-spin',
                    )}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-sm font-medium truncate">
                        {scan.scan_type === 'controller'
                          ? t('ScanHistoryPanel.scanType.controller')
                          : t('ScanHistoryPanel.scanType.network')}
                      </span>
                      <Badge variant="outline" className="text-[10px]">{t(`ScanHistoryPanel.${cfg.labelKey}`)}</Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      {scan.targets && (
                        <span className="truncate font-mono">
                          {Array.isArray(scan.targets) ? scan.targets[0] : scan.targets}
                          {Array.isArray(scan.targets) && scan.targets.length > 1
                            ? ` +${scan.targets.length - 1}`
                            : ''}
                        </span>
                      )}
                      {scan.total_discovered != null && (
                        <span>{t('ScanHistoryPanel.devicesCount', { count: scan.total_discovered })}</span>
                      )}
                      {scan.started_at && (
                        <span>{formatRelativeTime(scan.started_at, t)}</span>
                      )}
                    </div>
                    {scan.status === 'running' && scan.progress != null && (
                      <div className="mt-1.5 h-1 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                    )}
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
