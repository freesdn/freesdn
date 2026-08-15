// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import {
  Signal,
  Clock,
  GitCompareArrows,
  AlertTriangle,
  Cpu,
  Download,
} from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { enterpriseApi, type DeviceHealthResponse } from '@/lib/api';
import { HealthGauge } from './HealthGauge';
import { ScoreBar } from './ScoreBar';

interface DeviceHealthDrawerProps {
  deviceId: string | null;
  deviceName?: string;
  siteName?: string;
  onClose: () => void;
}

export function DeviceHealthDrawer({ deviceId, deviceName, siteName, onClose }: DeviceHealthDrawerProps) {
  const { t } = useTranslation('enterprise');
  const { data: device, isLoading, isError } = useQuery<DeviceHealthResponse>({
    queryKey: ['health', 'device', deviceId],
    queryFn: () => enterpriseApi.getDeviceHealth(deviceId!).then((r) => r.data),
    enabled: !!deviceId,
  });

  // Backend emits ``{t: ISO, s: int}`` per ``services/enterprise.py:_record_score``.
  // The previous accessor read ``p.time / p.score`` and produced
  // ``Invalid Date`` x-axis labels + undefined y-axis values, the chart
  // looked empty for every device.
  const sparklineData = (device?.score_history ?? []).map((p) => ({
    time: new Date(p.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    score: p.s,
  }));

  return (
    <Sheet open={!!deviceId} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-md overflow-y-auto">
        <SheetHeader>
          <SheetTitle>{t('DeviceHealthDrawer.title')}</SheetTitle>
          <SheetDescription>
            {deviceName ?? (device ? device.device_id : t('DeviceHealthDrawer.loading'))}
          </SheetDescription>
        </SheetHeader>

        {isError && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive mt-4">
            {t('DeviceHealthDrawer.error')}
          </div>
        )}

        {isLoading && (
          <div className="space-y-4 mt-6">
            <Skeleton className="h-40 w-40 rounded-full mx-auto" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
            <Skeleton className="h-6" />
          </div>
        )}

        {device && !isLoading && (
          <div className="space-y-6 mt-6">
            {/* Device info */}
            <div className="space-y-1 text-sm">
              <p className="font-medium text-foreground">{deviceName ?? device.device_id}</p>
              <p className="text-muted-foreground">{t('DeviceHealthDrawer.site')}: {siteName ?? device.site_id ?? t('DeviceHealthDrawer.notAvailable')}</p>
            </div>

            {/* Large gauge */}
            <div className="flex justify-center">
              <HealthGauge score={Math.round(device.health_score)} size="lg" />
            </div>

            {/* Component scores */}
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-foreground">{t('DeviceHealthDrawer.componentScores')}</h4>
              <ScoreBar label={t('DeviceHealthDrawer.scores.reachability')} score={device.reachability_score} icon={Signal} />
              <ScoreBar label={t('DeviceHealthDrawer.scores.latency')} score={device.latency_score} icon={Clock} />
              <ScoreBar label={t('DeviceHealthDrawer.scores.configDrift')} score={device.drift_score} icon={GitCompareArrows} />
              <ScoreBar label={t('DeviceHealthDrawer.scores.errorRate')} score={device.error_score} icon={AlertTriangle} />
              <ScoreBar label={t('DeviceHealthDrawer.scores.utilization')} score={device.utilization_score} icon={Cpu} />
              <ScoreBar label={t('DeviceHealthDrawer.scores.firmware')} score={device.firmware_score} icon={Download} />
            </div>

            {/* Score history sparkline */}
            {sparklineData.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-foreground">{t('DeviceHealthDrawer.scoreHistory')}</h4>
                <div className="h-[150px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 5, right: 5, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="drawerGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                          <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.05} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" tick={{ fontSize: 10 }} className="text-muted-foreground" />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} width={30} className="text-muted-foreground" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: 'hsl(var(--card))',
                          border: '1px solid hsl(var(--border))',
                          borderRadius: '0.5rem',
                          fontSize: '0.75rem',
                        }}
                        formatter={(value) => [`${Number(value)}`, t('DeviceHealthDrawer.scoreLabel')]}
                      />
                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#3b82f6"
                        strokeWidth={1.5}
                        fill="url(#drawerGradient)"
                        animationDuration={600}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Last updated, backend column is ``updated_at``; the
                previous ``last_computed_at`` never existed on the wire,
                so this line never rendered. */}
            {device.updated_at && (
              <p className="text-xs text-muted-foreground">
                {t('DeviceHealthDrawer.lastUpdated')}:{' '}
                {new Date(device.updated_at).toLocaleString([], {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </p>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
