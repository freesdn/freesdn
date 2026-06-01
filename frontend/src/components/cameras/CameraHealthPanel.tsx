// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Activity,
  Clock,
  Film,
  Gauge,
  MonitorPlay,
  Wifi,
  WifiOff,
} from "lucide-react";
import { camerasApi } from "@/lib/api";
import type { CameraHealthData } from "@/lib/api";
import { cn } from "@/lib/utils";

interface CameraHealthPanelProps {
  cameraId: string;
}

// ---------------------------------------------------------------------------
// Sparkline, renders last `maxPoints` bitrate values as an SVG polyline
// ---------------------------------------------------------------------------

let sparklineIdCounter = 0;

function BitrateSparkline({ snapshots }: { snapshots: CameraHealthData[] }) {
  const { t } = useTranslation("common");
  const gradientId = useMemo(() => `sparkFill-${++sparklineIdCounter}`, []);
  const maxPoints = 50;
  const points = snapshots
    .slice(-maxPoints)
    .map((s) => s.bitrate_kbps ?? 0);

  if (points.length < 2) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("CameraHealthPanel.chart.notEnoughData")}
      </p>
    );
  }

  const width = 600;
  const height = 120;
  const padX = 4;
  const padY = 8;

  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;

  const coords = points.map((v, i) => {
    const x = padX + (i / (points.length - 1)) * (width - padX * 2);
    const y = padY + (1 - (v - min) / range) * (height - padY * 2);
    return `${x},${y}`;
  });

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-[120px]"
      preserveAspectRatio="none"
    >
      {/* gradient fill beneath the line */}
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.25} />
          <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
        </linearGradient>
      </defs>

      {/* area fill */}
      <polygon
        points={`${padX},${height - padY} ${coords.join(" ")} ${
          padX + ((points.length - 1) / (points.length - 1)) * (width - padX * 2)
        },${height - padY}`}
        fill={`url(#${gradientId})`}
      />

      {/* line */}
      <polyline
        points={coords.join(" ")}
        fill="none"
        stroke="hsl(var(--primary))"
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Stat card
// ---------------------------------------------------------------------------

function StatCard({
  label,
  value,
  icon: Icon,
  className,
}: {
  label: string;
  value: React.ReactNode;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  className?: string;
}) {
  return (
    <Card
      className={cn(
        "bg-card/60 border-border/40 backdrop-blur-sm",
        className,
      )}
    >
      <CardContent noOffset className="flex items-center gap-3 p-4">
        <div className="rounded-md bg-muted/50 p-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className="text-sm font-semibold leading-none">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

function HealthSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="bg-card/60 border-border/40">
            <CardContent noOffset className="flex items-center gap-3 p-4">
              <Skeleton className="h-8 w-8 rounded-md" />
              <div className="space-y-1.5">
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-4 w-20" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card className="bg-card/60 border-border/40">
        <CardHeader>
          <Skeleton className="h-5 w-40" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[120px] w-full rounded-md" />
        </CardContent>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBitrate(kbps: number | null): string {
  if (kbps == null) return "-";
  return `${kbps.toLocaleString()} kbps`;
}

function formatFrameRate(fps: number | null): string {
  if (fps == null) return "-";
  return `${fps} fps`;
}

function formatResolution(w: number | null, h: number | null): string {
  if (w == null || h == null) return "-";
  return `${w}\u00D7${h}`;
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Status Timeline · shows online/offline segments over 24h
// ---------------------------------------------------------------------------

function StatusTimeline({ snapshots }: { snapshots: CameraHealthData[] }) {
  const { t } = useTranslation("common");
  if (snapshots.length < 2) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("CameraHealthPanel.timeline.notEnoughData")}
      </p>
    );
  }

  // Bucket snapshots into 15-minute intervals (96 buckets for 24h)
  const now = Date.now();
  const bucketCount = 96;
  const bucketMs = (24 * 60 * 60 * 1000) / bucketCount;
  const startMs = now - 24 * 60 * 60 * 1000;

  // Initialize buckets as null (no data)
  const buckets: (boolean | null)[] = new Array(bucketCount).fill(null);

  // Fill buckets based on snapshot data
  for (const snap of snapshots) {
    try {
      const t = new Date(snap.captured_at).getTime();
      const idx = Math.floor((t - startMs) / bucketMs);
      if (idx >= 0 && idx < bucketCount) {
        buckets[idx] = snap.is_online;
      }
    } catch { /* skip invalid timestamps */ }
  }

  return (
    <div className="space-y-2">
      <div className="flex h-6 rounded-md overflow-hidden border border-border/40">
        {buckets.map((isOnline, i) => {
          const bucketStart = new Date(startMs + i * bucketMs);
          const bucketEnd = new Date(startMs + (i + 1) * bucketMs);
          const timeLabel = `${bucketStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}, ${bucketEnd.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

          return (
            <div
              key={i}
              className={cn(
                'flex-1 transition-colors',
                isOnline === true && 'bg-emerald-500/60 hover:bg-emerald-500/80',
                isOnline === false && 'bg-red-500/60 hover:bg-red-500/80',
                isOnline === null && 'bg-muted/30 hover:bg-muted/50',
              )}
              title={`${timeLabel}: ${isOnline === true ? t("CameraHealthPanel.status.online") : isOnline === false ? t("CameraHealthPanel.status.offline") : t("CameraHealthPanel.status.noData")}`}
            />
          );
        })}
      </div>

      {/* Time labels */}
      <div className="flex justify-between text-[9px] text-muted-foreground/60">
        <span>{new Date(startMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        <span>{new Date(startMs + 6 * 60 * 60 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        <span>{new Date(startMs + 12 * 60 * 60 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        <span>{new Date(startMs + 18 * 60 * 60 * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        <span>{t("CameraHealthPanel.timeline.now")}</span>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="h-2 w-4 rounded-sm bg-emerald-500/60" /> {t("CameraHealthPanel.status.online")}
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-4 rounded-sm bg-red-500/60" /> {t("CameraHealthPanel.status.offline")}
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-4 rounded-sm bg-muted/30 border border-border/30" /> {t("CameraHealthPanel.status.noData")}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

function CameraHealthPanel({ cameraId }: CameraHealthPanelProps) {
  const { t } = useTranslation("common");
  const {
    data: healthData,
    isLoading: healthLoading,
    isError: healthError,
  } = useQuery({
    queryKey: ["camera-health", cameraId],
    queryFn: () => camerasApi.getHealth(cameraId),
    refetchInterval: 30_000,
    enabled: !!cameraId,
  });

  const {
    data: historyData,
    isLoading: historyLoading,
    isError: historyError,
  } = useQuery({
    queryKey: ["camera-health-history", cameraId],
    queryFn: () => camerasApi.getHealthHistory(cameraId, 24),
    enabled: !!cameraId,
    staleTime: 60_000,
    refetchInterval: 120_000,
  });

  if (healthLoading) return <HealthSkeleton />;

  if (healthError || !healthData) {
    return (
      <Card className="bg-card/60 border-border/40">
        <CardContent noOffset className="p-6 text-center text-sm text-muted-foreground">
          {t("CameraHealthPanel.errors.loadHealth")}
        </CardContent>
      </Card>
    );
  }

  const health = healthData.data;

  return (
    <div className="space-y-6">
      {/* ---- Live metric cards ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {/* Status */}
        <Card className="bg-card/60 border-border/40 backdrop-blur-sm">
          <CardContent noOffset className="flex items-center gap-3 p-4">
            <div className="rounded-md bg-muted/50 p-2">
              {health.is_online ? (
                <Wifi className="h-4 w-4 text-emerald-500" />
              ) : (
                <WifiOff className="h-4 w-4 text-red-500" />
              )}
            </div>
            <div className="space-y-0.5">
              <p className="text-xs text-muted-foreground">{t("CameraHealthPanel.stats.status")}</p>
              <Badge
                variant={health.is_online ? "default" : "destructive"}
                className={cn(
                  "text-xs",
                  health.is_online &&
                    "bg-emerald-500/15 text-emerald-500 hover:bg-emerald-500/25 border-emerald-500/30",
                )}
              >
                {health.is_online ? t("CameraHealthPanel.status.online") : t("CameraHealthPanel.status.offline")}
              </Badge>
            </div>
          </CardContent>
        </Card>

        {/* Bitrate */}
        <StatCard
          label={t("CameraHealthPanel.stats.bitrate")}
          value={formatBitrate(health.bitrate_kbps)}
          icon={Gauge}
        />

        {/* Frame Rate */}
        <StatCard
          label={t("CameraHealthPanel.stats.frameRate")}
          value={formatFrameRate(health.frame_rate)}
          icon={Activity}
        />

        {/* Codec */}
        <StatCard
          label={t("CameraHealthPanel.stats.codec")}
          value={health.codec ?? "-"}
          icon={Film}
        />

        {/* Resolution */}
        <StatCard
          label={t("CameraHealthPanel.stats.resolution")}
          value={formatResolution(health.resolution_width, health.resolution_height)}
          icon={MonitorPlay}
        />

        {/* Last Checked */}
        <StatCard
          label={t("CameraHealthPanel.stats.lastChecked")}
          value={formatTimestamp(health.captured_at)}
          icon={Clock}
        />
      </div>

      <Separator className="opacity-40" />

      {/* ---- Bitrate history sparkline ---- */}
      <Card className="bg-card/60 border-border/40 backdrop-blur-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            {t("CameraHealthPanel.cards.bitrateHistory")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {historyLoading ? (
            <Skeleton className="h-[120px] w-full rounded-md" />
          ) : historyError ? (
            <p className="text-sm text-destructive">
              {t("CameraHealthPanel.errors.loadHistory")}
            </p>
          ) : historyData?.data?.snapshots ? (
            <BitrateSparkline snapshots={historyData.data.snapshots} />
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("CameraHealthPanel.cards.noHistoryData")}
            </p>
          )}
        </CardContent>
      </Card>

      {/* ---- Status Timeline (online/offline history) ---- */}
      <Card className="bg-card/60 border-border/40 backdrop-blur-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            {t("CameraHealthPanel.cards.statusTimeline")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {historyLoading ? (
            <Skeleton className="h-8 w-full rounded-md" />
          ) : historyData?.data?.snapshots ? (
            <StatusTimeline snapshots={historyData.data.snapshots} />
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("CameraHealthPanel.cards.noStatusData")}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default CameraHealthPanel;
