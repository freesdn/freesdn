// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { camerasApi } from "@/lib/api";
import type { RecordingScheduleConfig, RecordingScheduleDay, RecordingTimeBlock } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Calendar, Save, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface RecordingSchedulePanelProps {
  cameraId: string;
}

const DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const DAY_ABBR: Record<string, string> = {
  Monday: "Mon",
  Tuesday: "Tue",
  Wednesday: "Wed",
  Thursday: "Thu",
  Friday: "Fri",
  Saturday: "Sat",
  Sunday: "Sun",
};

const ACTION_COLORS: Record<string, { bg: string; border: string; labelKey: string }> = {
  continuous: { bg: "bg-blue-500/70", border: "border-blue-600", labelKey: "continuous" },
  motion: { bg: "bg-amber-500/70", border: "border-amber-600", labelKey: "motion" },
  alarm: { bg: "bg-red-500/70", border: "border-red-600", labelKey: "alarm" },
};

const HOUR_LABELS = Array.from({ length: 25 }, (_, i) => i);

function parseTimeToFraction(time: string): number {
  const [h, m] = (time ?? "").split(":").map(Number);
  return ((h || 0) + (m || 0) / 60) / 24;
}

function TimeBlock({ block }: { block: RecordingTimeBlock }) {
  const left = parseTimeToFraction(block.begin_time) * 100;
  const right = parseTimeToFraction(block.end_time) * 100;
  const width = Math.max(0, right - left);
  if (width <= 0) return null; // Skip invalid/overnight blocks
  const colors = ACTION_COLORS[block.record_type] ?? ACTION_COLORS.continuous;

  return (
    <div
      className={cn(
        "absolute top-0.5 bottom-0.5 rounded-sm border",
        colors.bg,
        colors.border
      )}
      style={{ left: `${left}%`, width: `${width}%` }}
      title={`${block.record_type}: ${block.begin_time} - ${block.end_time}`}
    />
  );
}

function ScheduleGrid({ days }: { days: RecordingScheduleDay[] }) {
  const sortedDays = useMemo(() => {
    // NVR returns id 1=Mon, 2=Tue, ..., 7=Sun; sort by id
    const mapped = [...(days ?? [])];
    mapped.sort((a, b) => (a.id ?? 0) - (b.id ?? 0));
    return mapped;
  }, [days]);

  return (
    <div className="space-y-1.5">
      {/* Hour ruler */}
      <div className="flex items-center gap-3">
        <span className="w-10 shrink-0" />
        <div className="relative flex-1 flex justify-between text-[10px] text-muted-foreground select-none">
          {HOUR_LABELS.filter((h) => h % 3 === 0).map((h) => (
            <span
              key={h}
              className="absolute -translate-x-1/2"
              style={{ left: `${(h / 24) * 100}%` }}
            >
              {String(h).padStart(2, "0")}
            </span>
          ))}
        </div>
      </div>

      <div className="mt-4 space-y-1">
        {sortedDays.map((day, idx) => {
          // NVR id is 1-based; map to DAY_ORDER (0-based)
          const dayIdx = (day.id ?? 0) - 1;
          const dayName = dayIdx >= 0 && dayIdx < DAY_ORDER.length ? DAY_ORDER[dayIdx] : undefined;
          return (
            <div key={day.id ?? idx} className="flex items-center gap-3">
              <span className="w-10 shrink-0 text-xs font-medium text-muted-foreground">
                {dayName ? DAY_ABBR[dayName] : `D${idx + 1}`}
              </span>
              <div className="relative h-6 flex-1 rounded bg-muted/40 border border-border/40">
                {(day.time_blocks ?? []).map((block) => (
                  <TimeBlock key={block.id} block={block} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Legend() {
  const { t } = useTranslation("common");
  return (
    <div className="flex items-center gap-4 flex-wrap">
      {Object.entries(ACTION_COLORS).map(([key, val]) => (
        <div key={key} className="flex items-center gap-1.5">
          <span className={cn("inline-block h-3 w-6 rounded-sm border", val.bg, val.border)} />
          <span className="text-xs text-muted-foreground">
            {t(`RecordingSchedulePanel.recordTypes.${val.labelKey}`)}
          </span>
        </div>
      ))}
    </div>
  );
}

function SkeletonGrid() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 7 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="w-10 h-4 rounded bg-muted animate-pulse" />
          <div className="flex-1 h-6 rounded bg-muted animate-pulse" />
        </div>
      ))}
    </div>
  );
}

export default function RecordingSchedulePanel({ cameraId }: RecordingSchedulePanelProps) {
  const { t } = useTranslation("common");
  const queryClient = useQueryClient();
  const queryKey = ["cameras", cameraId, "recording-schedule"];

  const { data, isLoading, isError, error } = useQuery({
    queryKey,
    queryFn: () => camerasApi.getRecordingSchedule(cameraId),
    select: (res) => res.data as RecordingScheduleConfig,
    retry: false,
  });

  const [localEnabled, setLocalEnabled] = useState<boolean | null>(null);
  const enabled = localEnabled ?? data?.enabled ?? false;

  const mutation = useMutation({
    mutationFn: (config: RecordingScheduleConfig) =>
      camerasApi.setRecordingSchedule(cameraId, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      setLocalEnabled(null);
    },
  });

  const handleToggle = (checked: boolean) => {
    setLocalEnabled(checked);
  };

  const handleSave = () => {
    if (!data) return;
    mutation.mutate({ ...data, enabled });
  };

  const isDirty = localEnabled !== null && localEnabled !== data?.enabled;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div className="flex items-center gap-2">
          <Calendar className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">{t("RecordingSchedulePanel.title")}</CardTitle>
        </div>

        {data && data.supported !== false && (
          <Badge variant={enabled ? "default" : "secondary"} className="text-xs">
            {enabled ? t("RecordingSchedulePanel.status.enabled") : t("RecordingSchedulePanel.status.disabled")}
          </Badge>
        )}
      </CardHeader>

      <CardContent className="space-y-5">
        {/* Loading state */}
        {isLoading && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-5 w-9 rounded-full bg-muted animate-pulse" />
              <div className="h-4 w-40 rounded bg-muted animate-pulse" />
            </div>
            <SkeletonGrid />
          </div>
        )}

        {/* Error state */}
        {isError && (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            {t("RecordingSchedulePanel.errors.loadFailed")}
            {error instanceof Error ? `: ${error.message}` : "."}
          </div>
        )}

        {/* Not exposed by this NVR (per-channel schedule 401/403/404 over ISAPI) */}
        {data && !isLoading && data.supported === false && (
          <div className="rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
            {t("RecordingSchedulePanel.managedByNvr")}
          </div>
        )}

        {/* Loaded state */}
        {data && !isLoading && data.supported !== false && (
          <>
            {/* Enable / Disable toggle */}
            <div className="flex items-center gap-3">
              <Switch
                id="schedule-enabled"
                checked={enabled}
                onCheckedChange={handleToggle}
                disabled={mutation.isPending}
              />
              <Label htmlFor="schedule-enabled" className="text-sm">
                {t("RecordingSchedulePanel.enableLabel")}
              </Label>
            </div>

            <Separator />

            {/* Schedule grid */}
            <div className={cn(!enabled && "opacity-40 pointer-events-none select-none")}>
              <ScheduleGrid days={data.days} />
            </div>

            <Separator />

            {/* Legend */}
            <Legend />

            {/* Save */}
            <div className="flex justify-end pt-1">
              <Button
                size="sm"
                onClick={handleSave}
                disabled={!isDirty || mutation.isPending}
              >
                {mutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Save className="mr-2 h-4 w-4" />
                )}
                {t("RecordingSchedulePanel.actions.save")}
              </Button>
            </div>

            {/* Mutation feedback */}
            {mutation.isSuccess && (
              <p className="text-xs text-green-600">{t("RecordingSchedulePanel.feedback.saveSuccess")}</p>
            )}
            {mutation.isError && (
              <p className="text-xs text-destructive">
                {t("RecordingSchedulePanel.errors.saveFailed")}
                {mutation.error instanceof Error ? `: ${mutation.error.message}` : "."}
              </p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
