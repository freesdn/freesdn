// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Holiday Schedule Panel
 *
 * Two-section panel:
 * 1. Holiday entries (NVR-level or camera-level), list of named date ranges
 * 2. Holiday recording schedule, per-camera schedule for holiday days
 */

import { useState, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm, Controller } from "react-hook-form";
import { camerasApi, nvrApi } from "@/lib/api";
import type {
  HolidayEntry,
  HolidayListConfig,
  HolidayScheduleConfig,
  RecordingScheduleDay,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { FormFieldArray } from "@/components/ui/form-field-array";
import {
  CalendarDays,
  Save,
  Loader2,
  Trash2,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ── Props ────────────────────────────────────────────────────────────────────

interface HolidaySchedulePanelProps {
  cameraId: string;
  nvrId?: string | null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Translation key suffixes for month abbreviations; translated at render site.
const MONTH_KEYS = [
  "jan", "feb", "mar", "apr", "may", "jun",
  "jul", "aug", "sep", "oct", "nov", "dec",
];

// ── Holidays form (react-hook-form via FormFieldArray) ──────────────────────

interface HolidaysFormValues {
  holidays: HolidayEntry[];
}

// ── Holiday Schedule Grid (reuses recording schedule visual pattern) ──────

// `labelKey` is a translation key suffix; translated at the render site.
const ACTION_COLORS: Record<string, { bg: string; border: string; labelKey: string }> = {
  continuous: { bg: "bg-blue-500/70", border: "border-blue-600", labelKey: "continuous" },
  motion: { bg: "bg-amber-500/70", border: "border-amber-600", labelKey: "motion" },
  alarm: { bg: "bg-red-500/70", border: "border-red-600", labelKey: "alarm" },
};

function parseTimeToFraction(time: string): number {
  const [h, m] = (time ?? "").split(":").map(Number);
  return ((h || 0) + (m || 0) / 60) / 24;
}

function HolidayScheduleGrid({ days }: { days: RecordingScheduleDay[] }) {
  const { t } = useTranslation("common");
  const sorted = useMemo(() => [...(days ?? [])].sort((a, b) => (a.id ?? 0) - (b.id ?? 0)), [days]);
  const DAY_NAMES = [
    t("HolidaySchedulePanel.days.mon"),
    t("HolidaySchedulePanel.days.tue"),
    t("HolidaySchedulePanel.days.wed"),
    t("HolidaySchedulePanel.days.thu"),
    t("HolidaySchedulePanel.days.fri"),
    t("HolidaySchedulePanel.days.sat"),
    t("HolidaySchedulePanel.days.sun"),
  ];

  return (
    <div className="space-y-1.5">
      {/* Hour ruler */}
      <div className="flex items-center gap-3">
        <span className="w-10 shrink-0" />
        <div className="relative flex-1 flex justify-between text-[10px] text-muted-foreground select-none">
          {[0, 3, 6, 9, 12, 15, 18, 21, 24].map((h) => (
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
        {sorted.map((day, idx) => {
          const dayIdx = (day.id ?? 0) - 1;
          const label = dayIdx >= 0 && dayIdx < DAY_NAMES.length ? DAY_NAMES[dayIdx] : `D${idx + 1}`;
          return (
            <div key={day.id ?? idx} className="flex items-center gap-3">
              <span className="w-10 shrink-0 text-xs font-medium text-muted-foreground">
                {label}
              </span>
              <div className="relative h-6 flex-1 rounded bg-muted/40 border border-border/40">
                {(day.time_blocks ?? []).map((block) => {
                  const left = parseTimeToFraction(block.begin_time) * 100;
                  const right = parseTimeToFraction(block.end_time) * 100;
                  const width = Math.max(0, right - left);
                  if (width <= 0) return null;
                  const colors = ACTION_COLORS[block.record_type] ?? ACTION_COLORS.continuous;
                  return (
                    <div
                      key={block.id}
                      className={cn("absolute top-0.5 bottom-0.5 rounded-sm border", colors.bg, colors.border)}
                      style={{ left: `${left}%`, width: `${width}%` }}
                      title={`${block.record_type}: ${block.begin_time}, ${block.end_time}`}
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function HolidaySchedulePanel({ cameraId, nvrId }: HolidaySchedulePanelProps) {
  const { t } = useTranslation("common");
  const qc = useQueryClient();

  // ── NVR Holiday Definitions ───────────────────────────────────────────────
  const {
    data: holidaysData,
    isLoading: holidaysLoading,
  } = useQuery({
    queryKey: ["nvr", nvrId, "holidays"],
    queryFn: () => nvrApi.getHolidays(nvrId!).then((r) => r.data as HolidayListConfig),
    enabled: !!nvrId,
    retry: false,
  });

  const holidaysForm = useForm<HolidaysFormValues>({
    defaultValues: { holidays: [] },
  });
  const watchedHolidays = holidaysForm.watch("holidays");
  const holidaysDirty = holidaysForm.formState.isDirty;

  // The next id for new rows is computed from the current watched values
  // (max(id)+1) · matches the original setHolidays-based logic.
  const nextHolidayId = useMemo(
    () => (watchedHolidays.length > 0 ? Math.max(...watchedHolidays.map((h) => h.id)) + 1 : 1),
    [watchedHolidays],
  );

  useEffect(() => {
    if (holidaysData?.holidays) {
      holidaysForm.reset({ holidays: holidaysData.holidays.map((h) => ({ ...h })) });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [holidaysData]);

  const [holidaySaveStatus, setHolidaySaveStatus] = useState<"idle" | "saving" | "success" | "error">("idle");

  const holidayMutation = useMutation({
    mutationFn: () => nvrApi.setHolidays(nvrId!, { holidays: holidaysForm.getValues("holidays") }),
    onMutate: () => setHolidaySaveStatus("saving"),
    onSuccess: () => {
      setHolidaySaveStatus("success");
      // Reset dirty flag without changing values
      holidaysForm.reset(holidaysForm.getValues());
      qc.invalidateQueries({ queryKey: ["nvr", nvrId, "holidays"] });
      setTimeout(() => setHolidaySaveStatus("idle"), 2000);
    },
    onError: () => {
      setHolidaySaveStatus("error");
      setTimeout(() => setHolidaySaveStatus("idle"), 3000);
    },
  });

  // ── Camera Holiday Recording Schedule ─────────────────────────────────────
  const {
    data: scheduleData,
    isLoading: scheduleLoading,
  } = useQuery({
    queryKey: ["cameras", cameraId, "holiday-schedule"],
    queryFn: () => camerasApi.getHolidaySchedule(cameraId).then((r) => r.data as HolidayScheduleConfig),
    retry: false,
  });

  const [scheduleEnabled, setScheduleEnabled] = useState<boolean | null>(null);
  const schedEnabled = scheduleEnabled ?? scheduleData?.enabled ?? false;
  const schedDirty = scheduleEnabled !== null && scheduleEnabled !== scheduleData?.enabled;

  const scheduleMutation = useMutation({
    mutationFn: (config: HolidayScheduleConfig) =>
      camerasApi.setHolidaySchedule(cameraId, config),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cameras", cameraId, "holiday-schedule"] });
      setScheduleEnabled(null);
    },
  });

  const handleSaveSchedule = () => {
    if (!scheduleData) return;
    scheduleMutation.mutate({ ...scheduleData, enabled: schedEnabled });
  };

  return (
    <div className="space-y-6">
      {/* ── Section 1: Holiday Definitions (NVR-level) ──────────────────────── */}
      {nvrId && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
            <div className="flex items-center gap-2">
              <CalendarDays className="h-5 w-5 text-muted-foreground" />
              <CardTitle className="text-base">{t("HolidaySchedulePanel.definitions.title")}</CardTitle>
            </div>
            <Badge variant="secondary" className="text-xs">
              {t("HolidaySchedulePanel.definitions.nvrLevel")}
            </Badge>
          </CardHeader>

          <CardContent className="space-y-4">
            {holidaysLoading ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t("HolidaySchedulePanel.definitions.loading")}
              </div>
            ) : (
              <>
                <p className="text-xs text-muted-foreground">
                  {t("HolidaySchedulePanel.definitions.help")}
                </p>

                <FormFieldArray<HolidaysFormValues, "holidays">
                  control={holidaysForm.control}
                  name="holidays"
                  defaultItem={{
                    id: nextHolidayId,
                    enabled: true,
                    name: "",
                    mode: "date",
                    start_month: 1,
                    start_day: 1,
                    end_month: 1,
                    end_day: 1,
                  }}
                  addLabel={t("HolidaySchedulePanel.definitions.addHoliday")}
                  maxItems={32}
                  showCount={false}
                  emptyState={{
                    icon: CalendarDays,
                    title: t("HolidaySchedulePanel.definitions.empty"),
                  }}
                >
                  {(_item, index, { remove }) => (
                    <div className="flex items-center gap-3 py-2 px-3 rounded-md border bg-muted/20">
                      <Controller
                        control={holidaysForm.control}
                        name={`holidays.${index}.enabled` as const}
                        render={({ field }) => (
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            className="shrink-0"
                          />
                        )}
                      />
                      <Controller
                        control={holidaysForm.control}
                        name={`holidays.${index}.name` as const}
                        render={({ field }) => (
                          <Input
                            value={field.value}
                            onChange={field.onChange}
                            placeholder={t("HolidaySchedulePanel.definitions.namePlaceholder")}
                            className="h-8 text-sm flex-1 min-w-0"
                          />
                        )}
                      />

                      {/* Start date */}
                      <div className="flex items-center gap-1 shrink-0">
                        <Controller
                          control={holidaysForm.control}
                          name={`holidays.${index}.start_month` as const}
                          render={({ field }) => (
                            <select
                              value={field.value}
                              onChange={(e) => field.onChange(Number(e.target.value))}
                              className="h-8 rounded-md border bg-background px-2 text-xs"
                            >
                              {MONTH_KEYS.map((m, i) => (
                                <option key={i} value={i + 1}>{t(`HolidaySchedulePanel.months.${m}`)}</option>
                              ))}
                            </select>
                          )}
                        />
                        <Controller
                          control={holidaysForm.control}
                          name={`holidays.${index}.start_day` as const}
                          render={({ field }) => (
                            <Input
                              type="number"
                              min={1}
                              max={31}
                              value={field.value}
                              onChange={(e) =>
                                field.onChange(Math.max(1, Math.min(31, Number(e.target.value))))
                              }
                              className="h-8 w-14 text-xs text-center"
                            />
                          )}
                        />
                      </div>

                      <span className="text-muted-foreground text-xs">-</span>

                      {/* End date */}
                      <div className="flex items-center gap-1 shrink-0">
                        <Controller
                          control={holidaysForm.control}
                          name={`holidays.${index}.end_month` as const}
                          render={({ field }) => (
                            <select
                              value={field.value}
                              onChange={(e) => field.onChange(Number(e.target.value))}
                              className="h-8 rounded-md border bg-background px-2 text-xs"
                            >
                              {MONTH_KEYS.map((m, i) => (
                                <option key={i} value={i + 1}>{t(`HolidaySchedulePanel.months.${m}`)}</option>
                              ))}
                            </select>
                          )}
                        />
                        <Controller
                          control={holidaysForm.control}
                          name={`holidays.${index}.end_day` as const}
                          render={({ field }) => (
                            <Input
                              type="number"
                              min={1}
                              max={31}
                              value={field.value}
                              onChange={(e) =>
                                field.onChange(Math.max(1, Math.min(31, Number(e.target.value))))
                              }
                              className="h-8 w-14 text-xs text-center"
                            />
                          )}
                        />
                      </div>

                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 shrink-0 text-destructive"
                        onClick={() => remove()}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  )}
                </FormFieldArray>

                <div className="flex items-center justify-end pt-2">
                  <div className="flex items-center gap-2">
                    {holidaySaveStatus === "success" && (
                      <span className="flex items-center gap-1 text-xs text-green-600">
                        <CheckCircle2 className="h-3.5 w-3.5" /> {t("HolidaySchedulePanel.definitions.saved")}
                      </span>
                    )}
                    {holidaySaveStatus === "error" && (
                      <span className="flex items-center gap-1 text-xs text-destructive">
                        <XCircle className="h-3.5 w-3.5" /> {t("HolidaySchedulePanel.definitions.failed")}
                      </span>
                    )}
                    <Button
                      size="sm"
                      disabled={!holidaysDirty || holidaySaveStatus === "saving"}
                      onClick={() => holidayMutation.mutate()}
                    >
                      {holidaySaveStatus === "saving" ? (
                        <Loader2 className="h-4 w-4 animate-spin mr-1" />
                      ) : (
                        <Save className="h-4 w-4 mr-1" />
                      )}
                      {t("HolidaySchedulePanel.definitions.saveHolidays")}
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Section 2: Holiday Recording Schedule (per-camera) ──────────────── */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <div className="flex items-center gap-2">
            <CalendarDays className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">{t("HolidaySchedulePanel.schedule.title")}</CardTitle>
          </div>
          {scheduleData && (
            <Badge variant={schedEnabled ? "default" : "secondary"} className="text-xs">
              {schedEnabled ? t("HolidaySchedulePanel.schedule.enabled") : t("HolidaySchedulePanel.schedule.disabled")}
            </Badge>
          )}
        </CardHeader>

        <CardContent className="space-y-5">
          {scheduleLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t("HolidaySchedulePanel.schedule.loading")}
            </div>
          ) : scheduleData ? (
            <>
              <div className="flex items-center gap-3">
                <Switch
                  checked={schedEnabled}
                  onCheckedChange={setScheduleEnabled}
                  disabled={scheduleMutation.isPending}
                />
                <Label className="text-sm">{t("HolidaySchedulePanel.schedule.enableLabel")}</Label>
              </div>

              <Separator />

              <div className={cn(!schedEnabled && "opacity-40 pointer-events-none select-none")}>
                <HolidayScheduleGrid days={scheduleData.days} />
              </div>

              <Separator />

              {/* Legend */}
              <div className="flex items-center gap-4 flex-wrap">
                {Object.entries(ACTION_COLORS).map(([key, val]) => (
                  <div key={key} className="flex items-center gap-1.5">
                    <span className={cn("inline-block h-3 w-6 rounded-sm border", val.bg, val.border)} />
                    <span className="text-xs text-muted-foreground">{t(`HolidaySchedulePanel.actions.${val.labelKey}`)}</span>
                  </div>
                ))}
              </div>

              {/* Save */}
              <div className="flex justify-end pt-1">
                <Button
                  size="sm"
                  onClick={handleSaveSchedule}
                  disabled={!schedDirty || scheduleMutation.isPending}
                >
                  {scheduleMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  {t("HolidaySchedulePanel.schedule.save")}
                </Button>
              </div>

              {scheduleMutation.isSuccess && (
                <p className="text-xs text-green-600">{t("HolidaySchedulePanel.schedule.saveSuccess")}</p>
              )}
              {scheduleMutation.isError && (
                <p className="text-xs text-destructive">{t("HolidaySchedulePanel.schedule.saveError")}</p>
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">
              {t("HolidaySchedulePanel.schedule.unavailable")}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
