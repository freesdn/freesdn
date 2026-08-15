// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, PTZ Tours (Patrols) Panel
 *
 * Lets users view, create, edit, start/stop PTZ patrol tours.
 * Each tour has an ordered list of preset stops with dwell time and speed.
 */

import { useState, useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm, Controller } from "react-hook-form";
import { camerasApi } from "@/lib/api";
import type { PTZPatrol, PTZPatrolAction } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Slider } from "@/components/ui/slider";
import { FormFieldArray } from "@/components/ui/form-field-array";
import {
  Route,
  Play,
  Square,
  Trash2,
  Save,
  Loader2,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  Pencil,
} from "lucide-react";

// ── Props ────────────────────────────────────────────────────────────────────

interface PTZToursPanelProps {
  cameraId: string;
  isOnline: boolean;
}

// ── Tour form types ──────────────────────────────────────────────────────────

interface TourFormValues {
  name: string;
  enabled: boolean;
  actions: PTZPatrolAction[];
}

// ── Tour Card ────────────────────────────────────────────────────────────────

function TourCard({
  tour,
  cameraId,
  isOnline,
}: {
  tour: PTZPatrol;
  cameraId: string;
  isOnline: boolean;
}) {
  const { t } = useTranslation("common");
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "success" | "error">("idle");

  const tourForm = useForm<TourFormValues>({
    defaultValues: {
      name: tour.name,
      enabled: tour.enabled,
      actions: tour.actions.map((a) => ({ ...a })),
    },
  });
  const watchedActions = tourForm.watch("actions");
  const watchedEnabled = tourForm.watch("enabled");

  // Compute the next id so newly-added stops keep stable ids (matches the
  // previous Math.max(...actions.map(a => a.id)) + 1 logic).
  const nextActionId = useMemo(
    () => (watchedActions.length > 0 ? Math.max(...watchedActions.map((a) => a.id)) + 1 : 1),
    [watchedActions],
  );

  useEffect(() => {
    tourForm.reset({
      name: tour.name,
      enabled: tour.enabled,
      actions: tour.actions.map((a) => ({ ...a })),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tour]);

  const saveMutation = useMutation({
    mutationFn: () => {
      const v = tourForm.getValues();
      return camerasApi.setPTZTour(cameraId, tour.id, {
        name: v.name,
        enabled: v.enabled,
        actions: v.actions.map(({ preset_id, dwell, speed }) => ({ preset_id, dwell, speed })),
      });
    },
    onMutate: () => setSaveStatus("saving"),
    onSuccess: () => {
      setSaveStatus("success");
      setEditing(false);
      qc.invalidateQueries({ queryKey: ["camera", cameraId, "ptz-tours"] });
      setTimeout(() => setSaveStatus("idle"), 2000);
    },
    onError: () => {
      setSaveStatus("error");
      setTimeout(() => setSaveStatus("idle"), 3000);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => camerasApi.deletePTZTour(cameraId, tour.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["camera", cameraId, "ptz-tours"] }),
    onError: () => setSaveStatus("error"),
  });

  const startMutation = useMutation({
    mutationFn: () => camerasApi.startPTZTour(cameraId, tour.id),
    onError: () => setSaveStatus("error"),
  });

  const stopMutation = useMutation({
    mutationFn: () => camerasApi.stopPTZTour(cameraId, tour.id),
    onError: () => setSaveStatus("error"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <div className="flex items-center gap-2">
          <Route className="h-4 w-4 text-muted-foreground" />
          {editing ? (
            <Controller
              control={tourForm.control}
              name="name"
              render={({ field }) => (
                <Input
                  value={field.value}
                  onChange={field.onChange}
                  className="h-7 text-sm w-40"
                />
              )}
            />
          ) : (
            <CardTitle className="text-sm font-medium">
              {tour.name || t("PTZToursPanel.tourFallbackName", { id: tour.id })}
            </CardTitle>
          )}
          <Badge variant={watchedEnabled ? "default" : "secondary"} className="text-[10px]">
            {watchedEnabled ? t("PTZToursPanel.enabled") : t("PTZToursPanel.disabled")}
          </Badge>
          <Badge variant="outline" className="text-[10px]">
            {tour.actions.length === 1
              ? t("PTZToursPanel.stepCount_one", { count: tour.actions.length })
              : t("PTZToursPanel.stepCount_other", { count: tour.actions.length })}
          </Badge>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Start/Stop */}
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1"
            disabled={!isOnline || !tour.enabled}
            onClick={() => startMutation.mutate()}
          >
            {startMutation.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Play className="h-3 w-3" />
            )}
            {t("PTZToursPanel.actions.start")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1"
            disabled={!isOnline}
            onClick={() => stopMutation.mutate()}
          >
            <Square className="h-3 w-3" />
            {t("PTZToursPanel.actions.stop")}
          </Button>

          {/* Edit toggle */}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setEditing(!editing)}
          >
            <Pencil className="h-3.5 w-3.5" />
          </Button>

          {/* Delete */}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-destructive"
            onClick={() => {
              if (confirm(t("PTZToursPanel.confirmDelete"))) deleteMutation.mutate();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </CardHeader>

      {editing && (
        <CardContent className="space-y-3 pt-0">
          <div className="flex items-center gap-3">
            <Controller
              control={tourForm.control}
              name="enabled"
              render={({ field }) => (
                <Switch checked={field.value} onCheckedChange={field.onChange} />
              )}
            />
            <Label className="text-sm">{t("PTZToursPanel.enabled")}</Label>
          </div>

          <Separator />

          <FormFieldArray<TourFormValues, "actions">
            control={tourForm.control}
            name="actions"
            defaultItem={{ id: nextActionId, preset_id: 1, dwell: 10, speed: 50 }}
            addLabel={t("PTZToursPanel.addStop")}
            maxItems={32}
            showCount={false}
            emptyState={{
              icon: Route,
              title: t("PTZToursPanel.emptyStops.title"),
              description: t("PTZToursPanel.emptyStops.description"),
            }}
          >
            {(_item, index, { remove, move, isFirst, isLast }) => {
              const watched = watchedActions[index];
              return (
                <div className="flex items-center gap-2 py-1.5 px-3 rounded-md border bg-muted/20">
                  {/* Reorder arrows */}
                  <div className="flex flex-col gap-0.5 shrink-0">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5"
                      disabled={isFirst}
                      onClick={() => move(index - 1)}
                    >
                      <ChevronUp className="h-3 w-3" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-5 w-5"
                      disabled={isLast}
                      onClick={() => move(index + 1)}
                    >
                      <ChevronDown className="h-3 w-3" />
                    </Button>
                  </div>

                  {/* Step number */}
                  <span className="text-xs text-muted-foreground font-mono w-6 shrink-0 text-center">
                    #{index + 1}
                  </span>

                  {/* Preset ID */}
                  <div className="shrink-0 space-y-0">
                    <Label className="text-[10px] text-muted-foreground">{t("PTZToursPanel.fields.preset")}</Label>
                    <Controller
                      control={tourForm.control}
                      name={`actions.${index}.preset_id` as const}
                      render={({ field }) => (
                        <Input
                          type="number"
                          min={1}
                          max={255}
                          value={field.value}
                          onChange={(e) =>
                            field.onChange(Math.max(1, Math.min(255, Number(e.target.value))))
                          }
                          className="h-7 w-16 text-xs"
                        />
                      )}
                    />
                  </div>

                  {/* Dwell time */}
                  <div className="shrink-0 space-y-0">
                    <Label className="text-[10px] text-muted-foreground">{t("PTZToursPanel.fields.dwell")}</Label>
                    <Controller
                      control={tourForm.control}
                      name={`actions.${index}.dwell` as const}
                      render={({ field }) => (
                        <Input
                          type="number"
                          min={1}
                          max={300}
                          value={field.value}
                          onChange={(e) =>
                            field.onChange(Math.max(1, Math.min(300, Number(e.target.value))))
                          }
                          className="h-7 w-16 text-xs"
                        />
                      )}
                    />
                  </div>

                  {/* Speed */}
                  <div className="flex-1 space-y-0 min-w-0">
                    <div className="flex items-center justify-between">
                      <Label className="text-[10px] text-muted-foreground">{t("PTZToursPanel.fields.speed")}</Label>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        {watched?.speed ?? 0}
                      </span>
                    </div>
                    <Controller
                      control={tourForm.control}
                      name={`actions.${index}.speed` as const}
                      render={({ field }) => (
                        <Slider
                          min={1}
                          max={100}
                          step={1}
                          value={[field.value]}
                          onValueChange={([v]) => field.onChange(v)}
                          className="w-full"
                        />
                      )}
                    />
                  </div>

                  {/* Remove */}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0 text-destructive"
                    onClick={() => remove()}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              );
            }}
          </FormFieldArray>

          <div className="flex items-center justify-end pt-2">
            <div className="flex items-center gap-2">
              {saveStatus === "success" && (
                <span className="flex items-center gap-1 text-xs text-green-600">
                  <CheckCircle2 className="h-3.5 w-3.5" /> {t("PTZToursPanel.status.saved")}
                </span>
              )}
              {saveStatus === "error" && (
                <span className="flex items-center gap-1 text-xs text-destructive">
                  <XCircle className="h-3.5 w-3.5" /> {t("PTZToursPanel.status.failed")}
                </span>
              )}
              <Button
                size="sm"
                disabled={saveStatus === "saving" || watchedActions.length === 0}
                onClick={() => saveMutation.mutate()}
              >
                {saveStatus === "saving" ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <Save className="h-4 w-4 mr-1" />
                )}
                {t("PTZToursPanel.actions.saveTour")}
              </Button>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

// ── Main Panel ───────────────────────────────────────────────────────────────

export default function PTZToursPanel({ cameraId, isOnline }: PTZToursPanelProps) {
  const { t } = useTranslation("common");
  const { data: toursRes, isLoading } = useQuery({
    queryKey: ["camera", cameraId, "ptz-tours"],
    queryFn: () => camerasApi.getPTZTours(cameraId),
    enabled: isOnline,
  });

  const rawData = toursRes?.data;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tours: PTZPatrol[] = Array.isArray(rawData) ? rawData : (rawData as any)?.patrols ?? [];

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <div className="flex items-center gap-2">
          <Route className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">{t("PTZToursPanel.title")}</CardTitle>
        </div>
        <Badge variant="outline" className="text-xs">
          {tours.length === 1
            ? t("PTZToursPanel.tourCount_one", { count: tours.length })
            : t("PTZToursPanel.tourCount_other", { count: tours.length })}
        </Badge>
      </CardHeader>

      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" /> {t("PTZToursPanel.loading")}
          </div>
        ) : tours.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-6">
            {t("PTZToursPanel.empty")}
          </p>
        ) : (
          <div className="space-y-3">
            {tours.map((tour) => (
              <TourCard
                key={tour.id}
                tour={tour}
                cameraId={cameraId}
                isOnline={isOnline}
              />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
