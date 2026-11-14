// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notificationApi, type SLAPolicy } from "@/lib/api";
import {
  slaReportsApi,
  type Report,
  type ReportSchedule,
  type ReportScheduleInput,
} from "@/lib/api/slaReports";
import { useAuthStore } from "@/stores/authStore";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { getApiErrorMessage } from '@/lib/api/errors';

const PAGE_SIZE = 25;
const stamp = (value?: string | null) =>
  value ? new Date(value).toLocaleString() : "-";
const emptySchedule = (): ReportScheduleInput => ({
  name: "",
  frequency: "monthly",
  day_of_week: 0,
  day_of_month: 1,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  time_of_day: "09:00",
  recipients: [],
  sla_policy_ids: [],
  enabled: true,
  delivery_enabled: false,
  delivery_provider_id: null,
});

function errorMessage(error: unknown, fallback: string): string {
  return getApiErrorMessage(error, fallback);
}

// Delivery states the backend records (app/services/sla_report_delivery.py);
// anything else is shown as sent.
const DELIVERY_STATES = new Set([
  "pending",
  "sending",
  "retry",
  "accepted",
  "unknown",
  "failed",
  "skipped",
  "cancelled",
]);
const FREQUENCIES = new Set(["weekly", "monthly", "quarterly"]);
// The backend counts day_of_week from 0 = Monday.
const WEEKDAYS = [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
] as const;

function deliveryStateLabel(t: TFunction, state: string): string {
  return DELIVERY_STATES.has(state)
    ? t(`SLAReportsPanel.deliveryStates.${state}`)
    : state;
}

function frequencyLabel(t: TFunction, frequency: string): string {
  return FREQUENCIES.has(frequency)
    ? t(`SLAReportsPanel.frequencies.${frequency}`)
    : frequency;
}

// Native controls get the theme's surface and text colours explicitly; a bare
// <select> keeps the browser's light popup in the default dark theme.
const selectClass =
  "block rounded-md border border-input bg-background p-2 text-sm text-foreground";

function Pagination({
  offset,
  total,
  change,
}: {
  offset: number;
  total: number;
  change: (n: number) => void;
}) {
  const { t } = useTranslation("enterprise");
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <Button
        variant="outline"
        disabled={offset === 0}
        onClick={() => change(Math.max(0, offset - PAGE_SIZE))}
      >
        {t("SLAReportsPanel.pagination.previous")}
      </Button>
      <span className="text-muted-foreground">
        {total === 0
          ? t("SLAReportsPanel.pagination.none")
          : t("SLAReportsPanel.pagination.range", {
              from: offset + 1,
              to: Math.min(offset + PAGE_SIZE, total),
              total,
            })}
      </span>
      <Button
        variant="outline"
        disabled={offset + PAGE_SIZE >= total}
        onClick={() => change(offset + PAGE_SIZE)}
      >
        {t("SLAReportsPanel.pagination.next")}
      </Button>
    </div>
  );
}

export function SLAReportsPanel({ policies }: { policies: SLAPolicy[] }) {
  const { t } = useTranslation("enterprise");
  const enabledId = useId();
  const deliveryId = useId();
  const client = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const canWrite = useAuthStore((s) => s.hasPermission("config:write"));
  const [params, setParams] = useSearchParams();
  const selectedReport = params.get("report") ?? "";
  const [reportOffset, setReportOffset] = useState(0);
  const [scheduleOffset, setScheduleOffset] = useState(0);
  const [form, setForm] = useState<ReportScheduleInput>(emptySchedule);
  const [editing, setEditing] = useState<string | null>(null);
  const [recipients, setRecipients] = useState("");
  const [policyIds, setPolicyIds] = useState<string[]>([]);
  const [schedulePolicies, setSchedulePolicies] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [format, setFormat] = useState("pdf");
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const key = ["sla-report-workspace", user?.id, user?.organization_id];
  const reports = useQuery({
    queryKey: [...key, "reports", reportOffset],
    queryFn: async () => (await slaReportsApi.list(reportOffset)).data,
    refetchInterval: 30000,
  });
  const schedules = useQuery({
    queryKey: [...key, "schedules", scheduleOffset],
    queryFn: async () => (await slaReportsApi.schedules(scheduleOffset)).data,
    refetchInterval: 30000,
  });
  const providers = useQuery({
    queryKey: [...key, "providers"],
    queryFn: async () =>
      (await notificationApi.getProviders("email", true)).data,
    enabled: canWrite,
  });
  const deliveries = useQuery({
    queryKey: [...key, "deliveries", selectedReport],
    queryFn: async () => (await slaReportsApi.deliveries(selectedReport)).data,
    enabled: !!selectedReport && canWrite,
    refetchInterval: 10000,
  });
  // The list envelopes are read defensively: a response without the expected
  // array (an older backend, a proxy error page parsed as JSON, the demo's
  // generic stub) used to throw on `.length` and take the whole SLA page down
  // with the route error boundary, hiding policies and breaches with it.
  const reportRows = Array.isArray(reports.data?.reports) ? reports.data.reports : [];
  const scheduleRows = Array.isArray(schedules.data?.schedules)
    ? schedules.data.schedules
    : [];
  const deliveryRows = Array.isArray(deliveries.data) ? deliveries.data : [];
  const refresh = () => client.invalidateQueries({ queryKey: key });
  const save = useMutation({
    mutationFn: (data: ReportScheduleInput) =>
      editing
        ? slaReportsApi.update(editing, data)
        : slaReportsApi.create(data),
    onSuccess: () => {
      setEditing(null);
      setForm(emptySchedule());
      setRecipients("");
      setSchedulePolicies("");
      void refresh();
    },
  });
  const toggle = useMutation({
    mutationFn: (s: ReportSchedule) =>
      slaReportsApi.update(s.id, { enabled: !s.enabled }),
    onSuccess: refresh,
  });
  const generate = useMutation({
    mutationFn: () =>
      slaReportsApi.generate({
        period_start: `${start}T00:00:00Z`,
        period_end: `${end}T00:00:00Z`,
        policy_ids: policyIds.length ? policyIds : null,
        format,
      }),
    onSuccess: () => {
      setReportOffset(0);
      void refresh();
    },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => slaReportsApi.cancel(selectedReport, id),
    onSuccess: refresh,
  });
  function edit(schedule: ReportSchedule) {
    setEditing(schedule.id);
    setForm({
      name: schedule.name,
      frequency: schedule.frequency,
      day_of_week: schedule.day_of_week,
      day_of_month: schedule.day_of_month,
      timezone: schedule.timezone,
      time_of_day: schedule.time_of_day,
      enabled: schedule.enabled,
      recipients: (schedule.recipients ?? []).filter(
        (s): s is string => typeof s === "string",
      ),
      sla_policy_ids: (schedule.sla_policy_ids ?? []).filter(
        (s): s is string => typeof s === "string",
      ),
      delivery_enabled: schedule.delivery_enabled,
      delivery_provider_id: schedule.delivery_provider_id,
    });
    setRecipients((schedule.recipients ?? []).join(", "));
    setSchedulePolicies((schedule.sla_policy_ids ?? []).join(", "));
    save.reset();
  }
  async function download(report: Pick<Report, "id" | "format">) {
    setDownloadError(null);
    try {
      const { data } = await slaReportsApi.download(report.id);
      const url = URL.createObjectURL(data);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `sla-report-${report.id}.${data.type.includes("csv") ? "csv" : "pdf"}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setDownloadError(errorMessage(error, t("SLAReportsPanel.errors.fallback")));
    }
  }
  function submitSchedule(event: FormEvent) {
    event.preventDefault();
    save.mutate({
      ...form,
      sla_policy_ids: schedulePolicies
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean),
      recipients: recipients
        .split(/[,;\n]/)
        .map((v) => v.trim())
        .filter(Boolean),
    });
  }
  const errors = [
    reports.error,
    schedules.error,
    providers.error,
    deliveries.error,
    save.error,
    toggle.error,
    generate.error,
    cancel.error,
  ].filter(Boolean);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {t("SLAReportsPanel.intro")}
      </p>
      {errors.map((error, i) => (
        <p role="alert" className="text-destructive" key={i}>
          {errorMessage(error, t("SLAReportsPanel.errors.fallback"))}
        </p>
      ))}
      {downloadError && (
        <p role="alert" className="text-destructive">
          {downloadError}
        </p>
      )}
      {canWrite && (
        <Card>
          <CardHeader>
            <CardTitle>{t("SLAReportsPanel.generate.title")}</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                generate.mutate();
              }}
            >
              <label className="text-sm">
                {t("SLAReportsPanel.generate.start")}
                <Input
                  aria-label={t("SLAReportsPanel.generate.startAria")}
                  type="date"
                  required
                  value={start}
                  onChange={(e) => setStart(e.target.value)}
                />
              </label>
              <label className="text-sm">
                {t("SLAReportsPanel.generate.end")}
                <Input
                  aria-label={t("SLAReportsPanel.generate.endAria")}
                  type="date"
                  required
                  min={start}
                  value={end}
                  onChange={(e) => setEnd(e.target.value)}
                />
              </label>
              <label className="text-sm">
                {t("SLAReportsPanel.generate.policies")}
                <select
                  aria-label={t("SLAReportsPanel.generate.policiesAria")}
                  className={selectClass}
                  multiple
                  value={policyIds}
                  onChange={(e) =>
                    setPolicyIds(
                      Array.from(e.target.selectedOptions, (o) => o.value),
                    )
                  }
                >
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
                <span className="block text-xs text-muted-foreground">
                  {t("SLAReportsPanel.generate.policiesHint")}
                </span>
              </label>
              <label className="text-sm">
                {t("SLAReportsPanel.generate.format")}
                <select
                  aria-label={t("SLAReportsPanel.generate.formatAria")}
                  className={selectClass}
                  value={format}
                  onChange={(e) => setFormat(e.target.value)}
                >
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                </select>
              </label>
              <Button
                disabled={generate.isPending || !start || !end || end <= start}
              >
                {t("SLAReportsPanel.generate.submit")}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>{t("SLAReportsPanel.archive.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            {t("SLAReportsPanel.archive.lastRefreshed", {
              time: reports.dataUpdatedAt
                ? stamp(new Date(reports.dataUpdatedAt).toISOString())
                : t("SLAReportsPanel.archive.waiting"),
            })}
          </p>
          {reports.isPending ? (
            <p className="text-sm text-muted-foreground">
              {t("SLAReportsPanel.archive.loading")}
            </p>
          ) : reports.isSuccess && reportRows.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("SLAReportsPanel.archive.empty")}
            </p>
          ) : null}
          {selectedReport && (
            <Button
              variant="outline"
              onClick={() =>
                void download({ id: selectedReport, format: "pdf" })
              }
            >
              {t("SLAReportsPanel.archive.downloadLinked")}
            </Button>
          )}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs text-muted-foreground">
                  <th className="py-2 font-medium">
                    {t("SLAReportsPanel.archive.columns.report")}
                  </th>
                  <th className="py-2 font-medium">
                    {t("SLAReportsPanel.archive.columns.generated")}
                  </th>
                  <th className="py-2 font-medium">
                    {t("SLAReportsPanel.archive.columns.actions")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {reportRows.map((report) => (
                  <tr key={report.id} className="border-t">
                    <td className="py-3">
                      {report.title}
                      <p className="text-xs text-muted-foreground">
                        {t("SLAReportsPanel.archive.period", {
                          start: stamp(report.period_start),
                          end: stamp(report.period_end),
                        })}
                      </p>
                    </td>
                    <td>{stamp(report.generated_at)}</td>
                    <td>
                      <Button
                        variant="outline"
                        onClick={() => void download(report)}
                      >
                        {t("SLAReportsPanel.archive.download", {
                          format: report.format.toUpperCase(),
                        })}
                      </Button>
                      {canWrite && (
                        <Button
                          variant="ghost"
                          onClick={() => setParams({ report: report.id })}
                        >
                          {t("SLAReportsPanel.archive.deliveryStatus")}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            offset={reportOffset}
            total={reports.data?.total ?? 0}
            change={setReportOffset}
          />
        </CardContent>
      </Card>
      {selectedReport && canWrite && (
        <Card>
          <CardHeader>
            <CardTitle>{t("SLAReportsPanel.delivery.title")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm">{t("SLAReportsPanel.delivery.explain")}</p>
            {deliveries.isPending && (
              <p className="text-sm text-muted-foreground">
                {t("SLAReportsPanel.delivery.loading")}
              </p>
            )}
            {deliveries.isSuccess && deliveryRows.length === 0 && (
              <p className="text-sm text-muted-foreground">
                {t("SLAReportsPanel.delivery.empty")}
              </p>
            )}
            {deliveryRows.map((d) => (
              <div key={d.id} className="rounded border p-3 text-sm">
                <p>
                  {d.recipient_email}:{" "}
                  <strong>{deliveryStateLabel(t, d.state)}</strong> ·{" "}
                  {t("SLAReportsPanel.delivery.attempts", { count: d.attempts })}
                </p>
                <p className="break-all text-xs text-muted-foreground">
                  {t("SLAReportsPanel.delivery.id", { id: d.id })}
                </p>
                {d.error_code && (
                  <p className="font-mono text-xs">
                    {t("SLAReportsPanel.delivery.code", { code: d.error_code })}
                  </p>
                )}
                {(d.state === "pending" || d.state === "retry") && (
                  <>
                    <p>
                      {t("SLAReportsPanel.delivery.nextAttempt", {
                        time: stamp(d.next_attempt_at),
                      })}
                    </p>
                    <Button
                      variant="outline"
                      disabled={cancel.isPending}
                      onClick={() => cancel.mutate(d.id)}
                    >
                      {t("SLAReportsPanel.delivery.cancel")}
                    </Button>
                  </>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>{t("SLAReportsPanel.schedules.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {schedules.isPending && (
            <p className="text-sm text-muted-foreground">
              {t("SLAReportsPanel.schedules.loading")}
            </p>
          )}
          {schedules.isSuccess && scheduleRows.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {t("SLAReportsPanel.schedules.empty")}
            </p>
          )}
          {scheduleRows.map((s) => (
            <div key={s.id} className="rounded border p-3 text-sm">
              <p>
                <strong>{s.name}</strong> ·{" "}
                {s.enabled
                  ? t("SLAReportsPanel.schedules.enabled")
                  : t("SLAReportsPanel.schedules.paused")}{" "}
                ·{" "}
                {t("SLAReportsPanel.schedules.cadence", {
                  frequency: frequencyLabel(t, s.frequency),
                  time: s.time_of_day,
                  timezone: s.timezone,
                })}
              </p>
              <p className="text-muted-foreground">
                {t("SLAReportsPanel.schedules.runs", {
                  next: stamp(s.next_run_at),
                  last: stamp(s.last_generated_at),
                  email: s.delivery_enabled
                    ? t("SLAReportsPanel.schedules.emailOn")
                    : t("SLAReportsPanel.schedules.emailOff"),
                })}
              </p>
              {s.execution_error && (
                <p className="text-destructive">
                  {t("SLAReportsPanel.schedules.needsReview", {
                    error: s.execution_error,
                  })}
                </p>
              )}
              {canWrite && (
                <>
                  <Button variant="ghost" onClick={() => edit(s)}>
                    {t("SLAReportsPanel.schedules.edit")}
                  </Button>
                  <Button
                    variant="outline"
                    disabled={toggle.isPending}
                    onClick={() => toggle.mutate(s)}
                  >
                    {s.enabled
                      ? t("SLAReportsPanel.schedules.pause")
                      : t("SLAReportsPanel.schedules.reapprove")}
                  </Button>
                </>
              )}
            </div>
          ))}
          <Pagination
            offset={scheduleOffset}
            total={schedules.data?.total ?? 0}
            change={setScheduleOffset}
          />
        </CardContent>
      </Card>
      {canWrite && (
        <Card>
          <CardHeader>
            <CardTitle>
              {editing
                ? t("SLAReportsPanel.form.reviewTitle")
                : t("SLAReportsPanel.form.createTitle")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={submitSchedule} className="space-y-3">
              <label className="block text-sm">
                {t("SLAReportsPanel.form.name")}
                <Input
                  required
                  maxLength={255}
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </label>
              <div className="flex flex-wrap gap-3">
                <label className="text-sm">
                  {t("SLAReportsPanel.form.frequency")}
                  <select
                    className={selectClass}
                    value={form.frequency}
                    onChange={(e) =>
                      setForm({ ...form, frequency: e.target.value })
                    }
                  >
                    <option value="weekly">
                      {t("SLAReportsPanel.frequencies.weekly")}
                    </option>
                    <option value="monthly">
                      {t("SLAReportsPanel.frequencies.monthly")}
                    </option>
                    <option value="quarterly">
                      {t("SLAReportsPanel.frequencies.quarterly")}
                    </option>
                  </select>
                </label>
                {form.frequency === "weekly" ? (
                  <label className="text-sm">
                    {t("SLAReportsPanel.form.dayOfWeek")}
                    <select
                      className={selectClass}
                      required
                      value={form.day_of_week ?? 0}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          day_of_week: Number(e.target.value),
                        })
                      }
                    >
                      {WEEKDAYS.map((day, index) => (
                        <option key={day} value={index}>
                          {t(`SLAReportsPanel.weekdays.${day}`)}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : (
                  <label className="text-sm">
                    {t("SLAReportsPanel.form.dayOfMonth")}
                    <Input
                      type="number"
                      min={1}
                      max={31}
                      required
                      value={form.day_of_month ?? 1}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          day_of_month: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                )}
                <label className="text-sm">
                  {t("SLAReportsPanel.form.timezone")}
                  <Input
                    required
                    value={form.timezone}
                    onChange={(e) =>
                      setForm({ ...form, timezone: e.target.value })
                    }
                  />
                </label>
                <label className="text-sm">
                  {t("SLAReportsPanel.form.localTime")}
                  <Input
                    type="time"
                    required
                    value={form.time_of_day}
                    onChange={(e) =>
                      setForm({ ...form, time_of_day: e.target.value })
                    }
                  />
                </label>
              </div>
              <label className="block text-sm">
                {t("SLAReportsPanel.form.policyIds")}
                <Input
                  value={schedulePolicies}
                  onChange={(e) => setSchedulePolicies(e.target.value)}
                />
              </label>
              <p className="text-xs text-muted-foreground">
                {t("SLAReportsPanel.form.policyHint")}
              </p>
              {/* The shared Checkbox: a native box is a bright white square in the dark theme. */}
              <div className="flex items-center gap-2">
                <Checkbox
                  id={enabledId}
                  checked={form.enabled}
                  onCheckedChange={(checked) =>
                    setForm({ ...form, enabled: checked === true })
                  }
                />
                <Label htmlFor={enabledId} className="font-normal">
                  {t("SLAReportsPanel.form.enableGeneration")}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id={deliveryId}
                  checked={form.delivery_enabled}
                  onCheckedChange={(checked) =>
                    setForm({ ...form, delivery_enabled: checked === true })
                  }
                />
                <Label htmlFor={deliveryId} className="font-normal">
                  {t("SLAReportsPanel.form.sendEmail")}
                </Label>
              </div>
              <p className="text-sm">{t("SLAReportsPanel.form.emailExplain")}</p>
              <label className="block text-sm">
                {t("SLAReportsPanel.form.recipients")}
                <Input
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  required={form.delivery_enabled}
                />
              </label>
              <label className="block text-sm">
                {t("SLAReportsPanel.form.provider")}
                <select
                  className={selectClass}
                  value={form.delivery_provider_id ?? ""}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      delivery_provider_id: e.target.value || null,
                    })
                  }
                  required={form.delivery_enabled}
                >
                  <option value="">
                    {t("SLAReportsPanel.form.providerPlaceholder")}
                  </option>
                  {providers.data
                    ?.filter(
                      (p) =>
                        p.is_verified &&
                        p.is_enabled &&
                        ["smtp", "gmail_smtp"].includes(p.provider_type),
                    )
                    .map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                </select>
              </label>
              <div className="flex gap-3">
                <Button disabled={save.isPending}>
                  {editing
                    ? t("SLAReportsPanel.form.saveReapprove")
                    : t("SLAReportsPanel.form.create")}
                </Button>
                {editing && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setEditing(null);
                      setForm(emptySchedule());
                      setRecipients("");
                      setSchedulePolicies("");
                    }}
                  >
                    {t("SLAReportsPanel.form.cancelEdit")}
                  </Button>
                )}
              </div>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
