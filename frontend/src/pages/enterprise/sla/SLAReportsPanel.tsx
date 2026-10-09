// SPDX-License-Identifier: AGPL-3.0-only
import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
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

const PAGE_SIZE = 25;
const stamp = (value?: string | null) =>
  value ? new Date(value).toLocaleString() : "—";
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

function errorMessage(error: unknown): string {
  if (
    axios.isAxiosError(error) &&
    typeof error.response?.data?.detail === "string"
  )
    return error.response.data.detail;
  return error instanceof Error
    ? error.message
    : "The request failed. Refresh and try again.";
}

function Pagination({
  offset,
  total,
  change,
}: {
  offset: number;
  total: number;
  change: (n: number) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <Button
        variant="outline"
        disabled={offset === 0}
        onClick={() => change(Math.max(0, offset - PAGE_SIZE))}
      >
        Previous
      </Button>
      <span>
        {total === 0
          ? "0 results"
          : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}`}
      </span>
      <Button
        variant="outline"
        disabled={offset + PAGE_SIZE >= total}
        onClick={() => change(offset + PAGE_SIZE)}
      >
        Next
      </Button>
    </div>
  );
}

export function SLAReportsPanel({ policies }: { policies: SLAPolicy[] }) {
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
      setDownloadError(errorMessage(error));
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
        Reports follow your organization and site permissions. Date inputs use
        UTC; displayed timestamps use your browser's timezone. Scheduled runs
        use their configured timezone and run during the next hourly generation
        pass.
      </p>
      {errors.map((error, i) => (
        <p role="alert" className="text-destructive" key={i}>
          {errorMessage(error)}
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
            <CardTitle>Generate a report</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                generate.mutate();
              }}
            >
              <label>
                Start (inclusive)
                <Input
                  aria-label="Report start"
                  type="date"
                  required
                  value={start}
                  onChange={(e) => setStart(e.target.value)}
                />
              </label>
              <label>
                End (exclusive)
                <Input
                  aria-label="Report end"
                  type="date"
                  required
                  min={start}
                  value={end}
                  onChange={(e) => setEnd(e.target.value)}
                />
              </label>
              <label>
                Policies
                <select
                  aria-label="Report policies"
                  className="block rounded border bg-background p-2"
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
                <span className="text-xs">
                  No selection means all accessible policies.
                </span>
              </label>
              <label>
                Format
                <select
                  aria-label="Report format"
                  className="block rounded border bg-background p-2"
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
                Generate
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Report archive</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Last refreshed:{" "}
            {reports.dataUpdatedAt
              ? stamp(new Date(reports.dataUpdatedAt).toISOString())
              : "Waiting for response"}
          </p>
          {reports.isPending ? (
            <p>Loading reports…</p>
          ) : reports.data?.reports.length === 0 ? (
            <p>No reports have been generated.</p>
          ) : null}
          {selectedReport && (
            <Button
              variant="outline"
              onClick={() =>
                void download({ id: selectedReport, format: "pdf" })
              }
            >
              Download linked report
            </Button>
          )}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Generated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.data?.reports.map((report) => (
                  <tr key={report.id} className="border-t">
                    <td className="py-3">
                      {report.title}
                      <p className="text-xs">
                        {stamp(report.period_start)} –{" "}
                        {stamp(report.period_end)}
                      </p>
                    </td>
                    <td>{stamp(report.generated_at)}</td>
                    <td>
                      <Button
                        variant="outline"
                        onClick={() => void download(report)}
                      >
                        Download {report.format.toUpperCase()}
                      </Button>
                      {canWrite && (
                        <Button
                          variant="ghost"
                          onClick={() => setParams({ report: report.id })}
                        >
                          Delivery status
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
            <CardTitle>Email delivery status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm">
              Accepted means the SMTP server accepted the notice; it does not
              prove inbox delivery. Unknown means acceptance could not be
              confirmed. Check relay logs using the delivery ID; FreeSDN will
              not automatically resend it.
            </p>
            {deliveries.isPending && <p>Loading delivery status…</p>}
            {deliveries.data?.length === 0 && (
              <p>No email deliveries were scheduled for this report.</p>
            )}
            {deliveries.data?.map((d) => (
              <div key={d.id} className="rounded border p-3 text-sm">
                <p>
                  {d.recipient_email}: <strong>{d.state}</strong> · {d.attempts}{" "}
                  attempts
                </p>
                <p className="break-all text-xs">Delivery ID: {d.id}</p>
                {d.error_code && <p>{d.error_code}</p>}
                {(d.state === "pending" || d.state === "retry") && (
                  <>
                    <p>Next attempt: {stamp(d.next_attempt_at)}</p>
                    <Button
                      variant="outline"
                      disabled={cancel.isPending}
                      onClick={() => cancel.mutate(d.id)}
                    >
                      Cancel pending delivery
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
          <CardTitle>Report schedules</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {schedules.isPending && <p>Loading schedules…</p>}
          {schedules.data?.schedules.length === 0 && (
            <p>No report schedules.</p>
          )}
          {schedules.data?.schedules.map((s) => (
            <div key={s.id} className="rounded border p-3 text-sm">
              <p>
                <strong>{s.name}</strong> · {s.enabled ? "Enabled" : "Paused"} ·{" "}
                {s.frequency} at {s.time_of_day} ({s.timezone})
              </p>
              <p>
                Next: {stamp(s.next_run_at)} · Last generated:{" "}
                {stamp(s.last_generated_at)} · Email:{" "}
                {s.delivery_enabled ? "Opted in" : "Off"}
              </p>
              {s.execution_error && (
                <p className="text-destructive">
                  Needs review: {s.execution_error}
                </p>
              )}
              {canWrite && (
                <>
                  <Button variant="ghost" onClick={() => edit(s)}>
                    Edit and review
                  </Button>
                  <Button
                    variant="outline"
                    disabled={toggle.isPending}
                    onClick={() => toggle.mutate(s)}
                  >
                    {s.enabled ? "Pause" : "Reapprove and enable"}
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
              {editing ? "Review schedule" : "Create schedule"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={submitSchedule} className="space-y-3">
              <label className="block">
                Name
                <Input
                  required
                  maxLength={255}
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </label>
              <div className="flex flex-wrap gap-3">
                <label>
                  Frequency
                  <select
                    className="block rounded border bg-background p-2"
                    value={form.frequency}
                    onChange={(e) =>
                      setForm({ ...form, frequency: e.target.value })
                    }
                  >
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                    <option value="quarterly">Quarterly</option>
                  </select>
                </label>
                {form.frequency === "weekly" ? (
                  <label>
                    Day (0 Monday – 6 Sunday)
                    <Input
                      type="number"
                      min={0}
                      max={6}
                      required
                      value={form.day_of_week ?? 0}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          day_of_week: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                ) : (
                  <label>
                    Day of month
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
                <label>
                  Timezone
                  <Input
                    required
                    value={form.timezone}
                    onChange={(e) =>
                      setForm({ ...form, timezone: e.target.value })
                    }
                  />
                </label>
                <label>
                  Local time
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
              <label className="block">
                Policy IDs (comma-separated; blank means all policies)
                <Input
                  value={schedulePolicies}
                  onChange={(e) => setSchedulePolicies(e.target.value)}
                />
              </label>
              <p className="text-xs text-muted-foreground">
                Site-limited operators must choose explicit policies. Editing a
                schedule replaces its delivery approval; old pending notices
                will be cancelled when processed.
              </p>
              <label className="flex gap-2">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) =>
                    setForm({ ...form, enabled: e.target.checked })
                  }
                />
                Enable report generation
              </label>
              <label className="flex gap-2">
                <input
                  type="checkbox"
                  checked={form.delivery_enabled}
                  onChange={(e) =>
                    setForm({ ...form, delivery_enabled: e.target.checked })
                  }
                />
                Send email notices for future scheduled reports
              </label>
              <p className="text-sm">
                Email is off by default. Notices contain a sign-in link, not an
                attachment. Recipients must be active users in this organization
                with access to the report. Configure an HTTPS FRONTEND_URL and
                verify your SMTP provider first.
              </p>
              <label className="block">
                Recipients (comma-separated)
                <Input
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  required={form.delivery_enabled}
                />
              </label>
              <label className="block">
                Verified SMTP provider
                <select
                  className="block rounded border bg-background p-2"
                  value={form.delivery_provider_id ?? ""}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      delivery_provider_id: e.target.value || null,
                    })
                  }
                  required={form.delivery_enabled}
                >
                  <option value="">Choose a provider</option>
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
                  {editing ? "Save and reapprove" : "Create schedule"}
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
                    Cancel edit
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
