// SPDX-License-Identifier: AGPL-3.0-only
import { api } from "./client";
import type { components } from "./generated/openapi";

export type Report = components["schemas"]["SLAReportResponse"];
export type ReportSchedule = components["schemas"]["SLAReportScheduleResponse"];
export type ReportScheduleInput =
  components["schemas"]["SLAReportScheduleCreate"];
export type ReportDelivery = components["schemas"]["SLAReportDeliveryResponse"];

export const slaReportsApi = {
  list: (offset: number) =>
    api.get<{ reports: Report[]; total: number }>("/sla/reports", {
      params: { limit: 25, offset },
    }),
  generate: (data: components["schemas"]["SLAReportGenerateRequest"]) =>
    api.post<Report>("/sla/reports/generate", data),
  download: (id: string) =>
    api.get<Blob>(`/sla/reports/${encodeURIComponent(id)}/download`, {
      responseType: "blob",
    }),
  schedules: (offset: number) =>
    api.get<{ schedules: ReportSchedule[]; total: number }>(
      "/sla/report-schedules",
      { params: { limit: 25, offset } },
    ),
  create: (data: ReportScheduleInput) =>
    api.post<ReportSchedule>("/sla/report-schedules", data),
  update: (
    id: string,
    data: components["schemas"]["SLAReportScheduleUpdate"],
  ) =>
    api.put<ReportSchedule>(
      `/sla/report-schedules/${encodeURIComponent(id)}`,
      data,
    ),
  deliveries: (id: string) =>
    api.get<ReportDelivery[]>(
      `/sla/reports/${encodeURIComponent(id)}/deliveries`,
    ),
  cancel: (reportId: string, deliveryId: string) =>
    api.post<ReportDelivery>(
      `/sla/reports/${encodeURIComponent(reportId)}/deliveries/${encodeURIComponent(deliveryId)}/cancel`,
    ),
};
