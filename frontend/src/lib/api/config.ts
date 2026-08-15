// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  AutomationRule, AutomationExecution,
  Webhook, WebhookStats, WebhookDelivery,
  Integration, IntegrationType, IntegrationTemplate, EventCategory,
  FirmwareSummary, DeviceFirmwareStatus, FirmwareUpgradeJob,
  FirmwareSchedule, FirmwareSummaryResponse, FirmwarePaginatedResponse,
} from './types';

// ==================== Automation API ====================

export const automationApi = {
  listRules: (params?: { enabled?: boolean; trigger_type?: string; status?: string }) =>
    api.get<{ items: AutomationRule[]; total: number; page: number; per_page: number; pages: number }>('/automation', { params }),

  getRule: (id: string) =>
    api.get<AutomationRule>(`/automation/${id}`),

  createRule: (data: Partial<AutomationRule>) =>
    api.post<AutomationRule>('/automation', data),

  updateRule: (id: string, data: Partial<AutomationRule>) =>
    api.patch<AutomationRule>(`/automation/${id}`, data),

  deleteRule: (id: string) =>
    api.delete(`/automation/${id}`),

  // Backend ``TriggerRuleRequest`` expects ``{data}``, not ``{context}``.
  // The previous payload key was silently dropped by pydantic so
  // manual triggers always ran with an empty payload.
  triggerRule: (id: string, data?: Record<string, unknown>) =>
    api.post(`/automation/${id}/trigger`, { data: data ?? {} }),

  enableRule: (id: string) =>
    api.post<AutomationRule>(`/automation/${id}/enable`),

  disableRule: (id: string) =>
    api.post<AutomationRule>(`/automation/${id}/disable`),

  listExecutions: (params?: { rule_id?: string; status?: string; limit?: number; page?: number; per_page?: number }) =>
    api.get<{ items: AutomationExecution[]; total: number; page: number; per_page: number; pages: number }>('/automation/executions/all', { params }),

  getRuleExecutions: (ruleId: string, params?: { status?: string; page?: number; per_page?: number }) =>
    api.get<{ items: AutomationExecution[]; total: number; page: number; per_page: number; pages: number }>(`/automation/${ruleId}/executions`, { params }),

  getSummary: () =>
    api.get<{ total_rules: number; active_rules: number; paused_rules: number; disabled_rules: number; error_rules: number; total_executions: number; successful_executions: number; failed_executions: number; by_trigger_type: Record<string, number> }>('/automation/summary'),

  getActionTypes: () =>
    api.get<{ action_types: Record<string, unknown>[] }>('/automation/actions/types'),

  getTriggerTypes: () =>
    api.get<{ trigger_types: Record<string, unknown>[] }>('/automation/triggers/types'),
};

// ==================== Webhooks API ====================

export const webhooksApi = {
  list: (params?: { page?: number; per_page?: number; enabled?: boolean }) =>
    api.get<{ items: Webhook[]; total: number; page: number; per_page: number; pages: number }>('/webhooks', { params }),

  get: (id: string) =>
    api.get<Webhook>(`/webhooks/${id}`),

  create: (data: Partial<Webhook>) =>
    api.post<Webhook>('/webhooks', data),

  update: (id: string, data: Partial<Webhook>) =>
    api.patch<Webhook>(`/webhooks/${id}`, data),

  delete: (id: string) =>
    api.delete(`/webhooks/${id}`),

  enable: (id: string) =>
    api.post<Webhook>(`/webhooks/${id}/enable`),

  disable: (id: string) =>
    api.post<Webhook>(`/webhooks/${id}/disable`),

  getStats: (id: string) =>
    api.get<WebhookStats>(`/webhooks/${id}/stats`),

  // Backend returns a paginated envelope, not a bare array. Typed as
  // such so consumers reach for ``.items`` explicitly.
  getDeliveries: (id: string, params?: { status?: string; page?: number; per_page?: number }) =>
    api.get<{ items: WebhookDelivery[]; total: number; page: number; per_page: number }>(`/webhooks/${id}/deliveries`, { params }),

  test: (id: string) =>
    api.post<{ status: string; delivery_id: string; response_status?: number; response_time_ms?: number; error?: string }>(`/webhooks/${id}/test`),
};

// ==================== Integrations API ====================

export const integrationsApi = {
  list: (params?: { page?: number; per_page?: number; integration_type?: string }) =>
    api.get<{ items: Integration[]; total: number; page: number; per_page: number; pages: number }>(
      '/integrations/',
      { params },
    ),

  get: (id: string) =>
    api.get<Integration>(`/integrations/${id}`),

  create: (data: {
    name: string;
    description?: string;
    integration_type: string;
    url: string;
    secret?: string;
    event_subscriptions?: string[];
    config?: Record<string, unknown>;
    verify_ssl?: boolean;
  }) => api.post<Integration>('/integrations/', data),

  update: (id: string, data: {
    name?: string;
    description?: string;
    url?: string;
    secret?: string;
    event_subscriptions?: string[];
    config?: Record<string, unknown>;
    verify_ssl?: boolean;
  }) => api.patch<Integration>(`/integrations/${id}`, data),

  delete: (id: string) =>
    api.delete(`/integrations/${id}`),

  enable: (id: string) =>
    api.post(`/integrations/${id}/enable`),

  disable: (id: string) =>
    api.post(`/integrations/${id}/disable`),

  test: (id: string) =>
    api.post<{
      status: string;
      delivery_id: string;
      response_code?: number;
      response_time_ms?: number;
      error?: string;
    }>(`/integrations/${id}/test`),

  getTypes: () =>
    api.get<{ types: IntegrationType[] }>('/integrations/types'),

  getEventCategories: () =>
    api.get<{ categories: EventCategory[] }>('/integrations/event-categories'),

  getTemplates: () =>
    api.get<{ templates: IntegrationTemplate[] }>('/integrations/templates'),

  applyTemplate: (
    templateId: string,
    data: { url: string; name?: string; description?: string; secret?: string },
  ) => api.post<Integration>(`/integrations/templates/${templateId}/apply`, data),

  listDeadLetters: (
    webhookId: string,
    params?: { page?: number; per_page?: number },
  ) =>
    api.get<{
      items: {
        id: string;
        webhook_id: string;
        delivery_id: string;
        event_type: string;
        failure_reason?: string;
        attempt_count: number;
        final_attempt_at: string;
        replayed_at?: string;
        created_at: string;
      }[];
      total: number;
      page: number;
      per_page: number;
      pages: number;
    }>(`/webhooks/${webhookId}/dead-letters`, { params }),

  replayDeadLetter: (webhookId: string, dlqId: string) =>
    api.post<{ status: string; new_delivery_id: string; message: string }>(
      `/webhooks/${webhookId}/dead-letters/${dlqId}/replay`,
    ),

  replayAllDeadLetters: (webhookId: string) =>
    api.post<{ status: string; count: number }>(
      `/webhooks/${webhookId}/dead-letters/replay-all`,
    ),
};

// ==================== Firmware API ====================

export const firmwareApi = {
  // Firmware repository
  listFirmwares: (params?: {
    vendor?: string;
    model?: string;
    device_type?: string;
    release_type?: string;
    is_latest?: boolean;
    is_critical?: boolean;
    page?: number;
    page_size?: number;
  }) => api.get<FirmwarePaginatedResponse<FirmwareSummary>>('/firmware/', { params }),

  getFirmware: (id: string) =>
    api.get<FirmwareSummary>(`/firmware/${id}`),

  createFirmware: (data: Partial<FirmwareSummary>) =>
    api.post<FirmwareSummary>('/firmware/', data),

  updateFirmware: (id: string, data: Partial<FirmwareSummary>) =>
    api.put<FirmwareSummary>(`/firmware/${id}`, data),

  deleteFirmware: (id: string) =>
    api.delete(`/firmware/${id}`),

  cacheFirmware: (id: string) =>
    api.post(`/firmware/${id}/cache`),

  uploadFirmware: (file: File, metadata: {
    vendor: string;
    model?: string;
    version: string;
    release_type?: string;
  }) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post<FirmwareSummary>('/firmware/upload', formData, {
      params: metadata,
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },

  // Device firmware status
  listDeviceStatus: (params?: {
    site_id?: string;
    device_type?: string;
    vendor?: string;
    update_available?: boolean;
    critical_only?: boolean;
    search?: string;
    page?: number;
    page_size?: number;
  }) => api.get<FirmwarePaginatedResponse<DeviceFirmwareStatus>>('/firmware/devices/status', { params }),

  getDeviceStatus: (deviceId: string) =>
    api.get<DeviceFirmwareStatus>(`/firmware/devices/${deviceId}/status`),

  checkUpdates: (params?: {
    device_ids?: string[];
    site_id?: string;
  }) => api.post('/firmware/devices/check', params),

  // Compatibility
  checkCompatibility: (firmwareId: string, deviceIds: string[]) =>
    api.post('/firmware/compatibility/check', { firmware_id: firmwareId, device_ids: deviceIds }),

  // Upgrade jobs
  listJobs: (params?: {
    status?: string;
    site_id?: string;
    page?: number;
    page_size?: number;
  }) => api.get<FirmwarePaginatedResponse<FirmwareUpgradeJob>>('/firmware/jobs', { params }),

  getJob: (jobId: string) =>
    api.get<FirmwareUpgradeJob>(`/firmware/jobs/${jobId}`),

  createJob: (data: {
    device_ids: string[];
    firmware_id: string;
    scheduled_at?: string;
    backup_before?: boolean;
    rollback_on_failure?: boolean;
    batch_size?: number;
    delay_between_batches?: number;
    notify_on_complete?: boolean;
    notify_on_failure?: boolean;
  }) => api.post<FirmwareUpgradeJob>('/firmware/jobs', data),

  cancelJob: (jobId: string) =>
    api.post(`/firmware/jobs/${jobId}/cancel`),

  retryJob: (jobId: string, failedOnly?: boolean) =>
    api.post(`/firmware/jobs/${jobId}/retry`, null, { params: { failed_only: failedOnly } }),

  // Schedules
  listSchedules: (params?: {
    site_id?: string;
    is_enabled?: boolean;
  }) => api.get<FirmwarePaginatedResponse<FirmwareSchedule>>('/firmware/schedules', { params }),

  createSchedule: (data: Omit<FirmwareSchedule, 'id' | 'next_run_at' | 'last_run_at' | 'last_job_id' | 'total_runs' | 'organization_id' | 'created_at' | 'updated_at' | 'created_by'>) =>
    api.post<FirmwareSchedule>('/firmware/schedules', data),

  updateSchedule: (id: string, data: Partial<FirmwareSchedule>) =>
    api.put<FirmwareSchedule>(`/firmware/schedules/${id}`, data),

  deleteSchedule: (id: string) =>
    api.delete(`/firmware/schedules/${id}`),

  toggleSchedule: (id: string) =>
    api.post(`/firmware/schedules/${id}/toggle`),

  runScheduleNow: (id: string) =>
    api.post(`/firmware/schedules/${id}/run-now`),

  // Rollback
  rollbackDevice: (deviceId: string, params?: {
    target_version?: string;
    backup_id?: string;
  }) => api.post(`/firmware/devices/${deviceId}/rollback`, params),

  // Summary
  getSummary: (siteId?: string) =>
    api.get<FirmwareSummaryResponse>('/firmware/summary', { params: { site_id: siteId } }),
};
