// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  Credential, CreateCredentialRequest, SecurityEvent,
} from './types';

export const credentialsApi = {
  // List credentials. NOTE: the backend returns a BARE ARRAY
  // (response_model=list[CredentialResponse]), not a {items} envelope.
  list: (params?: { scope?: string; vendor?: string; site_id?: string }) =>
    api.get<Credential[]>('/credentials', { params }),

  // Create credential
  create: (data: CreateCredentialRequest) =>
    api.post<Credential>('/credentials', data),

  // Update credential
  update: (id: string, data: Partial<CreateCredentialRequest>) =>
    api.put<Credential>(`/credentials/${id}`, data),

  // Delete credential
  delete: (id: string) =>
    api.delete(`/credentials/${id}`),

  // Test credential, matches backend CredentialTestResponse
  test: (id: string, targetIp: string) =>
    api.post<{
      success: boolean;
      message: string;
      device_info?: Record<string, unknown> | null;
      capabilities?: string[];
    }>(`/credentials/${id}/test`, { target_ip: targetIp }),
};

export const securityAuditApi = {
  // Only these reach the backend. `user_id`, `start_time`/`end_time` and
  // `site_id` were advertised here but /security/events accepts none of
  // them -- it takes start_date/end_date, and security events carry no
  // site column at all -- so they were silently dropped on every request.
  listEvents: (params?: {
    event_type?: string;
    severity?: string;
    category?: string;
    search?: string;
    reviewed?: boolean;
    start_date?: string;
    end_date?: string;
    page?: number;
    page_size?: number;
  }) =>
    api.get<{ items: SecurityEvent[]; total: number }>('/security/events', { params }),

  getSummary: (params?: { period?: string }) =>
    api.get('/security/summary', { params }),

  getAnomalies: (params?: { period?: string }) =>
    api.get('/security/anomalies', { params }),

  getUserActivity: (userId: string, period?: string) =>
    api.get(`/security/user/${userId}/activity`, { params: { period } }),

  getIpActivity: (ip: string, period?: string) =>
    api.get(`/security/ip/${ip}/activity`, { params: { period } }),

  getComplianceReport: (reportType?: string, period?: string) =>
    api.get('/security/compliance/report', { params: { report_type: reportType, period } }),

  getEventTypes: () =>
    api.get<{ event_types: Record<string, unknown>[] }>('/security/event-types'),

  exportLog: (startTime: string, endTime: string, format?: string) =>
    api.post('/security/export', null, { params: { start_time: startTime, end_time: endTime, format } }),
};
