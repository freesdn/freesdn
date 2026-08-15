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
  listEvents: (params?: {
    event_type?: string;
    severity?: string;
    user_id?: string;
    start_time?: string;
    end_time?: string;
    page?: number;
    page_size?: number;
    site_id?: string;
  }) =>
    api.get<{ items: SecurityEvent[]; total: number }>('/security/events', { params }),

  getSummary: (params?: { period?: string; site_id?: string }) =>
    api.get('/security/summary', { params }),

  getAnomalies: (params?: { period?: string; site_id?: string }) =>
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
