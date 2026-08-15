// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Gateway diagnostics API client
 * =========================================
 *
 * Talks to /api/v1/gateway-diagnostics/*. Live telemetry: trigger
 * speed-test, fetch result, session stats, active session list.
 * The trigger is non-staged (it doesn't change config, just starts
 * a short measurement).
 */

import { api } from './client';

const prefix = (controllerId: string, siteId: string, mac: string) =>
  `/gateway-diagnostics/${controllerId}/sites/${siteId}/gateways/${mac}`;

export const gatewayDiagnosticsApi = {
  runSpeedTest: (controllerId: string, siteId: string, mac: string) =>
    api.post(`${prefix(controllerId, siteId, mac)}/speed-test`),

  getSpeedTestResult: (
    controllerId: string,
    siteId: string,
    mac: string,
  ) => api.get(`${prefix(controllerId, siteId, mac)}/speed-test`),

  getSessionStats: (
    controllerId: string,
    siteId: string,
    mac: string,
  ) => api.get(`${prefix(controllerId, siteId, mac)}/sessions`),

  listActiveSessions: (
    controllerId: string,
    siteId: string,
    mac: string,
    params?: { limit?: number },
  ) =>
    api.get(`${prefix(controllerId, siteId, mac)}/sessions/list`, {
      params,
    }),
};
