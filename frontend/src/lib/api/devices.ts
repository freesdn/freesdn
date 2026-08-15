// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  DeviceCapabilitiesResponse,
  ActionResult,
  DeviceAction,
  PortState,
  IntentResponse,
} from './types';

export const devicesApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/devices/', { params }),
  getById: (id: string) => api.get(`/devices/${id}`),
  create: (data: Record<string, unknown>) => api.post('/devices/', data),
  update: (id: string, data: Record<string, unknown>) => api.patch(`/devices/${id}`, data),
  delete: (id: string) => api.delete(`/devices/${id}`),
  getStats: (siteId?: string) => api.get('/devices/stats/summary', { params: { site_id: siteId } }),
};

export const actionsApi = {
  poeCycle: (deviceId: string, port: number, duration?: number) =>
    api.post('/actions/poe/cycle', { device_id: deviceId, port, duration_seconds: duration }),
  toggleSsid: (controllerId: string, ssidName: string, enabled: boolean) =>
    api.post('/actions/wifi/ssid/toggle', { controller_id: controllerId, ssid_name: ssidName, enabled }),
  getSnapshot: (deviceId: string, stream?: string) =>
    api.post('/actions/camera/snapshot', { device_id: deviceId, stream }),
};

/** Device ports API (via Driver SDK) */
export const devicePortsApi = {
  getPorts: (deviceId: string, live?: boolean) =>
    api.get<PortState[]>(`/devices/${deviceId}/ports`, { params: { live } }),

  getPort: (deviceId: string, portNumber: number) =>
    api.get<PortState>(`/devices/${deviceId}/ports/${portNumber}`),

  setPoeState: (deviceId: string, portNumber: number, enabled: boolean, powerLimit?: number) =>
    api.post<IntentResponse>(`/devices/${deviceId}/ports/${portNumber}/poe`, {
      enabled,
      power_limit: powerLimit,
    }),

  cyclePoePort: (deviceId: string, portNumber: number, offDuration?: number) =>
    api.post<IntentResponse>(`/devices/${deviceId}/ports/${portNumber}/poe/cycle`, {
      off_duration: offDuration ?? 5,
    }),
};

export const deviceControlApi = {
  getCapabilities: (deviceId: string) =>
    api.get<DeviceCapabilitiesResponse>(`/devices/${deviceId}/capabilities`),

  reboot: (deviceId: string, force?: boolean) =>
    api.post<ActionResult>(`/devices/${deviceId}/reboot`, { force: force ?? false }),

  locate: (deviceId: string, enable?: boolean, durationSeconds?: number) =>
    api.post<ActionResult>(`/devices/${deviceId}/locate`, {
      enable: enable ?? true,
      duration_seconds: durationSeconds ?? 60,
    }),

  setPoeState: (deviceId: string, port: number, enabled: boolean) =>
    api.post<ActionResult>(`/devices/${deviceId}/poe`, { port, enabled }),

  cyclePoePort: (deviceId: string, port: number, delaySeconds?: number) =>
    api.post<ActionResult>(`/devices/${deviceId}/poe/cycle`, {
      port,
      delay_seconds: delaySeconds ?? 5,
    }),

  setSsidState: (deviceId: string, ssidName: string, enabled: boolean, radioId?: string) =>
    api.post<ActionResult>(`/devices/${deviceId}/ssid`, {
      ssid_name: ssidName,
      enabled,
      radio_id: radioId,
    }),

  setLed: (deviceId: string, setting: number) =>
    api.patch<ActionResult>(`/devices/${deviceId}/led`, { setting }),

  getActionHistory: (deviceId: string, limit?: number, offset?: number) =>
    api.get<{ items: DeviceAction[]; total: number }>(`/devices/${deviceId}/actions/history`, {
      params: { limit: limit ?? 50, offset: offset ?? 0 },
    }),
};
