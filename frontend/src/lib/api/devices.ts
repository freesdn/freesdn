// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  DeviceCapabilitiesResponse,
  ActionResult,
} from './types';

export const devicesApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/devices/', { params }),
  getById: (id: string) => api.get(`/devices/${id}`),
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

export const deviceControlApi = {
  getCapabilities: (deviceId: string) =>
    api.get<DeviceCapabilitiesResponse>(`/devices/${deviceId}/capabilities`),

  // The backend takes `confirm` as a QUERY parameter and 400s without it
  // (devices.py: `confirm: bool = False`, "Rebooting disrupts the device; pass
  // confirm=true to proceed."). This used to POST `{ force: false }` as a BODY,
  // which the endpoint ignores entirely -- so every Reboot button in the product
  // failed 100% of the time with that 400. Callers MUST obtain the operator's
  // confirmation before calling; the query flag is the acknowledgement the
  // backend asks for, not a way around it.
  reboot: (deviceId: string) =>
    api.post<ActionResult>(`/devices/${deviceId}/reboot?confirm=true`),

  locate: (deviceId: string, enable?: boolean, durationSeconds?: number) =>
    api.post<ActionResult>(`/devices/${deviceId}/locate`, {
      enable: enable ?? true,
      duration_seconds: durationSeconds ?? 60,
    }),


  setLed: (deviceId: string, setting: number) =>
    api.patch<ActionResult>(`/devices/${deviceId}/led`, { setting }),
};
