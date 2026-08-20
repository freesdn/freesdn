// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api, API_URL, getWebSocketUrl } from './client';
import { getDemoCameraSnapshotPath } from '@/demo/fixtures';
import { isDemoMode } from '@/demo/mode';
import type {
  SmartCapabilities, MotionDetectionConfig, PrivacyMaskConfig, LineCrossingConfig,
  IntrusionDetectionConfig, RecordingScheduleConfig, FaceDetectionConfig,
  HolidayScheduleConfig, PTZPatrol, PTZPatrolAction,
  CameraHealthData, CameraHealthHistory, FleetHealthSummary,
  NVRConnectionTestRequest, NVRConnectionTestResponse, NVRDiscoveryResponse,
  NVRImportRequest, NVRImportResponse, NVRSyncResponse,
  StandaloneCameraImportRequest, StandaloneCameraImportResponse,
  NVRChannelStatus, HolidayListConfig, HolidayEntry,
} from './types';

/** Encode a path segment for safe URL interpolation. */
const e = encodeURIComponent;

export interface CameraCreateRequest {
  name: string;
  ip_address: string;
  port?: number;
  site_id?: string;
  nvr_id?: string;
  channel_id?: number;
  vendor?: string;
  model?: string;
  device_type?: string;
  username?: string;
  password?: string;
  camera_type?: string;
  location?: string;
  description?: string;
}

export interface CameraUpdateRequest {
  name?: string;
  ip_address?: string;
  port?: number;
  site_id?: string;
  location?: string;
  description?: string;
  status?: string;
  camera_type?: string;
  stream_encryption_key?: string;
}

export interface ImageSettingsRequest {
  brightness?: number;
  contrast?: number;
  saturation?: number;
  sharpness?: number;
  hue?: number;
}

export interface StreamStats {
  active_streams: number;
  target_fps: number;
  frame_interval_ms: number;
  per_nvr: Record<string, { active: number; max: number; available: number }>;
  overloaded_nvrs: string[];
  snapshot_cache_channels: number;
}

export const camerasApi = {
  // Backend GET /cameras takes limit/offset (max limit 100); page/size are kept
  // for legacy callers but are ignored server-side, prefer limit/offset.
  getAll: (params?: { page?: number; size?: number; limit?: number; offset?: number; site_id?: string; status?: string; camera_type?: string; search?: string }) =>
    api.get('/cameras', { params }),
  getById: (id: string) => api.get(`/cameras/${e(id)}`),
  create: (data: CameraCreateRequest) => api.post('/cameras', data),
  update: (id: string, data: CameraUpdateRequest) => api.patch(`/cameras/${e(id)}`, data),
  delete: (id: string) => api.delete(`/cameras/${e(id)}`),
  getGroups: (params?: { site_id?: string }) => api.get('/cameras/groups', { params }),

  getSnapshot: (id: string) => api.get(`/cameras/${e(id)}/snapshot`, { responseType: 'blob' }),

  getStreamToken: async (id: string): Promise<string> => {
    const { data } = await api.post(`/cameras/${e(id)}/stream-token`);
    return data.token;
  },

  getSnapshotUrlAsync: async (id: string): Promise<string> => {
    if (isDemoMode) return getDemoCameraSnapshotPath(id);
    const token = await camerasApi.getStreamToken(id);
    const safeId = e(id);
    return `${API_URL}/api/v1/cameras/${safeId}/snapshot?token=${e(token)}`;
  },

  // Recorded frame at an absolute playback time (NVR recording, not live).
  // Backed by GET /cameras/{id}/playback-frame?time=<ISO>.
  getPlaybackFrameUrlAsync: async (id: string, time: string): Promise<string> => {
    if (isDemoMode) return getDemoCameraSnapshotPath(id);
    const token = await camerasApi.getStreamToken(id);
    const safeId = e(id);
    return `${API_URL}/api/v1/cameras/${safeId}/playback-frame?time=${e(time)}&token=${e(token)}`;
  },

  getMjpegStreamUrlAsync: async (id: string, quality: 'main' | 'sub' = 'sub'): Promise<string> => {
    if (isDemoMode) return getDemoCameraSnapshotPath(id);
    const token = await camerasApi.getStreamToken(id);
    const safeId = e(id);
    return `${API_URL}/api/v1/cameras/${safeId}/stream/mjpeg?quality=${quality}&token=${e(token)}`;
  },

  /** True live VIDEO (fragmented MP4 via the go2rtc restreamer) for a <video>
   *  element. Same-origin so the auth cookie is sent automatically; HEVC-capable
   *  browsers play it, others should fall back to the MJPEG snapshot URL. */
  getLiveVideoUrl: (id: string, quality: 'main' | 'sub' = 'main'): string =>
    isDemoMode ? getDemoCameraSnapshotPath(id) : `${API_URL}/api/v1/cameras/${e(id)}/live/stream.mp4?quality=${quality}`,

  /** Sub-second live via the go2rtc MSE WebSocket proxy (cookie auth on the
   *  same-origin handshake). Consumed by MseLivePlayer + MediaSource. */
  getLiveMseWsUrl: (id: string, quality: 'main' | 'sub' = 'main'): string =>
    isDemoMode ? '' : `${getWebSocketUrl().replace(/\/ws$/, '')}/cameras/${e(id)}/live/mse?quality=${quality}`,

  getStream: (id: string, quality?: string) => api.get(`/cameras/${e(id)}/stream`, { params: { quality } }),

  /** Recorded-footage availability (segments) for the scrubber, queried live
   *  from the NVR. Returns { segments: [{start,end,type}], supported }. */
  getCameraTimeline: (id: string, startIso: string, endIso: string) =>
    api.get(`/cameras/${e(id)}/timeline`, { params: { start: startIso, end: endIso } }),

  getStreamStats: async (): Promise<StreamStats> => {
    const { data } = await api.get('/cameras/streams/stats');
    return data;
  },

  getPTZPresets: (id: string) => api.get(`/cameras/${e(id)}/ptz/presets`),
  ptzControl: (id: string, action: string, speed?: number, preset?: number) =>
    api.post(`/cameras/${e(id)}/ptz`, null, { params: { action, speed: speed ?? 50, preset } }),
  setPTZPreset: (id: string, preset: number, name: string) =>
    api.post(`/cameras/${e(id)}/ptz/presets`, null, { params: { preset, name } }),

  getImageSettings: (id: string) => api.get(`/cameras/${e(id)}/image`),
  setImageSettings: (id: string, data: ImageSettingsRequest) => api.put(`/cameras/${e(id)}/image`, data),

  getRecordings: (params?: { camera_id?: string; start_time?: string; end_time?: string; recording_type?: string; limit?: number }) =>
    api.get('/cameras/recordings/search', { params }),
  getEvents: (params?: {
    camera_id?: string; event_type?: string; start_time?: string; end_time?: string;
    acknowledged?: boolean; limit?: number; offset?: number;
  }) => api.get('/cameras/events/', { params }),
  getUnacknowledgedCount: () => api.get<{ count: number }>('/cameras/events/unacknowledged/count'),
  getEvent: (eventId: string) => api.get(`/cameras/events/${e(eventId)}`),
  acknowledgeEvent: (eventId: string) => api.post(`/cameras/events/${e(eventId)}/acknowledge`),
  bulkAcknowledgeEvents: (eventIds: string[]) =>
    api.post('/cameras/events/acknowledge/bulk', { event_ids: eventIds }),

  listGroups: () => api.get('/cameras/groups/'),
  createGroup: (data: { name: string; description?: string; color?: string; icon?: string; camera_ids?: string[] }) =>
    api.post('/cameras/groups/', data),
  getGroup: (id: string) => api.get(`/cameras/groups/${e(id)}`),
  updateGroup: (id: string, data: { name?: string; description?: string; color?: string; icon?: string; camera_ids?: string[] }) =>
    api.patch(`/cameras/groups/${e(id)}`, data),
  deleteGroup: (id: string) => api.delete(`/cameras/groups/${e(id)}`),

  listViews: () => api.get('/cameras/views/'),
  createView: (data: { name: string; layout?: string; camera_ids?: string[]; description?: string; is_shared?: boolean }) =>
    api.post('/cameras/views/', data),
  updateView: (id: string, data: { name?: string; layout?: string; camera_ids?: string[]; description?: string; is_shared?: boolean; is_default?: boolean }) =>
    api.patch(`/cameras/views/${e(id)}`, data),
  deleteView: (id: string) => api.delete(`/cameras/views/${e(id)}`),

  getSmartCapabilities: (id: string) => api.get<SmartCapabilities>(`/cameras/${e(id)}/smart-capabilities`),

  getMotionDetection: (id: string) => api.get<MotionDetectionConfig>(`/cameras/${e(id)}/motion-detection`),
  setMotionDetection: (id: string, data: MotionDetectionConfig) => api.put<MotionDetectionConfig>(`/cameras/${e(id)}/motion-detection`, data),

  getPrivacyMasks: (id: string) => api.get<PrivacyMaskConfig>(`/cameras/${e(id)}/privacy-masks`),
  setPrivacyMasks: (id: string, data: PrivacyMaskConfig) => api.put<PrivacyMaskConfig>(`/cameras/${e(id)}/privacy-masks`, data),

  getLineCrossing: (id: string) => api.get<LineCrossingConfig>(`/cameras/${e(id)}/line-crossing`),
  setLineCrossing: (id: string, data: LineCrossingConfig) => api.put<LineCrossingConfig>(`/cameras/${e(id)}/line-crossing`, data),

  getIntrusionDetection: (id: string) => api.get<IntrusionDetectionConfig>(`/cameras/${e(id)}/intrusion-detection`),
  setIntrusionDetection: (id: string, data: IntrusionDetectionConfig) => api.put<IntrusionDetectionConfig>(`/cameras/${e(id)}/intrusion-detection`, data),

  getRecordingSchedule: (id: string) => api.get<RecordingScheduleConfig>(`/cameras/${e(id)}/recording-schedule`),
  setRecordingSchedule: (id: string, data: RecordingScheduleConfig) => api.put<RecordingScheduleConfig>(`/cameras/${e(id)}/recording-schedule`, data),

  getFaceDetection: (id: string) => api.get<FaceDetectionConfig>(`/cameras/${e(id)}/face-detection`),
  setFaceDetection: (id: string, data: Partial<FaceDetectionConfig>) => api.put<FaceDetectionConfig>(`/cameras/${e(id)}/face-detection`, data),

  getHolidaySchedule: (id: string) => api.get<HolidayScheduleConfig>(`/cameras/${e(id)}/holiday-schedule`),
  setHolidaySchedule: (id: string, data: HolidayScheduleConfig) => api.put<HolidayScheduleConfig>(`/cameras/${e(id)}/holiday-schedule`, data),

  getPTZTours: (id: string) => api.get<PTZPatrol[]>(`/cameras/${e(id)}/ptz/tours`),
  getPTZTour: (id: string, tourId: number) => api.get<PTZPatrol>(`/cameras/${e(id)}/ptz/tours/${e(tourId)}`),
  setPTZTour: (id: string, tourId: number, data: { name: string; enabled: boolean; actions: Omit<PTZPatrolAction, 'id'>[] }) =>
    api.put<PTZPatrol>(`/cameras/${e(id)}/ptz/tours/${e(tourId)}`, data),
  deletePTZTour: (id: string, tourId: number) => api.delete(`/cameras/${e(id)}/ptz/tours/${e(tourId)}`),
  startPTZTour: (id: string, tourId: number) => api.post(`/cameras/${e(id)}/ptz/tours/${e(tourId)}/start`),
  stopPTZTour: (id: string, tourId: number) => api.post(`/cameras/${e(id)}/ptz/tours/${e(tourId)}/stop`),

  getHealth: (id: string) => api.get<CameraHealthData>(`/cameras/${e(id)}/health`),
  getHealthHistory: (id: string, hours?: number) =>
    api.get<CameraHealthHistory>(`/cameras/${e(id)}/health/history`, { params: { hours: hours ?? 24 } }),
  getFleetHealth: () => api.get<FleetHealthSummary>(`/cameras/health/fleet-summary`),

  exportVideoClip: (id: string, data: { start_time: string; end_time: string; playback_uri?: string; watermark?: boolean }) =>
    api.post(`/cameras/${e(id)}/recordings/export`, data, { responseType: 'blob' }),

  // Recording templates
  listRecordingTemplates: () => api.get('/cameras/recording-templates/'),
  createRecordingTemplate: (data: { name: string; description?: string; schedule: Record<string, unknown> }) =>
    api.post('/cameras/recording-templates/', data),
  updateRecordingTemplate: (id: string, data: { name: string; description?: string; schedule: Record<string, unknown> }) =>
    api.patch(`/cameras/recording-templates/${e(id)}`, data),
  deleteRecordingTemplate: (id: string) => api.delete(`/cameras/recording-templates/${e(id)}`),
};

export const nvrApi = {
  testConnection: (data: NVRConnectionTestRequest) =>
    api.post<NVRConnectionTestResponse>('/cameras/nvrs/test-connection', data),
  discover: (data: NVRConnectionTestRequest) =>
    api.post<NVRDiscoveryResponse>('/cameras/nvrs/discover', data),
  import: (data: NVRImportRequest) =>
    api.post<NVRImportResponse>('/cameras/nvrs/import', data),
  importCamera: (data: StandaloneCameraImportRequest) =>
    api.post<StandaloneCameraImportResponse>('/cameras/nvrs/import-camera', data),
  sync: (nvrId: string) =>
    api.post<NVRSyncResponse>(`/cameras/nvrs/${e(nvrId)}/sync`),
  getStorage: (nvrId: string) =>
    api.get(`/cameras/nvrs/${e(nvrId)}/storage`),
  getAll: (params?: { site_id?: string; status?: string; limit?: number; offset?: number }) =>
    api.get('/cameras/nvrs/', { params }),
  getById: (id: string) => api.get(`/cameras/nvrs/${e(id)}`),
  getChannels: (id: string) => api.get(`/cameras/nvrs/${e(id)}/channels`),
  getStats: (params?: { site_id?: string }) => api.get('/cameras/nvrs/stats', { params }),
  update: (id: string, data: { name?: string; description?: string; ip_address?: string; port?: number; status?: string; channel_count?: number; username?: string; password?: string; stream_encryption_key?: string }) =>
    api.patch(`/cameras/nvrs/${e(id)}`, data),
  delete: (id: string) => api.delete(`/cameras/nvrs/${e(id)}`),
  // Stream stats are pool counters for this process, not per-site data;
  // the endpoint never had a site dimension to filter on.
  getStreamStats: () => api.get('/cameras/streams/stats'),

  getSystemInfo: (id: string) => api.get(`/cameras/nvrs/${e(id)}/system-info`),
  getNetwork: (id: string) => api.get(`/cameras/nvrs/${e(id)}/network`),
  getRecordingStatus: (id: string) => api.get(`/cameras/nvrs/${e(id)}/recording-status`),
  searchRecordings: (id: string, params: { channel: number; start_time: string; end_time: string; max_results?: number }) =>
    api.post(`/cameras/nvrs/${e(id)}/recordings/search`, null, { params }),
  getPlaybackInfo: (nvrId: string, cameraId: string, params: { start_time: string; end_time: string }) =>
    api.get(`/cameras/nvrs/${e(nvrId)}/playback/${e(cameraId)}`, { params }),
  // NVR reboot is catastrophic (drops all streams/recordings ~1-2 min) and only
  // reached after the confirm dialog; thread confirmed=true so the backend gate passes.
  reboot: (id: string) => api.post(`/cameras/nvrs/${e(id)}/reboot`, undefined, { params: { confirmed: true } }),

  getChannelStatus: (id: string) =>
    api.get<NVRChannelStatus>(`/cameras/nvrs/${e(id)}/channel-status`),

  getHolidays: (id: string) =>
    api.get<HolidayListConfig>(`/cameras/nvrs/${e(id)}/holidays`),
  setHolidays: (id: string, data: { holidays: Partial<HolidayEntry>[] }) =>
    api.put<HolidayListConfig>(`/cameras/nvrs/${e(id)}/holidays`, data),
};

// ── Camera Access Control (Per-Camera RBAC) ──────────────────────────────────

export interface CameraAccessGrant {
  id: string;
  user_id: string;
  camera_id: string | null;
  group_id: string | null;
  access_level: 'viewer' | 'operator' | 'full';
  can_live: boolean;
  can_playback: boolean;
  can_ptz: boolean;
  can_export: boolean;
  can_configure: boolean;
  expires_at: string | null;
  created_at: string | null;
  user_email: string | null;
  user_name: string | null;
}

export interface CameraAccessCheck {
  has_access: boolean;
  access_level: string | null;
  can_live: boolean;
  can_playback: boolean;
  can_ptz: boolean;
  can_export: boolean;
  can_configure: boolean;
  grant_source: string | null;
}

export const cameraAccessApi = {
  listGrants: (params?: { camera_id?: string; user_id?: string }) =>
    api.get<{ items: CameraAccessGrant[]; total: number }>('/cameras/access/grants', { params }),

  createGrant: (data: {
    user_id: string;
    camera_id?: string;
    group_id?: string;
    access_level?: string;
    can_live?: boolean;
    can_playback?: boolean;
    can_ptz?: boolean;
    can_export?: boolean;
    can_configure?: boolean;
    expires_at?: string;
  }) => api.post<CameraAccessGrant>('/cameras/access/grants', data),

  updateGrant: (id: string, data: {
    access_level?: string;
    can_live?: boolean;
    can_playback?: boolean;
    can_ptz?: boolean;
    can_export?: boolean;
    can_configure?: boolean;
    expires_at?: string | null;
  }) => api.patch<CameraAccessGrant>(`/cameras/access/grants/${e(id)}`, data),

  deleteGrant: (id: string) => api.delete(`/cameras/access/grants/${e(id)}`),

  checkAccess: (cameraId: string) =>
    api.get<CameraAccessCheck>(`/cameras/access/check/${e(cameraId)}`),

  checkUserAccess: (cameraId: string, userId: string) =>
    api.get<CameraAccessCheck>(`/cameras/access/check/${e(cameraId)}/user/${e(userId)}`),
};

// ── HLS Streaming ────────────────────────────────────────────────────────────

export const hlsStreamApi = {
  // Live HLS (transcodes the camera's live RTSP stream).
  start: (cameraId: string, params: { quality?: string; sub_stream?: boolean }) =>
    api.post(`/cameras/${e(cameraId)}/stream/hls/start`, params),

  // Recorded-playback HLS, plays NVR footage forward from an absolute instant.
  // quality 'low' = H.264 ~360p (universal, real-time); 'source' = HEVC copy
  // (real-time full-res, HEVC-capable clients only). duration_s = forward window.
  startPlayback: (
    cameraId: string,
    params: { start_time: string; quality?: string; duration_s?: number },
  ) => api.post(`/cameras/${e(cameraId)}/playback/hls/start`, params),

  // stop/heartbeat live on the hls_router mounted at /cameras/streams/hls
  // (keyed by session id only, NOT under the camera path).
  stop: (sessionId: string) => api.delete(`/cameras/streams/hls/${e(sessionId)}`),

  heartbeat: (sessionId: string) =>
    api.post(`/cameras/streams/hls/${e(sessionId)}/heartbeat`),
};

// ── WebPush (browser push notifications for camera alerts) ───────────────────

export interface VapidKeyResponse {
  enabled: boolean;
  public_key: string;
}

export const pushApi = {
  /** VAPID public key + whether push is configured server-side. */
  getVapidKey: () => api.get<VapidKeyResponse>('/cameras/push/vapid-key'),
  subscribe: (subscription: PushSubscriptionJSON) =>
    api.post('/cameras/push/subscribe', subscription),
  unsubscribe: (endpoint: string) =>
    api.post('/cameras/push/unsubscribe', { endpoint }),
};

// ── Network discovery (ONVIF WS-Discovery) ───────────────────────────────────

export interface DiscoveredOnvifDevice {
  ip: string;
  vendor?: string | null;
  model?: string | null;
  hardware?: string | null;
  xaddrs: string[];
}

// Named cameraDiscoveryApi to avoid clashing with the platform network-discovery
// `discoveryApi` exported through the same barrel.
export const cameraDiscoveryApi = {
  /** Probe the server's LAN for ONVIF cameras/NVRs (read-only, nothing imported). */
  scan: (timeout = 4) =>
    api.post<{ devices: DiscoveredOnvifDevice[]; count: number }>(
      '/cameras/discovery/scan',
      null,
      { params: { timeout } },
    ),
};

// ── Evidence archive (legal hold) ────────────────────────────────────────────

export interface EvidenceArchive {
  id: string;
  camera_id: string;
  camera_name?: string | null;
  start_time: string;
  end_time: string;
  watermarked: boolean;
  status: 'pending' | 'archiving' | 'ready' | 'failed';
  file_size?: number | null;
  sha256?: string | null;
  note?: string | null;
  error?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export const evidenceApi = {
  /** Place a time window on legal hold (copies it off the NVR with a hash). */
  create: (data: { camera_id: string; start_time: string; end_time: string; watermark?: boolean; note?: string }) =>
    api.post<EvidenceArchive>('/cameras/evidence', data),
  /** Place the SAME window on hold for many cameras at once (one sealed clip each). */
  createBatch: (data: { camera_ids: string[]; start_time: string; end_time: string; watermark?: boolean; note?: string }) =>
    api.post<{ items: EvidenceArchive[] }>('/cameras/evidence/batch', data),
  list: (cameraId?: string) =>
    api.get<{ items: EvidenceArchive[] }>('/cameras/evidence', { params: { camera_id: cameraId } }),
  /** Same-origin download URL (the httpOnly cookie authenticates the GET). */
  downloadUrl: (id: string) =>
    isDemoMode ? '#' : `${API_URL}/api/v1/cameras/evidence/${e(id)}/download`,
  /** Same-origin ZIP-bundle URL for several ready archives + a SHA-256 manifest. */
  bundleUrl: (ids: string[]) =>
    isDemoMode ? '#' : `${API_URL}/api/v1/cameras/evidence/bundle?ids=${ids.map(e).join(',')}`,
  remove: (id: string) => api.delete(`/cameras/evidence/${e(id)}`),
};

// ── Codec Detection ──────────────────────────────────────────────────────────

export const codecApi = {
  getInfo: (cameraId: string) =>
    api.get(`/cameras/${e(cameraId)}/codec-info`),
};

// ── Cross-site Recording Search ──────────────────────────────────────────────

export const crossSiteRecordingsApi = {
  search: (params: {
    start_time: string;
    end_time: string;
    site_ids?: string[];
    camera_ids?: string[];
    keyword?: string;
    page?: number;
    per_page?: number;
  }) => api.post('/cameras/recordings/search-cross-site', params),
};

// ── Reports ──────────────────────────────────────────────────────────────────

export interface CameraReportData {
  total_cameras?: number;
  online_cameras?: number;
  total_events?: number;
  uptime_pct?: number;
  total_snapshots?: number;
  online_snapshots?: number;
}

export interface CameraReport {
  id: string;
  report_type: string;
  period_start: string;
  period_end: string;
  data: CameraReportData;
  generated_at: string;
}

export interface CameraReportListResponse {
  items: CameraReport[];
  total: number;
}

export const cameraReportsApi = {
  list: (params?: { report_type?: string; limit?: number }) =>
    api.get<CameraReportListResponse>('/cameras/reports/', { params }),
  getById: (reportId: string) => api.get<CameraReport>(`/cameras/reports/${e(reportId)}`),
};

// ── Two-way Audio ────────────────────────────────────────────────────────────

export const cameraAudioApi = {
  start: (cameraId: string) =>
    api.post(`/cameras/${e(cameraId)}/audio/start`),

  stop: (cameraId: string) =>
    api.post(`/cameras/${e(cameraId)}/audio/stop`),
};

// ── Thermal Camera ───────────────────────────────────────────────────────────

export const thermalApi = {
  getData: (cameraId: string) =>
    api.get(`/cameras/${e(cameraId)}/thermal`),

  setThreshold: (cameraId: string, params: { min_temp: number; max_temp: number; alert_enabled: boolean }) =>
    api.put(`/cameras/${e(cameraId)}/thermal/threshold`, params),
};

// ── LPR (License Plate Recognition) ──────────────────────────────────────────

export const lprApi = {
  getConfig: (cameraId: string) =>
    api.get(`/cameras/${e(cameraId)}/lpr/config`),

  setConfig: (cameraId: string, config: { provider: string; api_url?: string; api_key?: string; enabled?: boolean }) =>
    api.put(`/cameras/${e(cameraId)}/lpr/config`, config),
};

// ── AI Scene Labeling ────────────────────────────────────────────────────────

export const sceneApi = {
  analyze: (cameraId: string) =>
    api.post(`/cameras/${e(cameraId)}/scene/analyze`),

  getLabels: (cameraId: string) =>
    api.get(`/cameras/${e(cameraId)}/scene/labels`),
};

// ── PTZ Auto-tracking ────────────────────────────────────────────────────────

export const ptzAutoTrackingApi = {
  get: (cameraId: string) =>
    api.get(`/cameras/${e(cameraId)}/ptz/auto-tracking`),

  set: (cameraId: string, params: { enabled: boolean; track_duration_sec?: number; sensitivity?: number }) =>
    api.put(`/cameras/${e(cameraId)}/ptz/auto-tracking`, params),
};

// ── NVR Time Drift ───────────────────────────────────────────────────────────

export const nvrHealthApi = {
  getTimeDrift: (params?: { threshold_seconds?: number }) =>
    api.get('/cameras/nvrs/health/time-drift', { params }),
};

// ── Stream Stats (enhanced) ──────────────────────────────────────────────────

export const streamStatsApi = {
  get: () => api.get('/cameras/streams/stats'),
};
