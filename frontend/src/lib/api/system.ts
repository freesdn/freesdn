// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  SystemInfo, HealthCheck, FrontendVersions,
  Backup, BackupCreate, BackupListResponse, BackupSchedule, BackupScheduleCreate,
  RestoreRequest, RestoreJob, BackupStats, ExportOptions, ImportResult,
  BackupManifestPreview,
  BackupType, BackupStatus, BackupStorageType,
  StorageLocation, StorageLocationCreate, StorageLocationUpdate,
  StorageLocationTestResult, SupportedStorageTypes,
  ConfigVersion, ConfigDiff,
  NotificationProvider, NotificationTemplate, NotificationPreference,
  InAppNotification, ProviderType, TestProviderResult,
  ModuleManifestResponse, ModuleStateResponse, OrgModuleResponse,
  ModuleNavigationResponse, ModuleWidgetsResponse,
} from './types';

// Adapter read-only mode. When ``read_only`` is true device writes are
// refused platform-wide (the safe monitor-only mode); false means
// read-write ("manage"). Admin-only on the backend.
export interface AdapterReadOnly {
  read_only: boolean;
}

export const systemApi = {
  getInfo: () =>
    api.get<SystemInfo>('/system/info'),

  getHealth: () =>
    api.get<HealthCheck>('/health'),

  getFrontendVersions: () =>
    api.get<FrontendVersions>('/system/frontend-versions'),

  // GET current adapter read-only mode → { read_only: boolean }
  getAdapterReadOnly: () =>
    api.get<AdapterReadOnly>('/system/settings/adapter-read-only'),

  // PUT new adapter read-only mode → echoes { read_only: boolean }
  setAdapterReadOnly: (read_only: boolean) =>
    api.put<AdapterReadOnly>('/system/settings/adapter-read-only', { read_only }),
};

export const backupApi = {
  // ========== INSTANT EXPORT/IMPORT ==========
  export: async (options: ExportOptions = {}) => {
    const params = new URLSearchParams();
    if (options.include_devices !== undefined) params.append('include_devices', String(options.include_devices));
    if (options.include_vlans !== undefined) params.append('include_vlans', String(options.include_vlans));
    if (options.include_ssids !== undefined) params.append('include_ssids', String(options.include_ssids));
    if (options.include_users !== undefined) params.append('include_users', String(options.include_users));
    if (options.include_automation !== undefined) params.append('include_automation', String(options.include_automation));
    if (options.include_settings !== undefined) params.append('include_settings', String(options.include_settings));
    if (options.compress !== undefined) params.append('compress', String(options.compress));

    const response = await api.get('/backups/export', {
      params,
      responseType: 'blob',
    });

    const contentDisposition = response.headers['content-disposition'];
    let filename = 'freesdn_config.json';
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?(.+)"?/);
      if (match) filename = match[1];
    }

    return { data: response.data, filename };
  },

  import: async (file: File, dryRun: boolean = true, overwriteExisting: boolean = false) => {
    const formData = new FormData();
    formData.append('file', file);

    return api.post<ImportResult>('/backups/import', formData, {
      params: {
        dry_run: dryRun,
        overwrite_existing: overwriteExisting,
      },
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },

  // ========== SCHEDULED BACKUPS ==========
  list: (params?: {
    site_id?: string; backup_type?: BackupType; status?: BackupStatus;
    storage_type?: BackupStorageType; search?: string; page?: number; per_page?: number;
  }) => api.get<BackupListResponse>('/backups', { params }),

  get: (id: string) => api.get<Backup>(`/backups/${id}`),
  create: (data: BackupCreate) => api.post<Backup>('/backups', data),
  delete: (id: string) => api.delete(`/backups/${id}`),
  download: (id: string) => api.get(`/backups/${id}/download`, { responseType: 'blob' }),
  getStats: (siteId?: string) => api.get<BackupStats>('/backups/stats', { params: { site_id: siteId } }),

  listSchedules: (params?: { site_id?: string; is_enabled?: boolean }) =>
    api.get<BackupSchedule[]>('/backups/schedules', { params }),
  getSchedule: (id: string) => api.get<BackupSchedule>(`/backups/schedules/${id}`),
  createSchedule: (data: BackupScheduleCreate) =>
    api.post<BackupSchedule>('/backups/schedules', data),
  updateSchedule: (id: string, data: Partial<BackupScheduleCreate> & { is_enabled?: boolean }) =>
    api.put<BackupSchedule>(`/backups/schedules/${id}`, data),
  deleteSchedule: (id: string) => api.delete(`/backups/schedules/${id}`),
  toggleSchedule: (id: string, enabled: boolean) =>
    api.post(`/backups/schedules/${id}/toggle`, { is_enabled: enabled }),

  restore: (data: RestoreRequest) => api.post<RestoreJob>('/backups/restore', data),
  getRestoreJob: (id: string) => api.get<RestoreJob>(`/backups/restore/${id}`),

  // v2 manifest preview, read the per-contributor sections (+ counts +
  // per-contributor restorability) WITHOUT restoring. Powers the
  // selective-restore dialog.
  previewManifest: (id: string) =>
    api.get<BackupManifestPreview>(`/backups/${id}/manifest`),
};

export const storageLocationsApi = {
  list: (params?: { storage_type?: BackupStorageType; is_active?: boolean }) =>
    api.get<StorageLocation[]>('/backups/storage-locations', { params }),
  get: (id: string) => api.get<StorageLocation>(`/backups/storage-locations/${id}`),
  create: (data: StorageLocationCreate) =>
    api.post<StorageLocation>('/backups/storage-locations', data),
  update: (id: string, data: StorageLocationUpdate) =>
    api.patch<StorageLocation>(`/backups/storage-locations/${id}`, data),
  delete: (id: string) => api.delete(`/backups/storage-locations/${id}`),
  test: (id: string) =>
    api.post<StorageLocationTestResult>(`/backups/storage-locations/${id}/test`),
  getSupportedTypes: () =>
    api.get<SupportedStorageTypes>('/backups/storage-locations/types/supported'),
};

// Backend response shape from /enterprise/devices/{id}/config-versions
interface BackendConfigVersionListItem {
  id: string;
  version_number: number;
  change_summary: string | null;
  source: string;
  created_by: string | null;
  created_at: string | null;
}

// Backend response from /enterprise/config-versions/{a}/diff/{b}
interface BackendConfigDiff {
  version_a: Record<string, unknown>;
  version_b: Record<string, unknown>;
  added: Record<string, unknown>;
  removed: Record<string, unknown>;
  changed: Record<string, unknown>;
  has_changes: boolean;
  unified_diff: string;
}

// NOTE: The previous ``configApi`` pointed at ``/api/v1/config/*``,
// nine routes that had been removed when the feature moved to
// ``/api/v1/enterprise/devices/.../config-versions``. SwitchesPage's
// Config History tab + Diff viewer was silently 404'ing on every
// switch click. Methods with zero consumers (backupDevice,
// restoreDevice, getTemplates, applyTemplate, backupSite, backupAll,
// etc.) were deleted; the two live methods (``getVersions``,
// ``compareVersions``) now map the backend response shape into the
// existing FE ConfigVersion / ConfigDiff types so the tab works
// end-to-end without rewriting the viewer component.
export const configApi = {
  getVersions: async (deviceId: string, limit?: number, offset?: number) => {
    const r = await api.get<BackendConfigVersionListItem[]>(
      `/enterprise/devices/${deviceId}/config-versions`,
      { params: { limit: limit ?? 20, offset: offset ?? 0 } },
    );
    const items: ConfigVersion[] = r.data.map((v) => ({
      id: v.id,
      version: v.version_number,
      config_hash: '',
      config_size: 0,
      change_type: v.source || 'change',
      status: 'recorded',
      initiated_by: v.created_by || 'system',
      notes: v.change_summary || undefined,
      created_at: v.created_at || new Date().toISOString(),
    }));
    return { data: { items, total: items.length } };
  },

  // Takes version IDs (UUIDs), not version numbers. The component
  // resolves the IDs from the version-list response and passes them
  // here. The backend computes ``added_lines`` / ``removed_lines``
  // from the unified diff so we synthesize them client-side from the
  // unified_diff payload to preserve the existing FE shape.
  compareVersions: async (_deviceId: string, versionAId: string, versionBId: string) => {
    const r = await api.get<BackendConfigDiff>(
      `/enterprise/config-versions/${versionAId}/diff/${versionBId}`,
    );
    const diff = r.data;
    const lines = (diff.unified_diff || '').split('\n');
    const added_lines = lines.filter((l) => l.startsWith('+') && !l.startsWith('+++')).length;
    const removed_lines = lines.filter((l) => l.startsWith('-') && !l.startsWith('---')).length;
    return {
      data: {
        version_a: versionAId,
        version_b: versionBId,
        has_changes: diff.has_changes,
        added_lines,
        removed_lines,
        modified_sections: Object.keys(diff.changed || {}),
        unified_diff: diff.unified_diff || '',
        summary: '',
      } as ConfigDiff,
    };
  },
};

export const notificationApi = {
  getProviders: (channel?: string, enabledOnly?: boolean) =>
    api.get<NotificationProvider[]>('/notifications/providers', {
      params: { channel, enabled_only: enabledOnly },
    }),

  getProviderTypes: () =>
    api.get<ProviderType[]>('/notifications/providers/types'),

  getProvider: (providerId: string) =>
    api.get<NotificationProvider>(`/notifications/providers/${providerId}`),

  createProvider: (data: {
    name: string; provider_type: string; config: Record<string, unknown>;
    is_enabled?: boolean; is_default?: boolean; rate_limit_per_hour?: number; rate_limit_per_day?: number;
  }) => api.post<NotificationProvider>('/notifications/providers', data),

  updateProvider: (providerId: string, data: {
    name?: string; config?: Record<string, unknown>; is_enabled?: boolean;
    is_default?: boolean; rate_limit_per_hour?: number; rate_limit_per_day?: number;
  }) => api.put<NotificationProvider>(`/notifications/providers/${providerId}`, data),

  deleteProvider: (providerId: string) =>
    api.delete(`/notifications/providers/${providerId}`),

  verifyProvider: (providerId: string) =>
    api.post<TestProviderResult>(`/notifications/providers/${providerId}/verify`),

  testProvider: (providerId: string, testEmail?: string) =>
    api.post<TestProviderResult>(`/notifications/providers/${providerId}/test`, null, {
      params: { test_email: testEmail },
    }),

  getTemplates: (channel?: string, enabledOnly?: boolean) =>
    api.get<NotificationTemplate[]>('/notifications/templates', {
      params: { channel, enabled_only: enabledOnly },
    }),

  getTemplate: (templateId: string) =>
    api.get<NotificationTemplate>(`/notifications/templates/${templateId}`),

  createTemplate: (data: Partial<NotificationTemplate>) =>
    api.post<NotificationTemplate>('/notifications/templates', data),

  updateTemplate: (templateId: string, data: Partial<NotificationTemplate>) =>
    api.put<NotificationTemplate>(`/notifications/templates/${templateId}`, data),

  deleteTemplate: (templateId: string) =>
    api.delete(`/notifications/templates/${templateId}`),

  previewTemplate: (templateId: string, variables: Record<string, unknown>) =>
    api.post<{
      subject?: string; body_html?: string; body_text?: string;
      slack_blocks?: Record<string, unknown>[];
    }>(`/notifications/templates/${templateId}/preview`, { variables }),

  getPreferences: () =>
    api.get<NotificationPreference>('/notifications/preferences'),

  updatePreferences: (data: Partial<NotificationPreference>) =>
    api.put<NotificationPreference>('/notifications/preferences', data),

  // NOTE: BE returns the paginated envelope ``{items, total, limit, offset,
  // unread_count}``. ``include_dismissed`` selects Active (false) vs
  // Archive (true). The ``InAppNotification`` row uses BE field names
  // ``body`` / ``read`` (not ``message`` / ``is_read``).
  getInAppNotifications: (
    unreadOnly?: boolean,
    limit?: number,
    offset?: number,
    includeDismissed?: boolean,
  ) =>
    api.get<{
      items: InAppNotification[];
      total: number;
      limit: number;
      offset: number;
      unread_count: number;
    }>(
      '/notifications/in-app',
      {
        params: {
          unread_only: unreadOnly,
          limit,
          offset,
          include_dismissed: includeDismissed,
        },
      },
    ),

  // Mute / snooze categories. ``expiresAt=null`` (or omitted) is a
  // permanent mute; pass an ISO-8601 timestamp to snooze.
  muteCategories: (categories: string[], expiresAt?: string | null) =>
    api.patch<{ muted_categories: Record<string, { muted_until: string | null }> }>(
      '/notifications/preferences/mute',
      { categories, expires_at: expiresAt ?? null },
    ),

  unmuteCategory: (category: string) =>
    api.delete(`/notifications/preferences/mute/${encodeURIComponent(category)}`),

  getUnreadCount: () =>
    api.get<{ total: number; by_severity: Record<string, number>; by_category: Record<string, number> }>(
      '/notifications/in-app/unread-count'
    ),

  markNotifications: (notificationIds: string[], action: 'read' | 'dismiss') =>
    api.post<{ marked: number }>('/notifications/in-app/mark', {
      notification_ids: notificationIds,
      action,
    }),

  markAllAsRead: () =>
    api.post<{ marked: number }>('/notifications/in-app/mark-all-read'),

  sendNotification: (data: {
    user_ids?: string[]; emails?: string[]; channels: string[];
    category: string; severity: string; template_slug?: string;
    variables?: Record<string, unknown>; subject?: string; body?: string; body_html?: string;
  }) => api.post('/notifications/send', data),

  getRules: (eventType?: string, enabledOnly?: boolean) =>
    api.get('/notifications/rules', {
      params: { event_type: eventType, enabled_only: enabledOnly },
    }),

  getEventTypes: () =>
    api.get<{ events: Array<{ type: string; description: string; category: string }> }>(
      '/notifications/rules/events'
    ),
};

export const modulesApi = {
  getAll: () =>
    api.get<ModuleManifestResponse[]>('/modules/'),

  getStates: () =>
    api.get<ModuleStateResponse[]>('/modules/states'),

  getById: (moduleId: string) =>
    api.get<ModuleManifestResponse>(`/modules/${moduleId}`),

  getOrgModules: (orgId: string, includeDisabled = true) =>
    api.get<OrgModuleResponse[]>(`/modules/org/${orgId}`, { params: { include_disabled: includeDisabled } }),

  enableModule: (orgId: string, moduleId: string) =>
    api.post<OrgModuleResponse>(`/modules/org/${orgId}/enable`, { module_id: moduleId }),

  disableModule: (orgId: string, moduleId: string) =>
    api.post<OrgModuleResponse>(`/modules/org/${orgId}/disable`, { module_id: moduleId }),

  updateSettings: (orgId: string, moduleId: string, settings: Record<string, unknown>) =>
    api.put(`/modules/org/${orgId}/${moduleId}/settings`, { settings }),

  getNavigation: (orgId: string) =>
    api.get<ModuleNavigationResponse>(`/modules/org/${orgId}/navigation`),

  getWidgets: (orgId: string) =>
    api.get<ModuleWidgetsResponse>(`/modules/org/${orgId}/widgets`),

  getFeatureFlags: (orgId: string, moduleId: string) =>
    api.get(`/modules/org/${orgId}/${moduleId}/features`),

  updateFeatureFlag: (orgId: string, moduleId: string, featureKey: string, enabled: boolean) =>
    api.put(`/modules/org/${orgId}/${moduleId}/features/${featureKey}`, { enabled }),
};
