// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard API
 */
import { api } from './api';

// Types
export type SetupStep = 
  | 'not_started'
  | 'welcome'
  | 'database'
  | 'admin'
  | 'organization'
  | 'modules'
  | 'controllers'
  | 'complete';

export interface SetupStatus {
  is_complete: boolean;
  current_step: SetupStep;
  steps_completed: SetupStep[];
  message?: string;
}

export interface SystemRequirement {
  name: string;
  required: string;
  actual: string;
  passed: boolean;
  message?: string;
}

export interface StackInfo {
  name: string;
  version: string;
  category: string;
}

export interface DockerService {
  name: string;
  host: string;
  reachable: boolean;
  version?: string;
}

export interface WelcomeResponse {
  app_name: string;
  app_version: string;
  environment: string;
  requirements: SystemRequirement[];
  all_requirements_met: boolean;
  can_proceed: boolean;
  stack_info?: StackInfo[];
  docker_services?: DockerService[];
}

export interface DatabaseCheckResponse {
  connected: boolean;
  database_type?: string;
  database_version?: string;
  timescale_enabled?: boolean;
  timescale_version?: string;
  timescale_location?: string;
  logdb_connected?: boolean;
  schema_current?: boolean;
  migrations_pending?: number;
  migrations_applied?: number;
  error?: string;
}

export interface AdminCreateRequest {
  email: string;
  username: string;
  password: string;
  first_name?: string;
  last_name?: string;
  // Atomic-org bundle (v2.6+): when the Admin step submits these
  // alongside the user fields, the backend creates the first org +
  // default site + user→org link in the same transaction. Without
  // them the super_admin is created with organization_id=NULL,
  // every follow-up /setup/* call hits the now-closed gate, and
  // device-add flows silently 422 because the user has no org
  // context.
  organization_name?: string;
  organization_slug?: string;
  organization_timezone?: string;
  organization_locale?: string;
}

export interface AdminCreateResponse {
  success: boolean;
  user_id?: string;
  email?: string;
  username?: string;
  organization_id?: string;
  organization_slug?: string;
  default_site_id?: string;
  error?: string;
}

export interface OrganizationCreateRequest {
  name: string;
  slug?: string;
  timezone?: string;
  locale?: string;
  time_format?: string;
  date_format?: string;
  admin_id?: string;
}

export interface OrganizationCreateResponse {
  success: boolean;
  organization_id?: string;
  site_id?: string;
  name?: string;
  slug?: string;
  error?: string;
}

export interface ModuleOption {
  id: string;
  name: string;
  description: string;
  category: string;
  recommended: boolean;
  requires?: string[];
}

export interface ModuleSelectionRequest {
  enabled_modules: string[];
  organization_id: string;
}

export interface ModuleSelectionResponse {
  success: boolean;
  enabled_modules?: string[];
  error?: string;
}

export interface ControllerType {
  adapter_id: string;
  name: string;
  vendor: string;
  description: string;
  requires_controller: boolean;
  icon?: string;
}

export interface ControllerAddRequest {
  adapter_id: string;
  name: string;
  host: string;
  port?: number;
  username: string;
  password: string;
  verify_ssl?: boolean;
  site_id?: string;
  // Cloud mode fields
  connection_mode?: 'local' | 'cloud';
  client_id?: string;
  client_secret?: string;
  omada_id?: string;
  cloud_region?: string;
  // Site mappings: { omada_site_id: freesdn_site_uuid }
  site_mappings?: Record<string, string>;
}

export interface ControllerTestResult {
  success: boolean;
  adapter_id: string;
  host: string;
  message?: string;
  error?: string;
  devices_found?: number;
}

export interface ControllerAddResponse {
  success: boolean;
  controller_id?: string;
  test_result?: ControllerTestResult;
  error?: string;
}

export interface SetupSummary {
  admin_email: string;
  organization_name: string;
  enabled_modules: string[];
  controllers_added: number;
  total_devices: number;
}

export interface SetupCompleteRequest {
  install_sample_data?: boolean;
  organization_id?: string;
  site_id?: string;
  start_discovery?: boolean;
  send_welcome_email?: boolean;
}

export interface SetupCompleteResponse {
  success: boolean;
  summary?: SetupSummary;
  sample_data?: SampleDataResponse;
  login_url?: string;
  error?: string;
}

export interface SampleDataRequest {
  organization_id: string;
  site_id: string;
}

export interface SampleDataResponse {
  success: boolean;
  devices_created?: number;
  vlans_created?: number;
  wifi_networks_created?: number;
  clients_created?: number;
  alerts_created?: number;
  events_created?: number;
  audit_logs_created?: number;
  incidents_created?: number;
  backups_created?: number;
  firmware_images_created?: number;
  message?: string;
  error?: string;
}

// API Functions
export const setupApi = {
  /**
   * Get current setup status
   */
  getStatus: async (): Promise<SetupStatus> => {
    const response = await api.get('/setup/status');
    return response.data;
  },

  /**
   * Get welcome/system requirements
   */
  getWelcome: async (): Promise<WelcomeResponse> => {
    const response = await api.get('/setup/welcome');
    return response.data;
  },

  /**
   * Check database status
   */
  checkDatabase: async (): Promise<DatabaseCheckResponse> => {
    const response = await api.get('/setup/database');
    return response.data;
  },

  /**
   * Run database migrations
   */
  runMigrations: async (): Promise<{ success: boolean; message: string }> => {
    const response = await api.post('/setup/database/migrate');
    return response.data;
  },

  /**
   * Create admin user
   */
  createAdmin: async (data: AdminCreateRequest): Promise<AdminCreateResponse> => {
    const response = await api.post('/setup/admin', data);
    return response.data;
  },

  /**
   * Create organization
   */
  createOrganization: async (data: OrganizationCreateRequest): Promise<OrganizationCreateResponse> => {
    const response = await api.post('/setup/organization', data);
    return response.data;
  },

  /**
   * Get available modules
   */
  getModules: async (): Promise<ModuleOption[]> => {
    const response = await api.get('/setup/modules');
    return response.data;
  },

  /**
   * Enable modules
   */
  enableModules: async (data: ModuleSelectionRequest): Promise<ModuleSelectionResponse> => {
    const response = await api.post('/setup/modules', data);
    return response.data;
  },

  /**
   * Get available controller types
   */
  getControllerTypes: async (): Promise<ControllerType[]> => {
    const response = await api.get('/setup/controllers/types');
    return response.data;
  },

  /**
   * Test controller connection
   */
  testController: async (data: ControllerAddRequest): Promise<ControllerTestResult> => {
    const response = await api.post('/setup/controllers/test', data);
    return response.data;
  },

  /**
   * Add controller
   */
  addController: async (data: ControllerAddRequest): Promise<ControllerAddResponse> => {
    const response = await api.post('/setup/controllers', data);
    return response.data;
  },

  /**
   * Complete setup
   */
  completeSetup: async (data: SetupCompleteRequest): Promise<SetupCompleteResponse> => {
    const response = await api.post('/setup/complete', data);
    return response.data;
  },

  /**
   * Probe remote sites on a controller before creation.
   * Returns the Omada sites discovered plus existing FreeSdn sites for mapping.
   */
  probeRemoteSites: async (data: {
    controller_type: string;
    host: string;
    port?: number;
    username?: string;
    password?: string;
    verify_ssl?: boolean;
    connection_mode?: 'local' | 'cloud';
    client_id?: string;
    client_secret?: string;
    omada_id?: string;
    cloud_region?: string;
  }): Promise<{
    remote_sites: Array<{ id: string; name: string }>;
    freesdn_sites: Array<{ id: string; name: string }>;
  }> => {
    const response = await api.post('/controllers/probe-remote-sites', data);
    return response.data;
  },

  /**
   * Install sample / demo data
   */
  installSampleData: async (data: SampleDataRequest): Promise<SampleDataResponse> => {
    const response = await api.post('/setup/sample-data', data);
    return response.data;
  },

  /**
   * First-install restore: rebuild this instance from an uploaded secure
   * (.fsdnvault) full backup. Only callable while no super_admin exists.
   */
  restoreFromVault: async (
    file: File,
    passphrase: string,
    orgName?: string,
  ): Promise<{ success: boolean; organization_id: string }> => {
    const form = new FormData();
    form.append('file', file);
    form.append('passphrase', passphrase);
    if (orgName) form.append('org_name', orgName);
    const response = await api.post('/setup/restore', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
};
