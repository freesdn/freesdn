// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · VoIP Module Types
 *
 * Shared TypeScript interfaces for all VoIP pages.
 */

// =============================================================================
// Phone / Device
// =============================================================================

export type PhoneStatus = 'online' | 'offline' | 'in_call' | 'ringing' | 'dnd' | 'warning' | 'unknown';
export type LifecycleState = 'discovered' | 'onboarding' | 'managed' | 'maintenance' | 'firmware_updating' | 'decommissioned';
export type ProvisionStatus = 'pending' | 'generated' | 'pushed' | 'applied' | 'failed' | 'stale';

export interface VoIPPhone {
  id: string;
  name: string;
  model?: string;
  vendor?: string;
  mac_address?: string;
  ip_address?: string;
  firmware_version?: string;
  serial_number?: string;
  extension_id?: string;
  extension?: string;
  location?: string;
  description?: string;
  status: PhoneStatus;
  lifecycle_state?: LifecycleState;
  discovery_method?: string;
  provision_status?: ProvisionStatus;
  config_template_id?: string;
  config_checksum?: string;
  firmware_target?: string;
  sip_registered?: boolean;
  sip_server?: string;
  sip_user?: string;
  uptime_seconds?: number;
  cpu_usage?: number;
  memory_usage?: number;
  subnet?: string;
  vlan_id?: number;
  lldp_switch_port?: string;
  tags?: string[];
  last_seen?: string;
  last_polled?: string;
  discovered_at?: string;
  onboarded_at?: string;
  last_provisioned_at?: string;
  last_reboot?: string;
  created_at?: string;
  updated_at?: string;
  site_id?: string;
  pbx_id?: string;
  pbx_system_id?: string;
  pbx_system_name?: string;
  // Populated by the phones list endpoint when the phone is linked
  // to a FreePBX extension (see /voip/phones/auto-link).
  extension_display?: string;
  settings?: Record<string, unknown>;
}

// =============================================================================
// Phone Connection Test
// =============================================================================

export interface PhoneConnectionTestResult {
  success: boolean;
  status: string;  // connected, identified, reachable, unreachable, locked_out, error
  ip_address: string;
  mac_address?: string | null;
  model?: string | null;
  firmware_version?: string | null;
  vendor?: string | null;
  authenticated: boolean;
  api_accessible?: boolean;
  sip_registered: boolean;
  sip_account?: string | null;
  sip_registrar?: string | null;
  sip_accounts?: Array<Record<string, string>>;
  lockout_status?: string | null;
  config_items?: number | null;
  network_info?: Record<string, string>;
  auth_note?: string | null;
  error?: string | null;
  raw_data?: Record<string, unknown>;
}

// =============================================================================
// PBX
// =============================================================================

export type PBXType = 'asterisk' | 'freepbx' | 'freeswitch' | '3cx' | 'other';

export interface PBXSystem {
  id: string;
  name: string;
  description?: string;
  pbx_type: PBXType;
  ip_address?: string;
  api_port?: number;
  sip_port?: number;
  is_active: boolean;
  status?: string;
  extension_count?: number;
  last_seen?: string;
  last_synced?: string;
  api_username?: string;
  settings?: Record<string, unknown>;
}

export interface PBXDashboard {
  pbx_id: string;
  name: string;
  pbx_type: string;
  status: string;
  ip_address?: string;
  api_port?: number;
  sip_port?: number;
  uptime?: string;
  asterisk_version?: string;
  total_extensions: number;
  online_extensions: number;
  total_trunks: number;
  active_calls: number;
  calls_today: number;
  voicemail_boxes: number;
  unread_voicemails: number;
  ring_groups: number;
  queues: number;
  ivrs: number;
  dids: number;
  ami_connected: boolean;
  ari_connected: boolean;
  rest_available: boolean;
  last_sync?: string;
  /** A staged config change applied to the FreePBX DB but not yet reloaded
   * into the running Asterisk; drives the "Apply Config to activate" banner. */
  needs_reload?: boolean;
}

export interface PBXSystemInfo {
  host: string;
  asterisk_version?: string;
  freepbx_version?: string;
  ami_connected: boolean;
  ari_connected: boolean;
  rest_available: boolean;
  ari_info?: Record<string, unknown>;
  freepbx_status?: Record<string, unknown>;
}

export interface Trunk {
  trunk_id?: string;
  trunkid?: string;
  channelid?: string;
  name: string;
  trunk_type?: string;
  technology?: string;
  tech?: string;
  host?: string;
  port?: number;
  username?: string;
  secret?: string;
  status?: string;
  channels_used?: number;
  max_channels?: number;
  maxchans?: number;
  provider?: string;
  outcid?: string;
  keepcid?: string;
  disabled?: string;
  failover?: string;
  dialoutprefix?: string;
  continue?: string;
  // PJSIP-specific
  registration?: string;
  aor_contact?: string;
  match?: string;
  transport?: string;
  contact_user?: string;
  codecs?: string;
  sip_server?: string;
  sip_server_port?: string | number;
  auth_rejection_permanent?: string;
  // Additional PJSIP / trunk detail fields
  context?: string;
  from_domain?: string;
  from_user?: string;
  authentication?: string;
  pjsip_line?: string;
  expiration?: number | string;
  identify_by?: string;
  dtmfmode?: string;
  media_encryption?: string;
  rtp_symmetric?: string;
  force_rport?: string;
  t38_udptl?: string;
  qualify_frequency?: number | string;
  send_connected_line?: string;
  trust_rpid?: string;
  sendrpid?: string;
  fax_detect?: string;
  allow_unauthenticated_options?: string;
  max_retries?: number | string;
  retry_interval?: number | string;
  // Source marker
  _source?: 'live' | 'cache';
  settings?: Record<string, unknown>;
}

export interface Queue {
  name: string;
  display_name?: string;
  strategy?: string;
  members?: Array<Record<string, unknown>>;
  member_count?: number;
  callers_waiting?: number;
  calls_taken?: number;
  holdtime?: number;
  talk_time?: number;
  completed?: number;
  abandoned?: number;
  service_level?: number;
  settings?: Record<string, unknown>;
}

export interface IVR {
  ivr_id?: string;
  name: string;
  description?: string;
  announcement?: string;
  direct_dial?: boolean;
  timeout?: number;
  entries?: Array<Record<string, unknown>>;
  settings?: Record<string, unknown>;
}

export interface ActiveCall {
  channel: string;
  caller_id_name?: string;
  caller_id_num?: string;
  connected_line_name?: string;
  connected_line_num?: string;
  state?: string;
  application?: string;
  duration?: number;
  bridge_id?: string;
  context?: string;
  extension?: string;
}

export interface VoicemailBox {
  mailbox: string;
  context?: string;
  name?: string;
  email?: string;
  new_messages?: number;
  old_messages?: number;
  settings?: Record<string, unknown>;
}

// =============================================================================
// Rich FreePBX Data · Outbound Routes, Follow-Me, Announcements, etc.
// =============================================================================

/** Extension as fetched from the FreePBX grid (34+ fields). */
export interface FreePBXExtension {
  extension: string;
  password: string;
  name: string;
  voicemail: string;
  ringtimer: number;
  noanswer: string;
  recording: string;
  outboundcid: string;
  sipname: string;
  noanswer_cid: string;
  busy_cid: string;
  chanunavail_cid: string;
  noanswer_dest: string;
  busy_dest: string;
  chanunavail_dest: string;
  mohclass: string;
  id: string | number;
  tech: string;
  dial: string;
  devicetype: string;
  user: string;
  description: string;
  emergency_cid: string;
  hint_override: string;
  cwtone: string;
  recording_in_external: string;
  recording_out_external: string;
  recording_in_internal: string;
  recording_out_internal: string;
  recording_ondemand: string;
  recording_priority: string;
  answermode: string;
  intercom: string;
  settings?: {
    cw?: string;
    dnd?: string;
    cf?: string;
    cfb?: string;
    cfu?: string;
    fmfm?: string;
  };
  actions?: string;
}

/** DID / Inbound Route (17 fields). */
export interface DID {
  cidnum: string;
  extension: string;
  destination: string;
  privacyman: string;
  alertinfo: string;
  ringing: string;
  fanswer: string;
  mohclass: string;
  description: string;
  grppre: string;
  delay_answer: string;
  pricid: string;
  pmmaxretries: string;
  pmminlength: string;
  reversal: string;
  rvolume: string;
  indication_zone: string;
}

/** Outbound route. */
export interface OutboundRoute {
  route_id?: string | number;
  name?: string;
  outcid?: string;
  outcid_mode?: string;
  password?: string;
  emergency_route?: string;
  intracompany_route?: string;
  mohclass?: string;
  time_group_id?: string;
  dest?: string;
  seq?: number;
  [key: string]: unknown;
}

/** Follow-Me entry. */
export interface FollowMe {
  ext: string;
  grpnum?: string;
  strategy?: string;
  grptime?: string;
  grplist?: string;
  annmsg_id?: string;
  postdest?: string;
  grppre?: string;
  [key: string]: unknown;
}

/** Announcement. */
export interface Announcement {
  announcement_id: string | number;
  description: string;
  recording_id: string;
  allow_skip: string;
  post_dest: string;
  return_ivr: string;
  noanswer: string;
  repeat_msg: string;
}

/** Paging / intercom group. */
export interface PagingGroup {
  page_group: string | number;
  description: string;
  is_default?: string | boolean;
  [key: string]: unknown;
}

/** Day/Night call-flow control. */
export interface DayNight {
  ext: string;
  dest?: string;
  description?: string;
  [key: string]: unknown;
}

/** SSL/TLS certificate. */
export interface Certificate {
  cid: string | number;
  caid: string | number;
  basename: string;
  description: string;
  type: 'ss' | 'le' | string;
  default: string | boolean;
  additional: string;
}

/** FreePBX admin (AMP) user. */
export interface AdminUser {
  username: string;
  password_sha1?: string;
  extension_low?: string;
  extension_high?: string;
  deptname?: string;
  sections?: string;
  [key: string]: unknown;
}

/** Comprehensive PBX config returned from /config endpoint. */
export interface PBXFullConfig {
  pbx_id: string;
  pbx_name: string;
  pbx_type: string;
  synced_at?: string;
  extensions: Array<{
    id: string;
    extension_number: string;
    display_name?: string;
    status?: string;
    settings?: Record<string, unknown>;
  }>;
  ring_groups: Array<{
    id: string;
    group_number: string;
    name: string;
    strategy?: string;
    members?: string[];
    settings?: Record<string, unknown>;
  }>;
  trunks: Trunk[];
  queues: Queue[];
  ivrs: IVR[];
  dids: DID[];
  voicemail_boxes: VoicemailBox[];
  outbound_routes: OutboundRoute[];
  followme: FollowMe[];
  announcements: Announcement[];
  paging_groups: PagingGroup[];
  daynight: DayNight[];
  blacklist: Array<Record<string, unknown>>;
  certificates: Certificate[];
  admin_users: AdminUser[];
}

// =============================================================================
// Extensions & Ring Groups
// =============================================================================

export interface BoundPhone {
  id: string;
  name: string;
  ip_address?: string;
  mac_address?: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  status: string;
  sip_registered?: boolean;
  lifecycle_state?: string;
}

export interface Extension {
  id: string;
  pbx_id?: string;
  pbx_system_id?: string;
  extension_number: string;
  display_name?: string;
  caller_id_name?: string;
  caller_id_number?: string;
  voicemail_enabled?: boolean;
  ext_type?: string;
  extension_type?: string;
  status?: string;
  is_active: boolean;
  settings?: Record<string, unknown>;
  // Phones currently bound to this extension (populated by the
  // /voip/pbx/{id}/extensions endpoint via JOIN to voip.phones).
  bound_phones?: BoundPhone[];
}

export interface RingGroup {
  id: string;
  pbx_id?: string;
  pbx_system_id?: string;
  name: string;
  description?: string;
  group_number: string;
  extension_number?: string;
  ring_strategy: 'ringall' | 'hunt' | 'memoryhunt' | 'random';
  ring_time: number;
  members: string[];
  is_active: boolean;
}

// =============================================================================
// Call Logs
// =============================================================================

export interface CallLog {
  id: string;
  caller_number: string;
  caller?: string;
  caller_name?: string;
  callee_number: string;
  callee?: string;
  callee_name?: string;
  direction: 'inbound' | 'outbound' | 'internal';
  status: 'answered' | 'missed' | 'no_answer' | 'busy' | 'voicemail' | 'failed';
  duration_seconds: number;
  duration?: number;
  ring_duration_seconds?: number;
  start_time: string;
  started_at?: string;
  answer_time?: string;
  end_time?: string;
  recording_path?: string;
  pbx_system_name?: string;
}

// =============================================================================
// Voicemail
// =============================================================================

export interface VoicemailMessage {
  id: string;
  pbx_id?: string;
  extension_id?: string;
  extension?: string;
  mailbox?: string;
  extension_number: string;
  caller_id: string;
  caller_name?: string;
  duration: number;
  message_date: string;
  created_at?: string;
  is_read: boolean;
  is_urgent: boolean;
  transcription?: string;
  file_path?: string;
  audio_url?: string;
  folder?: string;
}

// =============================================================================
// Fleet Dashboard
// =============================================================================

export interface FleetDashboard {
  total_phones: number;
  online: number;
  offline: number;
  in_call: number;
  by_lifecycle: Record<string, number>;
  by_vendor: Record<string, number>;
  by_model: Record<string, number>;
  by_firmware: Record<string, number>;
  firmware_compliant?: number;
  firmware_non_compliant?: number;
  sip_registered: number;
  sip_unregistered: number;
  recently_discovered: number;
  pending_provision: number;
}

// =============================================================================
// Discovery
// =============================================================================

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface DiscoveryScan {
  id: string;
  site_id?: string;
  scan_type: string;
  subnet?: string;
  port_range?: string;
  status: ScanStatus;
  started_at?: string;
  completed_at?: string;
  devices_found?: number;
  new_devices?: number;
  results?: DiscoveredDevice[];
  discovered_devices?: DiscoveredDevice[];
  metadata_json?: Record<string, unknown>;
  created_at?: string;
}

export interface DiscoveredDevice {
  ip: string;
  ip_address?: string;
  mac?: string;
  mac_address?: string;
  vendor?: string;
  model?: string;
  firmware?: string;
  methods?: string[];
  discovery_method?: string;
  is_new?: boolean;
  phone_id?: string;
  sip_registered?: boolean;
  sip_account?: string;
  sip_registrar?: string;
  authenticated?: boolean;
}

export interface ScanProgressLog {
  ts: string;
  phase: string;
  message: string;
}

export interface ScanProgress {
  phase: string;
  percent: number;
  message: string;
  devices_found: number;
  log: ScanProgressLog[];
  devices: Array<{
    ip: string;
    mac: string;
    vendor: string;
    model?: string;
    firmware?: string;
    methods?: string[];
    sip_registered?: boolean;
    sip_account?: string;
    sip_registrar?: string;
    authenticated?: boolean;
  }>;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  devices_found: number;
  started_at?: string;
  completed_at?: string;
  progress: ScanProgress;
}

// =============================================================================
// Config Templates
// =============================================================================

export interface ConfigTemplate {
  id: string;
  name: string;
  description?: string;
  vendor?: string;
  model_pattern?: string;
  site_id?: string;
  sip_settings?: Record<string, unknown>;
  network_settings?: Record<string, unknown>;
  provisioning_settings?: Record<string, unknown>;
  feature_settings?: Record<string, unknown>;
  line_key_settings?: Record<string, unknown>;
  raw_overrides?: Record<string, string>;
  is_default?: boolean;
  phones_count?: number;
  created_at?: string;
  updated_at?: string;
}

// =============================================================================
// Firmware
// =============================================================================

export interface FirmwareTrack {
  id: string;
  vendor: string;
  model: string;
  version: string;
  target_version?: string;
  download_url?: string;
  checksum?: string;
  release_notes?: string;
  is_stable?: boolean;
  is_recommended?: boolean;
  is_mandatory?: boolean;
  site_id?: string;
  created_at?: string;
}

export interface FirmwareComplianceGroup {
  vendor: string;
  model: string;
  target_version?: string;
  recommended_version?: string;
  total: number;
  compliant: number;
  non_compliant: number;
  non_compliant_versions?: string[];
  versions: Record<string, number>;
}

export interface FirmwareComplianceReport {
  groups: FirmwareComplianceGroup[];
  vendor?: string;
  model?: string;
  recommended_version?: string;
  compliant?: number;
  non_compliant?: number;
  versions?: Record<string, number>;
}

// =============================================================================
// Stats
// =============================================================================

export interface PhoneStats {
  total: number;
  online: number;
  offline: number;
  in_call: number;
}

// =============================================================================
// Bulk Operations
// =============================================================================

export interface BulkOperationResult {
  operation: string;
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
  errors?: Array<{ phone_id: string; error: string }>;
}
