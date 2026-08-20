// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * ALL TypeScript interfaces and types exported from the API layer.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

// =============================================================================
// SWITCHES
// =============================================================================

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

export interface SwitchSummary {
  id: string;
  name: string;
  model: string;
  model_version?: string;
  vendor: string;
  serial_number?: string;
  mac_address?: string;
  ip_address?: string;
  ipv6_address?: string;
  controller_connection_ip?: string;
  site_id: string;
  site_name: string;
  total_ports: number;
  poe_ports: number;
  sfp_ports: number;
  status: string;
  uptime: number;
  cpu_usage: number;
  memory_usage: number;
  temperature?: number;
  fan_status?: string;
  ports_up: number;
  ports_down: number;
  ports_disabled: number;
  poe_budget: number;
  poe_used: number;
  firmware_version: string;
  hardware_version?: string;
  update_available: boolean;
  vlans_configured: number;
  connected_clients: number;
}

export interface SwitchPort {
  id: string;
  device_id: string;
  port_index: number;
  port_type: string;
  name: string;
  description?: string;
  enabled: boolean;
  speed?: string;
  duplex?: string;
  auto_negotiation: boolean;
  mtu: number;
  flow_control: boolean;
  vlan_config?: {
    mode: string;
    native_vlan: number;
    tagged_vlans: number[];
    // voice_vlan / guest_vlan removed: the port dialog collected them, the API
    // accepted them, and nothing ever pushed them to the controller.
  };
  poe_config?: {
    enabled: boolean;
    mode: string;
    power_limit?: number;
    // priority removed: no validated controller key exists for per-port PoE
    // priority, so it was collected and silently dropped.
  };
  stp_config?: {
    enabled: boolean;
    mode: string;
    guard?: string;
    bpdu_filter: boolean;
    bpdu_guard: boolean;
  };
  security_config?: {
    enabled: boolean;
    mac_limit?: number;
    violation_action?: string;
    dot1x_enabled?: boolean;
    dot1x_mode?: string;
  };
  status: {
    link_status: string;
    link_speed?: number;
    link_duplex?: string;
    tx_bytes: number;
    rx_bytes: number;
    tx_packets: number;
    rx_packets: number;
    tx_errors: number;
    rx_errors: number;
    tx_utilization: number;
    rx_utilization: number;
    poe_status?: string;
    poe_power_draw?: number;
    poe_class?: number;
    stp_state?: string;
    stp_role?: string;
    neighbor_device?: string;
    neighbor_port?: string;
    neighbor_ip?: string;
  };
  last_status_change?: string;
}

export interface SwitchPortProfile {
  id: string;
  name: string;
  description?: string;
  profile_type: string;
  site_id?: string;
  controller_id?: string;
  native_vlan?: number | null;
  tagged_vlans?: number[] | null;
  voice_vlan?: number | null;
  poe_enabled?: boolean | null;
  stp_enabled?: boolean | null;
  ports_using: number;
  created_at: string;
  updated_at?: string;
}

export interface SwitchLAG {
  id: string;
  device_id: string;
  name: string;
  lag_id: number;
  mode: string;
  member_ports: number[];
  lacp_mode: string;
  lacp_timeout: string;
  status: string;
  active_ports: number;
  aggregate_speed: number;
}

// =====================================================================
// Switch Network & Config Types
// =====================================================================

export interface STPConfig {
  enabled?: boolean;
  mode?: string; // "stp" | "rstp" | "mstp"
  priority?: number;
  hello_time?: number;
  forward_delay?: number;
  max_age?: number;
  root_bridge?: string;
  root_port?: number;
  root_path_cost?: number;
}

export interface ACLRule {
  id?: string;
  name?: string;
  enabled?: boolean;
  index?: number;
  action?: string; // "permit" | "deny"
  protocol?: string;
  src_ip?: string;
  src_mask?: string;
  dst_ip?: string;
  dst_mask?: string;
  src_port?: string;
  dst_port?: string;
  direction?: string; // "in" | "out"
}

export interface IGMPConfig {
  enabled?: boolean;
  version?: number;
  fast_leave?: boolean;
  querier?: boolean;
  query_interval?: number;
  max_response_time?: number;
  last_member_query_interval?: number;
}

export interface MirrorConfig {
  enabled?: boolean;
  session_id?: number;
  source_ports?: number[];
  destination_port?: number;
  direction?: string; // "ingress" | "egress" | "both"
}

export interface StaticRoute {
  id?: string;
  name?: string;
  enabled?: boolean;
  destination?: string;
  subnet_mask?: string;
  gateway?: string;
  interface?: string;
  metric?: number;
}

export interface DHCPSnoopingConfig {
  enabled?: boolean;
  trusted_ports?: number[];
  verify_mac?: boolean;
  rate_limit?: number;
}

export interface QoSConfig {
  enabled?: boolean;
  mode?: string; // "port_based" | "dscp_based" | "802.1p_based"
  trust_mode?: string;
  queues?: QoSQueue[];
}

export interface QoSQueue {
  queue_id: number;
  priority: number;
  weight?: number;
  description?: string;
}

export interface MACTableEntry {
  mac_address: string;
  vlan_id?: number;
  port?: number;
  type?: string; // "dynamic" | "static" | "filter"
}

export interface LLDPNeighbor {
  port_index: number;
  port_name?: string;
  neighbor_device?: string;
  neighbor_port?: string;
  neighbor_ip?: string;
  neighbor_mac?: string;
  chassis_id?: string;
  system_name?: string;
  system_description?: string;
}

export interface SwitchEvent {
  id?: string;
  timestamp?: number;
  level?: string; // "info" | "warning" | "error" | "critical"
  category?: string; // "device" | "client" | "system" | "security"
  message?: string;
  device_mac?: string;
  device_name?: string;
  client_mac?: string;
}

export interface BandwidthControl {
  bandwidth_ctrl_type: number; // 0=off, 1=rate_limit
  ingress_rate?: number; // kbps
  egress_rate?: number; // kbps
}

export interface StormControl {
  broadcast_enabled: boolean;
  broadcast_rate?: number; // pps
  multicast_enabled: boolean;
  multicast_rate?: number;
  unknown_unicast_enabled: boolean;
  unknown_unicast_rate?: number;
}

export interface CableTestResult {
  success: boolean;
  message?: string;
  data?: {
    port?: number;
    status?: string; // "ok" | "open" | "short" | "impedance_mismatch"
    length?: number; // meters
    pair_results?: Array<{
      pair: number;
      status: string;
      length?: number;
    }>;
  };
}

export interface PingResult {
  success: boolean;
  message?: string;
  data?: {
    target?: string;
    packets_sent?: number;
    packets_received?: number;
    packet_loss?: number; // percentage
    min_rtt?: number; // ms
    avg_rtt?: number;
    max_rtt?: number;
    results?: Array<{
      seq: number;
      rtt?: number;
      status: string;
    }>;
  };
}

export interface TracerouteResult {
  success: boolean;
  message?: string;
  data?: {
    target?: string;
    hops?: Array<{
      hop: number;
      ip?: string;
      hostname?: string;
      rtt1?: number;
      rtt2?: number;
      rtt3?: number;
    }>;
  };
}

export interface OUIVlanMapping {
  oui_prefix: string;
  vlan_id: number;
  description?: string;
}

export interface OUIVlanApplyRequest {
  mappings: OUIVlanMapping[];
  dry_run?: boolean;
}

export interface OUIVlanApplyResult {
  success: boolean;
  dry_run?: boolean;
  changes: Array<{
    port: number;
    mac: string;
    name?: string;
    oui: string;
    vlan_id: number;
    description?: string;
  }>;
  applied?: number;
}

export interface CLIProfileApplyRequest {
  name: string;
  port_indices: number[];
  config: Record<string, unknown>;
}

export interface CLIProfileApplyResult {
  success: boolean;
  profile_name: string;
  total_ports: number;
  succeeded: number;
  failed: number;
  results: Array<{
    port: number;
    success: boolean;
    error?: string;
  }>;
}

export interface SwitchClient {
  mac_address: string;
  name?: string;
  hostname?: string;
  ip_address?: string;
  connection_type?: string; // "wired" | "wireless"
  ssid?: string;
  ap_mac?: string;
  ap_name?: string;
  switch_mac?: string;
  switch_port?: number;
  vlan_id?: number;
  uptime?: number;
  signal?: number;
  rssi?: number;
  snr?: number;
  rx_rate?: number;
  tx_rate?: number;
  download?: number;
  upload?: number;
  activity?: number;
  blocked?: boolean;
  guest?: boolean;
  os_type?: string;
  device_category?: string;
  channel?: number;
  band?: string;
  wifi_mode?: string;
  last_seen?: string;
  first_seen?: string;
}

// =============================================================================
// ACCESS POINTS
// =============================================================================

export interface AccessPointSummary {
  id: string;
  name: string;
  model: string;
  vendor: string;
  mac_address: string;
  ip_address: string;
  site_id: string;
  site_name: string;
  controller_id: string | null;
  status: string;
  firmware_version: string;
  clients: number;
  uptime: number;
  cpu_usage: number;
  memory_usage: number;
  mesh_enabled: boolean;
  led_enabled: boolean | null;
  radios: APRadio[];
  update_available: boolean;
}

export interface AccessPointDetail extends AccessPointSummary {
  serial_number: string;
  lan_port_vlan_enabled: boolean;
  lan_port_vlan_id: number | null;
  lan_port_poe_enabled: boolean | null;
  ssid_overrides: APSsidOverride[];
  location: { latitude?: number; longitude?: number } | null;
}

export interface APRadio {
  band: string;
  channel: number;
  channel_width: number;
  tx_power: number;
  tx_power_mode: string | null;
  clients: number;
}

export interface APSsidOverride {
  index: number;
  globalSsid: string;
  supportBands: number[];
  security: number;
  enable: boolean;
  vlanEnable: boolean;
  vlanId: number;
  ssid: string;
  psk: string;
  ssidEnable: boolean;
}

export interface APClient {
  mac_address: string;
  name: string;
  ip_address: string;
  ssid: string;
  band: string;
  signal: number;
  rx_rate: number;
  tx_rate: number;
  uptime: number;
}

export interface APFirmwareInfo {
  curFwVer: string;
  latestFwVer?: string;
  needUpgrade?: boolean;
}

export interface APMetrics {
  mac: string;
  cpu: number;
  memory: number;
  uptime: number;
  clients: number;
  download: number;
  upload: number;
  temperature: number | null;
  timestamp: string | null;
}

// =============================================================================
// CAMERAS
// =============================================================================

export interface SmartCapabilities {
  motion_detection: boolean;
  line_crossing: boolean;
  intrusion_detection: boolean;
  privacy_mask: boolean;
  face_detection: boolean;
  vehicle_detection: boolean;
  person_detection: boolean;
}

export interface MotionDetectionConfig {
  enabled: boolean;
  sensitivity_level: number;
  grid_map: string;
}

export interface PrivacyMaskRegion {
  id: number;
  enabled: boolean;
  coordinates: { x: number; y: number }[];
}

export interface PrivacyMaskConfig {
  enabled: boolean;
  regions: PrivacyMaskRegion[];
}

export interface LineCrossingRule {
  id: number;
  enabled: boolean;
  sensitivity: number;
  direction: string;
  coordinates: { x: number; y: number }[];
}

export interface LineCrossingConfig {
  enabled: boolean;
  rules: LineCrossingRule[];
}

export interface IntrusionDetectionRule {
  id: number;
  enabled: boolean;
  sensitivity: number;
  time_threshold: number;
  coordinates: { x: number; y: number }[];
}

export interface IntrusionDetectionConfig {
  enabled: boolean;
  rules: IntrusionDetectionRule[];
}

export interface RecordingTimeBlock {
  id?: string | number;
  begin_time: string;
  end_time: string;
  record_type: string;
}

export interface RecordingScheduleDay {
  id: number;
  action_type: string;
  time_blocks: RecordingTimeBlock[];
}

export interface RecordingScheduleConfig {
  /** False when the NVR doesn't expose a per-channel schedule via ISAPI
   *  (recording managed at the NVR). UI shows an honest note, not an error. */
  supported?: boolean;
  enabled: boolean;
  days: RecordingScheduleDay[];
}

export interface FaceDetectionConfig {
  enabled: boolean;
  sensitivity: number;
  snap_interval: number;
  generation_speed: number;
  min_width: number;
  min_height: number;
  max_width: number;
  max_height: number;
}

export interface HolidayEntry {
  id: number;
  enabled: boolean;
  name: string;
  mode: string;
  start_month: number;
  start_day: number;
  end_month: number;
  end_day: number;
}

export interface HolidayListConfig {
  holidays: HolidayEntry[];
}

export interface HolidayScheduleConfig {
  enabled: boolean;
  days: RecordingScheduleDay[];
}

export interface PTZPatrolAction {
  id: number;
  preset_id: number;
  dwell: number;
  speed: number;
}

export interface PTZPatrol {
  id: number;
  name: string;
  enabled: boolean;
  actions: PTZPatrolAction[];
}

export interface CameraHealthData {
  camera_id: string;
  is_online: boolean;
  bitrate_kbps: number | null;
  frame_rate: number | null;
  codec: string | null;
  resolution_width: number | null;
  resolution_height: number | null;
  captured_at: string;
}

export interface CameraHealthHistory {
  camera_id: string;
  snapshots: CameraHealthData[];
}

export interface FleetHealthSummary {
  total_cameras: number;
  online_cameras: number;
  offline_cameras: number;
  avg_bitrate_kbps: number;
  total_bandwidth_mbps: number;
}

export interface NVRChannelStatusItem {
  id: number;
  name: string;
  online: boolean;
  ip_address: string;
}

export interface NVRChannelStatus {
  nvr_id: string;
  channels: NVRChannelStatusItem[];
}

// =============================================================================
// NVR DISCOVERY & IMPORT
// =============================================================================

export interface NVRConnectionTestRequest {
  host: string;
  port: number;
  username: string;
  password: string;
}

export interface NVRConnectionTestResponse {
  success: boolean;
  device_id?: string;
  device_name?: string;
  device_type?: string;
  model?: string;
  firmware_version?: string;
  serial_number?: string;
  mac_address?: string;
  error?: string;
}

export interface DiscoveredChannel {
  channel_id: number;
  name: string;
  enabled: boolean;
  online: boolean;
  source_ip?: string;
  has_ptz: boolean;
  has_audio: boolean;
  rtsp_main?: string;
  rtsp_sub?: string;
}

export interface NVRDiscoveryResponse {
  device_type: 'nvr' | 'camera' | 'unknown';
  nvr: {
    device_id: string;
    name: string;
    model: string;
    firmware: string;
    serial_number: string;
    mac_address: string;
  };
  channels: DiscoveredChannel[];
  storage: {
    total_gb: number;
    used_gb: number;
    free_gb: number;
    percent_used: number;
    disks: { name?: string; size_gb?: number; status?: string }[];
  };
}

export interface StandaloneCameraImportRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  site_id: string;
  name?: string;
}

export interface StandaloneCameraImportResponse {
  camera_id: string;
  camera_name: string;
}

export interface NVRImportRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  site_id: string;
  name?: string;
  selected_channels?: number[];
}

export interface NVRImportResponse {
  nvr_id: string;
  nvr_name: string;
  cameras_imported: number;
  cameras_skipped: number;
  cameras: Array<{ id: string; name: string; channel_id?: number }>;
  /** True when the NVR already existed and was re-synced (idempotent re-import). */
  synced?: boolean;
}

export interface NVRSyncResponse {
  added: number;
  removed: number;
  updated: number;
}

// =============================================================================
// DISCOVERY
// =============================================================================

export interface ScanRequest {
  site_id?: string;
  scan_type?: 'subnet' | 'controller';
  subnets?: string[];
  controller_url?: string;
  controller_type?: string;
  credential_id?: string;
  targets?: string[];
  exclude_targets?: string[];
  scan_methods?: string[];
  tcp_ports?: number[];
  max_concurrent_hosts?: number;
  timeout?: number;
  probe_services?: boolean;
  resolve_hostnames?: boolean;
  follow_controllers?: boolean;
  // Maps to backend ScanOptionsSchema, these field names are the ones the
  // server actually reads (discovery.py applies them to the scanner config).
  options?: {
    probe_services?: boolean;
    resolve_hostnames?: boolean;
    tcp_timeout?: number;
    max_concurrent_hosts?: number;
    max_concurrent_ports?: number;
    follow_controllers?: boolean;
  };
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
  estimated_duration_seconds?: number;
}

export interface ScanProgress {
  scan_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  hosts_scanned: number;
  devices_found: number;
  devices_identified: number;
  current_activity?: string;
  errors?: string[];
  total_hosts?: number;
  scanned_hosts?: number;
  discovered_hosts?: number;
  current_phase?: string;
  phase_progress?: number;
  elapsed_seconds?: number;
  estimated_remaining_seconds?: number;
  hosts_found?: string[];
}

export interface DiscoveredDevice {
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  vendor?: string;
  vendor_confidence?: number;
  device_type?: string;
  device_type_confidence?: number;
  open_ports?: number[];
  site_id?: string;
  adopted?: boolean;
  driver_match?: {
    driver_id: string;
    driver_name: string;
    confidence: number;
    match_reasons?: string[];
  };
  recommended_driver_id?: string;
  recommended_driver_name?: string;
  driver_match_score?: number;
  driver_matches?: Array<{
    driver_id: string;
    driver_name: string;
    match_score: number;
    match_reasons: string[];
  }>;
  is_manageable?: boolean;
  requires_credentials?: boolean;
  suggestions?: string[];
}

export interface ScanResults {
  scan_id: string;
  status: string;
  total_discovered: number;
  total_scans?: number;
  // Backend (ScanResultsSchema) emits total_manageable + elapsed_seconds.
  total_manageable?: number;
  manageable_count?: number;
  unmanageable_count?: number;
  devices: DiscoveredDevice[];
  started_at?: string;
  completed_at?: string;
  elapsed_seconds?: number;
  duration_seconds?: number;
}

export interface ControllerDiscoveryRequest {
  driver_id: string;
  host: string;
  port?: number;
  ssl?: boolean;
  username: string;
  password: string;
  site_id?: string;
}

export interface Driver {
  id: string;
  driver_id?: string;
  name: string;
  vendor: string;
  vendor_display?: string;
  description?: string;
  version?: string;
  device_types: string[];
  supported_types?: string[];
  capabilities?: string[];
  documentation_url?: string;
}

export interface DriverDetails {
  id: string;
  driver_id?: string;
  name: string;
  vendor: string;
  vendor_display?: string;
  description?: string;
  version: string;
  device_types: string[];
  supported_types?: string[];
  credential_type?: string;
  capabilities?: string[];
  documentation_url?: string;
  config_schema?: Record<string, any>;
  poll_interval_seconds?: number;
}

export interface AdoptDeviceRequest {
  ip_address: string;
  name: string;
  site_id: string;
  // Optional now: backend auto-matches against the matching DiscoveredHost
  // row's fingerprint when omitted, falling back to the "generic" driver
  // for hosts without a confident vendor adapter match.
  driver_id?: string;
  credential_id?: string;
  device_type?: string;
  mac_address?: string;
  controller_id?: string;
  tags?: string[];
  auto_provision?: boolean;
  control_tier?: string;
}

export interface AdoptDeviceResponse {
  device_id: string;
  name: string;
  status: string;
  driver_id: string;
  message: string;
  control_tier?: string;
  provisioning_status?: string;
}

export interface BulkAdoptResponse {
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{ ip_address: string; status: string; error?: string; name?: string }>;
}

export interface TestCredentialRequest {
  ip_address: string;
  driver_id?: string;
  credential_id?: string;
  username?: string;
  password?: string;
  port?: number;
}

export interface TestCredentialResponse {
  success: boolean;
  message: string;
  device_info?: Record<string, any>;
  capabilities?: string[];
}

export interface MatchDriverRequest {
  ip_address: string;
  mac_address?: string;
  open_ports?: number[];
  vendor?: string;
  device_type?: string;
  fingerprint_data?: Record<string, any>;
}

export interface MatchDriverResponse {
  matches: Array<{
    driver_id: string;
    driver_name: string;
    vendor: string;
    match_score: number;
    match_reasons: string[];
    capabilities: string[];
    device_types: string[];
  }>;
  recommended_driver?: {
    driver_id: string;
    driver_name: string;
    vendor: string;
    match_score: number;
    match_reasons: string[];
  };
  is_manageable: boolean;
  suggestions: string[];
}

export interface ScanHistoryItem {
  scan_id: string;
  id?: string;
  scan_type?: string;
  status: string;
  started_at: string;
  targets: string[];
  total_discovered: number;
  progress: number;
}

// =============================================================================
// SITES (Extended)
// =============================================================================

export interface SubnetConfig {
  cidr: string;
  name?: string;
  vlan_id?: number;
  gateway?: string;
  description?: string;
  is_management?: boolean;
  auto_discover?: boolean;
}

export interface DiscoverySettings {
  auto_discovery_enabled: boolean;
  auto_discover_enabled?: boolean;
  discovery_schedule?: string;
  auto_adopt_enabled?: boolean;
  default_credential_id?: string;
  exclude_patterns?: string[];
  scan_interval_hours: number;
  retry_on_failure: boolean;
  max_concurrent_scans: number;
}

export interface Site {
  id: string;
  name: string;
  slug?: string;
  description?: string;
  site_type?: 'local' | 'remote' | 'cloud';
  address?: string;
  city?: string;
  country?: string;
  timezone: string;
  time_format?: string;
  date_format?: string;
  latitude?: number;
  longitude?: number;
  subnets: SubnetConfig[];
  gateway_ip?: string;
  discovery_settings?: DiscoverySettings;
  is_active?: boolean;
  organization_id?: string;
  settings?: Record<string, unknown>;
  device_count: number;
  online_device_count: number;
  controller_count: number;
  created_at: string;
  updated_at: string;
}

export interface SiteHealth {
  site_id: string;
  site_name: string;
  status: 'healthy' | 'degraded' | 'critical' | 'unknown';
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  degraded_devices: number;
  critical_alerts: number;
  warning_alerts: number;
  last_scan?: string;
  last_device_change?: string;
  subnet_health: Array<{
    cidr: string;
    name?: string;
    status: string;
    device_count: number;
  }>;
}

export interface CreateSiteRequest {
  name: string;
  description?: string;
  site_type?: 'local' | 'remote' | 'cloud';
  address?: string;
  city?: string;
  country?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  subnets?: SubnetConfig[];
  discovery_settings?: Partial<DiscoverySettings>;
}

// =============================================================================
// CREDENTIALS
// =============================================================================

export interface Credential {
  id: string;
  name: string;
  type: string;
  credential_type?: 'basic_auth' | 'api_key' | 'token' | 'ssh_key' | 'certificate' | 'username_password';
  scope?: 'global' | 'vendor' | 'site' | 'device';
  vendor?: string;
  site_id?: string;
  device_id?: string;
  username?: string;
  description?: string;
  is_default?: boolean;
  devices_count?: number;
  created_at?: string;
  updated_at?: string;
  last_used?: string;
}

export interface CreateCredentialRequest {
  name: string;
  // ``type`` was the legacy field; backend silently dropped it and
  // defaulted ``credential_type`` to ``basic_auth``, mis-classifying
  // every API-key / SSH / token credential created via the FE.
  credential_type?: string;
  scope?: string;
  vendor?: string;
  site_id?: string;
  device_id?: string;
  username?: string;
  password?: string;
  api_key?: string;
  token?: string;
  // Backend column is ``ssh_private_key``, was ``ssh_key`` which
  // never reached the DB.
  ssh_private_key?: string;
  certificate?: string;
  description?: string;
  is_default?: boolean;
}

// =============================================================================
// ENTERPRISE / ORGANIZATIONS
// =============================================================================

export interface Organization {
  id: string;
  name: string;
  slug: string;
  tier: string;
  is_active: boolean;
  settings: Record<string, any>;
  quota: Record<string, any>;
  parent_id?: string;
  created_at: string;
  updated_at: string;
}

export interface OrganizationQuota {
  tier: string;
  max_users: number;
  max_sites: number;
  max_devices: number;
  max_api_calls_per_minute: number;
  max_webhooks: number;
  max_automation_rules: number;
  max_stored_metrics_days: number;
  features: string[];
}

export interface OrganizationMember {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  joined_at: string;
}

// =============================================================================
// AUTOMATION
// =============================================================================

export interface AutomationAction {
  id: string;
  action_type: string;
  params: Record<string, any>;
  order: number;
  on_failure: string;
  retry_count: number;
  retry_delay_seconds: number;
  timeout_seconds: number;
  condition?: Record<string, any>;
  execution_count: number;
  success_count: number;
  failure_count: number;
}

export interface AutomationRule {
  id: string;
  name: string;
  description?: string;
  organization_id?: string;
  site_id?: string;
  trigger_type: 'event' | 'schedule' | 'threshold' | 'manual' | 'webhook' | 'api';
  trigger_config: Record<string, any>;
  conditions?: Record<string, any>;
  actions: AutomationAction[];
  status: 'active' | 'paused' | 'disabled' | 'error';
  priority: number;
  cooldown_seconds: number;
  max_triggers_per_hour: number;
  trigger_count: number;
  // Backend returns ``last_triggered`` (singular). The previous
  // ``last_triggered_at`` field name was always undefined, every
  // RuleCard render showed "Never" regardless of actual activity.
  last_triggered?: string | null;
  // Optional fields that the backend doesn't currently surface but
  // the FE has rendering for. Keep as optional so existing UI
  // doesn't break if the backend adds them later.
  success_count?: number;
  failure_count?: number;
  last_success_at?: string;
  last_failure_at?: string;
  last_error?: string;
  tags?: string[];
  created_at: string;
  updated_at?: string | null;
  // Computed fields for UI compatibility
  enabled?: boolean;
  execution_count?: number;
  last_executed?: string;
}

export interface AutomationExecution {
  id: string;
  rule_id: string;
  // Backend returns ``success: bool`` + ``triggered_at`` + ``error``
  // (NOT ``status`` + ``started_at`` + ``error_message``). The previous
  // type drift meant ``execution.status`` / ``started_at`` /
  // ``error_message`` were always undefined → Execution History
  // rendered "neutral" badges + "Invalid Date" on every row.
  success: boolean;
  triggered_at: string;
  error?: string | null;
  actions_executed: Array<Record<string, any>>;
  duration_ms?: number;
  // Computed fields for UI compatibility
  rule_name?: string;
  actions_failed?: number;
}

// =============================================================================
// WEBHOOKS
// =============================================================================

export interface Webhook {
  id: string;
  name: string;
  description?: string;
  url: string;
  event_types: string[];
  site_ids?: string[];
  enabled: boolean;
  retry_count: number;
  failure_count: number;
  success_count: number;
  last_triggered?: string;
  last_success?: string;
  last_failure?: string;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_id?: string;
  event_type: string;
  status: string;
  response_code?: number;
  response_time_ms?: number;
  attempt_number: number;
  error_message?: string;
  created_at: string;
  sent_at?: string;
}

export interface WebhookStats {
  webhook_id: string;
  total_deliveries: number;
  success: number;
  failed: number;
  pending: number;
  retrying: number;
  success_rate: number;
  avg_response_time_ms?: number;
  enabled: boolean;
  failure_count: number;
  last_triggered?: string;
}

export interface MetricData {
  name: string;
  values: Array<{ timestamp: string; value: number }>;
  aggregation: string;
  start_time: string;
  end_time: string;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  severity: string;
  user_id?: string;
  source_ip?: string;
  resource_type?: string;
  action?: string;
  outcome: string;
  details: Record<string, any>;
  timestamp: string;
}

// =============================================================================
// USERS
// =============================================================================

export interface UserAccount {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  organization_id: string | null;
  is_active: boolean;
  is_verified: boolean;
  mfa_enabled: boolean;
  last_login: string | null;
  language: string;
  created_at: string;
  updated_at: string | null;
}

export interface UserCreatePayload {
  email: string;
  username: string;
  full_name?: string;
  password: string;
  role?: string;
  organization_id?: string;
}

export interface UserUpdatePayload {
  email?: string;
  username?: string;
  full_name?: string;
  role?: string;
  is_active?: boolean;
  language?: string;
}

// =============================================================================
// INTEGRATIONS
// =============================================================================

export interface Integration {
  id: string;
  name: string;
  description?: string;
  integration_type: string;
  webhook_id: string;
  is_enabled: boolean;
  event_subscriptions: string[];
  config: Record<string, any>;
  last_delivery_at?: string;
  last_delivery_status?: string;
  delivery_count_7d: number;
  success_count_7d: number;
  created_at: string;
  updated_at?: string;
}

export interface IntegrationType {
  id: string;
  label: string;
  description: string;
  default_events: string[];
  icon: string;
  setup_docs_url?: string;
}

export interface IntegrationTemplate {
  id: string;
  name: string;
  integration_type: string;
  description: string;
  default_events: string[];
}

export interface EventCategory {
  name: string;
  events: string[];
}

// =============================================================================
// REMOTE AGENTS
// =============================================================================

export interface AgentInfo {
  agent_id: string;
  site_id: string;
  site_name: string;
  status: 'online' | 'offline' | 'connecting' | 'error' | 'maintenance';
  connected_at?: string;
  last_heartbeat?: string;
  version: string;
  hostname: string;
  platform: string;
  local_ip?: string;
  public_ip?: string;
  subnets: string[];
  uptime_seconds: number;
  commands_processed: number;
  errors_count: number;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
}

export interface AgentSummary {
  id: string;
  name: string;
  agent_type: 'site' | 'scanner' | 'collector' | 'gateway';
  status: 'online' | 'offline' | 'connecting' | 'error' | 'maintenance';
  last_ip?: string;
  last_heartbeat?: string;
  site_id?: string;
  site_name?: string;
  is_approved: boolean;
  is_enabled: boolean;
}

export interface AgentDetail {
  id: string;
  name: string;
  description?: string;
  agent_type: 'site' | 'scanner' | 'collector' | 'gateway';
  version?: string;
  platform?: string;
  capabilities: Record<string, any>;
  supported_vendors: string[];
  config: Record<string, any>;
  last_ip?: string;
  last_hostname?: string;
  status: 'online' | 'offline' | 'connecting' | 'error' | 'maintenance';
  last_seen?: string;
  last_heartbeat?: string;
  uptime_seconds: number;
  connected_at?: string;
  disconnected_at?: string;
  total_connections: number;
  total_tasks_executed: number;
  failed_tasks: number;
  poll_interval: number;
  is_approved: boolean;
  approved_at?: string;
  is_enabled: boolean;
  site_id?: string;
  organization_id?: string;
  site_name?: string;
  organization_name?: string;
  approved_by_name?: string;
  notification_channels?: Record<string, any>;
  offline_threshold_seconds?: number;
  offline_notified_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentListResponse {
  items: AgentSummary[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface AgentStats {
  total: number;
  online: number;
  offline: number;
  error: number;
  pending_approval: number;
  by_type: Record<string, number>;
  by_platform: Record<string, number>;
}

export interface AgentHeartbeat {
  id: string;
  agent_id: string;
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  status: string;
  latency_ms?: number;
  managed_devices: number;
  active_tasks: number;
}

export interface AgentTask {
  id: string;
  agent_id: string;
  task_type: string;
  task_data: Record<string, any>;
  priority: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  result?: Record<string, any>;
  error_message?: string;
  scheduled_at?: string;
  started_at?: string;
  completed_at?: string;
  max_retries: number;
  retry_count: number;
  created_at: string;
  updated_at: string;
}

export interface AgentHealth {
  agent_id: string;
  healthy: boolean;
  status: string;
  last_heartbeat?: string;
  uptime_seconds: number;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  network_status: string;
}

export interface AgentRegisterRequest {
  site_id: string;
  name: string;
  description?: string;
  agent_type?: 'site' | 'scanner' | 'collector' | 'gateway';
}

export interface AgentRegisterResponse {
  agent_id: string;
  agent_key: string;
  websocket_url: string;
  instructions: string;
}

export interface AgentCommandRequest {
  command_type: string;
  payload: Record<string, any>;
  timeout_seconds?: number;
}

export interface AgentCommandResponse {
  command_id: string;
  success: boolean;
  result?: unknown;
  error?: string;
  duration_ms: number;
}

export interface RemoteScanRequest {
  targets: string[];
  methods?: string[];
  ports?: number[];
}

// =============================================================================
// AGENT DOWNLOADS
// =============================================================================

export interface AgentReleaseLatest {
  version: string;
  platform: string;
  agent_type: string;
  download_url: string;
  checksum_sha256: string;
  file_size: number;
  release_notes: string;
}

export interface PlatformInstallInfo {
  platform: string;
  display_name: string;
  icon: string;
  daemon: AgentReleaseLatest | null;
  desktop: AgentReleaseLatest | null;
  install_commands: string[];
}

export interface DownloadsPageResponse {
  platforms: PlatformInstallInfo[];
  latest_version: string;
  server_version: string;
}

export interface AgentReleaseSummary {
  version: string;
  platforms: string[];
  agent_types: string[];
  release_date: string;
  is_latest: boolean;
  is_prerelease: boolean;
}

export interface AgentUpdateCheckResponse {
  update_available: boolean;
  latest_version: string;
  download_url: string;
  checksum_sha256: string;
  release_notes: string;
}

// =============================================================================
// VPN INTEGRATION
// =============================================================================

export type VPNType = 'tailscale' | 'wireguard' | 'openvpn' | 'netbird' | 'ipsec' | 'zerotier' | 'generic';

export interface VPNConnection {
  id: string;
  name: string;
  vpn_type: VPNType;
  status: 'connected' | 'disconnected' | 'connecting' | 'error' | 'not_configured';
  endpoint?: string;
  port?: number;
  allowed_ips?: string[];
  dns_servers?: string[];
  connected_at?: string;
  connected_since?: string;
  last_handshake?: string;
  rx_bytes?: number;
  tx_bytes?: number;
  latency_ms?: number;
  local_ip?: string;
  remote_ip?: string;
  extra_data?: Record<string, any>;
  openvpn_config_path?: string;
  openvpn_protocol?: string;
  netbird_management_url?: string;
  organization_id?: string;
}

export interface VPNConnectionCreate {
  name: string;
  vpn_type: VPNType;
  endpoint?: string;
  port?: number;
  local_ip?: string;
  remote_ip?: string;
  allowed_ips?: string[];
  dns_servers?: string[];
  openvpn_config_path?: string;
  openvpn_protocol?: string;
  // Full .ovpn / wg-quick config text — materialized to disk at connect time.
  // Write-only (the API never returns it); required for OpenVPN/WireGuard to
  // actually connect.
  openvpn_config_content?: string;
  wireguard_config_content?: string;
  netbird_setup_key?: string;
  netbird_management_url?: string;
  extra_data?: Record<string, any>;
}

export interface VPNConnectionUpdate {
  name?: string;
  vpn_type?: VPNType;
  endpoint?: string;
  port?: number;
  local_ip?: string;
  remote_ip?: string;
  allowed_ips?: string[];
  dns_servers?: string[];
  openvpn_config_path?: string;
  openvpn_protocol?: string;
  openvpn_config_content?: string;
  wireguard_config_content?: string;
  netbird_setup_key?: string;
  netbird_management_url?: string;
  extra_data?: Record<string, any>;
}

export interface TailscaleNode {
  id: string;
  name: string;
  hostname: string;
  dns_name: string;
  tailscale_ip?: string;
  tailscale_ips: string[];
  public_ip?: string;
  advertised_routes?: string[];
  status: 'online' | 'offline' | 'idle';
  online: boolean;
  is_exit_node?: boolean;
  relay?: string;
  direct?: boolean;
  os: string;
  user?: string;
  tags?: string[];
}

export interface TailscaleStatus {
  connected: boolean;
  backend_state: string;
  tailnet_name?: string;
  magic_dns_suffix?: string;
  magic_dns_enabled: boolean;
  has_exit_node?: boolean;
  self_node?: TailscaleNode;
  self?: TailscaleNode;
  peers?: TailscaleNode[];
  peer_count?: number;
}

export type TailscaleSetupState =
  | 'not_installed'
  | 'daemon_stopped'
  | 'needs_login'
  | 'awaiting_auth'
  | 'connected'
  | 'error';

export interface TailscaleSetupStatus {
  state: TailscaleSetupState;
  installed: boolean;
  daemon_running: boolean;
  authenticated: boolean;
  connected: boolean;
  version?: string;
  hostname?: string;
  tailscale_ip?: string;
  tailscale_ips?: string[];
  tailnet?: string;
  magic_dns_suffix?: string;
  magic_dns_enabled?: boolean;
  online?: boolean;
  os?: string;
  login_url?: string;
  peer_count?: number;
  message?: string;
}

export interface TailscaleAuthKeyLogin {
  auth_key: string;
  hostname?: string;
  accept_routes?: boolean;
  advertise_routes?: string[];
  advertise_exit_node?: boolean;
  shields_up?: boolean;
}

export interface TailscaleInteractiveLogin {
  hostname?: string;
  accept_routes?: boolean;
}

export interface TailscaleLoginResponse {
  success: boolean;
  message: string;
  state: TailscaleSetupState;
  login_url?: string;
  hostname?: string;
  tailscale_ip?: string;
  tailnet?: string;
}

export interface TailscaleConfigureRequest {
  hostname?: string;
  accept_routes?: boolean;
  advertise_routes?: string[];
  accept_dns?: boolean;
  advertise_exit_node?: boolean;
  shields_up?: boolean;
}

export interface TailscaleActionResponse {
  success: boolean;
  message: string;
  state: TailscaleSetupState;
}

export interface NetbirdPeer {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  status: string;
  direct: boolean;
  relay?: string;
  last_handshake?: string;
  routes: string[];
}

export interface NetbirdStatus {
  connected: boolean;
  management_state: string;
  signal_state: string;
  management_url?: string;
  self_ip?: string;
  fqdn?: string;
  interface?: string;
  peers: NetbirdPeer[];
  peer_count: number;
  connected_peers: number;
}

export interface VPNProviderInfo {
  id: string;
  name: string;
  description: string;
  icon: string;
  supported: boolean;
  installed: boolean;
  features: string[];
}

export interface VPNSubnet {
  subnet: string;
  via: string;
  node?: string;
  interface?: string;
  direct?: boolean;
}

export interface SiteVPNConfig {
  id: string;
  site_id: string;
  organization_id?: string;
  vpn_type: string;
  enabled: boolean;
  auto_connect?: boolean;
  priority?: number;
  // Brain-VPN integration
  controller_id?: string;
  vpn_source?: string;  // 'manual' | 'brain_import' | 'agent_provision'
  brain_vpn_server_id?: string;
  last_config_sync?: string;
  // Tailscale
  tailscale_node?: string;
  tailscale_hostname?: string;
  tailscale_tags?: string[];
  // WireGuard
  wireguard_interface?: string;
  wireguard_endpoint?: string;
  wireguard_peer_public_key?: string;
  wireguard_allowed_ips?: string[];
  // Generic
  vpn_endpoint?: string;
  vpn_port?: number;
  // Health
  health_check_ip?: string;
  health_check_interval?: number;
  latency_threshold_ms?: number;
  remote_subnets?: string[];
  local_subnets?: string[];
  // OpenVPN
  openvpn_config_path?: string;
  openvpn_protocol?: string;
  openvpn_mode?: string;
  // ZeroTier
  zerotier_network_id?: string;
  zerotier_node_id?: string;
  // Netbird
  netbird_peer_id?: string;
  netbird_group?: string;
  // Multi-VPN
  is_primary?: boolean;
  // Certificate lifecycle
  cert_metadata?: Record<string, unknown> | null;
  cert_expires_at?: string | null;
  // Status
  status: string;
  last_health_check?: string;
  // Timestamps
  created_at?: string;
  updated_at?: string;
}

export interface BrainVPNServer {
  id: string;
  description?: string;
  name?: string;
  protocol?: string;
  port?: string | number;
  mode?: string;
  status?: string;
  public_key?: string;
  listen_port?: string | number;
  address?: string;
  dev_type?: string;
  remote_gateway?: string;
  peers?: unknown[];
}

export interface BrainVPNDiscovery {
  controller_id: string;
  controller_name: string;
  controller_type: string;
  site_id: string;
  openvpn: BrainVPNServer[];
  wireguard: BrainVPNServer[];
  ipsec: BrainVPNServer[];
}

export interface VPNStatusSummary {
  total_connections: number;
  connected: number;
  disconnected: number;
  error: number;
  tailscale_connected: boolean;
  wireguard_tunnels: number;
  total_peers: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
}

// Auto-Reconnect
export interface VPNReconnectStatus {
  connection_id: string;
  attempt_count: number;
  max_attempts: number;
  next_retry_at: string | null;
  backoff_seconds: number;
  state: 'idle' | 'retrying' | 'exhausted' | 'success';
  last_error: string | null;
}

// VPN Events
export interface VPNEvent {
  id: string;
  organization_id: string;
  site_id: string | null;
  connection_id: string | null;
  tunnel_id: string | null;
  event_type: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  details: Record<string, unknown>;
  source: string | null;
  actor_id: string | null;
  created_at: string;
}

export interface VPNEventList {
  events: VPNEvent[];
  total: number;
}

export interface VPNEventSummary {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  period_hours: number;
}

// Health History
export interface VPNHealthCheckRecord {
  id: string;
  time: string;
  connection_id: string | null;
  tunnel_id: string | null;
  site_id: string | null;
  is_healthy: boolean;
  latency_ms: number | null;
  status: string;
  error_message: string | null;
  rx_bytes: number;
  tx_bytes: number;
  peer_count: number;
}

// Preflight
export interface VPNPreflightResult {
  reachable: boolean;
  vpn_type: string | null;
  latency_ms: number | null;
  vpn_status: string | null;
  error: string | null;
  skipped: boolean;
}

export interface VPNDeviceReachability {
  device_id: string;
  device_name: string;
  device_type: string;
  ip: string | null;
  reachable: boolean;
  latency_ms: number | null;
  error: string | null;
}

export interface VPNSiteReachability {
  site_id: string;
  vpn_status: string | null;
  devices: VPNDeviceReachability[];
}

// Bandwidth Metrics
export interface VPNMetricsBucket {
  time: string;
  avg_latency_ms: number | null;
  max_latency_ms: number | null;
  rx_bytes_delta: number;
  tx_bytes_delta: number;
  health_pct: number;
}

export interface VPNAggregateMetrics {
  total_rx_bytes: number;
  total_tx_bytes: number;
  avg_latency_ms: number | null;
  connection_count: number;
  by_provider: Record<string, { count: number; rx_bytes: number; tx_bytes: number; avg_latency_ms: number | null }>;
}

// S2S Tunnels
export interface VPNTunnelTemplate {
  id: string;
  organization_id: string;
  name: string;
  vpn_type: 'ipsec' | 'wireguard' | 'openvpn';
  topology: 'hub_spoke' | 'full_mesh' | 'point_to_point';
  config_template: Record<string, unknown>;
  default_subnets: string[];
  mtu: number | null;
  mss_clamp: number | null;
  created_at: string;
  updated_at: string;
}

export interface VPNTunnelTemplateCreate {
  name: string;
  vpn_type: 'ipsec' | 'wireguard' | 'openvpn';
  topology?: 'hub_spoke' | 'full_mesh' | 'point_to_point';
  config_template?: Record<string, unknown>;
  default_subnets?: string[];
  mtu?: number;
  mss_clamp?: number;
}

export interface SiteToSiteTunnel {
  id: string;
  organization_id: string;
  template_id: string | null;
  site_a_id: string;
  site_b_id: string;
  gateway_a_device_id: string | null;
  gateway_b_device_id: string | null;
  status: 'pending' | 'provisioning' | 'active' | 'error' | 'disabled';
  config_a: Record<string, unknown>;
  config_b: Record<string, unknown>;
  provisioned_at: string | null;
  last_health_check: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

// Dashboard Widget
export interface VPNDashboard {
  active_connections: number;
  healthy_pct: number;
  avg_latency_ms: number | null;
  total_rx_bytes: number;
  total_tx_bytes: number;
  active_tunnels: number;
  error_tunnels: number;
  vpn_alerts: number;
  sites_with_vpn: number;
  sites_healthy: number;
}

// Multi-VPN per site
export interface SiteVPNConfigList {
  configs: SiteVPNConfig[];
  total: number;
}

// Route Conflict Detection
export interface VPNRouteConflict {
  subnet: string;
  source_a: string;
  source_b: string;
  source_a_type: string;
  source_b_type: string;
  severity: 'warning' | 'error';
  overlap_type: 'exact' | 'subset' | 'superset';
}

export interface VPNRouteConflictsResult {
  conflicts: VPNRouteConflict[];
  total: number;
  scanned_sources: number;
}

// Certificate Lifecycle
export interface VPNCertExpiry {
  config_id: string;
  site_id: string;
  site_name: string | null;
  vpn_type: string;
  cert_subject: string | null;
  expires_at: string;
  days_remaining: number;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

export interface VPNCertExpiryResult {
  certs: VPNCertExpiry[];
  total: number;
}

// Key Exchange
export interface VPNKeyExchangeResult {
  success: boolean;
  tunnel_id: string;
  message: string;
  config_a_generated: boolean;
  config_b_generated: boolean;
}

// =============================================================================
// ONBOARDING WORKFLOW
// =============================================================================

export interface OnboardingScanRequest {
  site_id: string;
  targets: string[];
  exclude_targets?: string[];
  scan_methods?: string[];
  ports?: number[];
  follow_controllers?: boolean;
}

export interface OnboardingScanResponse {
  scan_id: string;
  status: string;
  total_targets: number;
  message: string;
}

export interface OnboardingScanProgress {
  scan_id: string;
  status: string;
  started_at: string;
  current_phase: string;
  phase_progress: number;
  total_hosts: number;
  scanned_hosts: number;
  discovered_hosts: number;
  elapsed_seconds: number;
  estimated_remaining_seconds?: number;
  errors: string[];
}

export interface OnboardingDiscoveredDevice {
  id: string;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  vendor?: string;
  open_ports: number[];
  likely_device_types: string[];
  mdns_services: string[];
  discovery_method: string;
  discovered_at: string;
  fingerprint_status: string;
}

export interface FingerprintResult {
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  mac_vendor?: string;
  detected_vendor?: string;
  vendor_confidence: number;
  open_ports: number[];
  likely_device_type?: string;
  device_type_confidence: number;
  protocols_detected: string[];
  onvif_available: boolean;
  api_probes: Record<string, any>;
  http_info: Record<string, any>;
  fingerprint_duration_ms: number;
}

export interface DriverMatchResult {
  driver_id: string;
  driver_name: string;
  vendor: string;
  match_score: number;
  match_reasons: string[];
  warnings: string[];
  capabilities: Record<string, boolean>;
  supported_device_types: string[];
  recommended_tier: string;
  requires_credentials: boolean;
}

export interface MatchResult {
  fingerprint_summary: Record<string, any>;
  matches: DriverMatchResult[];
  recommended_driver?: DriverMatchResult;
  overall_confidence: number;
  is_manageable: boolean;
  requires_credentials: boolean;
  suggestions: string[];
}

// =============================================================================
// CONFIGURATION MANAGEMENT
// =============================================================================

export interface ConfigVersion {
  id: string;
  version: number;
  config_hash: string;
  config_size: number;
  change_type: string;
  status: string;
  initiated_by: string;
  notes?: string;
  device_firmware?: string;
  device_model?: string;
  restored_from_version?: number;
  created_at: string;
}

export interface ConfigDiff {
  version_a: string;
  version_b: string;
  has_changes: boolean;
  added_lines: number;
  removed_lines: number;
  modified_sections: string[];
  unified_diff: string;
  summary: string;
}

export interface BackupTemplate {
  id: string;
  name: string;
  description?: string;
  device_type?: string;
  vendor?: string;
  variables: string[];
  created_at: string;
  updated_at: string;
}

// =============================================================================
// DEVICE CONTROL
// =============================================================================

export interface CapabilityDetail {
  name: string;
  level: 'none' | 'read' | 'full' | 'experimental' | 'deprecated';
  supported: boolean;
  can_write: boolean;
  min_version?: string;
  reason_disabled?: string;
  notes?: string;
}

export interface DeviceCapabilitiesResponse {
  device_id: string;
  model: string;
  vendor: string;
  firmware_version?: string;
  driver_base_caps: Record<string, CapabilityDetail>;
  profile_restrictions: Record<string, string>;
  effective_caps: Record<string, CapabilityDetail>;
  can_poe_control: boolean;
  can_poe_status: boolean;
  can_port_control: boolean;
  can_port_status: boolean;
  can_port_config: boolean;
  can_vlan_config: boolean;
  can_ssid_control: boolean;
  can_client_list: boolean;
  can_firmware_update: boolean;
  can_backup: boolean;
  can_reboot: boolean;
  total_capabilities: number;
  supported_capabilities: number;
  restricted_capabilities: number;
}

export interface DeviceCapabilities {
  can_reboot: boolean;
  can_locate: boolean;
  can_poe_control: boolean;
  can_ssid_control: boolean;
  can_backup_config: boolean;
  can_restore_config: boolean;
  can_firmware_update: boolean;
  custom_actions: string[];
}

export interface ActionResult {
  success: boolean;
  message: string;
  action_id?: string;
  data?: Record<string, unknown>;
}

export interface DeviceAction {
  id: string;
  device_id: string;
  action_type: string;
  status: string;
  initiated_by: string;
  started_at: string;
  completed_at?: string;
  result?: Record<string, unknown>;
  error_message?: string;
}

export interface PortState {
  port_number: number;
  name: string;
  enabled: boolean;
  link_up: boolean;
  speed?: string;
  duplex?: string;
  vlan_mode?: string;
  native_vlan?: number;
  tagged_vlans: number[];
  poe_enabled?: boolean;
  poe_power_watts?: number;
  poe_power_limit?: number;
  poe_status?: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
}

export interface IntentResponse {
  success: boolean;
  message: string;
  intent_id?: string;
  observed_before?: Record<string, unknown>;
  observed_after?: Record<string, unknown>;
}

// =============================================================================
// NOTIFICATIONS
// =============================================================================

export interface NotificationProvider {
  id: string;
  name: string;
  provider_type: string;
  channel: string;
  is_enabled: boolean;
  is_default: boolean;
  is_verified: boolean;
  last_verified_at?: string;
  last_error?: string;
  rate_limit_per_hour: number;
  rate_limit_per_day: number;
  config_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface NotificationTemplate {
  id: string;
  name: string;
  slug: string;
  description?: string;
  channel: string;
  subject?: string;
  body_html?: string;
  body_text?: string;
  slack_blocks?: Record<string, unknown>[];
  variables: Array<{
    name: string;
    description: string;
    example?: string;
    required: boolean;
  }>;
  is_enabled: boolean;
  is_system: boolean;
  created_at: string;
  updated_at: string;
}

export interface NotificationPreference {
  id: string;
  user_id: string;
  notifications_enabled: boolean;
  email_enabled: boolean;
  slack_enabled: boolean;
  in_app_enabled: boolean;
  notification_email?: string;
  min_email_severity: string;
  min_slack_severity: string;
  min_in_app_severity: string;
  subscriptions: Record<string, { email: boolean; slack: boolean; in_app: boolean }>;
  quiet_hours_enabled: boolean;
  quiet_hours_start?: string;
  quiet_hours_end?: string;
  quiet_hours_timezone: string;
  quiet_hours_exceptions: string[];
  digest_enabled: boolean;
  digest_frequency: string;
  digest_time: string;
  created_at: string;
  updated_at: string;
}

export interface InAppNotification {
  id: string;
  user_id: string;
  title: string;
  message: string;
  icon?: string;
  category: string;
  severity: string;
  entity_type?: string;
  entity_id?: string;
  action_url?: string;
  is_read: boolean;
  read_at?: string;
  is_dismissed: boolean;
  dismissed_at?: string;
  expires_at?: string;
  created_at: string;
}

export interface ProviderType {
  type: string;
  name: string;
  channel: string;
  icon?: string;
  config_schema: Record<string, unknown>;
}

export interface TestProviderResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// FIREWALLS
// =============================================================================

export interface FirewallCreateRequest {
  name: string;
  description?: string;
  firewall_type: 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt';
  host: string;
  port: number;
  api_key: string;
  api_secret: string;
  username?: string;
  password?: string;
  verify_ssl: boolean;
  is_enabled: boolean;
  site_id?: string;
}

export interface TestConnectionRequest {
  firewall_type: string;
  host: string;
  port: number;
  api_key?: string;
  api_secret?: string;
  username?: string;
  password?: string;
  verify_ssl: boolean;
}

// =============================================================================
// POE
// =============================================================================

export interface PoEPortStatus {
  port_id: string;
  port_index: number;
  port_name: string;
  device_id: string;
  device_name: string;
  poe_enabled: boolean;
  poe_mode: string;
  poe_status: string;
  power_draw: number;
  power_limit: number;
  power_class?: number;
  voltage?: number;
  current?: number;
  pd_type?: string;
}

export interface PoESwitchSummary {
  device_id: string;
  device_name: string;
  model: string;
  power_budget: number;
  power_used: number;
  power_available: number;
  power_percentage: number;
  total_poe_ports: number;
  active_poe_ports: number;
  disabled_poe_ports: number;
  fault_poe_ports: number;
  near_budget: boolean;
  over_budget: boolean;
}

export interface PoESchedule {
  id: string;
  name: string;
  description?: string;
  port_ids: string[];
  schedule_type: string;
  days_of_week: number[];
  start_time: string;
  end_time: string;
  action: string;
  is_enabled: boolean;
  affected_ports: number;
  next_trigger?: string;
}

// =============================================================================
// FIRMWARE
// =============================================================================

export interface FirmwareSummary {
  id: string;
  vendor: string;
  model: string;
  device_type?: string;
  version: string;
  release_type: string;
  display_name?: string;
  description?: string;
  release_notes?: string;
  release_notes_url?: string;
  release_date?: string;
  file_path?: string;
  file_size_bytes?: number;
  download_url?: string;
  checksum_md5?: string;
  checksum_sha256?: string;
  is_latest: boolean;
  is_critical: boolean;
  is_recommended: boolean;
  is_deprecated: boolean;
  is_cached: boolean;
  cached_at?: string;
  min_version?: string;
  max_version?: string;
  compatible_models?: string[];
  upgrade_path?: string[];
  device_count: number;
  devices_up_to_date: number;
  organization_id?: string;
  created_at: string;
  updated_at?: string;
}

export interface DeviceFirmwareStatus {
  id: string;
  device_id: string;
  site_id?: string;
  device_name: string | null;
  device_type: string | null;
  vendor: string | null;
  model: string | null;
  current_version: string | null;
  latest_version?: string;
  recommended_version?: string;
  is_up_to_date: boolean;
  update_available: boolean;
  critical_update_available: boolean;
  can_upgrade: boolean;
  upgrade_path?: string[];
  last_checked_at?: string;
}

export interface FirmwareUpgradeJob {
  id: string;
  status: string;
  firmware_id: string;
  firmware_version: string;
  device_ids: string[];
  site_id?: string;
  backup_before: boolean;
  rollback_on_failure: boolean;
  batch_size: number;
  delay_between_batches: number;
  notify_on_complete: boolean;
  notify_on_failure: boolean;
  scheduled_at?: string;
  progress: number;
  total_devices: number;
  successful: number;
  failed: number;
  skipped: number;
  devices?: {
    device_id: string;
    device_name?: string;
    status: string;
    progress?: number;
  }[];
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  created_by?: string;
  celery_task_id?: string;
  created_at: string;
  updated_at?: string;
}

export interface FirmwareSchedule {
  id: string;
  name: string;
  description?: string;
  is_enabled: boolean;
  site_id?: string;
  device_type?: string;
  vendor?: string;
  model?: string;
  tags?: string[];
  device_ids?: string[];
  auto_latest: boolean;
  target_version?: string;
  release_type: string;
  frequency: string;
  time_of_day?: string;
  day_of_week?: number;
  day_of_month?: number;
  timezone?: string;
  maintenance_window_start?: string;
  maintenance_window_end?: string;
  backup_before: boolean;
  rollback_on_failure: boolean;
  max_concurrent: number;
  batch_size: number;
  delay_between_batches: number;
  notify_before: boolean;
  notify_before_hours: number;
  notify_on_complete: boolean;
  notify_on_failure: boolean;
  last_run_at?: string;
  next_run_at?: string;
  last_job_id?: string;
  total_runs: number;
  organization_id?: string;
  created_by?: string;
  created_at: string;
  updated_at?: string;
}

export interface FirmwareSummaryResponse {
  total_devices: number;
  up_to_date: number;
  update_available: number;
  critical_updates: number;
  total_firmware_images: number;
  active_jobs: number;
  scheduled_jobs: number;
  by_vendor: Record<string, { total: number; up_to_date: number; updates: number }>;
  by_device_type: Record<string, { total: number; up_to_date: number; updates: number }>;
  recent_upgrades: {
    device_name: string;
    from_version: string;
    to_version: string;
    upgraded_at: string;
    status: string;
  }[];
  repo_stats: Record<string, any>;
}

export interface FirmwarePaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// =============================================================================
// ANALYTICS
// =============================================================================

export interface DashboardSummary {
  total_devices: number;
  devices_online: number;
  devices_offline: number;
  devices_warning: number;
  total_sites: number;
  total_clients: number;
  active_alerts: number;
  critical_alerts: number;
  total_rx_bytes_24h: number;
  total_tx_bytes_24h: number;
  health_score_avg: number;
  metrics_summary: {
    api_calls: number;
    events_processed: number;
    automation_executions: number;
  };
  top_issues: Array<{
    id: string;
    severity: string;
    title: string;
    triggered_at: string;
  }>;
  recent_alerts: Array<{
    id: string;
    severity: string;
    status: string;
    title: string;
    triggered_at: string;
  }>;
  timestamp: string;
}

export interface EnterpriseAnalytics {
  timestamp: string;
  hours: number;
  health_score: number;
  fleet: {
    total: number;
    online: number;
    offline: number;
    degraded: number;
    avg_cpu: number;
    avg_memory: number;
    avg_temp: number | null;
    max_cpu: number | null;
    max_memory: number | null;
    max_temp: number | null;
    by_type: Record<string, { total: number; online: number; offline: number }>;
    by_manufacturer: Array<{ name: string; count: number }>;
  };
  clients: {
    total: number;
    online: number;
    band_2g: number;
    band_5g: number;
    band_6g: number;
    avg_signal_dbm: number | null;
    total_tx_bytes: number;
    total_rx_bytes: number;
    signal_distribution: Record<string, number>;
    top_ssids: Array<{ ssid: string; clients: number }>;
  };
  ports: {
    total: number;
    up: number;
    down: number;
    poe_ports: number;
    total_poe_watts: number;
    total_tx_bytes: number;
    total_rx_bytes: number;
    total_errors: number;
  };
  sites: Array<{
    id: string;
    name: string;
    devices: number;
    online: number;
    offline: number;
    health: number;
  }>;
  total_sites: number;
  controllers: Array<{
    id: string;
    name: string;
    type: string;
    status: string;
    host: string;
    sync_enabled: boolean;
    device_count: number;
  }>;
  security: {
    failed_logins_window: number;
    active_ip_blocks: number;
    unresolved_anomalies: number;
    total_security_events: number;
  };
  audit: {
    total_events: number;
    by_level: Record<string, number>;
    by_source: Record<string, number>;
  };
  incidents: {
    open: number;
    investigating: number;
    resolved: number;
    total: number;
  };
  top_devices_cpu: Array<{
    id: string;
    name: string;
    type: string;
    cpu: number;
    status: string;
  }>;
  top_devices_memory: Array<{
    id: string;
    name: string;
    type: string;
    memory: number;
    status: string;
  }>;
}

export interface TrafficDataPoint {
  timestamp: string;
  rx_bps: number;
  tx_bps: number;
  clients: number;
}

export interface TrafficAnalytics {
  site_id: string;
  period_hours: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
  peak_rx_bps: number;
  peak_tx_bps: number;
  avg_rx_bps: number;
  avg_tx_bps: number;
  data_points: TrafficDataPoint[];
  top_clients: Array<{
    mac: string;
    ip: string;
    hostname?: string;
    rx: number;
    tx: number;
  }>;
  top_applications: Array<{
    app: string;
    rx: number;
    tx: number;
    connections: number;
  }>;
  traffic_by_category: Record<string, number>;
}

export interface ClientAnalytics {
  total_clients: number;
  active_clients: number;
  wired_clients: number;
  wireless_clients: number;
  clients_by_os: Record<string, number>;
  clients_by_ssid: Record<string, number>;
  avg_signal_strength: number;
  avg_latency_ms: number;
  client_list: Array<{
    mac: string;
    ip?: string;
    hostname?: string;
    os?: string;
    connection_type: string;
    ssid?: string;
    signal_strength?: number;
    tx_rate?: number;
    rx_rate?: number;
    latency_ms?: number;
    session_duration?: number;
    is_active: boolean;
  }>;
}

export interface DeviceHealth {
  device_id: string;
  device_name?: string;
  is_online: boolean;
  health_score: number;
  health_issues: string[];
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  temperature?: number;
  uptime_seconds?: number;
  rx_rate_bps?: number;
  tx_rate_bps?: number;
  client_count?: number;
  last_updated?: string;
}

export interface NetworkOverview {
  site_id: string;
  site_name: string;
  total_devices: number;
  devices_online: number;
  devices_offline: number;
  total_clients: number;
  wired_clients: number;
  wireless_clients: number;
  guest_clients: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
  wan_utilization: number;
  active_alerts: number;
  timestamp: string;
}

export interface MetricDefinition {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  category: string;
  metric_type: string;
  unit?: string;
  labels: string[];
  default_aggregation: string;
  warning_threshold?: Record<string, any>;
  critical_threshold?: Record<string, any>;
  is_active: boolean;
  is_system: boolean;
}

export interface MetricQueryRequest {
  metric_name: string;
  start_time?: string;
  end_time?: string;
  granularity?: string;
  aggregation?: string;
  filters?: Record<string, any>;
  limit?: number;
}

export interface MetricDataPoint {
  timestamp: string;
  value: Record<string, any>;
  labels?: Record<string, any>;
}

export interface MetricQueryResponse {
  metric_name: string;
  display_name: string;
  unit?: string;
  granularity: string;
  data_points: MetricDataPoint[];
  aggregations?: {
    min: number;
    max: number;
    avg: number;
    count: number;
    sum: number;
    last: number;
  };
}

export interface AnalyticsAlert {
  id: string;
  severity: string;
  status: string;
  alert_type: string;
  title: string;
  message?: string;
  metric_name?: string;
  metric_value?: Record<string, any>;
  device_id?: string;
  site_id?: string;
  triggered_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
}

export interface DashboardWidget {
  id: string;
  dashboard_name: string;
  title: string;
  widget_type: string;
  position_x: number;
  position_y: number;
  width: number;
  height: number;
  metrics: string[];
  filters: Record<string, any>;
  aggregation: string;
  time_range: string;
  display_options: Record<string, any>;
  refresh_interval_seconds: number;
  created_at: string;
  updated_at: string;
}

// =============================================================================
// BACKUP
// =============================================================================

export type BackupType = 'full' | 'device_config' | 'site_config' | 'database' | 'manual' | 'scheduled';
export type BackupStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
export type BackupStorageType = 'local' | 's3' | 'sftp' | 'ftp' | 'nfs' | 'google_drive' | 'dropbox' | 'webdav';

export interface Backup {
  id: string;
  name: string;
  description: string | null;
  backup_type: BackupType;
  status: BackupStatus;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  storage_type: BackupStorageType;
  storage_location_id: string | null;
  storage_path: string | null;
  file_size: number | null;
  site_id: string | null;
  device_ids: string[];
  include_devices: boolean;
  include_vlans: boolean;
  include_ssids: boolean;
  include_users: boolean;
  include_automation: boolean;
  is_encrypted: boolean;
  retention_days: number;
  expires_at: string | null;
  error_message: string | null;
  created_at: string;
  created_by_id: string | null;
  schedule_id: string | null;
  // Set on auto-captured pre-restore snapshots (backup_type=
  // "rollback_slot"): links to the RestoreJob the snapshot preceded so
  // the UI can render an "Undo restore" action. Null on user backups.
  rollback_for_restore_job_id?: string | null;
}

export interface BackupCreate {
  name: string;
  description?: string;
  backup_type?: BackupType;
  site_id?: string;
  device_ids?: string[];
  include_devices?: boolean;
  include_vlans?: boolean;
  include_ssids?: boolean;
  include_users?: boolean;
  include_automation?: boolean;
  storage_type?: BackupStorageType;
  storage_location_id?: string;
  is_encrypted?: boolean;
  retention_days?: number;
}

export interface BackupListResponse {
  items: Backup[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface BackupSchedule {
  id: string;
  name: string;
  description: string | null;
  cron_expression: string;
  timezone: string;
  backup_type: BackupType;
  site_id: string | null;
  storage_type: BackupStorageType;
  storage_location_id: string | null;
  is_encrypted: boolean;
  retention_days: number;
  max_backups: number;
  is_enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

export interface BackupScheduleCreate {
  name: string;
  description?: string;
  cron_expression: string;
  timezone?: string;
  backup_type?: BackupType;
  site_id?: string;
  device_ids?: string[];
  include_devices?: boolean;
  include_vlans?: boolean;
  include_ssids?: boolean;
  include_users?: boolean;
  include_automation?: boolean;
  storage_type?: BackupStorageType;
  storage_location_id?: string;
  is_encrypted?: boolean;
  retention_days?: number;
  max_backups?: number;
}

export interface RestoreRequest {
  backup_id: string;
  target_site_id?: string;
  target_device_ids?: string[];
  restore_devices?: boolean;
  restore_vlans?: boolean;
  restore_ssids?: boolean;
  restore_users?: boolean;
  restore_automation?: boolean;
  overwrite_existing?: boolean;
  dry_run?: boolean;
  // Selective restore (enterprise backup v2): subset of manifest
  // contributor ids to restore. Omit/undefined = restore everything.
  contributors?: string[];
}

// ── v2 manifest preview (enterprise backup) ──
export interface ContributorPreview {
  id: string;
  schema_version: string;
  counts: Record<string, number>;
  restorable: boolean;
  incompatibility_reason: string | null;
}

export interface BackupManifestPreview {
  backup_id: string;
  format_version: string;
  created_at: string | null;
  source_version: string | null;
  organization_id: string | null;
  contributors: ContributorPreview[];
}

export interface RestoreJob {
  id: string;
  backup_id: string;
  status: BackupStatus;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  dry_run: boolean;
  dry_run_report: Record<string, any> | null;
  created_at: string;
}

export interface BackupStats {
  total_backups: number;
  completed_backups: number;
  failed_backups: number;
  in_progress: number;
  total_size_bytes: number;
  total_size_gb: number;
  recent_backups: Backup[];
  schedules_enabled: number;
  schedules_disabled: number;
}

export interface ExportOptions {
  include_devices?: boolean;
  include_vlans?: boolean;
  include_ssids?: boolean;
  include_users?: boolean;
  include_automation?: boolean;
  include_settings?: boolean;
  compress?: boolean;
}

export interface ImportResult {
  success?: boolean;
  dry_run?: boolean;
  would_import?: {
    devices: number;
    vlans: number;
    sites: number;
    controllers: number;
    users: number;
    automation_rules: number;
  };
  imported?: {
    devices: { restored: number; skipped: number; failed: number };
    vlans: { restored: number; skipped: number; failed: number };
    sites: { restored: number; skipped: number; failed: number };
    controllers: { restored: number; skipped: number; failed: number };
    users: { restored: number; skipped: number; failed: number };
    automation_rules: { restored: number; skipped: number; failed: number };
    errors: string[];
  };
  message?: string;
  metadata?: Record<string, unknown>;
}

// Storage Location Types
export interface StorageLocation {
  id: string;
  name: string;
  description: string | null;
  storage_type: BackupStorageType;
  is_active: boolean;
  is_default: boolean;
  last_test_at: string | null;
  last_test_status: 'success' | 'failed' | null;
  last_test_message: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface StorageLocationCreate {
  name: string;
  description?: string;
  storage_type: BackupStorageType;
  is_default?: boolean;
  config: StorageLocationConfig;
  /**
   * Secrets — access_key, secret_key, password, token, … The backend
   * Fernet-encrypts these into `encrypted_credentials` and never echoes them.
   *
   * These must NOT be sent inside `config`: `_validate_storage_config`
   * rejects any credential-class key there, which is why the storage-location
   * form used to 422 on every backend that has a secret.
   */
  credentials?: Record<string, string>;
}

export interface StorageLocationUpdate {
  name?: string;
  description?: string;
  is_active?: boolean;
  is_default?: boolean;
  config?: Partial<StorageLocationConfig>;
  /**
   * Merged with the stored credentials (new keys win) and re-encrypted.
   * An EMPTY dict clears every stored credential, so omit the field entirely
   * when the operator left the secret inputs blank to keep what is there.
   */
  credentials?: Record<string, string>;
}

export type StorageLocationConfig =
  | LocalStorageConfig
  | S3StorageConfig
  | SFTPStorageConfig
  | FTPStorageConfig
  | GoogleDriveStorageConfig
  | DropboxStorageConfig
  | WebDAVStorageConfig;

export interface LocalStorageConfig {
  path?: string;
}

export interface S3StorageConfig {
  bucket: string;
  region?: string;
  endpoint_url?: string;
  access_key: string;
  secret_key: string;
  path_prefix?: string;
}

export interface SFTPStorageConfig {
  host: string;
  port?: number;
  username: string;
  password?: string;
  private_key_path?: string;
  private_key_passphrase?: string;
  remote_path?: string;
}

export interface FTPStorageConfig {
  host: string;
  port?: number;
  username: string;
  password: string;
  remote_path?: string;
  use_tls?: boolean;
}

export interface GoogleDriveStorageConfig {
  credentials_json?: string;
  folder_id?: string;
  client_id?: string;
  client_secret?: string;
  access_token?: string;
  refresh_token?: string;
}

export interface DropboxStorageConfig {
  access_token?: string;
  refresh_token?: string;
  app_key?: string;
  app_secret?: string;
  folder_path?: string;
}

export interface WebDAVStorageConfig {
  url: string;
  username: string;
  password: string;
  path?: string;
}

export interface StorageLocationTestResult {
  success: boolean;
  message: string;
  latency_ms: number | null;
  details: Record<string, unknown> | null;
}

export interface StorageTypeInfo {
  id: BackupStorageType;
  name: string;
  description: string;
  icon: string;
  fields: StorageTypeField[];
}

export interface StorageTypeField {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'password' | 'textarea';
  label: string;
  required: boolean;
  default?: unknown;
  placeholder?: string;
}

export interface SupportedStorageTypes {
  types: StorageTypeInfo[];
}

// =============================================================================
// SYSTEM INFO
// =============================================================================

export interface ComponentVersion {
  name: string;
  version: string;
  status: 'current' | 'outdated' | 'unknown';
  latest_version: string | null;
  update_available: boolean;
}

export interface DatabaseInfo {
  type: string;
  version: string;
  host: string;
  database: string;
  pool_size: number;
  status: string;
}

export interface RedisInfo {
  host: string;
  port: number;
  database: number;
  status: string;
  version: string | null;
}

export interface SystemInfo {
  app_name: string;
  app_version: string;
  environment: string;
  server_time: string;
  uptime_seconds: number | null;
  python_version: string;
  python_implementation: string;
  os_name: string;
  os_version: string;
  os_platform: string;
  architecture: string;
  database: DatabaseInfo;
  redis: RedisInfo;
  components: ComponentVersion[];
}

export interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  /**
   * Per-component health from ``GET /api/v1/health``. The backend
   * returns ``components.{database,redis,celery}.status`` (not
   * ``checks.{...}: string``). Older code paths read ``checks``,
   * those should migrate to ``components``.
   */
  components?: {
    database?: { status: string; latency_ms?: number | null; error?: string | null };
    redis?: { status: string; latency_ms?: number | null; error?: string | null };
    celery?: { status: string; latency_ms?: number | null; error?: string | null };
  };
  /** @deprecated Read ``components.{x}.status`` instead. Left in
   *  the type so older consumers don't break compilation; the
   *  backend never populates this field. */
  checks?: {
    database?: string;
    redis?: string;
  };
}

export interface FrontendVersions {
  react: { current: string; latest: string };
  vite: { current: string; latest: string };
  typescript: { current: string; latest: string };
  node: { recommended: string; minimum: string };
  tailwindcss: { current: string; latest: string };
}

// =============================================================================
// NETWORK MANAGEMENT
// =============================================================================

export interface Vlan {
  id: string;
  vlan_id: number;
  name: string;
  description?: string;
  site_id?: string;
  dhcp_enabled: boolean;
  dhcp_start?: string;
  dhcp_end?: string;
  gateway?: string;
  subnet_mask?: string;
}

export interface VlanCreate {
  vlan_id: number;
  name: string;
  description?: string;
  site_id?: string;
  dhcp_enabled?: boolean;
  dhcp_start?: string;
  dhcp_end?: string;
  gateway?: string;
  subnet_mask?: string;
}

export interface VlanUpdate {
  name?: string;
  description?: string;
  dhcp_enabled?: boolean;
  dhcp_start?: string;
  dhcp_end?: string;
  gateway?: string;
  subnet_mask?: string;
}

export interface WifiNetwork {
  id: string;
  ssid: string;
  security: string;
  vlan_id?: number;
  site_id?: string;
  hidden: boolean;
  enabled: boolean;
  band: '2.4ghz' | '5ghz' | 'both' | 'all' | '6ghz';
  client_isolation: boolean;
  band_steering: boolean;
  fast_roaming: boolean;
  rate_limit_enabled: boolean;
  rate_limit_up?: number;
  rate_limit_down?: number;
  guest_network: boolean;
  wlan_group_name?: string;
  wlan_group_id?: string;
  external_id?: string;
  controller_id?: string;
  schedule_enabled: boolean;
  mac_filter_enabled: boolean;
  portal_enabled: boolean;
}

export interface WifiNetworkCreate {
  ssid: string;
  password?: string;
  security?: string;
  vlan_id?: number;
  site_id?: string;
  hidden?: boolean;
  enabled?: boolean;
  band?: string;
  client_isolation?: boolean;
  band_steering?: boolean;
  fast_roaming?: boolean;
  rate_limit_enabled?: boolean;
  rate_limit_up?: number;
  rate_limit_down?: number;
}

export interface WifiNetworkUpdate {
  ssid?: string;
  password?: string;
  security?: string;
  vlan_id?: number;
  hidden?: boolean;
  enabled?: boolean;
  band?: string;
  client_isolation?: boolean;
  band_steering?: boolean;
  fast_roaming?: boolean;
  rate_limit_enabled?: boolean;
  rate_limit_up?: number;
  rate_limit_down?: number;
}

export interface NetworkClient {
  id: string;
  mac_address: string;
  ip_address?: string;
  hostname?: string;
  display_name?: string;
  connection_type: 'wired' | 'wireless' | 'unknown';
  status: 'online' | 'offline' | 'unknown';
  blocked: boolean;
  connected_device_id?: string;
  ssid?: string;
  signal_strength?: number;
  rx_bytes: number;
  tx_bytes: number;
  first_seen?: string;
  last_seen?: string;
}

export interface NetworkClientUpdate {
  display_name?: string;
  blocked?: boolean;
  notes?: string;
}

export interface NetworkDevice {
  id: string;
  name: string;
  device_type: string;
  model?: string;
  vendor?: string;
  firmware_version?: string;
  ip_address?: string;
  mac_address?: string;
  status: 'online' | 'offline' | 'unknown';
  uptime?: number;
  site_id?: string;
  capabilities?: Record<string, boolean>;
}

export interface SwitchPortConfig {
  id: string;
  device_id: string;
  port_number: number;
  name?: string;
  enabled: boolean;
  poe_enabled: boolean;
  native_vlan: number;
  tagged_vlans: number[];
  status: 'up' | 'down' | 'disabled' | 'unknown';
  speed?: string;
  duplex?: string;
  poe_power_draw?: number;
  rx_bytes: number;
  tx_bytes: number;
}

export interface SwitchPortUpdate {
  name?: string;
  enabled?: boolean;
  poe_enabled?: boolean;
  native_vlan?: number;
  tagged_vlans?: number[];
}

export interface NetworkTopologyNode {
  id: string;
  name: string;
  device_type: string;
  ip_address?: string;
  status: string;
  model?: string;
  vendor?: string;
}

export interface TopologyLink {
  source: string;
  target: string;
  source_port?: string;
  target_port?: string;
  speed?: string;
  status: string;
}

export interface NetworkTopology {
  nodes: NetworkTopologyNode[];
  links: TopologyLink[];
}

export interface NetworkSummary {
  devices: {
    total: number;
    online: number;
    offline: number;
    by_type: Record<string, number>;
  };
  clients: {
    total: number;
    online: number;
    wired: number;
    wireless: number;
    blocked: number;
  };
  total_vlans: number;
  total_wifi_networks: number;
}

export interface VlanListResponse {
  items: Vlan[];
  total: number;
  skip: number;
  limit: number;
}

export interface WifiNetworkListResponse {
  items: WifiNetwork[];
  total: number;
  skip: number;
  limit: number;
}

export interface NetworkClientListResponse {
  items: NetworkClient[];
  total: number;
  skip: number;
  limit: number;
}

export interface NetworkDeviceListResponse {
  items: NetworkDevice[];
  total: number;
  skip: number;
  limit: number;
}

// =============================================================================
// MODULES
// =============================================================================

export interface ModuleNavItemShape {
  path: string;
  label: string;
  icon: string;
  order: number;
  parent?: string;
  permission?: string;
  children?: ModuleNavItemShape[];
}

export interface ModuleManifestResponse {
  id: string;
  name: string;
  version: string;
  description: string;
  category: string;
  icon: string;
  color: string;
  is_core: boolean;
  is_beta: boolean;
  is_premium: boolean;
  capabilities: string[];
  device_types: string[];
  dependencies: { module_id: string; min_version: string; optional: boolean }[];
  permissions: { code: string; name: string; description: string }[];
  nav_items: ModuleNavItemShape[];
  widgets: { id: string; name: string; description: string; component: string; default_size: string }[];
  author: string;
  license: string;
}

export interface ModuleStateResponse {
  module_id: string;
  state: string;
  error?: string;
  started_orgs: string[];
}

export interface OrgModuleResponse {
  module_id: string;
  enabled: boolean;
  enabled_at?: string;
  settings: Record<string, unknown>;
}

export interface ModuleNavigationResponse {
  items: ModuleNavItemShape[];
}

export interface ModuleWidgetsResponse {
  widgets: { id: string; name: string; description: string; component: string; default_size: string }[];
}

// =============================================================================
// GATEWAY (Firewall Gateway Integrations)
// =============================================================================

export interface GatewayConnection {
  id: string;
  org_id: string;
  site_id?: string;
  device_id?: string;
  name: string;
  description?: string;
  vendor: 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt';
  host: string;
  port: number;
  verify_ssl: boolean;
  has_credentials: boolean;
  sync_enabled: boolean;
  sync_interval_seconds: number;
  sync_status: 'idle' | 'syncing' | 'success' | 'failed' | 'never';
  last_sync_at?: string;
  last_sync_error?: string;
  is_online?: boolean;
  last_seen_at?: string;
  detected_version?: string;
  detected_hostname?: string;
  detected_model?: string;
  capabilities: string[];
  settings: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface GatewayConnectionCreate {
  name: string;
  description?: string;
  vendor: 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt';
  host: string;
  port?: number;
  verify_ssl?: boolean;
  site_id?: string;
  device_id?: string;
  api_key?: string;
  api_secret?: string;
  username?: string;
  password?: string;
  sync_enabled?: boolean;
  sync_interval_seconds?: number;
  settings?: Record<string, any>;
}

export interface GatewayConnectionUpdate {
  name?: string;
  description?: string;
  host?: string;
  port?: number;
  verify_ssl?: boolean;
  site_id?: string;
  device_id?: string;
  api_key?: string;
  api_secret?: string;
  username?: string;
  password?: string;
  sync_enabled?: boolean;
  sync_interval_seconds?: number;
  settings?: Record<string, any>;
}

export interface GatewayTestRequest {
  vendor: 'opnsense' | 'pfsense' | 'mikrotik' | 'openwrt';
  host: string;
  port?: number;
  verify_ssl?: boolean;
  api_key?: string;
  api_secret?: string;
  username?: string;
  password?: string;
}

export interface GatewayTestResponse {
  success: boolean;
  message: string;
  vendor?: string;
  hostname?: string;
  version?: string;
  model?: string;
  capabilities?: string[];
  latency_ms?: number;
}

export interface GatewaySyncLog {
  id: string;
  gateway_id: string;
  started_at: string;
  finished_at?: string;
  duration_ms?: number;
  status: string;
  error?: string;
  items_synced: number;
  items_failed: number;
  details: Record<string, any>;
}

export interface GatewaySummary {
  total_gateways: number;
  online: number;
  offline: number;
  sync_success: number;
  sync_failed: number;
  sync_idle: number;
  sync_never: number;
  by_vendor: Record<string, number>;
}

export interface GatewayRulePushRequest {
  action: 'allow' | 'block' | 'reject';
  protocol?: string;
  source?: string;
  source_port?: string;
  destination?: string;
  destination_port?: string;
  description?: string;
  enabled?: boolean;
  log?: boolean;
  interface?: string;
  chain?: string;
}

export interface GatewayWriteResponse {
  success: boolean;
  message: string;
  vendor_id?: string;
  data?: Record<string, any>;
}

export interface DNSOverrideRequest {
  host: string;
  domain: string;
  ip: string;
  description?: string;
  enabled?: boolean;
}

export interface DNSDomainOverrideRequest {
  domain: string;
  server: string;
  port?: number;
  description?: string;
  enabled?: boolean;
}

export interface DHCPStaticMappingRequest {
  mac: string;
  ipaddr: string;
  hostname?: string;
  description?: string;
  interface?: string;
}

export interface PortForwardRequest {
  interface: string;
  protocol: string;
  src_address?: string;
  src_port?: string;
  dst_address?: string;
  dst_port: string;
  target_ip: string;
  target_port: string;
  description?: string;
  enabled?: boolean;
}

export interface SourceNATRuleRequest {
  interface: string;
  protocol?: string;
  source_net?: string;
  destination_net?: string;
  target?: string;
  description?: string;
  enabled?: boolean;
}

export interface AliasRequest {
  name: string;
  type: string;
  content: string[];
  description?: string;
  enabled?: boolean;
}

export interface WireGuardServerRequest {
  name: string;
  listen_port: number;
  tunnel_address: string[];
  peers?: string[];
  enabled?: boolean;
}

export interface WireGuardPeerRequest {
  name: string;
  public_key: string;
  allowed_ips: string[];
  endpoint?: string;
  keepalive?: number;
  server_id?: string;
  enabled?: boolean;
}

export interface OpenVPNInstanceRequest {
  description: string;
  role: 'server' | 'client';
  protocol?: string;
  port?: number;
  tunnel_network?: string;
  local_network?: string;
  remote_network?: string;
  enabled?: boolean;
}

export interface StaticRouteRequest {
  network: string;
  gateway: string;
  description?: string;
  disabled?: boolean;
}

export interface IDSSettingsUpdateRequest {
  enabled?: boolean;
  ips_mode?: boolean;
  pattern_matcher?: string;
  block_io?: boolean;
  interfaces?: string[];
}

export interface ShaperPipeRequest {
  description: string;
  bandwidth: number;
  bandwidth_metric: string;
  queue?: number;
  mask?: string;
  enabled?: boolean;
}

export interface ShaperQueueRequest {
  description?: string;
  pipe?: string;
  weight?: number;
  mask?: string;
  enabled?: boolean;
}

export interface ShaperRuleRequest {
  description?: string;
  sequence?: number;
  interface?: string;
  protocol?: string;
  source?: string;
  destination?: string;
  target_pipe?: string;
  target_queue?: string;
  direction?: string;
  enabled?: boolean;
}

export interface IDSControlRequest {
  action: 'start' | 'stop' | 'restart' | 'update-rules';
}

export interface DiagnosticPingRequest {
  host: string;
  count?: number;
}

export interface DiagnosticTracerouteRequest {
  host: string;
}

export interface DiagnosticDNSLookupRequest {
  hostname: string;
}

export interface ServiceControlRequest {
  action: 'start' | 'stop' | 'restart';
}

// =============================================================================
// ENTERPRISE CONFIG MANAGEMENT
// =============================================================================

export interface SiteGroup {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  parent_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeviceGroup {
  id: string;
  organization_id: string;
  site_id: string;
  name: string;
  description: string | null;
  match_rules: Record<string, any>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ConfigTemplate {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  scope: 'organization' | 'site_group' | 'site' | 'device_group';
  scope_id: string | null;
  device_type: string | null;
  config: Record<string, any>;
  priority: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeviceConfig {
  device_id: string;
  organization_id: string;
  desired_config: Record<string, any>;
  pushed_config: Record<string, any>;
  running_config: Record<string, any>;
  desired_updated_at: string | null;
  pushed_at: string | null;
  push_result: string | null;
  push_error: string | null;
  running_synced_at: string | null;
  has_drift: boolean;
  drift_details: Record<string, any> | null;
  drift_detected_at: string | null;
  drift_acknowledged: boolean;
  auto_remediate: boolean;
  config_version: number;
  device_overrides: Record<string, any>;
}

export interface ResolvedConfig {
  device_id: string;
  resolved_config: Record<string, any>;
  template_chain: string[];
}

export interface DeviceHealthResponse {
  device_id: string;
  organization_id: string;
  site_id: string;
  health_score: number;
  health_status: 'healthy' | 'warning' | 'degraded' | 'critical' | 'unknown';
  reachability_score: number | null;
  latency_score: number | null;
  drift_score: number | null;
  error_score: number | null;
  utilization_score: number | null;
  firmware_score: number | null;
  // Backend column is ``updated_at`` (see ``schemas/enterprise.py:DeviceHealthResponse``).
  // The previous ``last_computed_at`` was a guess that never matched the wire shape.
  updated_at: string | null;
  // Sparkline points emit ``{t: ISO, s: int}`` per ``services/enterprise.py:_record_score``.
  // The previous ``{score, time}`` was wrong, the Y-axis read undefined and the X-axis
  // rendered ``Invalid Date`` on every probe.
  score_history: Array<{ t: string; s: number }>;
}

export interface SiteHealthSummary {
  site_id: string;
  site_name: string;
  device_count: number;
  avg_health_score: number;
  health_status: string;
  healthy: number;
  warning: number;
  degraded: number;
  critical: number;
  uptime_percent?: number;
}

export interface OrgHealthSummary {
  organization_id: string;
  site_count: number;
  device_count: number;
  avg_health_score: number;
  health_status: string;
  sites: SiteHealthSummary[];
}

export interface LifecycleLogEntry {
  id: string;
  device_id: string;
  from_state: string;
  to_state: string;
  trigger: string;
  triggered_by: string | null;
  details: Record<string, any> | null;
  created_at: string;
}

export interface DeviceLifecycleResponse {
  device_id: string;
  lifecycle_state: string;
  lifecycle_changed_at: string | null;
  lifecycle_error: string | null;
}

export interface BulkOperation {
  job_id: string;
  operation: string;
  status: string;
  devices_total: number;
  devices_completed: number;
  devices_failed: number;
  devices_skipped?: number;
  current_stage: number;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
}

export interface ReconcileResult {
  total: number;
  compliant: number;
  drifted: number;
  errors: number;
  devices: Array<Record<string, any>>;
}

// =============================================================================
// EVENT CORRELATION
// =============================================================================

export interface CorrelationRule {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: string;
  event_patterns: Array<{ event_type: string; min_count: number; category?: string; conditions?: Record<string, any> }>;
  time_window_seconds: number;
  scope: string;
  conditions: Record<string, any> | null;
  severity: string;
  auto_resolve_seconds: number | null;
  notification_channels: Record<string, any> | null;
  fire_count: number;
  last_fired_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  organization_id: string;
  rule_id: string | null;
  site_id: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  opened_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  assigned_to: string | null;
  event_count: number;
  affected_devices: string[];
  root_cause: string | null;
  resolution_notes: string | null;
  tags: string[];
  context: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface IncidentEvent {
  id: string;
  event_id: string;
  matched_pattern: string | null;
  added_at: string;
  event_type: string | null;
  event_category: string | null;
  event_timestamp: string | null;
  event_payload: Record<string, any> | null;
}

export interface CorrelationStats {
  total_rules: number;
  active_rules: number;
  open_incidents: number;
  incidents_last_24h: number;
  events_correlated_last_24h: number;
  top_firing_rules: Array<{ id: string; name: string; fire_count: number; last_fired_at: string | null }>;
}

// =============================================================================
// SLA MONITORING
// =============================================================================

export interface SLAPolicy {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: string;
  scope: string;
  scope_id: string | null;
  scope_name: string | null;
  thresholds: Record<string, any>;
  evaluation_window_minutes: number;
  breach_after_consecutive: number;
  warning_threshold_percent: number;
  notification_channels: Record<string, any> | null;
  escalation_policy: Record<string, any> | null;
  current_compliance_percent: number | null;
  last_evaluated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SLABreach {
  id: string;
  policy_id: string;
  organization_id: string;
  severity: string;
  status: string;
  violated_metric: string;
  threshold_value: number;
  actual_value: number;
  deviation_percent: number;
  started_at: string;
  resolved_at: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  duration_minutes: number | null;
  context: Record<string, any>;
  notes: string | null;
}

export interface SLAComplianceSummary {
  total_policies: number;
  active_policies: number;
  active_breaches: number;
  avg_compliance_percent: number | null;
  worst_policy: SLAPolicy | null;
  breaches_last_24h: number;
  compliance_trend: Array<{ id: string; policy_id: string; recorded_at: string; compliance_percent: number; metrics: Record<string, any>; in_breach: boolean }>;
}

// =============================================================================
// TOPOLOGY
// =============================================================================

export interface TopologyNode {
  id: string;
  label: string;
  device_type: string;
  status: string;
  ip_address: string | null;
  mac_address: string | null;
  model: string | null;
  site_id: string | null;
  site_name: string | null;
  health_score: number | null;
  health_status: string | null;
  x: number | null;
  y: number | null;
  pinned: boolean;
  layer: string | null;
  metadata: Record<string, any>;
}

export interface TopologyEdge {
  id: string;
  source_id: string;
  target_id: string;
  source_port: string | null;
  target_port: string | null;
  speed: string | null;
  status: string;
  link_type: string;
  discovered_via: string | null;
  metadata: Record<string, any>;
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  site_id: string | null;
  generated_at: string;
  stats: {
    total_nodes: number;
    total_edges: number;
    nodes_by_type: Record<string, number>;
    nodes_by_status: Record<string, number>;
    links_by_status: Record<string, number>;
    orphan_count: number;
  };
}

export interface TopologyLayout {
  id: string;
  site_id: string;
  user_id: string | null;
  name: string;
  positions: Record<string, { x: number; y: number; pinned: boolean }>;
  zoom: number;
  center_x: number;
  center_y: number;
  filters: Record<string, any> | null;
  created_at: string;
  updated_at: string;
}

// =============================================================================
// ALERT RULES ENGINE
// =============================================================================

export interface AlertRule {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  rule_type: string;
  status: string;
  severity: string;
  conditions: Record<string, any>;
  scope: string;
  scope_ids: string[] | null;
  device_types: string[] | null;
  check_interval_seconds: number;
  for_duration_seconds: number;
  cooldown_seconds: number;
  auto_resolve: boolean;
  auto_resolve_after_seconds: number | null;
  notification_channels: Record<string, any>;
  notify_on_resolve: boolean;
  dedupe_window_seconds: number;
  tags: string[];
  metadata: Record<string, any>;
  last_evaluated_at: string | null;
  last_fired_at: string | null;
  fire_count: number;
  is_system: boolean;
  created_at: string;
  updated_at: string | null;
}

export interface AlertRuleCreate {
  name: string;
  description?: string;
  rule_type?: string;
  severity?: string;
  conditions: Record<string, any>;
  scope?: string;
  scope_ids?: string[];
  device_types?: string[];
  check_interval_seconds?: number;
  for_duration_seconds?: number;
  cooldown_seconds?: number;
  auto_resolve?: boolean;
  auto_resolve_after_seconds?: number;
  notification_channels?: Record<string, any>;
  notify_on_resolve?: boolean;
  dedupe_window_seconds?: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface AlertRuleUpdate {
  name?: string;
  description?: string;
  status?: string;
  rule_type?: string;
  severity?: string;
  conditions?: Record<string, any>;
  scope?: string;
  scope_ids?: string[];
  device_types?: string[];
  check_interval_seconds?: number;
  for_duration_seconds?: number;
  cooldown_seconds?: number;
  auto_resolve?: boolean;
  auto_resolve_after_seconds?: number;
  notification_channels?: Record<string, any>;
  notify_on_resolve?: boolean;
  dedupe_window_seconds?: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface AlertInstance {
  id: string;
  organization_id: string;
  rule_id: string;
  site_id: string | null;
  device_id: string | null;
  severity: string;
  title: string;
  message: string;
  details: Record<string, any>;
  status: string;
  fired_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  fingerprint: string;
  occurrence_count: number;
  last_occurrence_at: string;
  suppressed: boolean;
  suppressed_until: string | null;
  suppression_reason: string | null;
  notifications_sent: number;
  last_notified_at: string | null;
  tags: string[];
  metadata: Record<string, any>;
  source: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface AlertRuleStats {
  total_rules: number;
  active_rules: number;
  disabled_rules: number;
  total_alerts: number;
  firing_alerts: number;
  acknowledged_alerts: number;
  alerts_last_24h: number;
  critical_firing: number;
}

// =============================================================================
// GATEWAY ORCHESTRATION
// =============================================================================

export interface RoleAssignmentData {
  gateway_id: string;
  role: 'brain' | 'brain_standby' | 'limb' | 'observer';
  priority: number;
  suppress_dhcp: boolean;
}

export interface SiteRoleMapUpdate {
  assignments: RoleAssignmentData[];
  authority_map?: Record<string, string> | null;
}

export interface SiteRoleAssignmentResponse {
  id: string;
  gateway_id: string;
  role: string;
  priority: number;
  capabilities: Record<string, unknown>;
  suppress_dhcp: boolean;
}

export interface SiteRoleMapResponse {
  id: string;
  organization_id: string;
  site_id: string;
  is_active: boolean;
  last_reconciled_at: string | null;
  authority_map: Record<string, string>;
  assignments: SiteRoleAssignmentResponse[];
  created_at: string;
  updated_at: string;
}

export interface TopologyValidationResult {
  is_valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface CanonicalVLANCreate {
  site_id: string;
  vlan_id: number;
  name: string;
  description?: string | null;
  subnet: string;
  gateway_ip: string;
  dhcp_enabled?: boolean;
  dhcp_range_start?: string | null;
  dhcp_range_end?: string | null;
  dhcp_lease_time?: number;
  dhcp_dns_servers?: string[];
  dhcp_domain?: string | null;
  purpose?: string;
  distribute?: boolean;
  template_id?: string | null;
}

export interface CanonicalVLANUpdate {
  name?: string | null;
  description?: string | null;
  subnet?: string | null;
  gateway_ip?: string | null;
  dhcp_enabled?: boolean | null;
  dhcp_range_start?: string | null;
  dhcp_range_end?: string | null;
  dhcp_lease_time?: number | null;
  dhcp_dns_servers?: string[] | null;
  dhcp_domain?: string | null;
  purpose?: string | null;
}

export interface CanonicalVLANResponse {
  id: string;
  organization_id: string;
  site_id: string;
  vlan_id: number;
  name: string;
  description: string | null;
  subnet: string;
  gateway_ip: string;
  dhcp_enabled: boolean;
  dhcp_range_start: string | null;
  dhcp_range_end: string | null;
  dhcp_lease_time: number;
  dhcp_dns_servers: string[];
  dhcp_domain: string | null;
  purpose: string;
  management_state: string;
  source_device_id: string | null;
  template_id: string | null;
  external_ids: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CanonicalVLANDetailResponse extends CanonicalVLANResponse {
  dhcp_scope: DHCPScopeResponse | null;
  dhcp_reservations: DHCPReservationResponse[];
  distribution_status: Record<string, string> | null;
}

export interface CanonicalVLANListResponse {
  items: CanonicalVLANResponse[];
  total: number;
}

export interface DHCPScopeCreate {
  vlan_id: string;
  range_start: string;
  range_end: string;
  subnet_mask: string;
  gateway: string;
  lease_time?: number;
  dns_servers?: string[];
  ntp_servers?: string[];
  domain_name?: string | null;
  custom_options?: Record<string, string>;
}

export interface DHCPScopeResponse {
  id: string;
  organization_id: string;
  site_id: string;
  vlan_id: string;
  range_start: string;
  range_end: string;
  subnet_mask: string;
  gateway: string;
  lease_time: number;
  dns_servers: string[];
  ntp_servers: string[];
  domain_name: string | null;
  custom_options: Record<string, string>;
  management_state: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DHCPReservationCreate {
  vlan_id: string;
  mac_address: string;
  ip_address: string;
  hostname?: string | null;
  description?: string | null;
}

export interface DHCPReservationResponse {
  id: string;
  organization_id: string;
  vlan_id: string;
  mac_address: string;
  ip_address: string;
  hostname: string | null;
  description: string | null;
  management_state: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DNSRecordCreate {
  site_id: string;
  record_type: 'A' | 'AAAA' | 'CNAME' | 'PTR' | 'MX' | 'TXT' | 'SRV';
  hostname: string;
  value: string;
  ttl?: number;
  priority?: number | null;
  description?: string | null;
}

export interface DNSRecordUpdate {
  value?: string | null;
  ttl?: number | null;
  priority?: number | null;
  description?: string | null;
}

export interface DNSRecordResponse {
  id: string;
  organization_id: string;
  site_id: string;
  record_type: string;
  hostname: string;
  value: string;
  ttl: number;
  priority: number | null;
  description: string | null;
  management_state: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DistributionTriggerRequest {
  vlan_id: string;
  site_id: string;
}

export interface DistributionRetractRequest {
  vlan_id: string;
  site_id: string;
}

export interface DistributionStepResult {
  tier: number;
  device_id: string;
  action: string;
  status: string;
  external_id?: string | null;
  duration_ms?: number | null;
  error?: string | null;
}

export interface DistributionResponse {
  id: string;
  organization_id: string;
  site_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  plan?: Record<string, unknown>;
  step_results?: DistributionStepResult[];
  rollback_plan?: Record<string, unknown> | null;
  rollback_executed?: boolean;
  error_device_id?: string | null;
  error_tier?: number | null;
}

export interface DriftEventResponse {
  id: string;
  organization_id: string;
  site_id: string;
  device_id: string;
  drift_type: string;
  resource_type: string;
  resource_id: string | null;
  expected_value: Record<string, unknown> | null;
  actual_value: Record<string, unknown> | null;
  severity: string;
  message: string;
  resolution: string;
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
}

export interface DriftResolveRequest {
  resolution: 'reapply' | 'accept' | 'ignore';
}

export interface DriftSummaryResponse {
  total: number;
  critical: number;
  warning: number;
  info: number;
  pending: number;
  resolved: number;
}

export interface DriftCheckResponse {
  site_id: string;
  new_events: number;
  events: DriftEventResponse[];
}

export interface SuppressionRuleCreate {
  organization_id: string;
  site_id: string;
  gateway_id?: string | null;
  resource_type: 'dhcp' | 'dns';
  pattern: string;
  reason?: string | null;
}

export interface SuppressionRuleResponse {
  id: string;
  organization_id: string;
  site_id: string;
  gateway_id: string | null;
  resource_type: string;
  pattern: string;
  reason: string | null;
  is_active: boolean;
  created_at: string;
  created_by: string | null;
}

export interface ImportSessionCreate {
  site_id: string;
  organization_id: string;
}

export interface ImportSessionStep {
  payload: Record<string, unknown>;
}

export interface ImportSessionResponse {
  id: string;
  organization_id: string;
  site_id: string;
  current_step: number;
  status: string;
  discovered_devices: Record<string, unknown>;
  role_assignments: Record<string, unknown>;
  scan_results: Record<string, unknown>;
  conflicts: Record<string, unknown>[];
  reconciliation_decisions: Record<string, unknown>;
  distribution_ids: string[];
  verification_report: Record<string, unknown>;
  initiated_by: string | null;
  created_at: string;
}

export interface GatewayDashboardOverview {
  total_vlans: number;
  total_role_maps: number;
  total_distributions: number;
  open_drift_events: number;
}

export interface ImportedFirewallRuleResponse {
  id: string;
  external_id: string;
  name: string;
  description: string | null;
  rule_index: number;
  direction: string;
  action: string;
  protocol: string;
  source: Record<string, unknown>;
  destination: Record<string, unknown>;
  is_enabled: boolean;
  hit_count: number;
  last_hit: string | null;
  last_synced_at: string;
}

export interface ImportedNATRuleResponse {
  id: string;
  external_id: string;
  name: string;
  description: string | null;
  nat_type: string;
  source: Record<string, unknown>;
  destination: Record<string, unknown>;
  translation: Record<string, unknown>;
  is_enabled: boolean;
  last_synced_at: string;
}

export interface ImportedVPNTunnelResponse {
  id: string;
  external_id: string;
  name: string;
  description: string | null;
  vpn_type: string;
  status: string;
  local_config: Record<string, unknown>;
  remote_config: Record<string, unknown>;
  stats: Record<string, unknown>;
  last_synced_at: string;
}

export interface ImportedIDSEventResponse {
  id: string;
  event_time: string;
  signature: string;
  severity: string;
  source_ip: string | null;
  source_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  action_taken: string | null;
  message: string | null;
  last_synced_at: string;
}

export interface ImportedInterfaceResponse {
  id: string;
  external_id: string;
  name: string;
  description: string | null;
  if_type: string | null;
  mac_address: string | null;
  mtu: number | null;
  is_enabled: boolean;
  is_up: boolean;
  ipv4_address: string | null;
  ipv4_subnet: string | null;
  ipv6_address: string | null;
  vlan_tag: number | null;
  parent_interface: string | null;
  stats: Record<string, unknown>;
  last_synced_at: string;
}

export interface ImportedDHCPLeaseResponse {
  id: string;
  organization_id: string;
  site_id: string;
  device_id: string;
  ip_address: string;
  mac_address: string;
  hostname: string | null;
  interface: string | null;
  status: string | null;
  last_synced_at: string | null;
}

export interface VLANTemplateCreate {
  name: string;
  description?: string | null;
  vlan_id: number;
  subnet_template: string;
  purpose?: string;
  dhcp_enabled?: boolean;
  dhcp_options?: Record<string, unknown>;
  settings?: Record<string, unknown>;
}

export interface VLANTemplateUpdate {
  name?: string | null;
  description?: string | null;
  vlan_id?: number | null;
  subnet_template?: string | null;
  purpose?: string | null;
  dhcp_enabled?: boolean | null;
  dhcp_options?: Record<string, unknown> | null;
  settings?: Record<string, unknown> | null;
}

export interface VLANTemplateResponse {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  vlan_id: number;
  subnet_template: string;
  purpose: string;
  dhcp_enabled: boolean;
  dhcp_options: Record<string, unknown>;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface VLANTemplateListResponse {
  items: VLANTemplateResponse[];
  total: number;
}

export interface TemplateApplyResponse {
  id: string;
  vlan_id: number;
  name: string;
  site_id: string;
  message: string;
}

export interface GatewayPingRequest {
  gateway_id: string;
  target: string;
  count?: number;
}

export interface GatewayTracerouteRequest {
  gateway_id: string;
  target: string;
}

export interface GatewayDNSLookupRequest {
  gateway_id: string;
  hostname: string;
  record_type?: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'PTR' | 'SRV';
}

export interface GatewayServiceRestartRequest {
  gateway_id: string;
  service_name: string;
}

// =============================================================================
// HYPERVISOR (Proxmox VE)
// =============================================================================

export interface HypervisorDashboard {
  cluster_name: string;
  quorate: boolean;
  total_nodes: number;
  online_nodes: number;
  total_vms: number;
  running_vms: number;
  total_containers: number;
  running_containers: number;
  total_cpu_cores: number;
  cpu_usage_percent: number;
  total_memory_bytes: number;
  used_memory_bytes: number;
  memory_usage_percent: number;
  total_storage_bytes: number;
  used_storage_bytes: number;
  storage_usage_percent: number;
  ha_active: boolean;
}

export interface HypervisorClusterStatus {
  name: string;
  quorate: boolean;
  node_count: number;
  version: number;
  nodes: HypervisorClusterNode[];
}

export interface HypervisorClusterNode {
  node: string;
  status: string;
  ip: string | null;
  level: string;
}

export interface HypervisorClusterResource {
  id: string;
  type: string;
  node: string;
  status: string;
  name: string;
  vmid: number | null;
  maxcpu: number | null;
  cpu: number | null;
  maxmem: number | null;
  mem: number | null;
  maxdisk: number | null;
  disk: number | null;
  uptime: number | null;
  template: boolean;
}

export interface HypervisorNode {
  id: string | null;
  node: string;
  status: string;
  ip_address: string | null;
  cpu_count: number;
  cpu_usage: number;
  cpu_percent: number;
  memory_total: number;
  memory_used: number;
  memory_percent: number;
  storage_total: number;
  storage_used: number;
  storage_percent: number;
  uptime: number;
  pve_version: string;
  kernel_version: string;
  cpu_model: string;
  subscription_level: string;
}

export interface HypervisorVM {
  id: string | null;
  vmid: number;
  name: string;
  node: string;
  vm_type: 'qemu' | 'lxc';
  status: string;
  cpu_cores: number;
  cpu_usage: number;
  cpu_percent: number;
  memory_mb: number;
  memory_used_mb: number;
  memory_percent: number;
  disk_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  ip_address: string | null;
  net_in: number;
  net_out: number;
  uptime: number;
  tags: string[];
  template: boolean;
  ha_state: string | null;
  lock: string | null;
  os_type: string | null;
}

export interface HypervisorSnapshot {
  name: string;
  description: string;
  created_at: string | null;
  vmstate: boolean;
  parent: string | null;
}

export interface HypervisorStorage {
  storage: string;
  node: string;
  storage_type: string;
  content: string;
  total: number;
  used: number;
  available: number;
  used_percent: number;
  active: boolean;
  shared: boolean;
  enabled: boolean;
}

export interface HypervisorStorageContent {
  volid: string;
  content: string;
  format: string;
  size: number;
  ctime: number;
  vmid: number | null;
  notes: string | null;
}

export interface HypervisorNetworkInterface {
  iface: string;
  node: string;
  type: string;
  active: boolean;
  address: string | null;
  netmask: string | null;
  gateway: string | null;
  cidr: string | null;
  bridge_ports: string | null;
  bond_slaves: string | null;
  method: string | null;
  autostart: boolean;
}

export interface HypervisorTask {
  upid: string;
  node: string;
  type: string;
  status: string;
  user: string;
  started_at: string | null;
  ended_at: string | null;
  is_running: boolean;
}

export interface HypervisorRRDPoint {
  time: number;
  cpu: number | null;
  maxcpu: number | null;
  mem: number | null;
  maxmem: number | null;
  netin: number | null;
  netout: number | null;
  diskread: number | null;
  diskwrite: number | null;
  iowait: number | null;
}

export interface HypervisorBackupJob {
  id: string;
  schedule: string;
  storage: string;
  vmid: string;
  mode: string;
  compress: string;
  enabled: boolean;
  mailto: string;
  node: string | null;
}

export interface HypervisorFirewallRule {
  pos: number;
  type: string;
  action: string;
  enable: boolean;
  source: string | null;
  dest: string | null;
  sport: string | null;
  dport: string | null;
  proto: string | null;
  macro: string | null;
  iface: string | null;
  log: string | null;
  comment: string | null;
}

export interface HypervisorTaskDetail {
  upid: string;
  node: string;
  type: string;
  status: string;
  user: string;
  started_at: string | null;
  is_running: boolean;
  exitstatus: string;
}

export interface HypervisorTaskLogEntry {
  n: number;
  t: string;
}

export interface HypervisorConsoleProxy {
  ticket: string;
  port: number | string;
  user: string;
  cert: string;
  upid: string;
}

export interface HypervisorDiskInfo {
  devpath: string;
  model: string;
  serial: string;
  size: number;
  vendor: string;
  wearout: number | null;
  rpm: number | null;
  disk_type: string;
  gpt: boolean;
  health: string;
}

export interface HypervisorNodeService {
  service: string;
  name: string;
  desc: string;
  state: string;
}

export interface HypervisorSyslogEntry {
  n: number;
  t: string;
}

export interface HypervisorHAResource {
  sid: string;
  state: string;
  group: string;
  max_relocate: number;
  max_restart: number;
  comment: string;
  request_state: string;
  status: string;
  node: string;
  crm_state: string;
}

export interface HypervisorHAGroup {
  group: string;
  nodes: string;
  nofailback: boolean;
  restricted: boolean;
  comment: string;
}

export interface HypervisorResourcePool {
  poolid: string;
  comment: string;
  members: Record<string, unknown>[];
}

export interface HypervisorCephStatus {
  health: string;
  num_osds: number;
  num_osds_up: number;
  num_osds_in: number;
  num_pgs: number;
  num_pools: number;
  total_bytes: number;
  used_bytes: number;
  avail_bytes: number;
  used_percent: number;
}

// ── VM/CT Creation ─────────────────────────────────────────────────────
export interface CreateVMRequest {
  vmid?: number;
  name: string;
  node: string;
  cores: number;
  sockets?: number;
  memory: number;
  balloon?: number;
  ostype?: string;
  storage?: string;
  disk_size?: string;
  iso?: string;
  net_bridge?: string;
  net_model?: string;
  cpu_type?: string;
  bios?: string;
  machine?: string;
  start_after_create?: boolean;
  pool?: string;
  description?: string;
  onboot?: boolean;
  tags?: string;
}

export interface CreateContainerRequest {
  vmid?: number;
  hostname: string;
  node: string;
  ostemplate: string;
  cores: number;
  memory: number;
  swap?: number;
  storage?: string;
  rootfs_size?: string;
  net_bridge?: string;
  net_ip?: string;
  password?: string;
  ssh_public_keys?: string;
  start_after_create?: boolean;
  pool?: string;
  description?: string;
  unprivileged?: boolean;
  onboot?: boolean;
  tags?: string;
  nameserver?: string;
  searchdomain?: string;
}

export interface CreateVMResponse {
  vmid: number;
  upid: string;
  message: string;
}

export interface NextVMIDResponse {
  vmid: number;
}

// ── Fleet (Multi-Cluster) ──────────────────────────────────────────────
export interface FleetClusterSummary {
  controller_id: string;
  controller_name: string;
  cluster_name: string;
  quorate: boolean;
  total_nodes: number;
  online_nodes: number;
  total_vms: number;
  running_vms: number;
  total_containers: number;
  running_containers: number;
  total_cpu_cores: number;
  cpu_usage_percent: number;
  total_memory_bytes: number;
  used_memory_bytes: number;
  memory_usage_percent: number;
  total_storage_bytes: number;
  used_storage_bytes: number;
  storage_usage_percent: number;
  status: string;
  error: string;
}

export interface FleetDashboard {
  total_clusters: number;
  online_clusters: number;
  total_nodes: number;
  online_nodes: number;
  total_vms: number;
  running_vms: number;
  total_containers: number;
  running_containers: number;
  total_cpu_cores: number;
  cpu_usage_percent: number;
  total_memory_bytes: number;
  used_memory_bytes: number;
  memory_usage_percent: number;
  total_storage_bytes: number;
  used_storage_bytes: number;
  storage_usage_percent: number;
  clusters: FleetClusterSummary[];
}

// ── Hypervisor: Bulk Operations ────────────────────────────────────────────

export interface BulkVMTarget {
  node: string;
  vm_type: string;
  vmid: number;
}

export interface BulkActionRequest {
  targets: BulkVMTarget[];
  action: string;
}

export interface BulkMigrateRequest {
  targets: BulkVMTarget[];
  target_node: string;
  online: boolean;
}

export interface BulkActionResult {
  vmid: number;
  node: string;
  success: boolean;
  upid?: string;
  error?: string;
}

// ── Hypervisor: Guest Agent ────────────────────────────────────────────────

export interface GuestAgentNetworkInterface {
  name: string;
  mac_address: string;
  ip_addresses: string[];
}

export interface GuestAgentInfo {
  hostname: string;
  os_type: string;
  os_version: string;
  interfaces: GuestAgentNetworkInterface[];
}

// ── Hypervisor: Backup Job CRUD ────────────────────────────────────────────

export interface BackupJobCreateRequest {
  storage: string;
  schedule: string;
  vmid?: string;
  mode?: string;
  compress?: string;
  node?: string;
  enabled?: boolean;
  mailto?: string;
  mailnotification?: string;
}

export interface BackupJobUpdateRequest {
  storage?: string;
  schedule?: string;
  vmid?: string;
  mode?: string;
  compress?: string;
  node?: string;
  enabled?: boolean;
  mailto?: string;
}

// ── Health Dashboard (expanded) ─────────────────────────────────────────────

export interface DeviceHealthDetail {
  device_id: string;
  device_name: string;
  device_type: string;
  ip_address: string | null;
  site_name: string | null;
  site_id: string | null;
  health_score: number;
  health_status: string;
  // Backend (DeviceHealthDetail inherits from DeviceHealthResponse) uses
  // ``<dimension>_score``, NOT ``score_<dimension>``. The previous names
  // never matched; every cell rendered "N/A" and 6 of the 8 sort buttons
  // silently fell back to ``health_score`` on the backend.
  reachability_score: number | null;
  latency_score: number | null;
  drift_score: number | null;
  error_score: number | null;
  utilization_score: number | null;
  firmware_score: number | null;
  score_history: Array<{ t: string; s: number }>;
  updated_at: string;
}

export interface DeviceHealthListResponse {
  devices: DeviceHealthDetail[];
  total: number;
}

export interface TopHealthIssue {
  device_id: string;
  device_name: string;
  device_type: string;
  site_name: string | null;
  site_id: string | null;
  health_score: number;
  health_status: string;
  worst_component: string;
  worst_component_score: number;
}

export interface TopIssuesResponse {
  issues: TopHealthIssue[];
}

export interface InfraComponentHealth {
  name: string;
  status: string;
  latency_ms: number | null;
  details: Record<string, unknown>;
}

export interface InfrastructureHealthResponse {
  status: string;
  uptime_seconds: number;
  components: InfraComponentHealth[];
}

export interface ModuleHealthSummary {
  module: string;
  device_count: number;
  avg_health_score: number;
  healthy: number;
  warning: number;
  degraded: number;
  critical: number;
}

// ── Health History (7d/30d snapshots) ────────────────────────────────────────

export interface HealthDailySnapshotResponse {
  snapshot_date: string;
  avg_health_score: number;
  device_count: number;
  healthy_count: number;
  warning_count: number;
  degraded_count: number;
  critical_count: number;
}

// ── WAN Health ───────────────────────────────────────────────────────────────

export interface WANDeviceHealth {
  device_id: string;
  device_name: string;
  device_type: string;
  site_name: string;
  ip_address: string | null;
  health_score: number;
  latency_score: number | null;
  reachability_score: number | null;
  utilization_score: number | null;
}

// ── Site Ranking ─────────────────────────────────────────────────────────────

export interface SiteRanking {
  site_id: string;
  site_name: string;
  avg_health_score: number;
  device_count: number;
  // Nullable: backend ``SiteHealthSummary.uptime_percent`` is ``float | None``
  // when the site has no reachability samples (fresh device / new site).
  uptime_percent: number | null;
  trend: 'up' | 'down' | 'stable';
  trend_delta: number;
}
