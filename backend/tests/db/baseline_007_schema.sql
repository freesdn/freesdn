--
-- FreeSDN: FROZEN baseline schema at alembic revision 007_widen_pending_status.
--
-- WHAT THIS IS
--   A schema-only pg_dump of a database built by `alembic upgrade
--   007_widen_pending_status` on 2026-08-28, i.e. the schema a FreeSDN
--   appliance released at that point actually carries on disk.
--
-- WHY IT IS CHECKED IN INSTEAD OF REBUILT
--   001_initial does not contain DDL; it calls Base.metadata.create_all() over
--   the LIVE ORM models. So a fixture that builds its "old" database by
--   running 001..007 does not get an old database at all -- it gets today's
--   models, minus only whatever the fixture explicitly rewinds. Any future
--   model change is therefore already present before the fixture "upgrades",
--   the comparison against the models passes, and a real upgraded appliance
--   still never receives the change. This file is immutable, so the fixture
--   starts from a genuinely historical schema and a model change with no
--   migration shows up as drift.
--
-- WHEN IT MAY BE REGENERATED
--   Only at a release boundary, and only once every model change since the
--   last regeneration HAS a migration on the chain. Regenerating it to silence
--   a failing test re-opens exactly the hole it exists to close --
--   tests/db/conftest.py pins its sha256 so that cannot happen by accident.
--
--   Recipe (needs a scratch server and pg_dump; see tests/db/conftest.py):
--     createdb freesdn_baseline_capture
--     DATABASE_URL=<scratch url> python -m alembic upgrade 007_widen_pending_status
--     pg_dump -d freesdn_baseline_capture --schema-only --no-owner --no-privileges
--   then drop the psql \restrict / \unrestrict lines, the SET / set_config
--   preamble and the "--" banner comments, and keep this header.
--

CREATE SCHEMA access;

CREATE SCHEMA agents;

CREATE SCHEMA ai;

CREATE SCHEMA analytics;

CREATE SCHEMA audit;

CREATE SCHEMA backup;

CREATE SCHEMA cameras;

CREATE SCHEMA collector;

CREATE SCHEMA core;

CREATE SCHEMA devices;

CREATE SCHEMA enterprise;

CREATE SCHEMA events;

CREATE SCHEMA fabric;

CREATE SCHEMA firewall;

CREATE SCHEMA gateway;

CREATE SCHEMA hypervisor;

CREATE SCHEMA network;

CREATE SCHEMA voip;

CREATE SCHEMA vpn;

CREATE TYPE public.sso_protocol AS ENUM (
    'OIDC',
    'SAML',
    'LDAP'
);

CREATE TYPE public.sso_provider_status AS ENUM (
    'ACTIVE',
    'INACTIVE',
    'TESTING'
);

CREATE TABLE access.cardholders (
    site_id uuid NOT NULL,
    user_id uuid,
    first_name character varying(100) NOT NULL,
    last_name character varying(100) NOT NULL,
    email character varying(255),
    phone character varying(50),
    employee_id character varying(50),
    department character varying(100),
    title character varying(100),
    is_active boolean NOT NULL,
    activation_date date,
    expiration_date date,
    photo_url character varying(500),
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE access.controllers (
    site_id uuid NOT NULL,
    device_controller_id uuid,
    name character varying(255) NOT NULL,
    description text,
    ip_address character varying(45) NOT NULL,
    port integer NOT NULL,
    mac_address character varying(17),
    vendor character varying(100),
    model character varying(100),
    firmware_version character varying(50),
    serial_number character varying(100),
    door_capacity integer NOT NULL,
    reader_capacity integer NOT NULL,
    is_online boolean NOT NULL,
    last_seen timestamp with time zone,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE access.credentials (
    cardholder_id uuid NOT NULL,
    credential_type character varying(50) NOT NULL,
    card_number character varying(512),
    facility_code character varying(512),
    pin character varying(255),
    is_active boolean NOT NULL,
    activation_date date,
    expiration_date date,
    last_used timestamp with time zone,
    last_door_id uuid,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE access.doors (
    site_id uuid NOT NULL,
    controller_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    door_number integer NOT NULL,
    status character varying(20) NOT NULL,
    is_locked boolean NOT NULL,
    last_status_change timestamp with time zone,
    unlock_time integer NOT NULL,
    held_open_time integer NOT NULL,
    default_schedule_id uuid,
    settings jsonb NOT NULL,
    location character varying(255),
    floor character varying(50),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE access.events (
    door_id uuid,
    credential_id uuid,
    cardholder_id uuid,
    event_type character varying(50) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    card_number character varying(100),
    description text,
    metadata_json jsonb NOT NULL,
    is_acknowledged boolean NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    prev_hash character varying(64),
    row_hmac character varying(64),
    id uuid NOT NULL
);

CREATE TABLE access.readers (
    controller_id uuid NOT NULL,
    door_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    reader_number integer NOT NULL,
    reader_type character varying(50) NOT NULL,
    credential_type character varying(50) NOT NULL,
    is_online boolean NOT NULL,
    last_seen timestamp with time zone,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE access.schedules (
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    is_24_7 boolean NOT NULL,
    intervals jsonb NOT NULL,
    honor_holidays boolean NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE agents.agent_releases (
    version character varying(50) NOT NULL,
    platform character varying(50) NOT NULL,
    agent_type character varying(50) NOT NULL,
    download_url character varying(500) NOT NULL,
    checksum_sha256 character varying(64) NOT NULL,
    file_size integer NOT NULL,
    release_notes text NOT NULL,
    min_backend_version character varying(50) NOT NULL,
    is_latest boolean NOT NULL,
    is_prerelease boolean NOT NULL,
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    download_count integer NOT NULL,
    signature text,
    organization_id uuid,
    filename character varying(128),
    id uuid NOT NULL
);

COMMENT ON COLUMN agents.agent_releases.agent_type IS 'daemon or desktop';

CREATE TABLE agents.agent_schedule_runs (
    schedule_id uuid NOT NULL,
    agent_id uuid,
    status character varying(16) NOT NULL,
    device_count integer NOT NULL,
    duration_seconds double precision,
    error_message text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE agents.agent_schedules (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    agent_id uuid,
    name character varying(128) NOT NULL,
    scan_type character varying(32) NOT NULL,
    cron character varying(64) NOT NULL,
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    interface character varying(64),
    enabled boolean NOT NULL,
    last_fired_at timestamp with time zone,
    notification_channels jsonb DEFAULT '{}'::jsonb NOT NULL,
    notify_on_failure boolean NOT NULL,
    notify_on_new_devices integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    id uuid NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE agents.agent_tasks (
    agent_id uuid NOT NULL,
    task_type character varying(100) NOT NULL,
    task_data jsonb NOT NULL,
    priority integer NOT NULL,
    status character varying(50) NOT NULL,
    progress integer NOT NULL,
    result jsonb,
    error_message text,
    scheduled_at timestamp with time zone,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    max_retries integer NOT NULL,
    retry_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL
);

COMMENT ON COLUMN agents.agent_tasks.priority IS 'Priority 1 (highest) to 10 (lowest)';

COMMENT ON COLUMN agents.agent_tasks.progress IS 'Progress percentage 0-100';

CREATE TABLE agents.remote_agents (
    agent_key character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    agent_type character varying(50) NOT NULL,
    version character varying(50),
    platform character varying(100),
    capabilities jsonb NOT NULL,
    supported_vendors jsonb NOT NULL,
    config jsonb NOT NULL,
    last_ip character varying(45),
    last_hostname character varying(255),
    status character varying(50) NOT NULL,
    last_seen timestamp with time zone,
    last_heartbeat timestamp with time zone,
    notification_channels jsonb DEFAULT '{}'::jsonb NOT NULL,
    offline_notified_at timestamp with time zone,
    offline_threshold_seconds integer DEFAULT 180 NOT NULL,
    uptime_seconds integer NOT NULL,
    connected_at timestamp with time zone,
    disconnected_at timestamp with time zone,
    total_connections integer NOT NULL,
    total_tasks_executed integer NOT NULL,
    failed_tasks integer NOT NULL,
    poll_interval integer NOT NULL,
    is_approved boolean NOT NULL,
    approved_at timestamp with time zone,
    approved_by_id uuid,
    is_enabled boolean NOT NULL,
    site_id uuid,
    organization_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

COMMENT ON COLUMN agents.remote_agents.agent_key IS 'SHA-256 hash of the agent API key';

COMMENT ON COLUMN agents.remote_agents.poll_interval IS 'Polling interval in seconds';

CREATE TABLE ai.ai_conversations (
    user_id uuid NOT NULL,
    organization_id uuid,
    title character varying(200),
    provider character varying(50) NOT NULL,
    model character varying(100) NOT NULL,
    total_tokens integer NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE ai.ai_messages (
    conversation_id uuid NOT NULL,
    role character varying(20) NOT NULL,
    content text,
    tool_calls jsonb,
    tool_call_id character varying(100),
    tool_name character varying(100),
    token_usage jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE ai.ai_provider_configs (
    organization_id uuid NOT NULL,
    provider character varying(50) NOT NULL,
    api_key_encrypted text,
    base_url character varying(512),
    default_model character varying(100),
    is_enabled boolean NOT NULL,
    settings jsonb NOT NULL,
    llm_org_policy character varying(20) DEFAULT 'disabled'::character varying NOT NULL,
    monthly_token_budget integer DEFAULT 100000 NOT NULL,
    tokens_used_this_month integer DEFAULT 0 NOT NULL,
    budget_reset_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE ai.llm_call_logs (
    organization_id uuid NOT NULL,
    rule_id uuid,
    execution_id uuid,
    provider character varying(20) NOT NULL,
    model character varying(100) NOT NULL,
    operation character varying(20) NOT NULL,
    input_fields_sent jsonb NOT NULL,
    prompt_tokens integer NOT NULL,
    completion_tokens integer NOT NULL,
    success boolean NOT NULL,
    error text,
    latency_ms double precision NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE ai.org_llm_policies (
    organization_id uuid NOT NULL,
    llm_org_policy character varying(20) DEFAULT 'disabled'::character varying NOT NULL,
    monthly_token_budget integer DEFAULT 100000 NOT NULL,
    tokens_used_this_month integer DEFAULT 0 NOT NULL,
    budget_reset_at timestamp with time zone,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE analytics.alerts (
    severity character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    alert_type character varying(100) NOT NULL,
    title character varying(500) NOT NULL,
    message text,
    metric_name character varying(255),
    metric_value jsonb,
    device_id uuid,
    site_id uuid,
    organization_id uuid,
    triggered_at timestamp with time zone NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by uuid,
    resolved_at timestamp with time zone,
    notes text,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE analytics.dashboard_widgets (
    dashboard_name character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    widget_type character varying(50) NOT NULL,
    position_x integer NOT NULL,
    position_y integer NOT NULL,
    width integer NOT NULL,
    height integer NOT NULL,
    metrics jsonb NOT NULL,
    filters jsonb NOT NULL,
    aggregation character varying(20) NOT NULL,
    time_range character varying(20) NOT NULL,
    display_options jsonb NOT NULL,
    refresh_interval_seconds integer NOT NULL,
    owner_id uuid,
    organization_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE analytics.metric_definitions (
    name character varying(255) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    category character varying(100) NOT NULL,
    metric_type character varying(20) NOT NULL,
    unit character varying(50),
    labels jsonb,
    default_aggregation character varying(20) NOT NULL,
    retention_hours integer NOT NULL,
    warning_threshold jsonb,
    critical_threshold jsonb,
    is_active boolean NOT NULL,
    is_system boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE analytics.sla_report_schedules (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    frequency character varying(20) NOT NULL,
    day_of_week integer,
    day_of_month integer,
    recipients jsonb NOT NULL,
    sla_policy_ids jsonb NOT NULL,
    enabled boolean NOT NULL,
    last_generated_at timestamp with time zone,
    next_run_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE analytics.sla_reports (
    organization_id uuid NOT NULL,
    title character varying(255) NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    format character varying(10) NOT NULL,
    file_path character varying(500),
    file_size integer,
    report_data jsonb NOT NULL,
    generated_by uuid,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE audit.audit_logs (
    "timestamp" timestamp with time zone NOT NULL,
    action character varying(50) NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id character varying(64),
    resource_name character varying(255),
    actor_id character varying(64),
    actor_type character varying(20) NOT NULL,
    actor_name character varying(255),
    actor_email character varying(255),
    organization_id uuid,
    site_id uuid,
    ip_address character varying(45),
    user_agent text,
    session_id character varying(64),
    request_id character varying(64),
    request_method character varying(10),
    request_path character varying(512),
    status character varying(20) NOT NULL,
    response_code integer,
    response_time_ms double precision,
    error_message text,
    changes jsonb,
    previous_state jsonb,
    new_state jsonb,
    tags jsonb,
    metadata jsonb,
    prev_hash character varying(64),
    row_hmac character varying(64),
    id uuid NOT NULL
);

CREATE TABLE audit.failed_logins (
    "timestamp" timestamp with time zone NOT NULL,
    username character varying(255) NOT NULL,
    ip_address character varying(45) NOT NULL,
    user_agent text,
    reason character varying(50) NOT NULL,
    geo_location jsonb,
    request_metadata jsonb,
    id uuid NOT NULL
);

CREATE TABLE audit.ip_blocks (
    ip_address character varying(45) NOT NULL,
    reason character varying(30) NOT NULL,
    blocked_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    is_active boolean NOT NULL,
    failed_attempts integer NOT NULL,
    blocked_username character varying(255),
    details jsonb,
    unblocked_at timestamp with time zone,
    unblocked_by uuid,
    unblock_reason text,
    id uuid NOT NULL
);

CREATE TABLE audit.security_anomalies (
    detected_at timestamp with time zone NOT NULL,
    anomaly_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    user_id uuid,
    user_email character varying(255),
    ip_address character varying(45),
    title character varying(255) NOT NULL,
    description text,
    evidence jsonb,
    risk_score integer NOT NULL,
    related_event_ids jsonb,
    resolved boolean NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution_notes text,
    organization_id uuid,
    id uuid NOT NULL
);

CREATE TABLE audit.security_events (
    "timestamp" timestamp with time zone NOT NULL,
    event_type character varying(50) NOT NULL,
    category character varying(30) NOT NULL,
    severity character varying(20) NOT NULL,
    user_id uuid,
    user_email character varying(255),
    ip_address character varying(45),
    user_agent text,
    success boolean NOT NULL,
    outcome character varying(20) NOT NULL,
    risk_score integer NOT NULL,
    risk_factors jsonb,
    details jsonb,
    source character varying(50),
    geo_location jsonb,
    reviewed boolean NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_notes text,
    organization_id uuid,
    id uuid NOT NULL
);

CREATE TABLE backup.backup_schedules (
    name character varying(128) NOT NULL,
    description text,
    schedule_type character varying(20) NOT NULL,
    cron_expression character varying(64),
    timezone character varying(64) NOT NULL,
    run_time character varying(5) NOT NULL,
    run_days jsonb,
    run_day_of_month integer,
    backup_type character varying(50) NOT NULL,
    retention_days integer NOT NULL,
    max_backups integer NOT NULL,
    device_ids jsonb,
    is_encrypted boolean NOT NULL,
    storage_type character varying(20) NOT NULL,
    storage_config jsonb,
    storage_location_id uuid,
    include_devices boolean NOT NULL,
    include_vlans boolean NOT NULL,
    include_ssids boolean NOT NULL,
    include_users boolean NOT NULL,
    include_automation boolean NOT NULL,
    is_enabled boolean NOT NULL,
    last_run_at timestamp with time zone,
    next_run_at timestamp with time zone,
    organization_id uuid,
    site_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE backup.backups (
    name character varying(128) NOT NULL,
    description text,
    backup_type character varying(50) NOT NULL,
    status character varying(20) NOT NULL,
    progress integer NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    storage_type character varying(20) NOT NULL,
    storage_path character varying(512),
    file_size bigint,
    checksum character varying(64),
    is_encrypted boolean NOT NULL,
    encryption_key_id character varying(64),
    include_devices boolean NOT NULL,
    include_vlans boolean NOT NULL,
    include_ssids boolean NOT NULL,
    include_users boolean NOT NULL,
    include_automation boolean NOT NULL,
    include_secrets boolean DEFAULT false NOT NULL,
    device_ids jsonb,
    device_count integer NOT NULL,
    error_message text,
    retention_days integer NOT NULL,
    expires_at timestamp with time zone,
    metadata_json jsonb NOT NULL,
    organization_id uuid,
    site_id uuid,
    created_by_id uuid,
    schedule_id uuid,
    storage_location_id uuid,
    rollback_for_restore_job_id uuid,
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE backup.restore_jobs (
    backup_id uuid NOT NULL,
    status character varying(20) NOT NULL,
    progress integer NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    restore_devices boolean NOT NULL,
    restore_vlans boolean NOT NULL,
    restore_ssids boolean NOT NULL,
    restore_users boolean NOT NULL,
    restore_automation boolean NOT NULL,
    overwrite_existing boolean NOT NULL,
    dry_run boolean NOT NULL,
    target_site_id uuid,
    items_restored integer NOT NULL,
    items_failed integer NOT NULL,
    error_message text,
    restore_log jsonb,
    dry_run_report jsonb,
    initiated_by_id uuid,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE backup.storage_locations (
    name character varying(128) NOT NULL,
    description text,
    storage_type character varying(20) NOT NULL,
    is_active boolean NOT NULL,
    is_default boolean NOT NULL,
    last_test_at timestamp with time zone,
    last_test_status character varying(20),
    last_test_message text,
    config jsonb NOT NULL,
    encrypted_credentials text,
    organization_id uuid,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE cameras.camera_access_grants (
    user_id uuid NOT NULL,
    camera_id uuid,
    group_id uuid,
    access_level character varying(20) NOT NULL,
    can_live boolean NOT NULL,
    can_playback boolean NOT NULL,
    can_ptz boolean NOT NULL,
    can_export boolean NOT NULL,
    can_configure boolean NOT NULL,
    organization_id uuid NOT NULL,
    expires_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_camera_access_grants_ck_camera_access_level CHECK (((access_level)::text = ANY ((ARRAY['viewer'::character varying, 'operator'::character varying, 'full'::character varying])::text[]))),
    CONSTRAINT ck_camera_access_grants_ck_camera_access_target CHECK ((((camera_id IS NOT NULL) AND (group_id IS NULL)) OR ((camera_id IS NULL) AND (group_id IS NOT NULL))))
);

CREATE TABLE cameras.camera_events (
    organization_id uuid NOT NULL,
    camera_id uuid NOT NULL,
    event_type character varying(50) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    description text,
    snapshot_path character varying(500),
    metadata_json jsonb NOT NULL,
    is_acknowledged boolean NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    id uuid NOT NULL
);

CREATE TABLE cameras.camera_group_members (
    group_id uuid NOT NULL,
    camera_id uuid NOT NULL,
    sort_order integer NOT NULL,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE cameras.camera_groups (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    color character varying(7) NOT NULL,
    icon character varying(50) NOT NULL,
    sort_order integer NOT NULL,
    is_default boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE cameras.camera_health_snapshots (
    organization_id uuid NOT NULL,
    camera_id uuid NOT NULL,
    captured_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    bitrate_kbps integer,
    frame_rate integer,
    codec character varying(20),
    resolution_width integer,
    resolution_height integer,
    is_online boolean NOT NULL,
    time_drift_seconds double precision,
    id uuid NOT NULL
);

CREATE TABLE cameras.camera_reports (
    organization_id uuid NOT NULL,
    report_type character varying(50) NOT NULL,
    generated_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    data jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE cameras.camera_views (
    organization_id uuid NOT NULL,
    user_id uuid,
    name character varying(255) NOT NULL,
    description text,
    layout character varying(20) NOT NULL,
    camera_ids uuid[] NOT NULL,
    filters jsonb NOT NULL,
    is_default boolean NOT NULL,
    is_shared boolean NOT NULL,
    sort_order integer NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE cameras.cameras (
    site_id uuid NOT NULL,
    nvr_id uuid,
    controller_id uuid,
    organization_id uuid NOT NULL,
    channel_id integer,
    name character varying(255) NOT NULL,
    description text,
    camera_type character varying(50) NOT NULL,
    ip_address character varying(45) NOT NULL,
    port integer NOT NULL,
    mac_address character varying(17),
    vendor character varying(100),
    model character varying(100),
    firmware_version character varying(50),
    serial_number character varying(100),
    rtsp_main_stream character varying(500),
    rtsp_sub_stream character varying(500),
    snapshot_url character varying(500),
    device_type character varying(50),
    username character varying(100),
    password_encrypted character varying(500),
    has_ptz boolean NOT NULL,
    has_audio boolean NOT NULL,
    has_two_way_audio boolean NOT NULL,
    has_ir boolean NOT NULL,
    resolution_width integer,
    resolution_height integer,
    status character varying(20) NOT NULL,
    last_seen timestamp with time zone,
    is_recording boolean NOT NULL,
    motion_detection_enabled boolean NOT NULL,
    settings jsonb NOT NULL,
    location character varying(255),
    floor character varying(50),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT ck_cameras_ck_cameras_port CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT ck_cameras_ck_cameras_status CHECK (((status)::text = ANY ((ARRAY['online'::character varying, 'offline'::character varying, 'recording'::character varying, 'error'::character varying, 'unknown'::character varying, 'maintenance'::character varying])::text[])))
);

CREATE TABLE cameras.evidence_archives (
    organization_id uuid NOT NULL,
    camera_id uuid NOT NULL,
    camera_name character varying(255),
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone NOT NULL,
    watermarked boolean NOT NULL,
    status character varying(20) NOT NULL,
    file_path character varying(500),
    file_size bigint,
    sha256 character varying(64),
    note text,
    error text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    id uuid NOT NULL
);

CREATE TABLE cameras.nvrs (
    site_id uuid NOT NULL,
    controller_id uuid,
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    ip_address character varying(45) NOT NULL,
    port integer NOT NULL,
    mac_address character varying(17),
    vendor character varying(100),
    model character varying(100),
    firmware_version character varying(50),
    serial_number character varying(100),
    device_type character varying(50) NOT NULL,
    username character varying(100),
    password_encrypted character varying(500),
    external_device_id character varying(255),
    channel_count integer NOT NULL,
    storage_total_gb double precision,
    storage_used_gb double precision,
    status character varying(20) NOT NULL,
    last_seen timestamp with time zone,
    last_synced_at timestamp with time zone,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT ck_nvrs_ck_nvrs_port CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT ck_nvrs_ck_nvrs_status CHECK (((status)::text = ANY ((ARRAY['online'::character varying, 'offline'::character varying, 'recording'::character varying, 'error'::character varying, 'unknown'::character varying, 'maintenance'::character varying])::text[])))
);

CREATE TABLE cameras.push_subscriptions (
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    endpoint text NOT NULL,
    p256dh character varying(255) NOT NULL,
    auth character varying(255) NOT NULL,
    user_agent character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    id uuid NOT NULL
);

CREATE TABLE cameras.recording_schedule_templates (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    is_builtin boolean NOT NULL,
    schedule jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE cameras.recordings (
    organization_id uuid NOT NULL,
    camera_id uuid NOT NULL,
    nvr_id uuid,
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone,
    duration_seconds integer,
    file_path character varying(500),
    file_size_bytes bigint,
    recording_type character varying(20) NOT NULL,
    is_locked boolean NOT NULL,
    id uuid NOT NULL,
    CONSTRAINT ck_recordings_ck_recordings_type CHECK (((recording_type)::text = ANY ((ARRAY['continuous'::character varying, 'motion'::character varying, 'manual'::character varying, 'alarm'::character varying, 'event'::character varying])::text[])))
);

CREATE TABLE collector.app_classification_rules (
    organization_id uuid,
    name character varying(100) NOT NULL,
    app_category character varying(50) NOT NULL,
    protocol integer,
    port integer,
    port_range_start integer,
    port_range_end integer,
    dest_ip_pattern character varying(255),
    is_system boolean NOT NULL,
    priority integer NOT NULL,
    enabled boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE collector.collector_configs (
    organization_id uuid NOT NULL,
    snmp_enabled boolean NOT NULL,
    snmp_port integer NOT NULL,
    snmp_community character varying(100) NOT NULL,
    syslog_enabled boolean NOT NULL,
    syslog_port integer NOT NULL,
    netflow_enabled boolean NOT NULL,
    netflow_port integer NOT NULL,
    log_retention_days integer NOT NULL,
    flow_retention_days integer NOT NULL,
    allowed_source_ips character varying(64)[],
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE collector.collector_logs (
    source_type character varying(20) NOT NULL,
    source_ip character varying(45) NOT NULL,
    device_id uuid,
    organization_id uuid,
    facility character varying(20),
    severity character varying(20),
    hostname character varying(255),
    app_name character varying(100),
    message text NOT NULL,
    enterprise_oid character varying(200),
    trap_type character varying(50),
    varbinds jsonb,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    raw_data text,
    id uuid NOT NULL
);

CREATE TABLE collector.flow_records (
    device_id uuid,
    organization_id uuid,
    source_ip character varying(45) NOT NULL,
    dest_ip character varying(45) NOT NULL,
    source_port integer,
    dest_port integer,
    protocol integer NOT NULL,
    bytes_in bigint NOT NULL,
    bytes_out bigint NOT NULL,
    packets bigint NOT NULL,
    bucket_time timestamp with time zone NOT NULL,
    app_name character varying(100),
    app_category character varying(50),
    id uuid NOT NULL
);

CREATE TABLE core.adapter_pending_changes (
    organization_id uuid NOT NULL,
    controller_id uuid,
    site_id uuid,
    omada_site_id character varying(128),
    feature character varying(128) NOT NULL,
    operation character varying(16) NOT NULL,
    target_id character varying(128),
    payload jsonb NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    applied_at timestamp with time zone,
    applied_response jsonb,
    failure_reason text,
    notes text,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.api_keys (
    user_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    key_prefix character varying(12) NOT NULL,
    key_hash character varying(64) NOT NULL,
    scopes jsonb NOT NULL,
    description text,
    last_used timestamp with time zone,
    expires_at timestamp with time zone,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.automation_executions (
    rule_id uuid NOT NULL,
    organization_id uuid,
    triggered_at timestamp with time zone NOT NULL,
    trigger_data jsonb,
    actions_executed jsonb NOT NULL,
    success boolean NOT NULL,
    error text,
    duration_ms double precision NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.automation_rules (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    trigger_type character varying(30) NOT NULL,
    trigger_config jsonb NOT NULL,
    conditions jsonb,
    actions jsonb NOT NULL,
    status character varying(20) NOT NULL,
    priority integer NOT NULL,
    cooldown_seconds integer NOT NULL,
    max_triggers_per_hour integer NOT NULL,
    trigger_count integer NOT NULL,
    last_triggered timestamp with time zone,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone,
    created_by uuid,
    id uuid NOT NULL
);

CREATE TABLE core.config_templates (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    scope character varying(20) NOT NULL,
    scope_id uuid,
    device_type character varying(50),
    config jsonb NOT NULL,
    priority integer NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

COMMENT ON COLUMN core.config_templates.scope IS 'Level in hierarchy: organization, site_group, site, device_group';

COMMENT ON COLUMN core.config_templates.scope_id IS 'ID of the scoped entity (site_group, site, or device_group). NULL for org-level.';

COMMENT ON COLUMN core.config_templates.device_type IS 'Filter: only apply to this device_type. NULL = all.';

COMMENT ON COLUMN core.config_templates.config IS 'Partial config fragment merged during template resolution';

CREATE TABLE core.controllers (
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    controller_type character varying(50) NOT NULL,
    host character varying(255) NOT NULL,
    port integer NOT NULL,
    use_ssl boolean NOT NULL,
    verify_ssl boolean NOT NULL,
    credential_id uuid,
    status character varying(20) NOT NULL,
    last_sync timestamp with time zone,
    last_error text,
    config jsonb NOT NULL,
    sync_enabled boolean NOT NULL,
    sync_interval_seconds integer NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.credentials (
    organization_id uuid NOT NULL,
    site_id uuid,
    name character varying(255) NOT NULL,
    description text,
    credential_type character varying(30) NOT NULL,
    scope character varying(20) NOT NULL,
    vendor character varying(100),
    username character varying(255),
    encrypted_password text,
    api_key text,
    token text,
    ssh_private_key text,
    certificate text,
    snmp_community character varying(255),
    options jsonb NOT NULL,
    is_default boolean NOT NULL,
    is_active boolean NOT NULL,
    last_used timestamp with time zone,
    last_test_result character varying(20),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.custom_roles (
    organization_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    slug character varying(100) NOT NULL,
    description text,
    permissions jsonb NOT NULL,
    level integer NOT NULL,
    is_default boolean NOT NULL,
    is_system boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.device_firmware_status (
    device_id uuid NOT NULL,
    site_id uuid,
    current_version character varying(50),
    latest_version character varying(50),
    recommended_version character varying(50),
    is_up_to_date boolean NOT NULL,
    update_available boolean NOT NULL,
    critical_update_available boolean NOT NULL,
    can_upgrade boolean NOT NULL,
    upgrade_path jsonb,
    device_name character varying(200),
    device_type character varying(50),
    vendor character varying(100),
    model character varying(100),
    last_checked_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.export_jobs (
    status character varying(20) NOT NULL,
    export_format character varying(10) NOT NULL,
    scope character varying(20) NOT NULL,
    entity_types jsonb,
    entity_filters jsonb,
    organization_id uuid,
    site_ids jsonb,
    progress_pct double precision NOT NULL,
    total_entities integer NOT NULL,
    exported_entities integer NOT NULL,
    file_path character varying(512),
    file_size_bytes integer,
    download_url character varying(512),
    error_message text,
    completed_at timestamp with time zone,
    created_by uuid,
    celery_task_id character varying(64),
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.firmware_images (
    vendor character varying(100) NOT NULL,
    model character varying(100) NOT NULL,
    device_type character varying(50),
    version character varying(50) NOT NULL,
    release_type character varying(20) NOT NULL,
    display_name character varying(200),
    description text,
    release_notes text,
    release_notes_url character varying(512),
    release_date timestamp with time zone,
    file_path character varying(512),
    file_size_bytes integer,
    download_url character varying(512),
    checksum_md5 character varying(32),
    checksum_sha256 character varying(64),
    is_latest boolean NOT NULL,
    is_critical boolean NOT NULL,
    is_recommended boolean NOT NULL,
    is_deprecated boolean NOT NULL,
    is_cached boolean NOT NULL,
    cached_at timestamp with time zone,
    min_version character varying(50),
    max_version character varying(50),
    compatible_models jsonb,
    upgrade_path jsonb,
    device_count integer NOT NULL,
    devices_up_to_date integer NOT NULL,
    organization_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.firmware_schedules (
    name character varying(200) NOT NULL,
    description text,
    is_enabled boolean NOT NULL,
    site_id uuid,
    device_type character varying(50),
    vendor character varying(100),
    model character varying(100),
    tags jsonb,
    device_ids jsonb,
    auto_latest boolean NOT NULL,
    target_version character varying(50),
    release_type character varying(20) NOT NULL,
    frequency character varying(20) NOT NULL,
    time_of_day character varying(5),
    day_of_week integer,
    day_of_month integer,
    timezone character varying(50),
    maintenance_window_start character varying(5),
    maintenance_window_end character varying(5),
    backup_before boolean NOT NULL,
    rollback_on_failure boolean NOT NULL,
    max_concurrent integer NOT NULL,
    batch_size integer NOT NULL,
    delay_between_batches integer NOT NULL,
    notify_before boolean NOT NULL,
    notify_before_hours integer NOT NULL,
    notify_on_complete boolean NOT NULL,
    notify_on_failure boolean NOT NULL,
    last_run_at timestamp with time zone,
    next_run_at timestamp with time zone,
    last_job_id uuid,
    total_runs integer NOT NULL,
    organization_id uuid,
    created_by uuid,
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.firmware_upgrade_jobs (
    status character varying(20) NOT NULL,
    firmware_id uuid,
    firmware_version character varying(50),
    device_ids jsonb NOT NULL,
    site_id uuid,
    backup_before boolean NOT NULL,
    rollback_on_failure boolean NOT NULL,
    batch_size integer NOT NULL,
    delay_between_batches integer NOT NULL,
    notify_on_complete boolean NOT NULL,
    notify_on_failure boolean NOT NULL,
    scheduled_at timestamp with time zone,
    progress double precision NOT NULL,
    total_devices integer NOT NULL,
    successful integer NOT NULL,
    failed integer NOT NULL,
    skipped integer NOT NULL,
    devices jsonb,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_by uuid,
    celery_task_id character varying(64),
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.import_jobs (
    status character varying(20) NOT NULL,
    source_format character varying(20) NOT NULL,
    conflict_resolution character varying(20) NOT NULL,
    original_filename character varying(255),
    file_path character varying(512),
    file_size_bytes integer,
    organization_id uuid,
    validation_result jsonb,
    progress_pct double precision NOT NULL,
    total_entities integer NOT NULL,
    imported_entities integer NOT NULL,
    skipped_entities integer NOT NULL,
    failed_entities integer NOT NULL,
    result_summary jsonb,
    error_message text,
    errors jsonb,
    warnings jsonb,
    rollback_data jsonb,
    can_rollback boolean NOT NULL,
    rolled_back_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_by uuid,
    celery_task_id character varying(64),
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.in_app_notifications (
    user_id uuid NOT NULL,
    organization_id uuid,
    title character varying(255) NOT NULL,
    body text NOT NULL,
    category character varying(30) NOT NULL,
    severity character varying(20) NOT NULL,
    action_url character varying(512),
    data jsonb,
    read boolean NOT NULL,
    dismissed boolean NOT NULL,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    read_at timestamp with time zone,
    id uuid NOT NULL
);

CREATE TABLE core.installed_plugins (
    plugin_id character varying(100) NOT NULL,
    name character varying(200) NOT NULL,
    version character varying(20) NOT NULL,
    description text,
    author character varying(200),
    license character varying(50),
    homepage character varying(512),
    installed_by uuid,
    installed_from character varying(512),
    plugin_dir character varying(512) NOT NULL,
    is_active boolean NOT NULL,
    status character varying(20) NOT NULL,
    manifest_cache jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.integrations (
    organization_id uuid NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    integration_type character varying(50) NOT NULL,
    webhook_id uuid NOT NULL,
    is_enabled boolean NOT NULL,
    event_subscriptions jsonb NOT NULL,
    config jsonb NOT NULL,
    last_delivery_at timestamp with time zone,
    last_delivery_status character varying(20),
    delivery_count_7d integer NOT NULL,
    success_count_7d integer NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.marketplace_plugin_versions (
    marketplace_plugin_id uuid NOT NULL,
    version character varying(20) NOT NULL,
    changelog text,
    download_url character varying(512) NOT NULL,
    checksum_sha256 character varying(64) NOT NULL,
    min_core_version character varying(20) NOT NULL,
    released_at timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.marketplace_plugins (
    plugin_id character varying(100) NOT NULL,
    slug character varying(100) NOT NULL,
    name character varying(200) NOT NULL,
    short_description character varying(500) NOT NULL,
    description text,
    author_name character varying(200) NOT NULL,
    author_url character varying(512),
    category character varying(50) NOT NULL,
    tags jsonb NOT NULL,
    latest_version character varying(20) NOT NULL,
    min_core_version character varying(20) NOT NULL,
    icon_url character varying(512),
    banner_url character varying(512),
    screenshots jsonb NOT NULL,
    download_url character varying(512) NOT NULL,
    checksum_sha256 character varying(64) NOT NULL,
    package_size integer,
    download_count integer NOT NULL,
    rating double precision NOT NULL,
    rating_count integer NOT NULL,
    is_verified boolean NOT NULL,
    is_featured boolean NOT NULL,
    status character varying(20) NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.module_events (
    organization_id uuid,
    module_id character varying(100) NOT NULL,
    event_type character varying(50) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    user_id uuid,
    details jsonb NOT NULL,
    error_message text,
    id uuid NOT NULL
);

CREATE TABLE core.module_feature_flags (
    organization_id uuid NOT NULL,
    module_id character varying(100) NOT NULL,
    feature_key character varying(100) NOT NULL,
    is_enabled boolean NOT NULL,
    value jsonb,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.notification_deliveries (
    user_id uuid,
    organization_id uuid,
    channel character varying(20) NOT NULL,
    category character varying(30) NOT NULL,
    severity character varying(20) NOT NULL,
    subject character varying(255),
    success boolean NOT NULL,
    status character varying(20) NOT NULL,
    error_message text,
    provider character varying(50),
    message_id character varying(255),
    sent_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    attempt integer DEFAULT 1 NOT NULL,
    retry_dead_letter boolean DEFAULT false NOT NULL,
    last_error text,
    id uuid NOT NULL
);

CREATE TABLE core.notification_preferences (
    user_id uuid NOT NULL,
    enabled_channels jsonb NOT NULL,
    category_settings jsonb NOT NULL,
    quiet_hours jsonb,
    updated_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.notification_providers (
    organization_id uuid,
    name character varying(120) NOT NULL,
    provider_type character varying(40) NOT NULL,
    channel character varying(20) NOT NULL,
    is_enabled boolean NOT NULL,
    is_default boolean NOT NULL,
    is_verified boolean NOT NULL,
    config jsonb NOT NULL,
    rate_limit_per_hour integer NOT NULL,
    rate_limit_per_day integer NOT NULL,
    last_verified_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

COMMENT ON COLUMN core.notification_providers.provider_type IS 'e.g. smtp, slack_webhook, teams_webhook, generic_webhook, twilio_sms, twilio_whatsapp';

COMMENT ON COLUMN core.notification_providers.channel IS 'Matches NotificationChannel enum: email, slack, teams, webhook, sms, whatsapp, in_app';

COMMENT ON COLUMN core.notification_providers.config IS 'Channel-specific configuration (secrets stored encrypted at app layer)';

CREATE TABLE core.oauth2_apps (
    user_id uuid NOT NULL,
    organization_id uuid,
    name character varying(200) NOT NULL,
    description text,
    client_id character varying(64) NOT NULL,
    client_secret_hash character varying(64) NOT NULL,
    client_secret_prefix character varying(12) NOT NULL,
    redirect_uris jsonb NOT NULL,
    scopes jsonb NOT NULL,
    grant_types jsonb NOT NULL,
    is_active boolean NOT NULL,
    is_confidential boolean NOT NULL,
    logo_url character varying(512),
    homepage_url character varying(512),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.oauth2_authorization_codes (
    code character varying(128) NOT NULL,
    app_id uuid NOT NULL,
    user_id uuid NOT NULL,
    redirect_uri character varying(512) NOT NULL,
    scopes jsonb NOT NULL,
    code_challenge character varying(128),
    code_challenge_method character varying(10),
    expires_at timestamp with time zone NOT NULL,
    used boolean NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.oauth2_tokens (
    app_id uuid NOT NULL,
    user_id uuid NOT NULL,
    access_token_hash character varying(64) NOT NULL,
    refresh_token_hash character varying(64),
    scopes jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked boolean NOT NULL,
    user_token_version_at_issue integer DEFAULT 0 NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.organization_modules (
    organization_id uuid NOT NULL,
    module_id character varying(100) NOT NULL,
    is_enabled boolean NOT NULL,
    enabled_at timestamp with time zone,
    disabled_at timestamp with time zone,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.organizations (
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    description text,
    contact_email character varying(255),
    contact_phone character varying(50),
    settings jsonb NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.plugin_organization_states (
    plugin_id character varying(100) NOT NULL,
    organization_id uuid NOT NULL,
    is_enabled boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.plugin_reviews (
    marketplace_plugin_id uuid NOT NULL,
    user_id uuid NOT NULL,
    rating integer NOT NULL,
    title character varying(200),
    body text,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.plugin_settings (
    plugin_id character varying(100) NOT NULL,
    organization_id uuid NOT NULL,
    key character varying(200) NOT NULL,
    value jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.site_groups (
    organization_id uuid NOT NULL,
    parent_id uuid,
    name character varying(255) NOT NULL,
    description text,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.sites (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    description text,
    address text,
    city character varying(100),
    country character varying(100),
    timezone character varying(50) NOT NULL,
    time_format character varying(10) NOT NULL,
    date_format character varying(20) NOT NULL,
    site_group_id uuid,
    subnets jsonb NOT NULL,
    gateway_ip character varying(45),
    settings jsonb NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.sla_breaches (
    policy_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    severity character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    violated_metric character varying(100) NOT NULL,
    threshold_value double precision NOT NULL,
    actual_value double precision NOT NULL,
    deviation_percent double precision NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    acknowledged_by uuid,
    duration_minutes integer,
    context jsonb NOT NULL,
    notes text,
    id uuid NOT NULL
);

CREATE TABLE core.sla_policies (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    status character varying(20) NOT NULL,
    scope character varying(30) NOT NULL,
    scope_id uuid,
    scope_name character varying(255),
    thresholds jsonb NOT NULL,
    evaluation_window_minutes integer NOT NULL,
    breach_after_consecutive integer NOT NULL,
    warning_threshold_percent double precision NOT NULL,
    notification_channels jsonb,
    escalation_policy jsonb,
    current_compliance_percent double precision,
    last_evaluated_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.sla_snapshots (
    policy_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    compliance_percent double precision NOT NULL,
    metrics jsonb NOT NULL,
    in_breach boolean NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.sso_providers (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    description text,
    protocol public.sso_protocol NOT NULL,
    status public.sso_provider_status NOT NULL,
    icon_url character varying(512),
    display_order integer NOT NULL,
    oidc_issuer character varying(512),
    oidc_client_id character varying(255),
    oidc_client_secret character varying(512),
    oidc_scopes character varying(500),
    oidc_discovery_url character varying(512),
    saml_entity_id character varying(512),
    saml_sso_url character varying(512),
    saml_slo_url character varying(512),
    saml_certificate text,
    saml_signing_key text,
    saml_name_id_format character varying(255),
    ldap_url character varying(512),
    ldap_bind_dn character varying(512),
    ldap_bind_password character varying(512),
    ldap_base_dn character varying(512),
    ldap_user_search_filter character varying(512),
    ldap_group_search_filter character varying(512),
    ldap_use_tls boolean NOT NULL,
    ldap_tls_ca_cert text,
    attribute_mapping jsonb NOT NULL,
    role_mapping jsonb NOT NULL,
    jit_provisioning boolean NOT NULL,
    default_role character varying(20) NOT NULL,
    extra_settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.sso_sessions (
    provider_id uuid NOT NULL,
    user_id uuid,
    state character varying(255) NOT NULL,
    nonce character varying(255),
    redirect_uri character varying(512),
    external_id character varying(512),
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    idp_response jsonb,
    id uuid NOT NULL
);

CREATE TABLE core.user_sessions (
    user_id uuid NOT NULL,
    refresh_token_hash character varying(255),
    refresh_jti character varying(64),
    access_jti character varying(64),
    user_agent text,
    ip_address character varying(45),
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    is_revoked boolean NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.user_site_access (
    user_id uuid NOT NULL,
    site_id uuid NOT NULL,
    access_level character varying(20),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.users (
    organization_id uuid,
    email character varying(255) NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    hashed_password character varying(255) NOT NULL,
    role character varying(20) NOT NULL,
    mfa_enabled boolean NOT NULL,
    mfa_secret character varying(255),
    mfa_backup_codes text,
    mfa_pending_secret character varying(255),
    mfa_pending_backup_codes text,
    mfa_last_totp_step bigint,
    is_active boolean NOT NULL,
    is_verified boolean NOT NULL,
    last_login timestamp with time zone,
    failed_login_attempts integer NOT NULL,
    locked_until timestamp with time zone,
    token_version integer DEFAULT 0 NOT NULL,
    language character varying(10) NOT NULL,
    auth_provider character varying(50),
    external_id character varying(512),
    sso_provider_id uuid,
    preferences jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE core.webhook_dead_letters (
    webhook_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    organization_id uuid,
    event_type character varying(100) NOT NULL,
    payload jsonb,
    failure_reason text,
    attempt_count integer NOT NULL,
    final_attempt_at timestamp with time zone NOT NULL,
    replayed_at timestamp with time zone,
    replayed_by uuid,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE core.webhook_deliveries (
    webhook_id uuid NOT NULL,
    event_id character varying(64),
    event_type character varying(100) NOT NULL,
    status character varying(20) NOT NULL,
    response_code integer,
    response_time_ms double precision,
    attempt_number integer NOT NULL,
    error_message text,
    payload jsonb,
    sent_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE core.webhooks (
    name character varying(200) NOT NULL,
    description text,
    url character varying(512) NOT NULL,
    event_types jsonb NOT NULL,
    site_ids jsonb,
    enabled boolean NOT NULL,
    secret character varying(256),
    verify_ssl boolean NOT NULL,
    max_retries integer NOT NULL,
    retry_count integer NOT NULL,
    success_count integer NOT NULL,
    failure_count integer NOT NULL,
    last_triggered timestamp with time zone,
    last_success timestamp with time zone,
    last_failure timestamp with time zone,
    organization_id uuid,
    created_by uuid,
    id uuid NOT NULL,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE devices.adoption_jobs (
    device_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    status character varying(30) NOT NULL,
    current_step character varying(30) NOT NULL,
    steps_completed jsonb NOT NULL,
    error_message text,
    retry_count integer NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    triggered_by character varying(30) NOT NULL,
    rule_id uuid,
    profile_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE devices.auto_adoption_rules (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    priority integer NOT NULL,
    enabled boolean NOT NULL,
    match_device_type character varying(50),
    match_manufacturer character varying(100),
    match_model_pattern character varying(255),
    match_controller_id uuid,
    match_site_id uuid,
    target_site_id uuid,
    provisioning_profile_id uuid,
    auto_firmware_update boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON COLUMN devices.auto_adoption_rules.match_model_pattern IS 'SQL LIKE pattern, e.g. ''EAP%'' or ''TL-SG%''';

COMMENT ON COLUMN devices.auto_adoption_rules.target_site_id IS 'Move device to this site on adoption';

CREATE TABLE devices.bulk_operations (
    organization_id uuid NOT NULL,
    operation character varying(50) NOT NULL,
    status character varying(20) NOT NULL,
    target jsonb NOT NULL,
    config jsonb,
    rollout_strategy jsonb,
    devices_total integer NOT NULL,
    devices_completed integer NOT NULL,
    devices_failed integer NOT NULL,
    devices_skipped integer NOT NULL,
    current_stage smallint NOT NULL,
    device_results jsonb NOT NULL,
    triggered_by uuid,
    error_message text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE devices.device_clients (
    device_id uuid NOT NULL,
    mac_address character varying(17) NOT NULL,
    hostname character varying(255),
    ip_address character varying(45),
    ssid character varying(32),
    band character varying(10),
    channel integer,
    signal_dbm integer,
    noise_dbm integer,
    connected_at timestamp with time zone,
    last_seen timestamp with time zone,
    is_online boolean NOT NULL,
    tx_bytes bigint,
    rx_bytes bigint,
    tx_rate_mbps double precision,
    rx_rate_mbps double precision,
    client_metadata jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE devices.device_configs (
    device_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    desired_config jsonb NOT NULL,
    pushed_config jsonb NOT NULL,
    running_config jsonb NOT NULL,
    desired_updated_at timestamp with time zone,
    desired_updated_by uuid,
    pushed_at timestamp with time zone,
    push_result character varying(20),
    push_error text,
    running_synced_at timestamp with time zone,
    has_drift boolean NOT NULL,
    drift_details jsonb,
    drift_detected_at timestamp with time zone,
    drift_acknowledged boolean NOT NULL,
    auto_remediate boolean NOT NULL,
    config_version integer NOT NULL,
    device_overrides jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON COLUMN devices.device_configs.desired_config IS 'Source of truth — resolved from template hierarchy + overrides';

COMMENT ON COLUMN devices.device_configs.pushed_config IS 'Last config pushed to device via adapter';

COMMENT ON COLUMN devices.device_configs.running_config IS 'Config read back from device (actual running state)';

COMMENT ON COLUMN devices.device_configs.has_drift IS 'True when desired_config != running_config';

COMMENT ON COLUMN devices.device_configs.drift_details IS 'JSON diff of desired vs running for quick inspection';

COMMENT ON COLUMN devices.device_configs.auto_remediate IS 'If True, reconciliation loop auto-pushes desired_config on drift';

COMMENT ON COLUMN devices.device_configs.device_overrides IS 'Per-device overrides applied on top of template hierarchy';

CREATE TABLE devices.device_group_members (
    device_id uuid NOT NULL,
    group_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL
);

CREATE TABLE devices.device_groups (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    match_rules jsonb NOT NULL,
    is_active boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE devices.device_health (
    id uuid NOT NULL,
    device_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id uuid,
    health_score smallint NOT NULL,
    health_status character varying(20) NOT NULL,
    score_reachability smallint,
    score_latency smallint,
    score_drift smallint,
    score_error_rate smallint,
    score_utilization smallint,
    score_firmware smallint,
    score_history jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL
);

COMMENT ON COLUMN devices.device_health.health_score IS 'Composite score 0-100';

CREATE TABLE devices.device_lifecycle_log (
    device_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    from_state character varying(20) NOT NULL,
    to_state character varying(20) NOT NULL,
    trigger character varying(30) NOT NULL,
    triggered_by uuid,
    details jsonb,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

COMMENT ON COLUMN devices.device_lifecycle_log.triggered_by IS 'User ID — NULL if system-triggered';

CREATE TABLE devices.device_ports (
    device_id uuid NOT NULL,
    port_number integer NOT NULL,
    name character varying(100),
    port_type character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    is_enabled boolean NOT NULL,
    is_poe_enabled boolean NOT NULL,
    vlan_id integer,
    speed_mbps integer,
    duplex character varying(20),
    poe_power_watts double precision,
    poe_class integer,
    tx_bytes bigint,
    rx_bytes bigint,
    tx_packets bigint,
    rx_packets bigint,
    errors bigint,
    connected_mac character varying(17),
    connected_device_id uuid,
    port_metadata jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE devices.device_sync_locks (
    lock_key character varying(100) NOT NULL,
    locked_by character varying(100) NOT NULL,
    locked_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE devices.device_tags (
    device_id uuid NOT NULL,
    tag character varying(100) NOT NULL
);

CREATE TABLE devices.devices (
    controller_id uuid,
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    mac_address character varying(17),
    serial_number character varying(100),
    external_id character varying(255),
    device_type character varying(50) NOT NULL,
    model character varying(100),
    manufacturer character varying(100),
    firmware_version character varying(50),
    ip_address character varying(45),
    connection_type character varying(20),
    vlan_id integer,
    location character varying(255),
    floor character varying(50),
    room character varying(100),
    status character varying(20) NOT NULL,
    last_seen timestamp with time zone,
    uptime_seconds integer,
    cpu_usage_percent double precision,
    memory_usage_percent double precision,
    temperature_celsius double precision,
    metadata jsonb NOT NULL,
    capabilities jsonb NOT NULL,
    lifecycle_state character varying(20) NOT NULL,
    lifecycle_changed_at timestamp with time zone,
    lifecycle_error text,
    is_active boolean NOT NULL,
    is_managed boolean NOT NULL,
    notes text,
    is_adopted boolean NOT NULL,
    adopted_at timestamp with time zone,
    adopted_by uuid,
    driver_id character varying(100),
    credential_id uuid,
    discovery_method character varying(50),
    discovery_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

COMMENT ON COLUMN devices.devices.lifecycle_state IS 'FSM state: discovered, adopting, provisioning, managed, updating, offline, error, decommissioned, ignored';

COMMENT ON COLUMN devices.devices.lifecycle_error IS 'Human-readable error when lifecycle_state=error';

CREATE TABLE devices.discovered_hosts (
    site_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    mac_address character varying(17),
    ip_address character varying(45) NOT NULL,
    hostname character varying(255),
    vendor character varying(128),
    device_type character varying(64),
    manufacturer_confidence integer,
    discovered_by_agent_id uuid,
    discovered_via jsonb DEFAULT '[]'::jsonb NOT NULL,
    open_ports jsonb DEFAULT '[]'::jsonb NOT NULL,
    services jsonb DEFAULT '{}'::jsonb NOT NULL,
    mdns_services jsonb DEFAULT '[]'::jsonb NOT NULL,
    ssdp_info jsonb,
    http_title character varying(255),
    http_server character varying(255),
    lldp_chassis_id character varying(255),
    lldp_port_id character varying(255),
    lldp_system_name character varying(255),
    lldp_capabilities jsonb,
    likely_device_types jsonb DEFAULT '[]'::jsonb NOT NULL,
    recommended_driver character varying(64),
    is_adopted boolean NOT NULL,
    adopted_device_id uuid,
    adopted_at timestamp with time zone,
    ignored boolean NOT NULL,
    ignored_reason character varying(255),
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE devices.mac_pre_registrations (
    organization_id uuid NOT NULL,
    mac_address character varying(17) NOT NULL,
    device_name character varying(255),
    target_site_id uuid,
    provisioning_profile_id uuid,
    adopted boolean NOT NULL,
    adopted_at timestamp with time zone,
    adopted_device_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON COLUMN devices.mac_pre_registrations.mac_address IS 'Normalized MAC: AA:BB:CC:DD:EE:FF';

CREATE TABLE devices.poe_schedules (
    organization_id uuid NOT NULL,
    device_id uuid,
    device_group_id uuid,
    name character varying(255) NOT NULL,
    enabled boolean NOT NULL,
    port_numbers jsonb NOT NULL,
    power_off_time character varying(5) NOT NULL,
    power_on_time character varying(5) NOT NULL,
    days_of_week jsonb NOT NULL,
    timezone character varying(50) NOT NULL,
    last_action character varying(20),
    last_action_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT ck_poe_schedules_ck_poe_schedule_xor_target CHECK ((((device_id IS NOT NULL) AND (device_group_id IS NULL)) OR ((device_id IS NULL) AND (device_group_id IS NOT NULL))))
);

COMMENT ON COLUMN devices.poe_schedules.device_id IS 'Target a specific device. NULL if using device_group_id.';

COMMENT ON COLUMN devices.poe_schedules.device_group_id IS 'Target all devices in a group. NULL if using device_id.';

COMMENT ON COLUMN devices.poe_schedules.port_numbers IS 'List of port numbers to control, e.g. [1, 2, 5]';

COMMENT ON COLUMN devices.poe_schedules.power_off_time IS 'Time to disable PoE, e.g. ''22:00''';

COMMENT ON COLUMN devices.poe_schedules.power_on_time IS 'Time to enable PoE, e.g. ''06:00''';

COMMENT ON COLUMN devices.poe_schedules.days_of_week IS 'Days of week (0=Mon, 6=Sun), e.g. [0,1,2,3,4] for weekdays';

COMMENT ON COLUMN devices.poe_schedules.last_action IS 'Last action taken: ''power_off'' or ''power_on''';

CREATE TABLE devices.provisioning_profiles (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    device_type character varying(50) NOT NULL,
    manufacturer character varying(100),
    config_payload jsonb NOT NULL,
    config_template_id uuid,
    auto_firmware_update boolean NOT NULL,
    target_firmware_version character varying(50),
    is_default boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

COMMENT ON COLUMN devices.provisioning_profiles.device_type IS 'Target device type: access_point, switch, gateway, etc.';

COMMENT ON COLUMN devices.provisioning_profiles.manufacturer IS 'Optional: restrict to specific manufacturer';

COMMENT ON COLUMN devices.provisioning_profiles.config_payload IS 'Config blob: {wifi: [...], vlans: [...], ports: [...]}';

CREATE TABLE devices.topology_edges (
    site_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    discovered_by_agent_id uuid,
    protocol character varying(8) DEFAULT 'lldp'::character varying NOT NULL,
    local_interface character varying(64) NOT NULL,
    neighbor_chassis_id character varying(64) NOT NULL,
    neighbor_chassis_subtype character varying(16),
    neighbor_port_id character varying(64) NOT NULL,
    neighbor_port_subtype character varying(16),
    neighbor_port_description character varying(255),
    neighbor_system_name character varying(255),
    neighbor_system_description text,
    neighbor_capabilities jsonb,
    neighbor_mgmt_address character varying(45),
    vlan_id integer,
    neighbor_device_id uuid,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE enterprise.auto_backup_policies (
    organization_id uuid NOT NULL,
    enabled boolean NOT NULL,
    trigger_on_config_push boolean NOT NULL,
    trigger_on_firmware_update boolean NOT NULL,
    trigger_on_adoption boolean NOT NULL,
    retention_count integer NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE enterprise.config_versions (
    device_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    version_number integer NOT NULL,
    config_snapshot jsonb NOT NULL,
    change_summary text,
    source character varying(50) NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT '2026-08-28 08:19:01.630567+00'::timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

COMMENT ON COLUMN enterprise.config_versions.source IS 'config_push, manual_save, rollback, adoption';

CREATE TABLE enterprise.health_daily_snapshots (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    site_id uuid,
    snapshot_date date NOT NULL,
    avg_health_score double precision NOT NULL,
    device_count integer NOT NULL,
    healthy_count integer NOT NULL,
    warning_count integer NOT NULL,
    degraded_count integer NOT NULL,
    critical_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE events.alert_rules (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    rule_type character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    severity character varying(50) NOT NULL,
    conditions jsonb NOT NULL,
    scope character varying(50) NOT NULL,
    scope_ids jsonb,
    device_types jsonb,
    check_interval_seconds integer NOT NULL,
    for_duration_seconds integer NOT NULL,
    cooldown_seconds integer NOT NULL,
    auto_resolve boolean NOT NULL,
    auto_resolve_after_seconds integer,
    notification_channels jsonb NOT NULL,
    notify_on_resolve boolean NOT NULL,
    dedupe_window_seconds integer NOT NULL,
    tags jsonb NOT NULL,
    extra_metadata jsonb NOT NULL,
    last_evaluated_at timestamp with time zone,
    last_fired_at timestamp with time zone,
    fire_count integer NOT NULL,
    is_system boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE events.alerts (
    organization_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    site_id uuid,
    device_id uuid,
    severity character varying(50) NOT NULL,
    title character varying(500) NOT NULL,
    message text NOT NULL,
    details jsonb NOT NULL,
    status character varying(50) NOT NULL,
    fired_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by uuid,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    fingerprint character varying(255) NOT NULL,
    occurrence_count integer NOT NULL,
    last_occurrence_at timestamp with time zone DEFAULT now() NOT NULL,
    suppressed boolean NOT NULL,
    suppressed_until timestamp with time zone,
    suppression_reason character varying(500),
    notifications_sent integer NOT NULL,
    last_notified_at timestamp with time zone,
    tags jsonb NOT NULL,
    extra_metadata jsonb NOT NULL,
    source character varying(100),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE events.correlation_rules (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    status character varying(20) NOT NULL,
    event_patterns jsonb NOT NULL,
    time_window_seconds integer NOT NULL,
    scope character varying(50) NOT NULL,
    conditions jsonb,
    severity character varying(20) NOT NULL,
    auto_resolve_seconds integer,
    notification_channels jsonb,
    fire_count integer NOT NULL,
    last_fired_at timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE events.event_subscriptions (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    pattern character varying(255) NOT NULL,
    target_type character varying(50) NOT NULL,
    target_url text,
    target_config jsonb NOT NULL,
    organization_id uuid,
    site_ids jsonb,
    is_active boolean NOT NULL,
    last_triggered timestamp with time zone,
    trigger_count integer NOT NULL,
    retry_count integer NOT NULL,
    retry_delay_seconds integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE events.incident_events (
    incident_id uuid NOT NULL,
    event_id uuid NOT NULL,
    matched_pattern character varying(255),
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE events.incidents (
    organization_id uuid NOT NULL,
    rule_id uuid,
    site_id uuid,
    title character varying(500) NOT NULL,
    description text,
    severity character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    opened_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    resolved_at timestamp with time zone,
    closed_at timestamp with time zone,
    assigned_to uuid,
    event_count integer NOT NULL,
    affected_devices jsonb NOT NULL,
    root_cause text,
    resolution_notes text,
    tags jsonb NOT NULL,
    context jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE fabric.connection_runs (
    connection_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    source_event_type character varying(255) NOT NULL,
    trigger_payload jsonb NOT NULL,
    success boolean DEFAULT false NOT NULL,
    steps jsonb NOT NULL,
    error text,
    duration_ms integer DEFAULT 0 NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE fabric.connections (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    enabled boolean DEFAULT true NOT NULL,
    source_event character varying(255) NOT NULL,
    conditions jsonb,
    steps jsonb NOT NULL,
    cooldown_seconds integer DEFAULT 0 NOT NULL,
    last_run_at timestamp with time zone,
    run_count integer DEFAULT 0 NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE firewall.devices (
    site_id uuid NOT NULL,
    controller_id uuid,
    name character varying(255) NOT NULL,
    description text,
    device_type character varying(50) NOT NULL,
    ip_address character varying(45) NOT NULL,
    port integer NOT NULL,
    vendor character varying(100),
    model character varying(100),
    firmware_version character varying(50),
    serial_number character varying(100),
    is_online boolean NOT NULL,
    last_seen timestamp with time zone,
    supports_ids boolean NOT NULL,
    supports_vpn boolean NOT NULL,
    default_policy character varying(20) NOT NULL,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE firewall.gateway_connections (
    org_id uuid NOT NULL,
    site_id uuid,
    device_id uuid,
    name character varying(255) NOT NULL,
    description text,
    vendor character varying(20) NOT NULL,
    host character varying(255) NOT NULL,
    port integer NOT NULL,
    verify_ssl boolean NOT NULL,
    credentials jsonb NOT NULL,
    sync_enabled boolean NOT NULL,
    sync_interval_seconds integer NOT NULL,
    sync_status character varying(20) NOT NULL,
    last_sync_at timestamp with time zone,
    last_sync_error text,
    last_sync_duration_ms integer,
    is_online boolean NOT NULL,
    last_seen_at timestamp with time zone,
    detected_version character varying(100),
    detected_hostname character varying(255),
    detected_model character varying(255),
    capabilities jsonb NOT NULL,
    settings jsonb NOT NULL,
    fabric_health jsonb,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE firewall.gateway_sync_logs (
    gateway_id uuid NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    duration_ms integer,
    status character varying(20) NOT NULL,
    error text,
    items_synced integer NOT NULL,
    items_failed integer NOT NULL,
    details jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE firewall.ids_alerts (
    device_id uuid,
    signature_id character varying(50),
    signature_name character varying(255) NOT NULL,
    category character varying(100),
    severity character varying(20) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    source_ip character varying(45),
    source_port integer,
    dest_ip character varying(45),
    dest_port integer,
    protocol character varying(20),
    action_taken character varying(20),
    description text,
    metadata_json jsonb NOT NULL,
    is_acknowledged boolean NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    id uuid NOT NULL
);

CREATE TABLE firewall.logs (
    device_id uuid,
    rule_id uuid,
    "timestamp" timestamp with time zone NOT NULL,
    source_ip character varying(45),
    source_port integer,
    source_zone character varying(50),
    dest_ip character varying(45),
    dest_port integer,
    dest_zone character varying(50),
    protocol character varying(20),
    action character varying(20) NOT NULL,
    bytes_sent integer,
    bytes_received integer,
    application character varying(100),
    id uuid NOT NULL
);

CREATE TABLE firewall.nat_rules (
    device_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    nat_type character varying(20) NOT NULL,
    original_address character varying(100),
    original_port character varying(50),
    translated_address character varying(100),
    translated_port character varying(50),
    protocol character varying(20) NOT NULL,
    interface character varying(50),
    is_enabled boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE firewall.rules (
    device_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    rule_order integer NOT NULL,
    source_address character varying(100),
    source_port character varying(50),
    source_zone character varying(50),
    dest_address character varying(100),
    dest_port character varying(50),
    dest_zone character varying(50),
    protocol character varying(20) NOT NULL,
    action character varying(20) NOT NULL,
    log_enabled boolean NOT NULL,
    schedule_id uuid,
    is_enabled boolean NOT NULL,
    hit_count integer NOT NULL,
    last_hit timestamp with time zone,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE firewall.vpn_tunnels (
    device_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    vpn_type character varying(20) NOT NULL,
    remote_address character varying(100),
    remote_id character varying(255),
    local_address character varying(100),
    local_id character varying(255),
    local_subnets jsonb NOT NULL,
    remote_subnets jsonb NOT NULL,
    auth_type character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    is_enabled boolean NOT NULL,
    last_connected timestamp with time zone,
    bytes_in integer NOT NULL,
    bytes_out integer NOT NULL,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE gateway.gw_canonical_address_groups (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(255),
    group_type character varying(20) NOT NULL,
    members jsonb NOT NULL,
    auto_generated boolean NOT NULL,
    source_vlan_id uuid,
    management_state character varying(20) NOT NULL,
    external_id character varying(100),
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_canonical_dhcp_reservations (
    organization_id uuid NOT NULL,
    vlan_id uuid NOT NULL,
    mac_address character varying(17) NOT NULL,
    ip_address character varying(45) NOT NULL,
    hostname character varying(255),
    description character varying(255),
    management_state character varying(20) NOT NULL,
    external_id character varying(100),
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_canonical_dhcp_scopes (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    vlan_id uuid NOT NULL,
    range_start character varying(45) NOT NULL,
    range_end character varying(45) NOT NULL,
    subnet_mask character varying(45) NOT NULL,
    gateway character varying(45) NOT NULL,
    lease_time integer NOT NULL,
    dns_servers jsonb NOT NULL,
    ntp_servers jsonb NOT NULL,
    domain_name character varying(255),
    custom_options jsonb NOT NULL,
    management_state character varying(20) NOT NULL,
    external_id character varying(100),
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_canonical_dns_records (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    record_type character varying(10) NOT NULL,
    hostname character varying(255) NOT NULL,
    value character varying(255) NOT NULL,
    ttl integer NOT NULL,
    priority integer,
    description character varying(255),
    management_state character varying(20) NOT NULL,
    external_id character varying(100),
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_canonical_vlans (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    vlan_id integer NOT NULL,
    name character varying(64) NOT NULL,
    description character varying(255),
    subnet character varying(18) NOT NULL,
    gateway_ip character varying(45) NOT NULL,
    dhcp_enabled boolean NOT NULL,
    dhcp_range_start character varying(45),
    dhcp_range_end character varying(45),
    dhcp_lease_time integer NOT NULL,
    dhcp_dns_servers jsonb NOT NULL,
    dhcp_domain character varying(255),
    purpose character varying(20) NOT NULL,
    management_state character varying(20) NOT NULL,
    source_device_id uuid,
    template_id uuid,
    external_ids jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE gateway.gw_distribution_locks (
    site_id uuid NOT NULL,
    locked_by character varying(100) NOT NULL,
    locked_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    distribution_id uuid NOT NULL
);

CREATE TABLE gateway.gw_distribution_records (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id uuid NOT NULL,
    action character varying(20) NOT NULL,
    plan jsonb NOT NULL,
    step_results jsonb NOT NULL,
    status character varying(20) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    rollback_plan jsonb,
    rollback_executed boolean NOT NULL,
    error_message character varying(1000),
    error_device_id uuid,
    error_tier integer,
    triggered_by uuid,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_drift_events (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    drift_type character varying(30) NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id uuid,
    expected_value jsonb,
    actual_value jsonb,
    severity character varying(20) NOT NULL,
    message character varying(500) NOT NULL,
    resolution character varying(20) NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_import_sessions (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    current_step integer NOT NULL,
    status character varying(20) NOT NULL,
    discovered_devices jsonb NOT NULL,
    role_assignments jsonb NOT NULL,
    scan_results jsonb NOT NULL,
    conflicts jsonb NOT NULL,
    reconciliation_decisions jsonb NOT NULL,
    distribution_ids jsonb NOT NULL,
    verification_report jsonb NOT NULL,
    initiated_by uuid,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_dhcp_leases (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    ip_address character varying(45) NOT NULL,
    mac_address character varying(17) NOT NULL,
    hostname character varying(255),
    interface character varying(50),
    starts timestamp with time zone,
    ends timestamp with time zone,
    status character varying(20),
    last_synced_at timestamp with time zone NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_firewall_rules (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    external_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(500),
    rule_index integer NOT NULL,
    direction character varying(20) NOT NULL,
    action character varying(20) NOT NULL,
    protocol character varying(20) NOT NULL,
    source jsonb NOT NULL,
    destination jsonb NOT NULL,
    is_enabled boolean NOT NULL,
    hit_count integer NOT NULL,
    last_hit timestamp with time zone,
    last_synced_at timestamp with time zone NOT NULL,
    raw_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_ids_events (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    event_time timestamp with time zone NOT NULL,
    signature character varying(255) NOT NULL,
    severity character varying(20) NOT NULL,
    source_ip character varying(45),
    source_port integer,
    dest_ip character varying(45),
    dest_port integer,
    action_taken character varying(20),
    message character varying(500),
    last_synced_at timestamp with time zone NOT NULL,
    raw_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_interfaces (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    external_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(255),
    if_type character varying(30),
    mac_address character varying(17),
    mtu integer,
    is_enabled boolean NOT NULL,
    is_up boolean NOT NULL,
    ipv4_address character varying(18),
    ipv4_subnet character varying(18),
    ipv6_address character varying(43),
    vlan_tag integer,
    parent_interface character varying(100),
    stats jsonb NOT NULL,
    last_synced_at timestamp with time zone NOT NULL,
    raw_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_nat_rules (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    external_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(500),
    nat_type character varying(20) NOT NULL,
    source jsonb NOT NULL,
    destination jsonb NOT NULL,
    translation jsonb NOT NULL,
    is_enabled boolean NOT NULL,
    last_synced_at timestamp with time zone NOT NULL,
    raw_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_imported_vpn_tunnels (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    external_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(500),
    vpn_type character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    local_config jsonb NOT NULL,
    remote_config jsonb NOT NULL,
    stats jsonb NOT NULL,
    last_synced_at timestamp with time zone NOT NULL,
    raw_data jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_site_role_assignments (
    role_map_id uuid NOT NULL,
    gateway_id uuid,
    controller_id uuid,
    device_type character varying(20) NOT NULL,
    role character varying(20) NOT NULL,
    priority integer NOT NULL,
    capabilities jsonb NOT NULL,
    suppress_dhcp boolean NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_gw_site_role_assignments_ck_role_assign_one_device CHECK ((((gateway_id IS NOT NULL) AND (controller_id IS NULL)) OR ((gateway_id IS NULL) AND (controller_id IS NOT NULL))))
);

CREATE TABLE gateway.gw_site_role_maps (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    is_active boolean NOT NULL,
    last_reconciled_at timestamp with time zone,
    authority_map jsonb NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_suppression_rules (
    organization_id uuid NOT NULL,
    site_id uuid NOT NULL,
    device_id uuid NOT NULL,
    resource_type character varying(50) NOT NULL,
    scope character varying(100) NOT NULL,
    reason character varying(255) NOT NULL,
    suppression_action character varying(50) NOT NULL,
    is_active boolean NOT NULL,
    applied_at timestamp with time zone,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE gateway.gw_vlan_templates (
    organization_id uuid NOT NULL,
    name character varying(64) NOT NULL,
    description character varying(255),
    vlan_id integer NOT NULL,
    subnet_template character varying(18) NOT NULL,
    gateway_ip_template character varying(45) DEFAULT ''::character varying NOT NULL,
    purpose character varying(20) NOT NULL,
    dhcp_enabled boolean NOT NULL,
    dhcp_options jsonb NOT NULL,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE hypervisor.proxmox_nodes (
    id uuid NOT NULL,
    controller_id uuid NOT NULL,
    site_id uuid,
    node_name character varying(255) NOT NULL,
    status character varying(50) NOT NULL,
    ip_address character varying(45),
    cpu_count integer NOT NULL,
    cpu_usage double precision NOT NULL,
    memory_total bigint NOT NULL,
    memory_used bigint NOT NULL,
    storage_total bigint NOT NULL,
    storage_used bigint NOT NULL,
    pve_version character varying(50) NOT NULL,
    kernel_version character varying(100) NOT NULL,
    cpu_model character varying(255) NOT NULL,
    uptime bigint NOT NULL,
    subscription_level character varying(50) NOT NULL,
    extra jsonb,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE hypervisor.virtual_machines (
    id uuid NOT NULL,
    node_id uuid NOT NULL,
    site_id uuid,
    vmid integer NOT NULL,
    name character varying(255) NOT NULL,
    vm_type character varying(10) NOT NULL,
    status character varying(50) NOT NULL,
    template boolean NOT NULL,
    cpu_cores integer NOT NULL,
    cpu_usage double precision NOT NULL,
    memory_mb integer NOT NULL,
    memory_used_mb integer NOT NULL,
    disk_gb double precision NOT NULL,
    disk_used_gb double precision NOT NULL,
    ip_address character varying(45),
    net_in bigint NOT NULL,
    net_out bigint NOT NULL,
    os_type character varying(100),
    tags text NOT NULL,
    uptime bigint NOT NULL,
    ha_state character varying(50),
    lock character varying(50),
    description text,
    extra jsonb,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE network.client_roaming_events (
    organization_id uuid NOT NULL,
    client_mac character varying(17) NOT NULL,
    from_device_id uuid,
    to_device_id uuid,
    from_bssid character varying(17),
    to_bssid character varying(17),
    from_rssi integer,
    to_rssi integer,
    roam_time_ms integer,
    roam_type character varying(30),
    "timestamp" timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE network.dot1x_auth_events (
    organization_id uuid NOT NULL,
    controller_id uuid NOT NULL,
    device_id uuid,
    radius_profile_id uuid,
    client_mac character varying(17) NOT NULL,
    username character varying(255),
    auth_result character varying(20) NOT NULL,
    reject_reason character varying(255),
    assigned_vlan integer,
    "timestamp" timestamp with time zone NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE network.dot1x_port_configs (
    port_profile_id uuid,
    wifi_network_id uuid,
    controller_id uuid NOT NULL,
    radius_profile_id uuid NOT NULL,
    auth_mode character varying(30) NOT NULL,
    guest_vlan_id integer,
    dynamic_vlan boolean NOT NULL,
    reauthentication_interval integer NOT NULL,
    pushed_at timestamp with time zone,
    push_status character varying(20) NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE network.link_aggregation_groups (
    device_id uuid NOT NULL,
    external_id character varying(255),
    name character varying(255) NOT NULL,
    lag_id integer NOT NULL,
    mode character varying(20) NOT NULL,
    member_ports integer[] NOT NULL,
    lacp_mode character varying(20) NOT NULL,
    lacp_timeout character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    active_ports integer NOT NULL,
    aggregate_speed integer NOT NULL,
    lag_metadata jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE network.port_profiles (
    controller_id uuid,
    site_id uuid,
    external_id character varying(255),
    name character varying(255) NOT NULL,
    description text,
    profile_type character varying(50) NOT NULL,
    native_vlan integer,
    tagged_vlans integer[],
    voice_vlan integer,
    poe_enabled boolean,
    stp_enabled boolean,
    ports_using integer NOT NULL,
    profile_metadata jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE network.radius_server_profiles (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    host character varying(255) NOT NULL,
    port integer NOT NULL,
    shared_secret_encrypted text NOT NULL,
    auth_protocol character varying(20) NOT NULL,
    timeout_seconds integer NOT NULL,
    retry_count integer NOT NULL,
    accounting_enabled boolean NOT NULL,
    accounting_port integer NOT NULL,
    last_health_check timestamp with time zone,
    is_healthy boolean NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE network.topology_layouts (
    site_id uuid NOT NULL,
    user_id uuid,
    name character varying(255) NOT NULL,
    positions jsonb NOT NULL,
    zoom double precision NOT NULL,
    center_x double precision NOT NULL,
    center_y double precision NOT NULL,
    filters jsonb,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE network.topology_links (
    source_device_id uuid NOT NULL,
    target_device_id uuid NOT NULL,
    source_port character varying(50),
    target_port character varying(50),
    speed character varying(20),
    status character varying(20) NOT NULL,
    link_type character varying(30) NOT NULL,
    discovered_via character varying(30),
    link_metadata jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE network.vlans (
    controller_id uuid,
    site_id uuid,
    external_id character varying(255),
    name character varying(255) NOT NULL,
    vlan_id integer NOT NULL,
    description text,
    purpose character varying(50),
    gateway character varying(45),
    subnet character varying(45),
    subnet_mask character varying(45),
    cidr character varying(49),
    dhcp_enabled boolean NOT NULL,
    dhcp_start character varying(45),
    dhcp_end character varying(45),
    domain character varying(255),
    is_active boolean NOT NULL,
    network_metadata jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE network.wifi_networks (
    controller_id uuid,
    site_id uuid,
    external_id character varying(255),
    ssid character varying(64) NOT NULL,
    security character varying(50) NOT NULL,
    password_hash character varying(255),
    band character varying(20) NOT NULL,
    vlan_id integer,
    enabled boolean NOT NULL,
    hidden boolean NOT NULL,
    client_isolation boolean NOT NULL,
    band_steering boolean NOT NULL,
    fast_roaming boolean NOT NULL,
    rate_limit_enabled boolean NOT NULL,
    rate_limit_up integer,
    rate_limit_down integer,
    roaming_protocol character varying(30),
    minimum_rssi integer,
    wifi_metadata jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);

CREATE TABLE voip.call_logs (
    pbx_id uuid,
    unique_id character varying(100),
    caller_number character varying(50) NOT NULL,
    caller_name character varying(100),
    callee_number character varying(50) NOT NULL,
    callee_name character varying(100),
    direction character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    start_time timestamp with time zone NOT NULL,
    answer_time timestamp with time zone,
    end_time timestamp with time zone,
    duration_seconds integer NOT NULL,
    ring_duration_seconds integer NOT NULL,
    recording_path character varying(500),
    metadata_json jsonb NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE voip.config_templates (
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    vendor character varying(100) NOT NULL,
    model_pattern character varying(100),
    is_default boolean NOT NULL,
    sip_settings jsonb NOT NULL,
    network_settings jsonb NOT NULL,
    provisioning_settings jsonb NOT NULL,
    feature_settings jsonb NOT NULL,
    line_key_settings jsonb NOT NULL,
    raw_overrides jsonb NOT NULL,
    firmware_version character varying(50),
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE voip.discovery_scans (
    site_id uuid NOT NULL,
    triggered_by uuid,
    scan_type character varying(30) NOT NULL,
    subnet character varying(18),
    port_range character varying(50),
    status character varying(20) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    devices_found integer NOT NULL,
    new_devices integer NOT NULL,
    updated_devices integer NOT NULL,
    duration_seconds double precision NOT NULL,
    results jsonb NOT NULL,
    metadata_json jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE voip.extensions (
    pbx_id uuid NOT NULL,
    user_id uuid,
    extension_number character varying(20) NOT NULL,
    display_name character varying(255) NOT NULL,
    caller_id_name character varying(100),
    caller_id_number character varying(20),
    voicemail_enabled boolean NOT NULL,
    voicemail_pin character varying(20),
    is_active boolean NOT NULL,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE voip.firmware_tracks (
    site_id uuid NOT NULL,
    vendor character varying(100) NOT NULL,
    model character varying(100) NOT NULL,
    version character varying(50) NOT NULL,
    release_date timestamp with time zone,
    changelog text,
    download_url character varying(500),
    file_checksum character varying(64),
    file_size_bytes integer,
    is_stable boolean NOT NULL,
    is_recommended boolean NOT NULL,
    metadata_json jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE voip.pbx (
    site_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    pbx_type character varying(50) NOT NULL,
    ip_address character varying(45) NOT NULL,
    api_port integer NOT NULL,
    sip_port integer NOT NULL,
    is_active boolean NOT NULL,
    last_seen timestamp with time zone,
    settings jsonb NOT NULL,
    ami_secret_enc text,
    ari_password_enc text,
    web_password_enc text,
    api_client_id text,
    api_client_secret_enc text,
    tls_verify_disabled_acknowledged boolean DEFAULT false NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE voip.phones (
    site_id uuid NOT NULL,
    pbx_id uuid,
    extension_id uuid,
    controller_id uuid,
    config_template_id uuid,
    name character varying(255) NOT NULL,
    description text,
    ip_address character varying(45),
    mac_address character varying(17),
    vendor character varying(100),
    model character varying(100),
    firmware_version character varying(50),
    serial_number character varying(100),
    status character varying(20) NOT NULL,
    last_seen timestamp with time zone,
    lifecycle_state character varying(30) NOT NULL,
    discovery_method character varying(30),
    discovered_at timestamp with time zone,
    onboarded_at timestamp with time zone,
    provision_status character varying(20),
    last_provisioned_at timestamp with time zone,
    provisioning_url character varying(500),
    config_checksum character varying(64),
    firmware_target character varying(50),
    firmware_upgrade_scheduled timestamp with time zone,
    uptime_seconds integer,
    sip_registered boolean NOT NULL,
    sip_server character varying(255),
    last_reboot timestamp with time zone,
    cpu_usage double precision,
    memory_usage double precision,
    subnet character varying(18),
    vlan_id integer,
    lldp_switch_port character varying(100),
    settings jsonb NOT NULL,
    location character varying(255),
    tags jsonb NOT NULL,
    sip_password_enc text,
    admin_password_enc text,
    xml_password_enc text,
    use_ssl boolean DEFAULT true NOT NULL,
    acknowledge_plaintext boolean DEFAULT false NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE voip.ring_groups (
    pbx_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    group_number character varying(20) NOT NULL,
    ring_strategy character varying(20) NOT NULL,
    ring_time integer NOT NULL,
    members jsonb NOT NULL,
    is_active boolean NOT NULL,
    settings jsonb NOT NULL,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE voip.voicemail_messages (
    pbx_id uuid,
    extension_id uuid,
    extension_number character varying(20) NOT NULL,
    caller_id character varying(100) NOT NULL,
    caller_name character varying(100),
    duration integer NOT NULL,
    message_date timestamp with time zone NOT NULL,
    is_read boolean NOT NULL,
    is_urgent boolean NOT NULL,
    transcription text,
    file_path character varying(500),
    folder character varying(20) NOT NULL,
    id uuid NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE vpn.site_to_site_tunnels (
    organization_id uuid NOT NULL,
    template_id uuid,
    site_a_id uuid NOT NULL,
    site_b_id uuid NOT NULL,
    gateway_a_device_id uuid,
    gateway_b_device_id uuid,
    status character varying(30) NOT NULL,
    config_a jsonb NOT NULL,
    config_b jsonb NOT NULL,
    provisioned_at timestamp with time zone,
    last_health_check timestamp with time zone,
    error_message text,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE vpn.site_vpn_configs (
    site_id uuid NOT NULL,
    vpn_type character varying(20) NOT NULL,
    enabled boolean NOT NULL,
    auto_connect boolean NOT NULL,
    is_primary boolean NOT NULL,
    priority integer NOT NULL,
    controller_id uuid,
    vpn_source character varying(20) NOT NULL,
    brain_vpn_server_id character varying(255),
    last_config_sync timestamp with time zone,
    tailscale_node character varying(255),
    tailscale_hostname character varying(255),
    tailscale_tags jsonb,
    wireguard_interface character varying(50),
    wireguard_peer_public_key text,
    wireguard_endpoint character varying(255),
    wireguard_allowed_ips jsonb,
    vpn_endpoint character varying(255),
    vpn_port integer,
    openvpn_config_path character varying(500),
    openvpn_protocol character varying(10),
    openvpn_config_content text,
    openvpn_mode character varying(10),
    zerotier_network_id character varying(16),
    zerotier_node_id character varying(10),
    netbird_peer_id character varying(255),
    netbird_group character varying(255),
    health_check_ip character varying(45),
    health_check_interval integer NOT NULL,
    latency_threshold_ms integer,
    remote_subnets jsonb,
    local_subnets jsonb,
    status character varying(20) NOT NULL,
    last_health_check timestamp with time zone,
    cert_metadata jsonb,
    cert_expires_at timestamp with time zone,
    organization_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE vpn.vpn_connections (
    name character varying(255) NOT NULL,
    vpn_type character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    endpoint character varying(255),
    port integer,
    local_ip character varying(45),
    remote_ip character varying(45),
    allowed_ips jsonb,
    dns_servers jsonb,
    connected_at timestamp with time zone,
    last_handshake timestamp with time zone,
    rx_bytes integer NOT NULL,
    tx_bytes integer NOT NULL,
    latency_ms double precision,
    extra_data jsonb,
    openvpn_config_path character varying(500),
    openvpn_protocol character varying(10),
    openvpn_config_content text,
    wireguard_config_content text,
    netbird_setup_key text,
    netbird_management_url character varying(500),
    organization_id uuid,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE vpn.vpn_events (
    organization_id uuid NOT NULL,
    site_id uuid,
    connection_id uuid,
    tunnel_id uuid,
    event_type character varying(50) NOT NULL,
    severity character varying(10) NOT NULL,
    title character varying(255) NOT NULL,
    details jsonb NOT NULL,
    source character varying(50),
    actor_id uuid,
    created_at timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE vpn.vpn_reconnect_state (
    connection_id uuid NOT NULL,
    site_vpn_config_id uuid,
    attempt_count integer NOT NULL,
    max_attempts integer NOT NULL,
    next_retry_at timestamp with time zone,
    last_error text,
    backoff_seconds integer NOT NULL,
    state character varying(20) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    id uuid NOT NULL
);

CREATE TABLE vpn.vpn_tunnel_templates (
    organization_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    vpn_type character varying(20) NOT NULL,
    topology character varying(20) NOT NULL,
    config_template jsonb NOT NULL,
    default_subnets jsonb NOT NULL,
    mtu integer,
    mss_clamp integer,
    id uuid NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY access.cardholders
    ADD CONSTRAINT pk_cardholders PRIMARY KEY (id);

ALTER TABLE ONLY access.controllers
    ADD CONSTRAINT pk_controllers PRIMARY KEY (id);

ALTER TABLE ONLY access.credentials
    ADD CONSTRAINT pk_credentials PRIMARY KEY (id);

ALTER TABLE ONLY access.doors
    ADD CONSTRAINT pk_doors PRIMARY KEY (id);

ALTER TABLE ONLY access.events
    ADD CONSTRAINT pk_events PRIMARY KEY (id);

ALTER TABLE ONLY access.readers
    ADD CONSTRAINT pk_readers PRIMARY KEY (id);

ALTER TABLE ONLY access.schedules
    ADD CONSTRAINT pk_schedules PRIMARY KEY (id);

ALTER TABLE ONLY agents.agent_releases
    ADD CONSTRAINT pk_agent_releases PRIMARY KEY (id);

ALTER TABLE ONLY agents.agent_schedule_runs
    ADD CONSTRAINT pk_agent_schedule_runs PRIMARY KEY (id);

ALTER TABLE ONLY agents.agent_schedules
    ADD CONSTRAINT pk_agent_schedules PRIMARY KEY (id);

ALTER TABLE ONLY agents.agent_tasks
    ADD CONSTRAINT pk_agent_tasks PRIMARY KEY (id);

ALTER TABLE ONLY agents.remote_agents
    ADD CONSTRAINT pk_remote_agents PRIMARY KEY (id);

ALTER TABLE ONLY ai.ai_conversations
    ADD CONSTRAINT pk_ai_conversations PRIMARY KEY (id);

ALTER TABLE ONLY ai.ai_messages
    ADD CONSTRAINT pk_ai_messages PRIMARY KEY (id);

ALTER TABLE ONLY ai.ai_provider_configs
    ADD CONSTRAINT pk_ai_provider_configs PRIMARY KEY (id);

ALTER TABLE ONLY ai.llm_call_logs
    ADD CONSTRAINT pk_llm_call_logs PRIMARY KEY (id);

ALTER TABLE ONLY ai.org_llm_policies
    ADD CONSTRAINT pk_org_llm_policies PRIMARY KEY (id);

ALTER TABLE ONLY analytics.alerts
    ADD CONSTRAINT pk_alerts PRIMARY KEY (id);

ALTER TABLE ONLY analytics.dashboard_widgets
    ADD CONSTRAINT pk_dashboard_widgets PRIMARY KEY (id);

ALTER TABLE ONLY analytics.metric_definitions
    ADD CONSTRAINT pk_metric_definitions PRIMARY KEY (id);

ALTER TABLE ONLY analytics.sla_report_schedules
    ADD CONSTRAINT pk_sla_report_schedules PRIMARY KEY (id);

ALTER TABLE ONLY analytics.sla_reports
    ADD CONSTRAINT pk_sla_reports PRIMARY KEY (id);

ALTER TABLE ONLY analytics.metric_definitions
    ADD CONSTRAINT uq_metric_definitions_name UNIQUE (name);

ALTER TABLE ONLY audit.audit_logs
    ADD CONSTRAINT pk_audit_logs PRIMARY KEY (id);

ALTER TABLE ONLY audit.failed_logins
    ADD CONSTRAINT pk_failed_logins PRIMARY KEY (id);

ALTER TABLE ONLY audit.ip_blocks
    ADD CONSTRAINT pk_ip_blocks PRIMARY KEY (id);

ALTER TABLE ONLY audit.security_anomalies
    ADD CONSTRAINT pk_security_anomalies PRIMARY KEY (id);

ALTER TABLE ONLY audit.security_events
    ADD CONSTRAINT pk_security_events PRIMARY KEY (id);

ALTER TABLE ONLY audit.ip_blocks
    ADD CONSTRAINT uq_ip_blocks_ip UNIQUE (ip_address);

ALTER TABLE ONLY backup.backup_schedules
    ADD CONSTRAINT pk_backup_schedules PRIMARY KEY (id);

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT pk_backups PRIMARY KEY (id);

ALTER TABLE ONLY backup.restore_jobs
    ADD CONSTRAINT pk_restore_jobs PRIMARY KEY (id);

ALTER TABLE ONLY backup.storage_locations
    ADD CONSTRAINT pk_storage_locations PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT pk_camera_access_grants PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_events
    ADD CONSTRAINT pk_camera_events PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_group_members
    ADD CONSTRAINT pk_camera_group_members PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_groups
    ADD CONSTRAINT pk_camera_groups PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_health_snapshots
    ADD CONSTRAINT pk_camera_health_snapshots PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_reports
    ADD CONSTRAINT pk_camera_reports PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_views
    ADD CONSTRAINT pk_camera_views PRIMARY KEY (id);

ALTER TABLE ONLY cameras.cameras
    ADD CONSTRAINT pk_cameras PRIMARY KEY (id);

ALTER TABLE ONLY cameras.evidence_archives
    ADD CONSTRAINT pk_evidence_archives PRIMARY KEY (id);

ALTER TABLE ONLY cameras.nvrs
    ADD CONSTRAINT pk_nvrs PRIMARY KEY (id);

ALTER TABLE ONLY cameras.push_subscriptions
    ADD CONSTRAINT pk_push_subscriptions PRIMARY KEY (id);

ALTER TABLE ONLY cameras.recording_schedule_templates
    ADD CONSTRAINT pk_recording_schedule_templates PRIMARY KEY (id);

ALTER TABLE ONLY cameras.recordings
    ADD CONSTRAINT pk_recordings PRIMARY KEY (id);

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT uq_camera_access_user_camera UNIQUE (user_id, camera_id);

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT uq_camera_access_user_group UNIQUE (user_id, group_id);

ALTER TABLE ONLY cameras.camera_group_members
    ADD CONSTRAINT uq_group_camera UNIQUE (group_id, camera_id);

ALTER TABLE ONLY cameras.push_subscriptions
    ADD CONSTRAINT uq_push_subscriptions_endpoint UNIQUE (endpoint);

ALTER TABLE ONLY collector.app_classification_rules
    ADD CONSTRAINT pk_app_classification_rules PRIMARY KEY (id);

ALTER TABLE ONLY collector.collector_configs
    ADD CONSTRAINT pk_collector_configs PRIMARY KEY (id);

ALTER TABLE ONLY collector.collector_logs
    ADD CONSTRAINT pk_collector_logs PRIMARY KEY (id);

ALTER TABLE ONLY collector.flow_records
    ADD CONSTRAINT pk_flow_records PRIMARY KEY (id);

ALTER TABLE ONLY collector.collector_configs
    ADD CONSTRAINT uq_collector_configs_organization_id UNIQUE (organization_id);

ALTER TABLE ONLY core.adapter_pending_changes
    ADD CONSTRAINT pk_adapter_pending_changes PRIMARY KEY (id);

ALTER TABLE ONLY core.api_keys
    ADD CONSTRAINT pk_api_keys PRIMARY KEY (id);

ALTER TABLE ONLY core.automation_executions
    ADD CONSTRAINT pk_automation_executions PRIMARY KEY (id);

ALTER TABLE ONLY core.automation_rules
    ADD CONSTRAINT pk_automation_rules PRIMARY KEY (id);

ALTER TABLE ONLY core.config_templates
    ADD CONSTRAINT pk_config_templates PRIMARY KEY (id);

ALTER TABLE ONLY core.controllers
    ADD CONSTRAINT pk_controllers PRIMARY KEY (id);

ALTER TABLE ONLY core.credentials
    ADD CONSTRAINT pk_credentials PRIMARY KEY (id);

ALTER TABLE ONLY core.custom_roles
    ADD CONSTRAINT pk_custom_roles PRIMARY KEY (id);

ALTER TABLE ONLY core.device_firmware_status
    ADD CONSTRAINT pk_device_firmware_status PRIMARY KEY (id);

ALTER TABLE ONLY core.export_jobs
    ADD CONSTRAINT pk_export_jobs PRIMARY KEY (id);

ALTER TABLE ONLY core.firmware_images
    ADD CONSTRAINT pk_firmware_images PRIMARY KEY (id);

ALTER TABLE ONLY core.firmware_schedules
    ADD CONSTRAINT pk_firmware_schedules PRIMARY KEY (id);

ALTER TABLE ONLY core.firmware_upgrade_jobs
    ADD CONSTRAINT pk_firmware_upgrade_jobs PRIMARY KEY (id);

ALTER TABLE ONLY core.import_jobs
    ADD CONSTRAINT pk_import_jobs PRIMARY KEY (id);

ALTER TABLE ONLY core.in_app_notifications
    ADD CONSTRAINT pk_in_app_notifications PRIMARY KEY (id);

ALTER TABLE ONLY core.installed_plugins
    ADD CONSTRAINT pk_installed_plugins PRIMARY KEY (id);

ALTER TABLE ONLY core.integrations
    ADD CONSTRAINT pk_integrations PRIMARY KEY (id);

ALTER TABLE ONLY core.marketplace_plugin_versions
    ADD CONSTRAINT pk_marketplace_plugin_versions PRIMARY KEY (id);

ALTER TABLE ONLY core.marketplace_plugins
    ADD CONSTRAINT pk_marketplace_plugins PRIMARY KEY (id);

ALTER TABLE ONLY core.module_events
    ADD CONSTRAINT pk_module_events PRIMARY KEY (id);

ALTER TABLE ONLY core.module_feature_flags
    ADD CONSTRAINT pk_module_feature_flags PRIMARY KEY (id);

ALTER TABLE ONLY core.notification_deliveries
    ADD CONSTRAINT pk_notification_deliveries PRIMARY KEY (id);

ALTER TABLE ONLY core.notification_preferences
    ADD CONSTRAINT pk_notification_preferences PRIMARY KEY (id);

ALTER TABLE ONLY core.notification_providers
    ADD CONSTRAINT pk_notification_providers PRIMARY KEY (id);

ALTER TABLE ONLY core.oauth2_apps
    ADD CONSTRAINT pk_oauth2_apps PRIMARY KEY (id);

ALTER TABLE ONLY core.oauth2_authorization_codes
    ADD CONSTRAINT pk_oauth2_authorization_codes PRIMARY KEY (id);

ALTER TABLE ONLY core.oauth2_tokens
    ADD CONSTRAINT pk_oauth2_tokens PRIMARY KEY (id);

ALTER TABLE ONLY core.organization_modules
    ADD CONSTRAINT pk_organization_modules PRIMARY KEY (id);

ALTER TABLE ONLY core.organizations
    ADD CONSTRAINT pk_organizations PRIMARY KEY (id);

ALTER TABLE ONLY core.plugin_organization_states
    ADD CONSTRAINT pk_plugin_organization_states PRIMARY KEY (id);

ALTER TABLE ONLY core.plugin_reviews
    ADD CONSTRAINT pk_plugin_reviews PRIMARY KEY (id);

ALTER TABLE ONLY core.plugin_settings
    ADD CONSTRAINT pk_plugin_settings PRIMARY KEY (id);

ALTER TABLE ONLY core.site_groups
    ADD CONSTRAINT pk_site_groups PRIMARY KEY (id);

ALTER TABLE ONLY core.sites
    ADD CONSTRAINT pk_sites PRIMARY KEY (id);

ALTER TABLE ONLY core.sla_breaches
    ADD CONSTRAINT pk_sla_breaches PRIMARY KEY (id);

ALTER TABLE ONLY core.sla_policies
    ADD CONSTRAINT pk_sla_policies PRIMARY KEY (id);

ALTER TABLE ONLY core.sla_snapshots
    ADD CONSTRAINT pk_sla_snapshots PRIMARY KEY (id);

ALTER TABLE ONLY core.sso_providers
    ADD CONSTRAINT pk_sso_providers PRIMARY KEY (id);

ALTER TABLE ONLY core.sso_sessions
    ADD CONSTRAINT pk_sso_sessions PRIMARY KEY (id);

ALTER TABLE ONLY core.user_sessions
    ADD CONSTRAINT pk_user_sessions PRIMARY KEY (id);

ALTER TABLE ONLY core.user_site_access
    ADD CONSTRAINT pk_user_site_access PRIMARY KEY (id);

ALTER TABLE ONLY core.users
    ADD CONSTRAINT pk_users PRIMARY KEY (id);

ALTER TABLE ONLY core.webhook_dead_letters
    ADD CONSTRAINT pk_webhook_dead_letters PRIMARY KEY (id);

ALTER TABLE ONLY core.webhook_deliveries
    ADD CONSTRAINT pk_webhook_deliveries PRIMARY KEY (id);

ALTER TABLE ONLY core.webhooks
    ADD CONSTRAINT pk_webhooks PRIMARY KEY (id);

ALTER TABLE ONLY core.integrations
    ADD CONSTRAINT uq_integrations_webhook_id UNIQUE (webhook_id);

ALTER TABLE ONLY core.notification_preferences
    ADD CONSTRAINT uq_notification_preferences_user_id UNIQUE (user_id);

ALTER TABLE ONLY core.oauth2_apps
    ADD CONSTRAINT uq_oauth2_apps_client_id UNIQUE (client_id);

ALTER TABLE ONLY core.oauth2_authorization_codes
    ADD CONSTRAINT uq_oauth2_authorization_codes_code UNIQUE (code);

ALTER TABLE ONLY core.organization_modules
    ADD CONSTRAINT uq_org_module UNIQUE (organization_id, module_id);

ALTER TABLE ONLY core.module_feature_flags
    ADD CONSTRAINT uq_org_module_feature UNIQUE (organization_id, module_id, feature_key);

ALTER TABLE ONLY core.plugin_reviews
    ADD CONSTRAINT uq_plugin_review_user_plugin UNIQUE (marketplace_plugin_id, user_id);

ALTER TABLE ONLY core.site_groups
    ADD CONSTRAINT uq_site_groups_org_name UNIQUE (organization_id, name);

ALTER TABLE ONLY core.sso_providers
    ADD CONSTRAINT uq_sso_providers_slug UNIQUE (slug);

ALTER TABLE ONLY core.sso_sessions
    ADD CONSTRAINT uq_sso_sessions_state UNIQUE (state);

ALTER TABLE ONLY devices.adoption_jobs
    ADD CONSTRAINT pk_adoption_jobs PRIMARY KEY (id);

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT pk_auto_adoption_rules PRIMARY KEY (id);

ALTER TABLE ONLY devices.bulk_operations
    ADD CONSTRAINT pk_bulk_operations PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_clients
    ADD CONSTRAINT pk_device_clients PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_configs
    ADD CONSTRAINT pk_device_configs PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_group_members
    ADD CONSTRAINT pk_device_group_members PRIMARY KEY (device_id, group_id);

ALTER TABLE ONLY devices.device_groups
    ADD CONSTRAINT pk_device_groups PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_health
    ADD CONSTRAINT pk_device_health PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_lifecycle_log
    ADD CONSTRAINT pk_device_lifecycle_log PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_ports
    ADD CONSTRAINT pk_device_ports PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_sync_locks
    ADD CONSTRAINT pk_device_sync_locks PRIMARY KEY (lock_key);

ALTER TABLE ONLY devices.device_tags
    ADD CONSTRAINT pk_device_tags PRIMARY KEY (device_id, tag);

ALTER TABLE ONLY devices.devices
    ADD CONSTRAINT pk_devices PRIMARY KEY (id);

ALTER TABLE ONLY devices.discovered_hosts
    ADD CONSTRAINT pk_discovered_hosts PRIMARY KEY (id);

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT pk_mac_pre_registrations PRIMARY KEY (id);

ALTER TABLE ONLY devices.poe_schedules
    ADD CONSTRAINT pk_poe_schedules PRIMARY KEY (id);

ALTER TABLE ONLY devices.provisioning_profiles
    ADD CONSTRAINT pk_provisioning_profiles PRIMARY KEY (id);

ALTER TABLE ONLY devices.topology_edges
    ADD CONSTRAINT pk_topology_edges PRIMARY KEY (id);

ALTER TABLE ONLY devices.device_configs
    ADD CONSTRAINT uq_device_configs_device UNIQUE (device_id);

ALTER TABLE ONLY devices.device_groups
    ADD CONSTRAINT uq_device_groups_site_name UNIQUE (site_id, name);

ALTER TABLE ONLY devices.device_health
    ADD CONSTRAINT uq_device_health_device_id UNIQUE (device_id);

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT uq_mac_preregistrations_mac_org UNIQUE (mac_address, organization_id);

ALTER TABLE ONLY enterprise.auto_backup_policies
    ADD CONSTRAINT pk_auto_backup_policies PRIMARY KEY (id);

ALTER TABLE ONLY enterprise.config_versions
    ADD CONSTRAINT pk_config_versions PRIMARY KEY (id);

ALTER TABLE ONLY enterprise.health_daily_snapshots
    ADD CONSTRAINT pk_health_daily_snapshots PRIMARY KEY (id);

ALTER TABLE ONLY enterprise.auto_backup_policies
    ADD CONSTRAINT uq_auto_backup_policies_org UNIQUE (organization_id);

ALTER TABLE ONLY enterprise.config_versions
    ADD CONSTRAINT uq_config_versions_device_version UNIQUE (device_id, version_number);

ALTER TABLE ONLY enterprise.health_daily_snapshots
    ADD CONSTRAINT uq_health_daily_org_site_date UNIQUE (organization_id, site_id, snapshot_date);

ALTER TABLE ONLY events.alert_rules
    ADD CONSTRAINT pk_alert_rules PRIMARY KEY (id);

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT pk_alerts PRIMARY KEY (id);

ALTER TABLE ONLY events.correlation_rules
    ADD CONSTRAINT pk_correlation_rules PRIMARY KEY (id);

ALTER TABLE ONLY events.event_subscriptions
    ADD CONSTRAINT pk_event_subscriptions PRIMARY KEY (id);

ALTER TABLE ONLY events.incident_events
    ADD CONSTRAINT pk_incident_events PRIMARY KEY (id);

ALTER TABLE ONLY events.incidents
    ADD CONSTRAINT pk_incidents PRIMARY KEY (id);

ALTER TABLE ONLY events.incident_events
    ADD CONSTRAINT uq_incident_event UNIQUE (incident_id, event_id);

ALTER TABLE ONLY fabric.connection_runs
    ADD CONSTRAINT pk_connection_runs PRIMARY KEY (id);

ALTER TABLE ONLY fabric.connections
    ADD CONSTRAINT pk_connections PRIMARY KEY (id);

ALTER TABLE ONLY firewall.devices
    ADD CONSTRAINT pk_devices PRIMARY KEY (id);

ALTER TABLE ONLY firewall.gateway_connections
    ADD CONSTRAINT pk_gateway_connections PRIMARY KEY (id);

ALTER TABLE ONLY firewall.gateway_sync_logs
    ADD CONSTRAINT pk_gateway_sync_logs PRIMARY KEY (id);

ALTER TABLE ONLY firewall.ids_alerts
    ADD CONSTRAINT pk_ids_alerts PRIMARY KEY (id);

ALTER TABLE ONLY firewall.logs
    ADD CONSTRAINT pk_logs PRIMARY KEY (id);

ALTER TABLE ONLY firewall.nat_rules
    ADD CONSTRAINT pk_nat_rules PRIMARY KEY (id);

ALTER TABLE ONLY firewall.rules
    ADD CONSTRAINT pk_rules PRIMARY KEY (id);

ALTER TABLE ONLY firewall.vpn_tunnels
    ADD CONSTRAINT pk_vpn_tunnels PRIMARY KEY (id);

ALTER TABLE ONLY firewall.gateway_connections
    ADD CONSTRAINT uq_gateway_connections_org_name UNIQUE (org_id, name, deleted_at);

ALTER TABLE ONLY gateway.gw_canonical_address_groups
    ADD CONSTRAINT pk_gw_canonical_address_groups PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_canonical_dhcp_reservations
    ADD CONSTRAINT pk_gw_canonical_dhcp_reservations PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_canonical_dhcp_scopes
    ADD CONSTRAINT pk_gw_canonical_dhcp_scopes PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_canonical_dns_records
    ADD CONSTRAINT pk_gw_canonical_dns_records PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT pk_gw_canonical_vlans PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_distribution_locks
    ADD CONSTRAINT pk_gw_distribution_locks PRIMARY KEY (site_id);

ALTER TABLE ONLY gateway.gw_distribution_records
    ADD CONSTRAINT pk_gw_distribution_records PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_drift_events
    ADD CONSTRAINT pk_gw_drift_events PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_import_sessions
    ADD CONSTRAINT pk_gw_import_sessions PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_dhcp_leases
    ADD CONSTRAINT pk_gw_imported_dhcp_leases PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_firewall_rules
    ADD CONSTRAINT pk_gw_imported_firewall_rules PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_ids_events
    ADD CONSTRAINT pk_gw_imported_ids_events PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_interfaces
    ADD CONSTRAINT pk_gw_imported_interfaces PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_nat_rules
    ADD CONSTRAINT pk_gw_imported_nat_rules PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_imported_vpn_tunnels
    ADD CONSTRAINT pk_gw_imported_vpn_tunnels PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_site_role_assignments
    ADD CONSTRAINT pk_gw_site_role_assignments PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_site_role_maps
    ADD CONSTRAINT pk_gw_site_role_maps PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_suppression_rules
    ADD CONSTRAINT pk_gw_suppression_rules PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_vlan_templates
    ADD CONSTRAINT pk_gw_vlan_templates PRIMARY KEY (id);

ALTER TABLE ONLY gateway.gw_site_role_maps
    ADD CONSTRAINT uq_gw_site_role_maps_site_id UNIQUE (site_id);

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT uq_gw_vlan_per_site UNIQUE (site_id, vlan_id);

ALTER TABLE ONLY hypervisor.proxmox_nodes
    ADD CONSTRAINT pk_proxmox_nodes PRIMARY KEY (id);

ALTER TABLE ONLY hypervisor.virtual_machines
    ADD CONSTRAINT pk_virtual_machines PRIMARY KEY (id);

ALTER TABLE ONLY network.client_roaming_events
    ADD CONSTRAINT pk_client_roaming_events PRIMARY KEY (id);

ALTER TABLE ONLY network.dot1x_auth_events
    ADD CONSTRAINT pk_dot1x_auth_events PRIMARY KEY (id);

ALTER TABLE ONLY network.dot1x_port_configs
    ADD CONSTRAINT pk_dot1x_port_configs PRIMARY KEY (id);

ALTER TABLE ONLY network.link_aggregation_groups
    ADD CONSTRAINT pk_link_aggregation_groups PRIMARY KEY (id);

ALTER TABLE ONLY network.port_profiles
    ADD CONSTRAINT pk_port_profiles PRIMARY KEY (id);

ALTER TABLE ONLY network.radius_server_profiles
    ADD CONSTRAINT pk_radius_server_profiles PRIMARY KEY (id);

ALTER TABLE ONLY network.topology_layouts
    ADD CONSTRAINT pk_topology_layouts PRIMARY KEY (id);

ALTER TABLE ONLY network.topology_links
    ADD CONSTRAINT pk_topology_links PRIMARY KEY (id);

ALTER TABLE ONLY network.vlans
    ADD CONSTRAINT pk_vlans PRIMARY KEY (id);

ALTER TABLE ONLY network.wifi_networks
    ADD CONSTRAINT pk_wifi_networks PRIMARY KEY (id);

ALTER TABLE ONLY network.topology_layouts
    ADD CONSTRAINT uq_topology_layout_site_user UNIQUE (site_id, user_id);

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);

ALTER TABLE ONLY voip.call_logs
    ADD CONSTRAINT pk_call_logs PRIMARY KEY (id);

ALTER TABLE ONLY voip.config_templates
    ADD CONSTRAINT pk_config_templates PRIMARY KEY (id);

ALTER TABLE ONLY voip.discovery_scans
    ADD CONSTRAINT pk_discovery_scans PRIMARY KEY (id);

ALTER TABLE ONLY voip.extensions
    ADD CONSTRAINT pk_extensions PRIMARY KEY (id);

ALTER TABLE ONLY voip.firmware_tracks
    ADD CONSTRAINT pk_firmware_tracks PRIMARY KEY (id);

ALTER TABLE ONLY voip.pbx
    ADD CONSTRAINT pk_pbx PRIMARY KEY (id);

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT pk_phones PRIMARY KEY (id);

ALTER TABLE ONLY voip.ring_groups
    ADD CONSTRAINT pk_ring_groups PRIMARY KEY (id);

ALTER TABLE ONLY voip.voicemail_messages
    ADD CONSTRAINT pk_voicemail_messages PRIMARY KEY (id);

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT pk_site_to_site_tunnels PRIMARY KEY (id);

ALTER TABLE ONLY vpn.site_vpn_configs
    ADD CONSTRAINT pk_site_vpn_configs PRIMARY KEY (id);

ALTER TABLE ONLY vpn.vpn_connections
    ADD CONSTRAINT pk_vpn_connections PRIMARY KEY (id);

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT pk_vpn_events PRIMARY KEY (id);

ALTER TABLE ONLY vpn.vpn_reconnect_state
    ADD CONSTRAINT pk_vpn_reconnect_state PRIMARY KEY (id);

ALTER TABLE ONLY vpn.vpn_tunnel_templates
    ADD CONSTRAINT pk_vpn_tunnel_templates PRIMARY KEY (id);

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT uq_s2s_tunnel_sites UNIQUE (site_a_id, site_b_id);

ALTER TABLE ONLY vpn.vpn_connections
    ADD CONSTRAINT uq_vpn_connections_name_org UNIQUE (name, organization_id);

ALTER TABLE ONLY vpn.vpn_reconnect_state
    ADD CONSTRAINT uq_vpn_reconnect_conn UNIQUE (connection_id);

CREATE INDEX ix_access_controllers_site_id ON access.controllers USING btree (site_id);

CREATE INDEX ix_access_events_credential_id ON access.events USING btree (credential_id);

CREATE INDEX ix_access_events_door_id ON access.events USING btree (door_id);

CREATE INDEX ix_access_events_event_type ON access.events USING btree (event_type);

CREATE INDEX ix_access_events_row_hmac ON access.events USING btree (row_hmac) WHERE (row_hmac IS NOT NULL);

CREATE INDEX ix_access_events_timestamp ON access.events USING btree ("timestamp");

CREATE INDEX ix_cardholders_employee_id ON access.cardholders USING btree (employee_id);

CREATE INDEX ix_cardholders_site_id ON access.cardholders USING btree (site_id);

CREATE INDEX ix_credentials_card_number ON access.credentials USING btree (card_number);

CREATE INDEX ix_credentials_cardholder_id ON access.credentials USING btree (cardholder_id);

CREATE INDEX ix_doors_controller_id ON access.doors USING btree (controller_id);

CREATE INDEX ix_doors_site_id ON access.doors USING btree (site_id);

CREATE INDEX ix_doors_status ON access.doors USING btree (status);

CREATE INDEX ix_readers_controller_id ON access.readers USING btree (controller_id);

CREATE INDEX ix_readers_door_id ON access.readers USING btree (door_id);

CREATE INDEX ix_schedules_site_id ON access.schedules USING btree (site_id);

CREATE INDEX ix_agent_releases_platform_type_latest ON agents.agent_releases USING btree (platform, agent_type, is_latest);

CREATE INDEX ix_agent_releases_version ON agents.agent_releases USING btree (version);

CREATE INDEX ix_agent_schedules_agent ON agents.agent_schedules USING btree (agent_id);

CREATE INDEX ix_agent_schedules_org ON agents.agent_schedules USING btree (organization_id);

CREATE INDEX ix_agent_schedules_site ON agents.agent_schedules USING btree (site_id);

CREATE INDEX ix_agent_tasks_agent_status ON agents.agent_tasks USING btree (agent_id, status);

CREATE INDEX ix_agent_tasks_scheduled_at ON agents.agent_tasks USING btree (scheduled_at);

CREATE UNIQUE INDEX ix_remote_agents_agent_key ON agents.remote_agents USING btree (agent_key) WHERE (deleted_at IS NULL);

CREATE INDEX ix_remote_agents_organization_id ON agents.remote_agents USING btree (organization_id);

CREATE INDEX ix_remote_agents_site_id ON agents.remote_agents USING btree (site_id);

CREATE INDEX ix_remote_agents_status ON agents.remote_agents USING btree (status);

CREATE INDEX ix_schedule_runs_agent ON agents.agent_schedule_runs USING btree (agent_id);

CREATE INDEX ix_schedule_runs_schedule ON agents.agent_schedule_runs USING btree (schedule_id, started_at);

CREATE UNIQUE INDEX uq_agent_schedules_dedup ON agents.agent_schedules USING btree (site_id, name) WHERE (deleted_at IS NULL);

CREATE INDEX ix_ai_conv_org ON ai.ai_conversations USING btree (organization_id);

CREATE INDEX ix_ai_conv_user ON ai.ai_conversations USING btree (user_id);

CREATE INDEX ix_ai_msg_conv ON ai.ai_messages USING btree (conversation_id);

CREATE UNIQUE INDEX ix_ai_provider_org_provider ON ai.ai_provider_configs USING btree (organization_id, provider);

CREATE INDEX ix_llm_call_logs_created ON ai.llm_call_logs USING btree (created_at);

CREATE INDEX ix_llm_call_logs_org ON ai.llm_call_logs USING btree (organization_id);

CREATE INDEX ix_llm_call_logs_rule ON ai.llm_call_logs USING btree (rule_id);

CREATE UNIQUE INDEX ix_org_llm_policy_org ON ai.org_llm_policies USING btree (organization_id);

CREATE INDEX ix_alerts_severity_status ON analytics.alerts USING btree (severity, status);

CREATE INDEX ix_alerts_site ON analytics.alerts USING btree (site_id);

CREATE INDEX ix_alerts_status ON analytics.alerts USING btree (status);

CREATE INDEX ix_alerts_triggered ON analytics.alerts USING btree (triggered_at);

CREATE INDEX ix_sla_report_schedules_next_run ON analytics.sla_report_schedules USING btree (next_run_at);

CREATE INDEX ix_sla_report_schedules_org ON analytics.sla_report_schedules USING btree (organization_id);

CREATE INDEX ix_sla_reports_org ON analytics.sla_reports USING btree (organization_id);

CREATE INDEX ix_sla_reports_period ON analytics.sla_reports USING btree (period_start, period_end);

CREATE INDEX ix_widgets_dashboard ON analytics.dashboard_widgets USING btree (dashboard_name);

CREATE INDEX ix_widgets_owner ON analytics.dashboard_widgets USING btree (owner_id);

CREATE INDEX ix_anomalies_resolved ON audit.security_anomalies USING btree (resolved);

CREATE INDEX ix_anomalies_severity ON audit.security_anomalies USING btree (severity);

CREATE INDEX ix_anomalies_timestamp ON audit.security_anomalies USING btree (detected_at);

CREATE INDEX ix_anomalies_type ON audit.security_anomalies USING btree (anomaly_type);

CREATE INDEX ix_audit_audit_logs_timestamp ON audit.audit_logs USING btree ("timestamp");

CREATE INDEX ix_audit_logs_action ON audit.audit_logs USING btree (action);

CREATE INDEX ix_audit_logs_actor ON audit.audit_logs USING btree (actor_id);

CREATE INDEX ix_audit_logs_org ON audit.audit_logs USING btree (organization_id);

CREATE INDEX ix_audit_logs_resource ON audit.audit_logs USING btree (resource_type, resource_id);

CREATE INDEX ix_audit_logs_row_hmac ON audit.audit_logs USING btree (row_hmac) WHERE (row_hmac IS NOT NULL);

CREATE INDEX ix_audit_logs_status ON audit.audit_logs USING btree (status);

CREATE INDEX ix_audit_logs_timestamp ON audit.audit_logs USING btree ("timestamp");

CREATE INDEX ix_audit_security_events_timestamp ON audit.security_events USING btree ("timestamp");

CREATE INDEX ix_failed_logins_ip ON audit.failed_logins USING btree (ip_address);

CREATE INDEX ix_failed_logins_ip_time ON audit.failed_logins USING btree (ip_address, "timestamp");

CREATE INDEX ix_failed_logins_timestamp ON audit.failed_logins USING btree ("timestamp");

CREATE INDEX ix_failed_logins_user ON audit.failed_logins USING btree (username);

CREATE INDEX ix_ip_blocks_active ON audit.ip_blocks USING btree (is_active);

CREATE INDEX ix_ip_blocks_expires ON audit.ip_blocks USING btree (expires_at);

CREATE INDEX ix_ip_blocks_ip ON audit.ip_blocks USING btree (ip_address);

CREATE INDEX ix_security_events_category ON audit.security_events USING btree (category);

CREATE INDEX ix_security_events_ip ON audit.security_events USING btree (ip_address);

CREATE INDEX ix_security_events_reviewed ON audit.security_events USING btree (reviewed);

CREATE INDEX ix_security_events_severity ON audit.security_events USING btree (severity);

CREATE INDEX ix_security_events_timestamp ON audit.security_events USING btree ("timestamp");

CREATE INDEX ix_security_events_type ON audit.security_events USING btree (event_type);

CREATE INDEX ix_security_events_user ON audit.security_events USING btree (user_id);

CREATE INDEX ix_bak_backups_created_at ON backup.backups USING btree (created_at);

CREATE INDEX ix_bak_backups_expires_at ON backup.backups USING btree (expires_at);

CREATE INDEX ix_bak_backups_organization_id ON backup.backups USING btree (organization_id);

CREATE INDEX ix_bak_backups_schedule_id ON backup.backups USING btree (schedule_id);

CREATE INDEX ix_bak_backups_site_id ON backup.backups USING btree (site_id);

CREATE INDEX ix_bak_backups_status ON backup.backups USING btree (status);

CREATE INDEX ix_bak_restore_backup_id ON backup.restore_jobs USING btree (backup_id);

CREATE INDEX ix_bak_restore_status ON backup.restore_jobs USING btree (status);

CREATE INDEX ix_bak_sched_enabled ON backup.backup_schedules USING btree (is_enabled);

CREATE INDEX ix_bak_sched_next_run ON backup.backup_schedules USING btree (next_run_at);

CREATE INDEX ix_bak_storage_org_id ON backup.storage_locations USING btree (organization_id);

CREATE INDEX ix_camera_access_camera ON cameras.camera_access_grants USING btree (camera_id);

CREATE INDEX ix_camera_access_group ON cameras.camera_access_grants USING btree (group_id);

CREATE INDEX ix_camera_access_org ON cameras.camera_access_grants USING btree (organization_id);

CREATE INDEX ix_camera_access_user ON cameras.camera_access_grants USING btree (user_id);

CREATE INDEX ix_camera_events_camera_id ON cameras.camera_events USING btree (camera_id);

CREATE INDEX ix_camera_events_camera_ts ON cameras.camera_events USING btree (camera_id, "timestamp");

CREATE INDEX ix_camera_events_event_type ON cameras.camera_events USING btree (event_type);

CREATE INDEX ix_camera_events_org_id ON cameras.camera_events USING btree (organization_id);

CREATE INDEX ix_camera_events_org_ts ON cameras.camera_events USING btree (organization_id, "timestamp");

CREATE INDEX ix_camera_events_timestamp ON cameras.camera_events USING btree ("timestamp");

CREATE INDEX ix_camera_events_unack ON cameras.camera_events USING btree (organization_id) WHERE (is_acknowledged = false);

CREATE INDEX ix_camera_group_members_camera ON cameras.camera_group_members USING btree (camera_id);

CREATE INDEX ix_camera_group_members_group ON cameras.camera_group_members USING btree (group_id);

CREATE INDEX ix_camera_groups_org ON cameras.camera_groups USING btree (organization_id);

CREATE INDEX ix_camera_health_camera ON cameras.camera_health_snapshots USING btree (camera_id);

CREATE INDEX ix_camera_health_camera_ts ON cameras.camera_health_snapshots USING btree (camera_id, captured_at);

CREATE INDEX ix_camera_health_org_id ON cameras.camera_health_snapshots USING btree (organization_id);

CREATE INDEX ix_camera_health_org_ts ON cameras.camera_health_snapshots USING btree (organization_id, captured_at);

CREATE INDEX ix_camera_health_ts ON cameras.camera_health_snapshots USING btree (captured_at);

CREATE INDEX ix_camera_reports_generated ON cameras.camera_reports USING btree (generated_at);

CREATE INDEX ix_camera_reports_org ON cameras.camera_reports USING btree (organization_id);

CREATE INDEX ix_camera_reports_type ON cameras.camera_reports USING btree (report_type);

CREATE INDEX ix_camera_views_org ON cameras.camera_views USING btree (organization_id);

CREATE INDEX ix_camera_views_user ON cameras.camera_views USING btree (user_id);

CREATE INDEX ix_cameras_channel_id ON cameras.cameras USING btree (channel_id);

CREATE INDEX ix_cameras_nvr_id ON cameras.cameras USING btree (nvr_id);

CREATE INDEX ix_cameras_org_deleted ON cameras.cameras USING btree (organization_id, deleted_at);

CREATE INDEX ix_cameras_organization_id ON cameras.cameras USING btree (organization_id);

CREATE INDEX ix_cameras_site_id ON cameras.cameras USING btree (site_id);

CREATE INDEX ix_cameras_status ON cameras.cameras USING btree (status);

CREATE INDEX ix_evidence_camera ON cameras.evidence_archives USING btree (camera_id);

CREATE INDEX ix_evidence_org ON cameras.evidence_archives USING btree (organization_id);

CREATE INDEX ix_nvrs_org_deleted ON cameras.nvrs USING btree (organization_id, deleted_at);

CREATE INDEX ix_nvrs_organization_id ON cameras.nvrs USING btree (organization_id);

CREATE INDEX ix_nvrs_site_id ON cameras.nvrs USING btree (site_id);

CREATE INDEX ix_nvrs_status ON cameras.nvrs USING btree (status);

CREATE INDEX ix_push_subscriptions_org ON cameras.push_subscriptions USING btree (organization_id);

CREATE INDEX ix_push_subscriptions_user ON cameras.push_subscriptions USING btree (user_id);

CREATE INDEX ix_rec_sched_org ON cameras.recording_schedule_templates USING btree (organization_id);

CREATE INDEX ix_recordings_camera_id ON cameras.recordings USING btree (camera_id);

CREATE INDEX ix_recordings_camera_time ON cameras.recordings USING btree (camera_id, start_time);

CREATE INDEX ix_recordings_nvr_id ON cameras.recordings USING btree (nvr_id);

CREATE INDEX ix_recordings_org_id ON cameras.recordings USING btree (organization_id);

CREATE INDEX ix_recordings_start_time ON cameras.recordings USING btree (start_time);

CREATE UNIQUE INDEX uq_nvrs_org_external_device_id_active ON cameras.nvrs USING btree (organization_id, external_device_id) WHERE ((deleted_at IS NULL) AND (external_device_id IS NOT NULL));

CREATE INDEX ix_app_rules_org ON collector.app_classification_rules USING btree (organization_id);

CREATE INDEX ix_app_rules_port ON collector.app_classification_rules USING btree (protocol, port);

CREATE INDEX ix_collector_collector_logs_timestamp ON collector.collector_logs USING btree ("timestamp");

CREATE INDEX ix_collector_flow_records_bucket_time ON collector.flow_records USING btree (bucket_time);

CREATE INDEX ix_collector_logs_device ON collector.collector_logs USING btree (device_id);

CREATE INDEX ix_collector_logs_severity ON collector.collector_logs USING btree (severity);

CREATE INDEX ix_collector_logs_source ON collector.collector_logs USING btree (source_type, source_ip);

CREATE INDEX ix_collector_logs_timestamp ON collector.collector_logs USING btree ("timestamp");

CREATE INDEX ix_flow_records_app ON collector.flow_records USING btree (app_name, app_category);

CREATE INDEX ix_flow_records_bucket ON collector.flow_records USING btree (bucket_time);

CREATE INDEX ix_flow_records_device ON collector.flow_records USING btree (device_id);

CREATE INDEX ix_flow_records_src_ip ON collector.flow_records USING btree (source_ip);

CREATE INDEX ix_adapter_pending_controller ON core.adapter_pending_changes USING btree (controller_id, status);

CREATE INDEX ix_adapter_pending_feature ON core.adapter_pending_changes USING btree (feature, status);

CREATE INDEX ix_adapter_pending_org_status ON core.adapter_pending_changes USING btree (organization_id, status);

CREATE INDEX ix_api_keys_prefix ON core.api_keys USING btree (key_prefix);

CREATE INDEX ix_api_keys_user_id ON core.api_keys USING btree (user_id);

CREATE INDEX ix_auto_exec_org_triggered ON core.automation_executions USING btree (organization_id, triggered_at);

CREATE INDEX ix_auto_exec_rule ON core.automation_executions USING btree (rule_id);

CREATE INDEX ix_auto_exec_triggered ON core.automation_executions USING btree (triggered_at);

CREATE INDEX ix_auto_rules_org_status ON core.automation_rules USING btree (organization_id, status);

CREATE INDEX ix_auto_rules_trigger ON core.automation_rules USING btree (trigger_type);

CREATE INDEX ix_config_templates_org_id ON core.config_templates USING btree (organization_id);

CREATE INDEX ix_config_templates_scope ON core.config_templates USING btree (scope, scope_id);

CREATE INDEX ix_controllers_site_id ON core.controllers USING btree (site_id);

CREATE INDEX ix_controllers_type ON core.controllers USING btree (controller_type);

CREATE UNIQUE INDEX ix_core_installed_plugins_plugin_id ON core.installed_plugins USING btree (plugin_id);

CREATE INDEX ix_core_marketplace_plugin_versions_marketplace_plugin_id ON core.marketplace_plugin_versions USING btree (marketplace_plugin_id);

CREATE INDEX ix_core_marketplace_plugins_category ON core.marketplace_plugins USING btree (category);

CREATE UNIQUE INDEX ix_core_marketplace_plugins_plugin_id ON core.marketplace_plugins USING btree (plugin_id);

CREATE UNIQUE INDEX ix_core_marketplace_plugins_slug ON core.marketplace_plugins USING btree (slug);

CREATE INDEX ix_core_plugin_organization_states_organization_id ON core.plugin_organization_states USING btree (organization_id);

CREATE INDEX ix_core_plugin_organization_states_plugin_id ON core.plugin_organization_states USING btree (plugin_id);

CREATE INDEX ix_core_plugin_reviews_marketplace_plugin_id ON core.plugin_reviews USING btree (marketplace_plugin_id);

CREATE INDEX ix_core_plugin_reviews_user_id ON core.plugin_reviews USING btree (user_id);

CREATE INDEX ix_core_plugin_settings_organization_id ON core.plugin_settings USING btree (organization_id);

CREATE INDEX ix_core_plugin_settings_plugin_id ON core.plugin_settings USING btree (plugin_id);

CREATE INDEX ix_credentials_credential_type ON core.credentials USING btree (credential_type);

CREATE INDEX ix_credentials_organization_id ON core.credentials USING btree (organization_id);

CREATE INDEX ix_credentials_scope ON core.credentials USING btree (scope);

CREATE INDEX ix_custom_roles_org ON core.custom_roles USING btree (organization_id);

CREATE UNIQUE INDEX ix_devfw_device ON core.device_firmware_status USING btree (device_id);

CREATE INDEX ix_devfw_site ON core.device_firmware_status USING btree (site_id);

CREATE INDEX ix_devfw_update_avail ON core.device_firmware_status USING btree (update_available);

CREATE INDEX ix_export_jobs_status ON core.export_jobs USING btree (status);

CREATE INDEX ix_export_jobs_user ON core.export_jobs USING btree (created_by);

CREATE INDEX ix_feature_flags_org_module ON core.module_feature_flags USING btree (organization_id, module_id);

CREATE INDEX ix_firmware_device_type ON core.firmware_images USING btree (device_type);

CREATE INDEX ix_firmware_release_type ON core.firmware_images USING btree (release_type);

CREATE INDEX ix_firmware_vendor_model ON core.firmware_images USING btree (vendor, model);

CREATE INDEX ix_firmware_version ON core.firmware_images USING btree (version);

CREATE INDEX ix_fwjob_created_by ON core.firmware_upgrade_jobs USING btree (created_by);

CREATE INDEX ix_fwjob_site ON core.firmware_upgrade_jobs USING btree (site_id);

CREATE INDEX ix_fwjob_status ON core.firmware_upgrade_jobs USING btree (status);

CREATE INDEX ix_fwsched_enabled ON core.firmware_schedules USING btree (is_enabled);

CREATE INDEX ix_fwsched_site ON core.firmware_schedules USING btree (site_id);

CREATE INDEX ix_import_jobs_status ON core.import_jobs USING btree (status);

CREATE INDEX ix_import_jobs_user ON core.import_jobs USING btree (created_by);

CREATE INDEX ix_inapp_notif_user_created ON core.in_app_notifications USING btree (user_id, created_at);

CREATE INDEX ix_inapp_notif_user_read ON core.in_app_notifications USING btree (user_id, read);

CREATE INDEX ix_integrations_org ON core.integrations USING btree (organization_id);

CREATE INDEX ix_integrations_type ON core.integrations USING btree (integration_type);

CREATE INDEX ix_module_events_module_id ON core.module_events USING btree (module_id);

CREATE INDEX ix_module_events_org_id ON core.module_events USING btree (organization_id);

CREATE INDEX ix_module_events_timestamp ON core.module_events USING btree ("timestamp");

CREATE INDEX ix_notif_delivery_channel ON core.notification_deliveries USING btree (channel);

CREATE INDEX ix_notif_delivery_dead_letter ON core.notification_deliveries USING btree (retry_dead_letter);

CREATE INDEX ix_notif_delivery_status ON core.notification_deliveries USING btree (status);

CREATE INDEX ix_notif_delivery_user ON core.notification_deliveries USING btree (user_id);

CREATE UNIQUE INDEX ix_notif_pref_user ON core.notification_preferences USING btree (user_id);

CREATE INDEX ix_notif_provider_channel ON core.notification_providers USING btree (channel);

CREATE INDEX ix_notif_provider_org ON core.notification_providers USING btree (organization_id);

CREATE INDEX ix_oauth2_apps_client_id ON core.oauth2_apps USING btree (client_id);

CREATE INDEX ix_oauth2_apps_user_id ON core.oauth2_apps USING btree (user_id);

CREATE INDEX ix_oauth2_codes_app_user ON core.oauth2_authorization_codes USING btree (app_id, user_id);

CREATE INDEX ix_oauth2_codes_code ON core.oauth2_authorization_codes USING btree (code);

CREATE INDEX ix_oauth2_tokens_access ON core.oauth2_tokens USING btree (access_token_hash);

CREATE INDEX ix_oauth2_tokens_app_user ON core.oauth2_tokens USING btree (app_id, user_id);

CREATE INDEX ix_oauth2_tokens_refresh ON core.oauth2_tokens USING btree (refresh_token_hash);

CREATE INDEX ix_org_modules_module_id ON core.organization_modules USING btree (module_id);

CREATE INDEX ix_org_modules_org_id ON core.organization_modules USING btree (organization_id);

CREATE UNIQUE INDEX ix_organizations_slug ON core.organizations USING btree (slug) WHERE (deleted_at IS NULL);

CREATE UNIQUE INDEX ix_plugin_org_states_lookup ON core.plugin_organization_states USING btree (plugin_id, organization_id);

CREATE UNIQUE INDEX ix_plugin_settings_lookup ON core.plugin_settings USING btree (plugin_id, organization_id, key);

CREATE INDEX ix_site_groups_org_id ON core.site_groups USING btree (organization_id);

CREATE INDEX ix_site_groups_parent_id ON core.site_groups USING btree (parent_id);

CREATE INDEX ix_sites_organization_id ON core.sites USING btree (organization_id);

CREATE UNIQUE INDEX ix_sites_slug ON core.sites USING btree (organization_id, slug) WHERE (deleted_at IS NULL);

CREATE INDEX ix_sla_breaches_policy ON core.sla_breaches USING btree (policy_id);

CREATE INDEX ix_sla_breaches_severity ON core.sla_breaches USING btree (severity);

CREATE INDEX ix_sla_breaches_started_brin ON core.sla_breaches USING brin (started_at);

CREATE INDEX ix_sla_breaches_status ON core.sla_breaches USING btree (status);

CREATE INDEX ix_sla_policies_org ON core.sla_policies USING btree (organization_id);

CREATE INDEX ix_sla_policies_scope ON core.sla_policies USING btree (scope, scope_id);

CREATE INDEX ix_sla_policies_status ON core.sla_policies USING btree (status);

CREATE INDEX ix_sla_snapshots_policy ON core.sla_snapshots USING btree (policy_id);

CREATE INDEX ix_sla_snapshots_ts_brin ON core.sla_snapshots USING brin (recorded_at);

CREATE INDEX ix_sso_providers_org_id ON core.sso_providers USING btree (organization_id);

CREATE INDEX ix_sso_providers_protocol ON core.sso_providers USING btree (protocol);

CREATE UNIQUE INDEX ix_sso_providers_slug ON core.sso_providers USING btree (slug);

CREATE UNIQUE INDEX ix_sso_sessions_state ON core.sso_sessions USING btree (state);

CREATE INDEX ix_sso_sessions_user_id ON core.sso_sessions USING btree (user_id);

CREATE INDEX ix_user_sessions_access_jti ON core.user_sessions USING btree (access_jti);

CREATE UNIQUE INDEX ix_user_sessions_refresh_jti ON core.user_sessions USING btree (refresh_jti);

CREATE INDEX ix_user_sessions_refresh_token ON core.user_sessions USING btree (refresh_token_hash);

CREATE INDEX ix_user_sessions_user_id ON core.user_sessions USING btree (user_id);

CREATE INDEX ix_user_site_access_site_id ON core.user_site_access USING btree (site_id);

CREATE UNIQUE INDEX ix_user_site_access_user_site ON core.user_site_access USING btree (user_id, site_id);

CREATE UNIQUE INDEX ix_users_email ON core.users USING btree (email) WHERE (deleted_at IS NULL);

CREATE INDEX ix_users_organization_id ON core.users USING btree (organization_id);

CREATE UNIQUE INDEX ix_users_username ON core.users USING btree (username) WHERE (deleted_at IS NULL);

CREATE INDEX ix_webhooks_enabled ON core.webhooks USING btree (enabled);

CREATE INDEX ix_webhooks_org ON core.webhooks USING btree (organization_id);

CREATE INDEX ix_wh_delivery_created ON core.webhook_deliveries USING btree (created_at);

CREATE INDEX ix_wh_delivery_status ON core.webhook_deliveries USING btree (status);

CREATE INDEX ix_wh_delivery_webhook ON core.webhook_deliveries USING btree (webhook_id);

CREATE INDEX ix_wh_dlq_created ON core.webhook_dead_letters USING btree (created_at);

CREATE INDEX ix_wh_dlq_org ON core.webhook_dead_letters USING btree (organization_id);

CREATE INDEX ix_wh_dlq_webhook ON core.webhook_dead_letters USING btree (webhook_id);

CREATE UNIQUE INDEX uq_custom_roles_org_slug ON core.custom_roles USING btree (organization_id, slug) WHERE (deleted_at IS NULL);

CREATE INDEX ix_adoption_jobs_device ON devices.adoption_jobs USING btree (device_id);

CREATE INDEX ix_adoption_jobs_org ON devices.adoption_jobs USING btree (organization_id);

CREATE INDEX ix_adoption_jobs_status ON devices.adoption_jobs USING btree (status);

CREATE INDEX ix_bulk_operations_org_status ON devices.bulk_operations USING btree (organization_id, status);

CREATE INDEX ix_device_clients_device_id ON devices.device_clients USING btree (device_id);

CREATE INDEX ix_device_clients_is_online ON devices.device_clients USING btree (is_online);

CREATE INDEX ix_device_clients_mac ON devices.device_clients USING btree (mac_address);

CREATE INDEX ix_device_configs_drift ON devices.device_configs USING btree (organization_id, has_drift);

CREATE INDEX ix_device_configs_org_id ON devices.device_configs USING btree (organization_id);

CREATE INDEX ix_device_groups_org_id ON devices.device_groups USING btree (organization_id);

CREATE INDEX ix_device_groups_site_id ON devices.device_groups USING btree (site_id);

CREATE INDEX ix_device_health_org ON devices.device_health USING btree (organization_id, health_status);

CREATE INDEX ix_device_health_site ON devices.device_health USING btree (site_id, health_score);

CREATE INDEX ix_device_ports_device_id ON devices.device_ports USING btree (device_id);

CREATE INDEX ix_device_ports_is_enabled ON devices.device_ports USING btree (is_enabled);

CREATE INDEX ix_device_ports_status ON devices.device_ports USING btree (status);

CREATE INDEX ix_device_tags_device_id ON devices.device_tags USING btree (device_id);

CREATE INDEX ix_device_tags_tag ON devices.device_tags USING btree (tag);

CREATE INDEX ix_devices_controller_id ON devices.devices USING btree (controller_id);

CREATE INDEX ix_devices_credential_id ON devices.devices USING btree (credential_id);

CREATE INDEX ix_devices_device_clients_is_online ON devices.device_clients USING btree (is_online);

CREATE INDEX ix_devices_device_ports_is_enabled ON devices.device_ports USING btree (is_enabled);

CREATE INDEX ix_devices_device_type ON devices.devices USING btree (device_type);

CREATE INDEX ix_devices_devices_is_active ON devices.devices USING btree (is_active);

CREATE UNIQUE INDEX ix_devices_external_id ON devices.devices USING btree (external_id) WHERE (external_id IS NOT NULL);

CREATE INDEX ix_devices_is_active ON devices.devices USING btree (is_active);

CREATE INDEX ix_devices_mac ON devices.devices USING btree (mac_address);

CREATE INDEX ix_devices_site_id ON devices.devices USING btree (site_id);

CREATE INDEX ix_devices_status ON devices.devices USING btree (status);

CREATE INDEX ix_devices_type ON devices.devices USING btree (device_type);

CREATE INDEX ix_devices_type_site_deleted ON devices.devices USING btree (device_type, site_id, deleted_at);

CREATE INDEX ix_discovered_hosts_agent ON devices.discovered_hosts USING btree (discovered_by_agent_id);

CREATE INDEX ix_discovered_hosts_ip ON devices.discovered_hosts USING btree (ip_address);

CREATE INDEX ix_discovered_hosts_last_seen ON devices.discovered_hosts USING btree (last_seen);

CREATE INDEX ix_discovered_hosts_org ON devices.discovered_hosts USING btree (organization_id);

CREATE INDEX ix_discovered_hosts_site ON devices.discovered_hosts USING btree (site_id);

CREATE INDEX ix_lifecycle_log_device ON devices.device_lifecycle_log USING btree (device_id, created_at);

CREATE INDEX ix_lifecycle_log_org ON devices.device_lifecycle_log USING btree (organization_id, created_at);

CREATE INDEX ix_mac_prereg_mac ON devices.mac_pre_registrations USING btree (mac_address);

CREATE INDEX ix_mac_prereg_org ON devices.mac_pre_registrations USING btree (organization_id);

CREATE INDEX ix_poe_schedules_device_id ON devices.poe_schedules USING btree (device_id);

CREATE INDEX ix_poe_schedules_enabled ON devices.poe_schedules USING btree (enabled);

CREATE INDEX ix_poe_schedules_org_enabled ON devices.poe_schedules USING btree (organization_id, enabled);

CREATE INDEX ix_poe_schedules_org_id ON devices.poe_schedules USING btree (organization_id);

CREATE INDEX ix_prov_profiles_org ON devices.provisioning_profiles USING btree (organization_id);

CREATE INDEX ix_prov_profiles_type ON devices.provisioning_profiles USING btree (device_type);

CREATE INDEX ix_topology_edges_last_seen ON devices.topology_edges USING btree (last_seen);

CREATE INDEX ix_topology_edges_neighbor_chassis ON devices.topology_edges USING btree (neighbor_chassis_id);

CREATE INDEX ix_topology_edges_neighbor_device ON devices.topology_edges USING btree (neighbor_device_id);

CREATE INDEX ix_topology_edges_org ON devices.topology_edges USING btree (organization_id);

CREATE INDEX ix_topology_edges_site ON devices.topology_edges USING btree (site_id);

CREATE INDEX ix_ztp_rules_org ON devices.auto_adoption_rules USING btree (organization_id);

CREATE INDEX ix_ztp_rules_org_enabled_priority ON devices.auto_adoption_rules USING btree (organization_id, enabled, priority);

CREATE INDEX ix_ztp_rules_priority ON devices.auto_adoption_rules USING btree (priority);

CREATE UNIQUE INDEX uq_devices_mac_alive ON devices.devices USING btree (mac_address) WHERE ((mac_address IS NOT NULL) AND ((mac_address)::text <> ''::text) AND (deleted_at IS NULL));

CREATE UNIQUE INDEX uq_discovered_hosts_site_mac ON devices.discovered_hosts USING btree (site_id, mac_address) WHERE ((mac_address IS NOT NULL) AND (deleted_at IS NULL));

CREATE UNIQUE INDEX uq_topology_edges_dedup ON devices.topology_edges USING btree (site_id, local_interface, neighbor_chassis_id, neighbor_port_id) WHERE (deleted_at IS NULL);

CREATE INDEX ix_config_versions_device ON enterprise.config_versions USING btree (device_id, version_number);

CREATE INDEX ix_config_versions_org_device ON enterprise.config_versions USING btree (organization_id, device_id);

CREATE INDEX ix_alert_rules_org ON events.alert_rules USING btree (organization_id);

CREATE INDEX ix_alert_rules_scope_ids ON events.alert_rules USING gin (scope_ids);

CREATE INDEX ix_alert_rules_status ON events.alert_rules USING btree (status);

CREATE INDEX ix_alert_rules_type ON events.alert_rules USING btree (rule_type);

CREATE INDEX ix_alerts_fired_at ON events.alerts USING btree (fired_at);

CREATE INDEX ix_alerts_org ON events.alerts USING btree (organization_id);

CREATE INDEX ix_alerts_rule ON events.alerts USING btree (rule_id);

CREATE INDEX ix_alerts_severity ON events.alerts USING btree (severity);

CREATE INDEX ix_alerts_status ON events.alerts USING btree (status);

CREATE INDEX ix_correlation_rules_org ON events.correlation_rules USING btree (organization_id);

CREATE INDEX ix_correlation_rules_status ON events.correlation_rules USING btree (status);

CREATE INDEX ix_event_subscriptions_active ON events.event_subscriptions USING btree (is_active);

CREATE INDEX ix_event_subscriptions_pattern ON events.event_subscriptions USING btree (pattern);

CREATE INDEX ix_incident_events_event ON events.incident_events USING btree (event_id);

CREATE INDEX ix_incident_events_incident ON events.incident_events USING btree (incident_id);

CREATE INDEX ix_incidents_opened_at_brin ON events.incidents USING brin (opened_at);

CREATE INDEX ix_incidents_org ON events.incidents USING btree (organization_id);

CREATE INDEX ix_incidents_rule ON events.incidents USING btree (rule_id);

CREATE INDEX ix_incidents_severity ON events.incidents USING btree (severity);

CREATE INDEX ix_incidents_site ON events.incidents USING btree (site_id);

CREATE INDEX ix_incidents_status ON events.incidents USING btree (status);

CREATE INDEX ix_fabric_conn_org ON fabric.connections USING btree (organization_id);

CREATE INDEX ix_fabric_conn_org_enabled ON fabric.connections USING btree (organization_id, enabled);

CREATE INDEX ix_fabric_connection_runs_connection_id ON fabric.connection_runs USING btree (connection_id);

CREATE INDEX ix_fabric_connection_runs_organization_id ON fabric.connection_runs USING btree (organization_id);

CREATE INDEX ix_fabric_connections_organization_id ON fabric.connections USING btree (organization_id);

CREATE INDEX ix_fabric_run_conn ON fabric.connection_runs USING btree (connection_id);

CREATE INDEX ix_fabric_run_org_time ON fabric.connection_runs USING btree (organization_id, created_at);

CREATE INDEX ix_firewall_devices_site_id ON firewall.devices USING btree (site_id);

CREATE INDEX ix_firewall_logs_action ON firewall.logs USING btree (action);

CREATE INDEX ix_firewall_logs_device_id ON firewall.logs USING btree (device_id);

CREATE INDEX ix_firewall_logs_timestamp ON firewall.logs USING btree ("timestamp");

CREATE INDEX ix_firewall_rules_device_id ON firewall.rules USING btree (device_id);

CREATE INDEX ix_firewall_rules_order ON firewall.rules USING btree (rule_order);

CREATE INDEX ix_gateway_connections_org_deleted ON firewall.gateway_connections USING btree (org_id, deleted_at);

CREATE INDEX ix_gateway_connections_org_id ON firewall.gateway_connections USING btree (org_id);

CREATE INDEX ix_gateway_connections_site_id ON firewall.gateway_connections USING btree (site_id);

CREATE INDEX ix_gateway_connections_vendor ON firewall.gateway_connections USING btree (vendor);

CREATE INDEX ix_gateway_sync_logs_gw_id ON firewall.gateway_sync_logs USING btree (gateway_id);

CREATE INDEX ix_gateway_sync_logs_timestamp ON firewall.gateway_sync_logs USING btree (started_at);

CREATE INDEX ix_ids_alerts_device_id ON firewall.ids_alerts USING btree (device_id);

CREATE INDEX ix_ids_alerts_severity ON firewall.ids_alerts USING btree (severity);

CREATE INDEX ix_ids_alerts_timestamp ON firewall.ids_alerts USING btree ("timestamp");

CREATE INDEX ix_nat_rules_device_id ON firewall.nat_rules USING btree (device_id);

CREATE INDEX ix_vpn_tunnels_device_id ON firewall.vpn_tunnels USING btree (device_id);

CREATE INDEX ix_vpn_tunnels_status ON firewall.vpn_tunnels USING btree (status);

CREATE INDEX ix_gw_addrgrp_site ON gateway.gw_canonical_address_groups USING btree (site_id);

CREATE INDEX ix_gw_dhcp_lease_site ON gateway.gw_imported_dhcp_leases USING btree (site_id);

CREATE INDEX ix_gw_dhcp_res_vlan ON gateway.gw_canonical_dhcp_reservations USING btree (vlan_id);

CREATE INDEX ix_gw_dhcp_scopes_site ON gateway.gw_canonical_dhcp_scopes USING btree (site_id);

CREATE INDEX ix_gw_dist_site ON gateway.gw_distribution_records USING btree (site_id);

CREATE INDEX ix_gw_dist_status ON gateway.gw_distribution_records USING btree (status);

CREATE INDEX ix_gw_dns_site ON gateway.gw_canonical_dns_records USING btree (site_id);

CREATE INDEX ix_gw_drift_resolution ON gateway.gw_drift_events USING btree (resolution);

CREATE INDEX ix_gw_drift_severity ON gateway.gw_drift_events USING btree (severity);

CREATE INDEX ix_gw_drift_site ON gateway.gw_drift_events USING btree (site_id);

CREATE INDEX ix_gw_fw_rule_device ON gateway.gw_imported_firewall_rules USING btree (device_id);

CREATE INDEX ix_gw_fw_rule_site ON gateway.gw_imported_firewall_rules USING btree (site_id);

CREATE INDEX ix_gw_ids_severity ON gateway.gw_imported_ids_events USING btree (severity);

CREATE INDEX ix_gw_ids_site ON gateway.gw_imported_ids_events USING btree (site_id);

CREATE INDEX ix_gw_iface_site ON gateway.gw_imported_interfaces USING btree (site_id);

CREATE INDEX ix_gw_import_site ON gateway.gw_import_sessions USING btree (site_id);

CREATE INDEX ix_gw_nat_device ON gateway.gw_imported_nat_rules USING btree (device_id);

CREATE INDEX ix_gw_nat_site ON gateway.gw_imported_nat_rules USING btree (site_id);

CREATE INDEX ix_gw_role_assign_controller ON gateway.gw_site_role_assignments USING btree (controller_id);

CREATE INDEX ix_gw_role_assign_map ON gateway.gw_site_role_assignments USING btree (role_map_id);

CREATE INDEX ix_gw_role_maps_org ON gateway.gw_site_role_maps USING btree (organization_id);

CREATE INDEX ix_gw_suppress_device ON gateway.gw_suppression_rules USING btree (device_id);

CREATE INDEX ix_gw_suppress_site ON gateway.gw_suppression_rules USING btree (site_id);

CREATE INDEX ix_gw_tmpl_org ON gateway.gw_vlan_templates USING btree (organization_id);

CREATE INDEX ix_gw_vlans_org ON gateway.gw_canonical_vlans USING btree (organization_id);

CREATE INDEX ix_gw_vlans_site ON gateway.gw_canonical_vlans USING btree (site_id);

CREATE INDEX ix_gw_vpn_device ON gateway.gw_imported_vpn_tunnels USING btree (device_id);

CREATE INDEX ix_gw_vpn_site ON gateway.gw_imported_vpn_tunnels USING btree (site_id);

CREATE INDEX ix_proxmox_nodes_controller ON hypervisor.proxmox_nodes USING btree (controller_id);

CREATE INDEX ix_proxmox_nodes_site ON hypervisor.proxmox_nodes USING btree (site_id);

CREATE INDEX ix_proxmox_nodes_status ON hypervisor.proxmox_nodes USING btree (status);

CREATE INDEX ix_vms_node ON hypervisor.virtual_machines USING btree (node_id);

CREATE INDEX ix_vms_site ON hypervisor.virtual_machines USING btree (site_id);

CREATE INDEX ix_vms_status ON hypervisor.virtual_machines USING btree (status);

CREATE INDEX ix_vms_type ON hypervisor.virtual_machines USING btree (vm_type);

CREATE UNIQUE INDEX ix_vms_vmid_node ON hypervisor.virtual_machines USING btree (vmid, node_id);

CREATE INDEX ix_dot1x_cfg_controller ON network.dot1x_port_configs USING btree (controller_id);

CREATE INDEX ix_dot1x_cfg_controller_push_status ON network.dot1x_port_configs USING btree (controller_id, push_status);

CREATE INDEX ix_dot1x_cfg_radius_profile ON network.dot1x_port_configs USING btree (radius_profile_id);

CREATE INDEX ix_dot1x_events_client_mac ON network.dot1x_auth_events USING btree (client_mac);

CREATE INDEX ix_dot1x_events_org_id ON network.dot1x_auth_events USING btree (organization_id);

CREATE INDEX ix_dot1x_events_timestamp ON network.dot1x_auth_events USING btree ("timestamp");

CREATE INDEX ix_net_lags_device_id ON network.link_aggregation_groups USING btree (device_id);

CREATE INDEX ix_net_pp_controller_id ON network.port_profiles USING btree (controller_id);

CREATE INDEX ix_net_pp_site_id ON network.port_profiles USING btree (site_id);

CREATE INDEX ix_net_topo_source ON network.topology_links USING btree (source_device_id);

CREATE INDEX ix_net_topo_target ON network.topology_links USING btree (target_device_id);

CREATE INDEX ix_net_vlans_controller_id ON network.vlans USING btree (controller_id);

CREATE INDEX ix_net_vlans_site_id ON network.vlans USING btree (site_id);

CREATE INDEX ix_net_vlans_vlan_id ON network.vlans USING btree (vlan_id);

CREATE INDEX ix_net_wifi_controller_id ON network.wifi_networks USING btree (controller_id);

CREATE INDEX ix_net_wifi_site_id ON network.wifi_networks USING btree (site_id);

CREATE INDEX ix_radius_profiles_org_id ON network.radius_server_profiles USING btree (organization_id);

CREATE INDEX ix_roaming_client ON network.client_roaming_events USING btree (client_mac, "timestamp");

CREATE INDEX ix_roaming_org ON network.client_roaming_events USING btree (organization_id);

CREATE INDEX ix_topology_layouts_site ON network.topology_layouts USING btree (site_id);

CREATE INDEX ix_call_logs_callee ON voip.call_logs USING btree (callee_number);

CREATE INDEX ix_call_logs_caller ON voip.call_logs USING btree (caller_number);

CREATE INDEX ix_call_logs_direction ON voip.call_logs USING btree (direction);

CREATE INDEX ix_call_logs_pbx_id ON voip.call_logs USING btree (pbx_id);

CREATE INDEX ix_call_logs_start_time ON voip.call_logs USING btree (start_time);

CREATE INDEX ix_call_logs_status ON voip.call_logs USING btree (status);

CREATE INDEX ix_config_templates_site_id ON voip.config_templates USING btree (site_id);

CREATE INDEX ix_config_templates_vendor ON voip.config_templates USING btree (vendor);

CREATE INDEX ix_discovery_scans_site_id ON voip.discovery_scans USING btree (site_id);

CREATE INDEX ix_discovery_scans_status ON voip.discovery_scans USING btree (status);

CREATE INDEX ix_extensions_number ON voip.extensions USING btree (extension_number);

CREATE INDEX ix_extensions_pbx_id ON voip.extensions USING btree (pbx_id);

CREATE INDEX ix_firmware_vendor_model ON voip.firmware_tracks USING btree (vendor, model);

CREATE INDEX ix_pbx_site_id ON voip.pbx USING btree (site_id);

CREATE INDEX ix_phones_lifecycle_state ON voip.phones USING btree (lifecycle_state);

CREATE UNIQUE INDEX ix_phones_mac_address ON voip.phones USING btree (mac_address);

CREATE INDEX ix_phones_pbx_id ON voip.phones USING btree (pbx_id);

CREATE INDEX ix_phones_site_id ON voip.phones USING btree (site_id);

CREATE INDEX ix_phones_status ON voip.phones USING btree (status);

CREATE INDEX ix_phones_template_id ON voip.phones USING btree (config_template_id);

CREATE INDEX ix_ring_groups_pbx_id ON voip.ring_groups USING btree (pbx_id);

CREATE INDEX ix_voicemail_extension_id ON voip.voicemail_messages USING btree (extension_id);

CREATE INDEX ix_voicemail_message_date ON voip.voicemail_messages USING btree (message_date);

CREATE INDEX ix_s2s_tunnels_org ON vpn.site_to_site_tunnels USING btree (organization_id);

CREATE INDEX ix_s2s_tunnels_status ON vpn.site_to_site_tunnels USING btree (status);

CREATE INDEX ix_s2s_tunnels_template ON vpn.site_to_site_tunnels USING btree (template_id);

CREATE INDEX ix_site_vpn_configs_controller ON vpn.site_vpn_configs USING btree (controller_id);

CREATE INDEX ix_site_vpn_configs_org ON vpn.site_vpn_configs USING btree (organization_id);

CREATE INDEX ix_site_vpn_configs_site ON vpn.site_vpn_configs USING btree (site_id);

CREATE INDEX ix_vpn_connections_org ON vpn.vpn_connections USING btree (organization_id);

CREATE INDEX ix_vpn_connections_org_status ON vpn.vpn_connections USING btree (organization_id, status);

CREATE INDEX ix_vpn_connections_status ON vpn.vpn_connections USING btree (status);

CREATE INDEX ix_vpn_connections_type ON vpn.vpn_connections USING btree (vpn_type);

CREATE INDEX ix_vpn_events_org_time ON vpn.vpn_events USING btree (organization_id, created_at);

CREATE INDEX ix_vpn_events_site ON vpn.vpn_events USING btree (site_id, created_at);

CREATE INDEX ix_vpn_events_type ON vpn.vpn_events USING btree (event_type);

CREATE INDEX ix_vpn_templates_org ON vpn.vpn_tunnel_templates USING btree (organization_id);

ALTER TABLE ONLY access.cardholders
    ADD CONSTRAINT fk_cardholders_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.cardholders
    ADD CONSTRAINT fk_cardholders_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.controllers
    ADD CONSTRAINT fk_controllers_device_controller_id_controllers FOREIGN KEY (device_controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.controllers
    ADD CONSTRAINT fk_controllers_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.credentials
    ADD CONSTRAINT fk_credentials_cardholder_id_cardholders FOREIGN KEY (cardholder_id) REFERENCES access.cardholders(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.doors
    ADD CONSTRAINT fk_doors_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES access.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.doors
    ADD CONSTRAINT fk_doors_default_schedule_id_schedules FOREIGN KEY (default_schedule_id) REFERENCES access.schedules(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.doors
    ADD CONSTRAINT fk_doors_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.events
    ADD CONSTRAINT fk_events_cardholder_id_cardholders FOREIGN KEY (cardholder_id) REFERENCES access.cardholders(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.events
    ADD CONSTRAINT fk_events_credential_id_credentials FOREIGN KEY (credential_id) REFERENCES access.credentials(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.events
    ADD CONSTRAINT fk_events_door_id_doors FOREIGN KEY (door_id) REFERENCES access.doors(id) ON DELETE SET NULL;

ALTER TABLE ONLY access.readers
    ADD CONSTRAINT fk_readers_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES access.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.readers
    ADD CONSTRAINT fk_readers_door_id_doors FOREIGN KEY (door_id) REFERENCES access.doors(id) ON DELETE CASCADE;

ALTER TABLE ONLY access.schedules
    ADD CONSTRAINT fk_schedules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_releases
    ADD CONSTRAINT fk_agent_releases_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_schedule_runs
    ADD CONSTRAINT fk_agent_schedule_runs_agent_id_remote_agents FOREIGN KEY (agent_id) REFERENCES agents.remote_agents(id) ON DELETE SET NULL;

ALTER TABLE ONLY agents.agent_schedule_runs
    ADD CONSTRAINT fk_agent_schedule_runs_schedule_id_agent_schedules FOREIGN KEY (schedule_id) REFERENCES agents.agent_schedules(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_schedules
    ADD CONSTRAINT fk_agent_schedules_agent_id_remote_agents FOREIGN KEY (agent_id) REFERENCES agents.remote_agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_schedules
    ADD CONSTRAINT fk_agent_schedules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_schedules
    ADD CONSTRAINT fk_agent_schedules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.agent_tasks
    ADD CONSTRAINT fk_agent_tasks_agent_id_remote_agents FOREIGN KEY (agent_id) REFERENCES agents.remote_agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.remote_agents
    ADD CONSTRAINT fk_remote_agents_approved_by_id_users FOREIGN KEY (approved_by_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY agents.remote_agents
    ADD CONSTRAINT fk_remote_agents_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY agents.remote_agents
    ADD CONSTRAINT fk_remote_agents_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY ai.ai_conversations
    ADD CONSTRAINT fk_ai_conversations_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai.ai_messages
    ADD CONSTRAINT fk_ai_messages_conversation_id_ai_conversations FOREIGN KEY (conversation_id) REFERENCES ai.ai_conversations(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai.ai_provider_configs
    ADD CONSTRAINT fk_ai_provider_configs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai.llm_call_logs
    ADD CONSTRAINT fk_llm_call_logs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY ai.org_llm_policies
    ADD CONSTRAINT fk_org_llm_policies_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY analytics.sla_report_schedules
    ADD CONSTRAINT fk_sla_report_schedules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY analytics.sla_reports
    ADD CONSTRAINT fk_sla_reports_generated_by_users FOREIGN KEY (generated_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY analytics.sla_reports
    ADD CONSTRAINT fk_sla_reports_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY audit.audit_logs
    ADD CONSTRAINT fk_audit_logs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.audit_logs
    ADD CONSTRAINT fk_audit_logs_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.ip_blocks
    ADD CONSTRAINT fk_ip_blocks_unblocked_by_users FOREIGN KEY (unblocked_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_anomalies
    ADD CONSTRAINT fk_security_anomalies_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_anomalies
    ADD CONSTRAINT fk_security_anomalies_resolved_by_users FOREIGN KEY (resolved_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_anomalies
    ADD CONSTRAINT fk_security_anomalies_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_events
    ADD CONSTRAINT fk_security_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_events
    ADD CONSTRAINT fk_security_events_reviewed_by_users FOREIGN KEY (reviewed_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY audit.security_events
    ADD CONSTRAINT fk_security_events_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.backup_schedules
    ADD CONSTRAINT fk_backup_schedules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY backup.backup_schedules
    ADD CONSTRAINT fk_backup_schedules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY backup.backup_schedules
    ADD CONSTRAINT fk_backup_schedules_storage_location_id_storage_locations FOREIGN KEY (storage_location_id) REFERENCES backup.storage_locations(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_created_by_id_users FOREIGN KEY (created_by_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_rollback_for_restore_job_id_restore_jobs FOREIGN KEY (rollback_for_restore_job_id) REFERENCES backup.restore_jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_schedule_id_backup_schedules FOREIGN KEY (schedule_id) REFERENCES backup.backup_schedules(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY backup.backups
    ADD CONSTRAINT fk_backups_storage_location_id_storage_locations FOREIGN KEY (storage_location_id) REFERENCES backup.storage_locations(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.restore_jobs
    ADD CONSTRAINT fk_restore_jobs_backup_id_backups FOREIGN KEY (backup_id) REFERENCES backup.backups(id) ON DELETE CASCADE;

ALTER TABLE ONLY backup.restore_jobs
    ADD CONSTRAINT fk_restore_jobs_initiated_by_id_users FOREIGN KEY (initiated_by_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.restore_jobs
    ADD CONSTRAINT fk_restore_jobs_target_site_id_sites FOREIGN KEY (target_site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY backup.storage_locations
    ADD CONSTRAINT fk_storage_locations_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT fk_camera_access_grants_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT fk_camera_access_grants_group_id_camera_groups FOREIGN KEY (group_id) REFERENCES cameras.camera_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT fk_camera_access_grants_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_access_grants
    ADD CONSTRAINT fk_camera_access_grants_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_events
    ADD CONSTRAINT fk_camera_events_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_events
    ADD CONSTRAINT fk_camera_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_group_members
    ADD CONSTRAINT fk_camera_group_members_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_group_members
    ADD CONSTRAINT fk_camera_group_members_group_id_camera_groups FOREIGN KEY (group_id) REFERENCES cameras.camera_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_groups
    ADD CONSTRAINT fk_camera_groups_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_health_snapshots
    ADD CONSTRAINT fk_camera_health_snapshots_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_health_snapshots
    ADD CONSTRAINT fk_camera_health_snapshots_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_reports
    ADD CONSTRAINT fk_camera_reports_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_views
    ADD CONSTRAINT fk_camera_views_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.camera_views
    ADD CONSTRAINT fk_camera_views_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.cameras
    ADD CONSTRAINT fk_cameras_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY cameras.cameras
    ADD CONSTRAINT fk_cameras_nvr_id_nvrs FOREIGN KEY (nvr_id) REFERENCES cameras.nvrs(id) ON DELETE SET NULL;

ALTER TABLE ONLY cameras.cameras
    ADD CONSTRAINT fk_cameras_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.cameras
    ADD CONSTRAINT fk_cameras_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.evidence_archives
    ADD CONSTRAINT fk_evidence_archives_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.evidence_archives
    ADD CONSTRAINT fk_evidence_archives_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY cameras.evidence_archives
    ADD CONSTRAINT fk_evidence_archives_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.nvrs
    ADD CONSTRAINT fk_nvrs_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY cameras.nvrs
    ADD CONSTRAINT fk_nvrs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.nvrs
    ADD CONSTRAINT fk_nvrs_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.push_subscriptions
    ADD CONSTRAINT fk_push_subscriptions_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.push_subscriptions
    ADD CONSTRAINT fk_push_subscriptions_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.recording_schedule_templates
    ADD CONSTRAINT fk_recording_schedule_templates_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.recordings
    ADD CONSTRAINT fk_recordings_camera_id_cameras FOREIGN KEY (camera_id) REFERENCES cameras.cameras(id) ON DELETE CASCADE;

ALTER TABLE ONLY cameras.recordings
    ADD CONSTRAINT fk_recordings_nvr_id_nvrs FOREIGN KEY (nvr_id) REFERENCES cameras.nvrs(id) ON DELETE SET NULL;

ALTER TABLE ONLY cameras.recordings
    ADD CONSTRAINT fk_recordings_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.adapter_pending_changes
    ADD CONSTRAINT fk_adapter_pending_changes_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.adapter_pending_changes
    ADD CONSTRAINT fk_adapter_pending_changes_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.adapter_pending_changes
    ADD CONSTRAINT fk_adapter_pending_changes_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.api_keys
    ADD CONSTRAINT fk_api_keys_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.automation_executions
    ADD CONSTRAINT fk_automation_executions_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.automation_executions
    ADD CONSTRAINT fk_automation_executions_rule_id_automation_rules FOREIGN KEY (rule_id) REFERENCES core.automation_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.automation_rules
    ADD CONSTRAINT fk_automation_rules_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.automation_rules
    ADD CONSTRAINT fk_automation_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.config_templates
    ADD CONSTRAINT fk_config_templates_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.controllers
    ADD CONSTRAINT fk_controllers_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.credentials
    ADD CONSTRAINT fk_credentials_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.credentials
    ADD CONSTRAINT fk_credentials_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.custom_roles
    ADD CONSTRAINT fk_custom_roles_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.device_firmware_status
    ADD CONSTRAINT fk_device_firmware_status_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.device_firmware_status
    ADD CONSTRAINT fk_device_firmware_status_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.export_jobs
    ADD CONSTRAINT fk_export_jobs_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.export_jobs
    ADD CONSTRAINT fk_export_jobs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_images
    ADD CONSTRAINT fk_firmware_images_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_schedules
    ADD CONSTRAINT fk_firmware_schedules_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_schedules
    ADD CONSTRAINT fk_firmware_schedules_last_job_id_firmware_upgrade_jobs FOREIGN KEY (last_job_id) REFERENCES core.firmware_upgrade_jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_schedules
    ADD CONSTRAINT fk_firmware_schedules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_schedules
    ADD CONSTRAINT fk_firmware_schedules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_upgrade_jobs
    ADD CONSTRAINT fk_firmware_upgrade_jobs_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_upgrade_jobs
    ADD CONSTRAINT fk_firmware_upgrade_jobs_firmware_id_firmware_images FOREIGN KEY (firmware_id) REFERENCES core.firmware_images(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.firmware_upgrade_jobs
    ADD CONSTRAINT fk_firmware_upgrade_jobs_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.import_jobs
    ADD CONSTRAINT fk_import_jobs_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.import_jobs
    ADD CONSTRAINT fk_import_jobs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.in_app_notifications
    ADD CONSTRAINT fk_in_app_notifications_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.in_app_notifications
    ADD CONSTRAINT fk_in_app_notifications_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.installed_plugins
    ADD CONSTRAINT fk_installed_plugins_installed_by_users FOREIGN KEY (installed_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.integrations
    ADD CONSTRAINT fk_integrations_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.integrations
    ADD CONSTRAINT fk_integrations_webhook_id_webhooks FOREIGN KEY (webhook_id) REFERENCES core.webhooks(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.module_events
    ADD CONSTRAINT fk_module_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.module_events
    ADD CONSTRAINT fk_module_events_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.module_feature_flags
    ADD CONSTRAINT fk_module_feature_flags_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.notification_deliveries
    ADD CONSTRAINT fk_notification_deliveries_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.notification_deliveries
    ADD CONSTRAINT fk_notification_deliveries_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.notification_preferences
    ADD CONSTRAINT fk_notification_preferences_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.notification_providers
    ADD CONSTRAINT fk_notification_providers_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.oauth2_apps
    ADD CONSTRAINT fk_oauth2_apps_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.oauth2_apps
    ADD CONSTRAINT fk_oauth2_apps_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.oauth2_authorization_codes
    ADD CONSTRAINT fk_oauth2_authorization_codes_app_id_oauth2_apps FOREIGN KEY (app_id) REFERENCES core.oauth2_apps(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.oauth2_authorization_codes
    ADD CONSTRAINT fk_oauth2_authorization_codes_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.oauth2_tokens
    ADD CONSTRAINT fk_oauth2_tokens_app_id_oauth2_apps FOREIGN KEY (app_id) REFERENCES core.oauth2_apps(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.oauth2_tokens
    ADD CONSTRAINT fk_oauth2_tokens_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.organization_modules
    ADD CONSTRAINT fk_organization_modules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.plugin_organization_states
    ADD CONSTRAINT fk_plugin_organization_states_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.site_groups
    ADD CONSTRAINT fk_site_groups_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.site_groups
    ADD CONSTRAINT fk_site_groups_parent_id_site_groups FOREIGN KEY (parent_id) REFERENCES core.site_groups(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.sites
    ADD CONSTRAINT fk_sites_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sites
    ADD CONSTRAINT fk_sites_site_group_id_site_groups FOREIGN KEY (site_group_id) REFERENCES core.site_groups(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.sla_breaches
    ADD CONSTRAINT fk_sla_breaches_acknowledged_by_users FOREIGN KEY (acknowledged_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.sla_breaches
    ADD CONSTRAINT fk_sla_breaches_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sla_breaches
    ADD CONSTRAINT fk_sla_breaches_policy_id_sla_policies FOREIGN KEY (policy_id) REFERENCES core.sla_policies(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sla_policies
    ADD CONSTRAINT fk_sla_policies_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sla_snapshots
    ADD CONSTRAINT fk_sla_snapshots_policy_id_sla_policies FOREIGN KEY (policy_id) REFERENCES core.sla_policies(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sso_providers
    ADD CONSTRAINT fk_sso_providers_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sso_sessions
    ADD CONSTRAINT fk_sso_sessions_provider_id_sso_providers FOREIGN KEY (provider_id) REFERENCES core.sso_providers(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.sso_sessions
    ADD CONSTRAINT fk_sso_sessions_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.user_sessions
    ADD CONSTRAINT fk_user_sessions_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.user_site_access
    ADD CONSTRAINT fk_user_site_access_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.user_site_access
    ADD CONSTRAINT fk_user_site_access_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.users
    ADD CONSTRAINT fk_users_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.users
    ADD CONSTRAINT fk_users_sso_provider_id_sso_providers FOREIGN KEY (sso_provider_id) REFERENCES core.sso_providers(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.webhook_dead_letters
    ADD CONSTRAINT fk_webhook_dead_letters_delivery_id_webhook_deliveries FOREIGN KEY (delivery_id) REFERENCES core.webhook_deliveries(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.webhook_dead_letters
    ADD CONSTRAINT fk_webhook_dead_letters_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.webhook_dead_letters
    ADD CONSTRAINT fk_webhook_dead_letters_replayed_by_users FOREIGN KEY (replayed_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.webhook_dead_letters
    ADD CONSTRAINT fk_webhook_dead_letters_webhook_id_webhooks FOREIGN KEY (webhook_id) REFERENCES core.webhooks(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.webhook_deliveries
    ADD CONSTRAINT fk_webhook_deliveries_webhook_id_webhooks FOREIGN KEY (webhook_id) REFERENCES core.webhooks(id) ON DELETE CASCADE;

ALTER TABLE ONLY core.webhooks
    ADD CONSTRAINT fk_webhooks_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY core.webhooks
    ADD CONSTRAINT fk_webhooks_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.adoption_jobs
    ADD CONSTRAINT fk_adoption_jobs_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.adoption_jobs
    ADD CONSTRAINT fk_adoption_jobs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.adoption_jobs
    ADD CONSTRAINT fk_adoption_jobs_profile_id_provisioning_profiles FOREIGN KEY (profile_id) REFERENCES devices.provisioning_profiles(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.adoption_jobs
    ADD CONSTRAINT fk_adoption_jobs_rule_id_auto_adoption_rules FOREIGN KEY (rule_id) REFERENCES devices.auto_adoption_rules(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT fk_auto_adoption_rules_match_controller_id_controllers FOREIGN KEY (match_controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT fk_auto_adoption_rules_match_site_id_sites FOREIGN KEY (match_site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT fk_auto_adoption_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT fk_auto_adoption_rules_provisioning_profile_id_provisio_5dd1 FOREIGN KEY (provisioning_profile_id) REFERENCES devices.provisioning_profiles(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.auto_adoption_rules
    ADD CONSTRAINT fk_auto_adoption_rules_target_site_id_sites FOREIGN KEY (target_site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.bulk_operations
    ADD CONSTRAINT fk_bulk_operations_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id);

ALTER TABLE ONLY devices.bulk_operations
    ADD CONSTRAINT fk_bulk_operations_triggered_by_users FOREIGN KEY (triggered_by) REFERENCES core.users(id);

ALTER TABLE ONLY devices.device_clients
    ADD CONSTRAINT fk_device_clients_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_configs
    ADD CONSTRAINT fk_device_configs_desired_updated_by_users FOREIGN KEY (desired_updated_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.device_configs
    ADD CONSTRAINT fk_device_configs_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_configs
    ADD CONSTRAINT fk_device_configs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_group_members
    ADD CONSTRAINT fk_device_group_members_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_group_members
    ADD CONSTRAINT fk_device_group_members_group_id_device_groups FOREIGN KEY (group_id) REFERENCES devices.device_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_groups
    ADD CONSTRAINT fk_device_groups_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_groups
    ADD CONSTRAINT fk_device_groups_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_health
    ADD CONSTRAINT fk_device_health_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_health
    ADD CONSTRAINT fk_device_health_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_health
    ADD CONSTRAINT fk_device_health_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_lifecycle_log
    ADD CONSTRAINT fk_device_lifecycle_log_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_lifecycle_log
    ADD CONSTRAINT fk_device_lifecycle_log_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_lifecycle_log
    ADD CONSTRAINT fk_device_lifecycle_log_triggered_by_users FOREIGN KEY (triggered_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.device_ports
    ADD CONSTRAINT fk_device_ports_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.device_tags
    ADD CONSTRAINT fk_device_tags_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.devices
    ADD CONSTRAINT fk_devices_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.devices
    ADD CONSTRAINT fk_devices_credential_id_credentials FOREIGN KEY (credential_id) REFERENCES core.credentials(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.devices
    ADD CONSTRAINT fk_devices_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.discovered_hosts
    ADD CONSTRAINT fk_discovered_hosts_adopted_device_id_devices FOREIGN KEY (adopted_device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.discovered_hosts
    ADD CONSTRAINT fk_discovered_hosts_discovered_by_agent_id_remote_agents FOREIGN KEY (discovered_by_agent_id) REFERENCES agents.remote_agents(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.discovered_hosts
    ADD CONSTRAINT fk_discovered_hosts_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.discovered_hosts
    ADD CONSTRAINT fk_discovered_hosts_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT fk_mac_pre_registrations_adopted_device_id_devices FOREIGN KEY (adopted_device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT fk_mac_pre_registrations_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT fk_mac_pre_registrations_provisioning_profile_id_provis_ed67 FOREIGN KEY (provisioning_profile_id) REFERENCES devices.provisioning_profiles(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.mac_pre_registrations
    ADD CONSTRAINT fk_mac_pre_registrations_target_site_id_sites FOREIGN KEY (target_site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.poe_schedules
    ADD CONSTRAINT fk_poe_schedules_device_group_id_device_groups FOREIGN KEY (device_group_id) REFERENCES devices.device_groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.poe_schedules
    ADD CONSTRAINT fk_poe_schedules_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.poe_schedules
    ADD CONSTRAINT fk_poe_schedules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.provisioning_profiles
    ADD CONSTRAINT fk_provisioning_profiles_config_template_id_config_templates FOREIGN KEY (config_template_id) REFERENCES core.config_templates(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.provisioning_profiles
    ADD CONSTRAINT fk_provisioning_profiles_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.topology_edges
    ADD CONSTRAINT fk_topology_edges_discovered_by_agent_id_remote_agents FOREIGN KEY (discovered_by_agent_id) REFERENCES agents.remote_agents(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.topology_edges
    ADD CONSTRAINT fk_topology_edges_neighbor_device_id_devices FOREIGN KEY (neighbor_device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY devices.topology_edges
    ADD CONSTRAINT fk_topology_edges_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY devices.topology_edges
    ADD CONSTRAINT fk_topology_edges_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY enterprise.auto_backup_policies
    ADD CONSTRAINT fk_auto_backup_policies_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY enterprise.config_versions
    ADD CONSTRAINT fk_config_versions_created_by_users FOREIGN KEY (created_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY enterprise.config_versions
    ADD CONSTRAINT fk_config_versions_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY enterprise.config_versions
    ADD CONSTRAINT fk_config_versions_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY enterprise.health_daily_snapshots
    ADD CONSTRAINT fk_health_daily_snapshots_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id);

ALTER TABLE ONLY enterprise.health_daily_snapshots
    ADD CONSTRAINT fk_health_daily_snapshots_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id);

ALTER TABLE ONLY events.alert_rules
    ADD CONSTRAINT fk_alert_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_acknowledged_by_users FOREIGN KEY (acknowledged_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_resolved_by_users FOREIGN KEY (resolved_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_rule_id_alert_rules FOREIGN KEY (rule_id) REFERENCES events.alert_rules(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.alerts
    ADD CONSTRAINT fk_alerts_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.correlation_rules
    ADD CONSTRAINT fk_correlation_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.event_subscriptions
    ADD CONSTRAINT fk_event_subscriptions_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.incident_events
    ADD CONSTRAINT fk_incident_events_incident_id_incidents FOREIGN KEY (incident_id) REFERENCES events.incidents(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.incidents
    ADD CONSTRAINT fk_incidents_assigned_to_users FOREIGN KEY (assigned_to) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.incidents
    ADD CONSTRAINT fk_incidents_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY events.incidents
    ADD CONSTRAINT fk_incidents_rule_id_correlation_rules FOREIGN KEY (rule_id) REFERENCES events.correlation_rules(id) ON DELETE SET NULL;

ALTER TABLE ONLY events.incidents
    ADD CONSTRAINT fk_incidents_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY fabric.connection_runs
    ADD CONSTRAINT fk_connection_runs_connection_id_connections FOREIGN KEY (connection_id) REFERENCES fabric.connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY fabric.connection_runs
    ADD CONSTRAINT fk_connection_runs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY fabric.connections
    ADD CONSTRAINT fk_connections_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.devices
    ADD CONSTRAINT fk_devices_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.devices
    ADD CONSTRAINT fk_devices_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.gateway_connections
    ADD CONSTRAINT fk_gateway_connections_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.gateway_connections
    ADD CONSTRAINT fk_gateway_connections_org_id_organizations FOREIGN KEY (org_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.gateway_connections
    ADD CONSTRAINT fk_gateway_connections_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.gateway_sync_logs
    ADD CONSTRAINT fk_gateway_sync_logs_gateway_id_gateway_connections FOREIGN KEY (gateway_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.ids_alerts
    ADD CONSTRAINT fk_ids_alerts_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.logs
    ADD CONSTRAINT fk_logs_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.logs
    ADD CONSTRAINT fk_logs_rule_id_rules FOREIGN KEY (rule_id) REFERENCES firewall.rules(id) ON DELETE SET NULL;

ALTER TABLE ONLY firewall.nat_rules
    ADD CONSTRAINT fk_nat_rules_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.rules
    ADD CONSTRAINT fk_rules_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY firewall.vpn_tunnels
    ADD CONSTRAINT fk_vpn_tunnels_device_id_devices FOREIGN KEY (device_id) REFERENCES firewall.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_address_groups
    ADD CONSTRAINT fk_gw_canonical_address_groups_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_address_groups
    ADD CONSTRAINT fk_gw_canonical_address_groups_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_address_groups
    ADD CONSTRAINT fk_gw_canonical_address_groups_source_vlan_id_gw_canoni_d217 FOREIGN KEY (source_vlan_id) REFERENCES gateway.gw_canonical_vlans(id) ON DELETE SET NULL;

ALTER TABLE ONLY gateway.gw_canonical_dhcp_reservations
    ADD CONSTRAINT fk_gw_canonical_dhcp_reservations_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dhcp_reservations
    ADD CONSTRAINT fk_gw_canonical_dhcp_reservations_vlan_id_gw_canonical_vlans FOREIGN KEY (vlan_id) REFERENCES gateway.gw_canonical_vlans(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dhcp_scopes
    ADD CONSTRAINT fk_gw_canonical_dhcp_scopes_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dhcp_scopes
    ADD CONSTRAINT fk_gw_canonical_dhcp_scopes_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dhcp_scopes
    ADD CONSTRAINT fk_gw_canonical_dhcp_scopes_vlan_id_gw_canonical_vlans FOREIGN KEY (vlan_id) REFERENCES gateway.gw_canonical_vlans(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dns_records
    ADD CONSTRAINT fk_gw_canonical_dns_records_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_dns_records
    ADD CONSTRAINT fk_gw_canonical_dns_records_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT fk_gw_canonical_vlans_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT fk_gw_canonical_vlans_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT fk_gw_canonical_vlans_source_device_id_gateway_connections FOREIGN KEY (source_device_id) REFERENCES firewall.gateway_connections(id) ON DELETE SET NULL;

ALTER TABLE ONLY gateway.gw_canonical_vlans
    ADD CONSTRAINT fk_gw_canonical_vlans_template_id_gw_vlan_templates FOREIGN KEY (template_id) REFERENCES gateway.gw_vlan_templates(id) ON DELETE SET NULL;

ALTER TABLE ONLY gateway.gw_distribution_records
    ADD CONSTRAINT fk_gw_distribution_records_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_distribution_records
    ADD CONSTRAINT fk_gw_distribution_records_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_drift_events
    ADD CONSTRAINT fk_gw_drift_events_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_drift_events
    ADD CONSTRAINT fk_gw_drift_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_drift_events
    ADD CONSTRAINT fk_gw_drift_events_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_import_sessions
    ADD CONSTRAINT fk_gw_import_sessions_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_import_sessions
    ADD CONSTRAINT fk_gw_import_sessions_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_dhcp_leases
    ADD CONSTRAINT fk_gw_imported_dhcp_leases_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_dhcp_leases
    ADD CONSTRAINT fk_gw_imported_dhcp_leases_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_dhcp_leases
    ADD CONSTRAINT fk_gw_imported_dhcp_leases_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_firewall_rules
    ADD CONSTRAINT fk_gw_imported_firewall_rules_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_firewall_rules
    ADD CONSTRAINT fk_gw_imported_firewall_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_firewall_rules
    ADD CONSTRAINT fk_gw_imported_firewall_rules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_ids_events
    ADD CONSTRAINT fk_gw_imported_ids_events_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_ids_events
    ADD CONSTRAINT fk_gw_imported_ids_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_ids_events
    ADD CONSTRAINT fk_gw_imported_ids_events_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_interfaces
    ADD CONSTRAINT fk_gw_imported_interfaces_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_interfaces
    ADD CONSTRAINT fk_gw_imported_interfaces_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_interfaces
    ADD CONSTRAINT fk_gw_imported_interfaces_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_nat_rules
    ADD CONSTRAINT fk_gw_imported_nat_rules_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_nat_rules
    ADD CONSTRAINT fk_gw_imported_nat_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_nat_rules
    ADD CONSTRAINT fk_gw_imported_nat_rules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_vpn_tunnels
    ADD CONSTRAINT fk_gw_imported_vpn_tunnels_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_vpn_tunnels
    ADD CONSTRAINT fk_gw_imported_vpn_tunnels_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_imported_vpn_tunnels
    ADD CONSTRAINT fk_gw_imported_vpn_tunnels_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_site_role_assignments
    ADD CONSTRAINT fk_gw_site_role_assignments_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_site_role_assignments
    ADD CONSTRAINT fk_gw_site_role_assignments_gateway_id_gateway_connections FOREIGN KEY (gateway_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_site_role_assignments
    ADD CONSTRAINT fk_gw_site_role_assignments_role_map_id_gw_site_role_maps FOREIGN KEY (role_map_id) REFERENCES gateway.gw_site_role_maps(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_site_role_maps
    ADD CONSTRAINT fk_gw_site_role_maps_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_site_role_maps
    ADD CONSTRAINT fk_gw_site_role_maps_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_suppression_rules
    ADD CONSTRAINT fk_gw_suppression_rules_device_id_gateway_connections FOREIGN KEY (device_id) REFERENCES firewall.gateway_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_suppression_rules
    ADD CONSTRAINT fk_gw_suppression_rules_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_suppression_rules
    ADD CONSTRAINT fk_gw_suppression_rules_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY gateway.gw_vlan_templates
    ADD CONSTRAINT fk_gw_vlan_templates_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY hypervisor.proxmox_nodes
    ADD CONSTRAINT fk_proxmox_nodes_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY hypervisor.proxmox_nodes
    ADD CONSTRAINT fk_proxmox_nodes_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY hypervisor.virtual_machines
    ADD CONSTRAINT fk_virtual_machines_node_id_proxmox_nodes FOREIGN KEY (node_id) REFERENCES hypervisor.proxmox_nodes(id) ON DELETE CASCADE;

ALTER TABLE ONLY hypervisor.virtual_machines
    ADD CONSTRAINT fk_virtual_machines_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.client_roaming_events
    ADD CONSTRAINT fk_client_roaming_events_from_device_id_devices FOREIGN KEY (from_device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.client_roaming_events
    ADD CONSTRAINT fk_client_roaming_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.client_roaming_events
    ADD CONSTRAINT fk_client_roaming_events_to_device_id_devices FOREIGN KEY (to_device_id) REFERENCES devices.devices(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.dot1x_auth_events
    ADD CONSTRAINT fk_dot1x_auth_events_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.dot1x_auth_events
    ADD CONSTRAINT fk_dot1x_auth_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.dot1x_auth_events
    ADD CONSTRAINT fk_dot1x_auth_events_radius_profile_id_radius_server_profiles FOREIGN KEY (radius_profile_id) REFERENCES network.radius_server_profiles(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.dot1x_port_configs
    ADD CONSTRAINT fk_dot1x_port_configs_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.dot1x_port_configs
    ADD CONSTRAINT fk_dot1x_port_configs_port_profile_id_port_profiles FOREIGN KEY (port_profile_id) REFERENCES network.port_profiles(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.dot1x_port_configs
    ADD CONSTRAINT fk_dot1x_port_configs_radius_profile_id_radius_server_profiles FOREIGN KEY (radius_profile_id) REFERENCES network.radius_server_profiles(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.dot1x_port_configs
    ADD CONSTRAINT fk_dot1x_port_configs_wifi_network_id_wifi_networks FOREIGN KEY (wifi_network_id) REFERENCES network.wifi_networks(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.link_aggregation_groups
    ADD CONSTRAINT fk_link_aggregation_groups_device_id_devices FOREIGN KEY (device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.port_profiles
    ADD CONSTRAINT fk_port_profiles_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.port_profiles
    ADD CONSTRAINT fk_port_profiles_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.radius_server_profiles
    ADD CONSTRAINT fk_radius_server_profiles_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.topology_layouts
    ADD CONSTRAINT fk_topology_layouts_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.topology_layouts
    ADD CONSTRAINT fk_topology_layouts_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.topology_links
    ADD CONSTRAINT fk_topology_links_source_device_id_devices FOREIGN KEY (source_device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.topology_links
    ADD CONSTRAINT fk_topology_links_target_device_id_devices FOREIGN KEY (target_device_id) REFERENCES devices.devices(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.vlans
    ADD CONSTRAINT fk_vlans_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.vlans
    ADD CONSTRAINT fk_vlans_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY network.wifi_networks
    ADD CONSTRAINT fk_wifi_networks_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY network.wifi_networks
    ADD CONSTRAINT fk_wifi_networks_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.call_logs
    ADD CONSTRAINT fk_call_logs_pbx_id_pbx FOREIGN KEY (pbx_id) REFERENCES voip.pbx(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.config_templates
    ADD CONSTRAINT fk_config_templates_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.discovery_scans
    ADD CONSTRAINT fk_discovery_scans_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.discovery_scans
    ADD CONSTRAINT fk_discovery_scans_triggered_by_users FOREIGN KEY (triggered_by) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.extensions
    ADD CONSTRAINT fk_extensions_pbx_id_pbx FOREIGN KEY (pbx_id) REFERENCES voip.pbx(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.extensions
    ADD CONSTRAINT fk_extensions_user_id_users FOREIGN KEY (user_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.firmware_tracks
    ADD CONSTRAINT fk_firmware_tracks_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.pbx
    ADD CONSTRAINT fk_pbx_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT fk_phones_config_template_id_config_templates FOREIGN KEY (config_template_id) REFERENCES voip.config_templates(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT fk_phones_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT fk_phones_extension_id_extensions FOREIGN KEY (extension_id) REFERENCES voip.extensions(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT fk_phones_pbx_id_pbx FOREIGN KEY (pbx_id) REFERENCES voip.pbx(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.phones
    ADD CONSTRAINT fk_phones_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.ring_groups
    ADD CONSTRAINT fk_ring_groups_pbx_id_pbx FOREIGN KEY (pbx_id) REFERENCES voip.pbx(id) ON DELETE CASCADE;

ALTER TABLE ONLY voip.voicemail_messages
    ADD CONSTRAINT fk_voicemail_messages_extension_id_extensions FOREIGN KEY (extension_id) REFERENCES voip.extensions(id) ON DELETE SET NULL;

ALTER TABLE ONLY voip.voicemail_messages
    ADD CONSTRAINT fk_voicemail_messages_pbx_id_pbx FOREIGN KEY (pbx_id) REFERENCES voip.pbx(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT fk_site_to_site_tunnels_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT fk_site_to_site_tunnels_site_a_id_sites FOREIGN KEY (site_a_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT fk_site_to_site_tunnels_site_b_id_sites FOREIGN KEY (site_b_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.site_to_site_tunnels
    ADD CONSTRAINT fk_site_to_site_tunnels_template_id_vpn_tunnel_templates FOREIGN KEY (template_id) REFERENCES vpn.vpn_tunnel_templates(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.site_vpn_configs
    ADD CONSTRAINT fk_site_vpn_configs_controller_id_controllers FOREIGN KEY (controller_id) REFERENCES core.controllers(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.site_vpn_configs
    ADD CONSTRAINT fk_site_vpn_configs_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.site_vpn_configs
    ADD CONSTRAINT fk_site_vpn_configs_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT fk_vpn_events_actor_id_users FOREIGN KEY (actor_id) REFERENCES core.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT fk_vpn_events_connection_id_vpn_connections FOREIGN KEY (connection_id) REFERENCES vpn.vpn_connections(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT fk_vpn_events_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT fk_vpn_events_site_id_sites FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.vpn_events
    ADD CONSTRAINT fk_vpn_events_tunnel_id_site_to_site_tunnels FOREIGN KEY (tunnel_id) REFERENCES vpn.site_to_site_tunnels(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.vpn_reconnect_state
    ADD CONSTRAINT fk_vpn_reconnect_state_connection_id_vpn_connections FOREIGN KEY (connection_id) REFERENCES vpn.vpn_connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY vpn.vpn_reconnect_state
    ADD CONSTRAINT fk_vpn_reconnect_state_site_vpn_config_id_site_vpn_configs FOREIGN KEY (site_vpn_config_id) REFERENCES vpn.site_vpn_configs(id) ON DELETE SET NULL;

ALTER TABLE ONLY vpn.vpn_tunnel_templates
    ADD CONSTRAINT fk_vpn_tunnel_templates_organization_id_organizations FOREIGN KEY (organization_id) REFERENCES core.organizations(id) ON DELETE CASCADE;
