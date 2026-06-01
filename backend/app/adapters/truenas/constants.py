# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""TrueNAS adapter constants — endpoint paths and limits.

TrueNAS exposes a stable REST API at ``/api/v2.0/`` on both SCALE
and CORE. Endpoints used by the read-only foundation are listed
here so the client + tests can share a single source of truth.

NOTE on auth: TrueNAS supports two auth modes:

  1. API key in ``Authorization: Bearer <key>`` header — preferred
     for service-to-service (key is generated in Settings → API Keys).
  2. Username + password basic auth — works but ties the integration
     to a UI account and bypasses key revocation policy.

This adapter accepts both via the BaseAdapter ``password`` slot. If
``api_key`` is provided in the kwargs dict, the client uses Bearer
auth; otherwise it falls back to HTTP Basic with username + password.
"""

from __future__ import annotations

# Base path — versioned. v2.0 has been the stable surface since
# FreeNAS 11.3; v3.0 is in development on SCALE but not GA.
API_BASE = "/api/v2.0"

# Read-only endpoint paths (no trailing slash — httpx handles that).
EP_SYSTEM_INFO = f"{API_BASE}/system/info"
EP_SYSTEM_STATE = f"{API_BASE}/system/state"
EP_POOL = f"{API_BASE}/pool"
EP_DATASET = f"{API_BASE}/pool/dataset"
EP_SNAPSHOT = f"{API_BASE}/zfs/snapshot"
EP_DISK = f"{API_BASE}/disk"
EP_SHARING_NFS = f"{API_BASE}/sharing/nfs"
EP_SHARING_SMB = f"{API_BASE}/sharing/smb"

# Auth probe — cheapest authenticated GET available.
EP_AUTH_CHECK = f"{API_BASE}/system/state"

# ---------------------------------------------------------------------------
# WebSocket JSON-RPC API (TrueNAS 25.04+ / 26.0)
# ---------------------------------------------------------------------------
# 25.04 (Fangtooth) deprecated REST v2.0; 25.10 / 26.0 removed it
# (``/api/v2.0/*`` → 404). The supported surface is a JSON-RPC 2.0 API
# over a WebSocket at ``/api/current``. NOTE: API keys MUST be used over
# ``wss://`` — TrueNAS auto-revokes a key the moment it's seen on a
# plaintext (``ws://``) connection, so the WS client is TLS-only.
WS_PATH = "/api/current"

# JSON-RPC method names (read-only surface). Query methods take
# ``[query-filters, query-options]``; we pass ``[]`` for "all".
WS_METHOD_SYSTEM_INFO = "system.info"
WS_METHOD_POOLS = "pool.query"
WS_METHOD_DATASETS = "pool.dataset.query"
WS_METHOD_DISKS = "disk.query"
WS_METHOD_SNAPSHOTS = "pool.snapshot.query"
WS_METHOD_SNAPSHOTS_LEGACY = "zfs.snapshot.query"  # pre-25.x method name
# Richer health surface (25.x):
WS_METHOD_ALERTS = "alert.list"
WS_METHOD_DISK_TEMPS = "disk.temperatures"
WS_METHOD_SERVICES = "service.query"
WS_METHOD_SNAPSHOT_TASKS = "pool.snapshottask.query"
WS_METHOD_REPLICATION = "replication.query"
WS_METHOD_CLOUDSYNC = "cloudsync.query"

# ---------------------------------------------------------------------------
# Write surface (v2 — Fabric storage.store_blob).
# ---------------------------------------------------------------------------
# Uploading a file to a dataset is a JOB on SCALE 25.04+/26.0: the bytes are
# streamed over a separate multipart HTTPS POST to ``/_upload`` whose ``data``
# field carries ``{"method": "filesystem.put", "params": [path, opts]}``; the
# POST creates+runs the job and returns its id, which we then poll over WS via
# ``core.get_jobs`` until it leaves the RUNNING/WAITING state. (Verified live
# against S4 / TrueNAS 26.0: ``filesystem.put`` is present with ``job=True``.)
WS_METHOD_FILESYSTEM_PUT = "filesystem.put"
WS_METHOD_CORE_GET_JOBS = "core.get_jobs"
UPLOAD_PATH = "/_upload"
# Job-completion polling (seconds). A snapshot JPEG is small, but the appliance
# may be busy; cap the wait so a stuck job surfaces as a timeout, not a hang.
JOB_POLL_INTERVAL_SEC = 1.0
JOB_POLL_TIMEOUT_SEC = 120.0
# The /_upload multipart POST streams the whole blob, so it needs a MUCH longer
# ceiling than the 30s WS read timeout — a multi-MB blob over a slow link can
# legitimately take minutes. Independent so a slow upload doesn't trip the WS
# read budget (and orphan a half-created job).
UPLOAD_POST_TIMEOUT_SEC = 300.0

# Response size cap — pool/dataset listings on a large appliance with
# hundreds of datasets + many snapshots can be sizable. 50 MB matches
# the headroom Proxmox + OpenWrt clients give for the same reason.
MAX_RESPONSE_BYTES = 50 * 1024 * 1024

# HTTP timeouts (seconds). Connect timeout is shorter than read
# because TrueNAS can be slow to respond on a populated pool listing
# but should accept the TCP handshake immediately.
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 30.0

# Circuit breaker — same defaults as the OpenWrt/Proxmox clients so
# operators see consistent breaker behavior across adapters.
BREAKER_FAILURE_THRESHOLD = 5
BREAKER_RESET_TIMEOUT_SEC = 60.0
