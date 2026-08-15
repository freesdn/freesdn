# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — TrueNAS Storage Adapter (read-only foundation).

BaseAdapter implementation for TrueNAS SCALE / CORE. v1 is read-only:
the adapter surfaces system identity, ZFS pool/dataset/snapshot/disk
inventory, and per-pool health. Writes (dataset CRUD, snapshot
rollback, share toggle) are deferred to a follow-up chapter.

Domains exposed v1:
  System     — version, hostname, uptime
  Storage    — pools (ONLINE/DEGRADED), datasets, snapshots, disks
  Inventory  — total / used / free per pool, encryption + lock state
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
)
from app.adapters.truenas.client import TrueNASClient
from app.adapters.truenas.models import (
    Dataset,
    Disk,
    Pool,
    Snapshot,
    SystemInfo,
    parse_dataset,
    parse_disk,
    parse_pool,
    parse_snapshot,
)
from app.adapters.truenas.ws_client import TrueNASWSClient

logger = logging.getLogger(__name__)

# ZFS path / filename safety for the write surface. Destinations MUST live under
# ``/mnt`` and every segment is a conservative allow-list (letters, digits, and
# ``. _ -``) — defeats traversal (``..``), absolute escapes, and shell/whitespace
# metacharacters smuggled through a staged payload.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_PATH = 1024
_MAX_FILENAME = 255


def _validate_mnt_path(path: str) -> str:
    p = (path or "").strip().rstrip("/")
    if not p or len(p) > _MAX_PATH or not p.startswith("/mnt/"):
        raise AdapterError(f"invalid dataset path (must be under /mnt): {path!r}")
    if ".." in p:
        raise AdapterError(f"dataset path may not contain '..': {path!r}")
    segments = p[len("/mnt/") :].split("/")
    if not segments or any(not _SEGMENT_RE.match(seg) for seg in segments):
        raise AdapterError(f"dataset path has an unsafe segment: {path!r}")
    return p


def _validate_filename(name: str) -> str:
    n = (name or "").strip()
    if not n or len(n) > _MAX_FILENAME or "/" in n or "\\" in n or ".." in n:
        raise AdapterError(f"invalid filename: {name!r}")
    if not _SEGMENT_RE.match(n):
        raise AdapterError(f"unsafe filename: {name!r}")
    return n


class TrueNASAdapter(BaseAdapter):
    """Read-only adapter for TrueNAS storage appliances.

    Auth precedence — pass ``api_key`` via kwargs to use Bearer auth
    (preferred). Falls back to HTTP Basic with ``username`` /
    ``password`` from the BaseAdapter slots.

    Example::

        async with TrueNASAdapter(
            host="truenas.lab", username="root", password="",
            api_key="1-abc...", verify_ssl=False,
        ) as nas:
            info = await nas.get_system_info()
            pools = await nas.list_pools()
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="truenas",
        name="TrueNAS Storage",
        vendor="iXsystems",
        version="1.0.0",
        description=(
            "TrueNAS SCALE / CORE — read-only ZFS storage inventory (write surface deferred to v2)"
        ),
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        # SCALE 22.12+ (Bluefin/Cobia/Dragonfish/ElectricEel) over REST
        # v2.0, plus Fangtooth 25.04 / 25.10 / 26.0 over the WebSocket
        # JSON-RPC API; CORE 13.0+ over REST. The adapter auto-selects
        # the transport on connect.
        supported_versions=[
            "22.12",
            "23.10",
            "24.04",
            "24.10",
            "25.04",
            "25.10",
            "26.0",
            "13.0",
            "13.1",
        ],
        device_types={
            "storage": DeviceTypeCapabilities(
                module="backup",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_BACKUP,
                    Capability.DEVICE_LOGS,
                ],
                models=["TrueNAS*", "FreeNAS*", "*"],
            ),
        },
        auth_methods=["api_key", "username_password"],
        # TrueNAS tolerates more polling than network controllers —
        # but its REST handler is single-threaded so we keep concurrency
        # low (≤2) to avoid head-of-line blocking on big pool listings.
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=2,
        default_sync_interval=300,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=False,
    )

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host, username, password, **kwargs)
        # Connection params shared by both transports; the live client
        # is selected on connect() (WS for 25.04+, REST for legacy).
        self._conn_params: dict[str, Any] = {
            "host": host,
            "username": username,
            "password": password,
            "api_key": kwargs.get("api_key"),
            "port": kwargs.get("port", 443),
            "verify_ssl": kwargs.get("verify_ssl", False),
            "timeout": kwargs.get("timeout"),
        }
        # Populated on connect(); tests may inject a mock here directly.
        self._api: Any = None
        self._transport: str | None = None

    # ------------------------------------------------------------------
    # BaseAdapter — required
    # ------------------------------------------------------------------

    async def _open_transport(self) -> Any:
        """Pick the live transport: modern WS JSON-RPC, REST fallback.

        TrueNAS 25.04+ / 26.0 only expose the JSON-RPC-over-WebSocket
        API at ``/api/current``; the REST v2.0 surface is gone. Older
        boxes (≤24.10 / CORE 13.x) only have REST. We try WS first and
        fall back to REST when the WS endpoint is *unreachable* — but an
        auth failure on a reachable WS endpoint is surfaced as-is, not
        masked by a doomed REST retry.
        """
        ws = TrueNASWSClient(**self._conn_params)
        try:
            await ws.connect()
            self._transport = "ws"
            return ws
        except AdapterAuthenticationError:
            await ws.disconnect()
            raise
        except AdapterConnectionError:
            # WS endpoint not present/reachable → legacy REST box.
            await ws.disconnect()
            logger.debug(
                "TrueNAS %s: WS API unavailable, falling back to REST",
                self._conn_params.get("host"),
            )
            rest = TrueNASClient(**self._conn_params)
            await rest.connect()
            self._transport = "rest"
            return rest

    async def connect(self) -> bool:
        if self._api is None:
            self._api = await self._open_transport()
        else:
            # Injected/pre-built client (tests, or an explicit transport).
            await self._api.connect()
        self._connected = True
        return True

    async def disconnect(self) -> None:
        if self._api is not None:
            await self._api.disconnect()
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        """Cheap auth + reachability probe.

        Used by ``/controllers/{id}/test`` to confirm the credential is
        live before saving. We don't fetch pool data here — the auth
        probe in ``connect`` is enough. ``connect`` selects the live
        transport (WS for 25.04+, REST for legacy).
        """
        try:
            await self.connect()
            info = await self._api.get_system_info()
            await self.disconnect()
            return AdapterResult.ok(
                data={
                    "version": info.get("version", ""),
                    "hostname": info.get("hostname", ""),
                },
                message="TrueNAS connection OK",
            )
        except AdapterAuthenticationError as exc:
            return AdapterResult.fail(
                f"TrueNAS auth failed: {exc}",
                error_code="AUTH",
            )
        except AdapterConnectionError as exc:
            return AdapterResult.fail(
                f"TrueNAS unreachable: {exc}",
                error_code="UNREACHABLE",
            )
        except Exception as exc:  # noqa: BLE001 — surface to caller
            return AdapterResult.fail(
                f"TrueNAS test failed: {exc}",
                error_code="UNKNOWN",
            )

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """The appliance itself is a single discovered device.

        TrueNAS doesn't manage other devices — it IS the device. We
        emit one ``DiscoveredDevice`` representing the appliance so
        site-level discovery can attach it to the site without
        special-casing storage in the discovery service.
        """
        try:
            info = await self._api.get_system_info()
        except Exception as exc:
            logger.warning("TrueNAS discover_devices failed: %s", exc)
            return []

        return [
            DiscoveredDevice(
                # TrueNAS doesn't expose a single canonical MAC — the
                # serial works as the unique identifier downstream.
                mac_address=str(info.get("system_serial") or "")[:17],
                ip_address=None,  # caller sets this from controller record
                name=str(info.get("hostname") or "truenas"),
                vendor="iXsystems",
                model=str(info.get("system_product") or "TrueNAS"),
                firmware_version=str(info.get("version") or ""),
                device_type="storage",
                status="online",
                serial_number=str(info.get("system_serial") or ""),
                raw_data=info,
            ),
        ]

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Return high-level appliance health.

        ``device_id`` is ignored — TrueNAS is a single appliance and
        the controller record already identifies which one.
        """
        try:
            info = await self._api.get_system_info()
            pools = await self._api.list_pools()
        except AdapterAuthenticationError as exc:
            # Credential revoked/expired — distinct from pool-health "error"
            # so the dashboard prompts a re-auth instead of treating it as a
            # transient appliance fault. Mirrors test_connection()'s AUTH path.
            return {"status": "auth_failed", "error": str(exc)}
        except AdapterConnectionError as exc:
            # Appliance unreachable — a connectivity signal, not a health fault.
            return {"status": "unreachable", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 — any other failure is a generic error
            return {"status": "error", "error": str(exc)}

        # Pool health rollup — DEGRADED on any pool drops the appliance
        # to "warning"; OFFLINE/FAULTED to "error". Mirrors the way the
        # Proxmox adapter rolls up node health from nodes.
        worst = "ok"
        for raw in pools:
            status = (raw.get("status") or "").upper()
            if status in ("FAULTED", "OFFLINE", "REMOVED"):
                worst = "error"
                break
            if status in ("DEGRADED", "UNAVAIL"):
                worst = "warning"

        return {
            "status": worst,
            "hostname": info.get("hostname", ""),
            "version": info.get("version", ""),
            "pool_count": len(pools),
        }

    async def get_device_info(
        self,
        device_id: str | None = None,
    ) -> DiscoveredDevice | None:
        """Return the single discovered-device record for this appliance."""
        devs = await self.discover_devices()
        return devs[0] if devs else None

    # ------------------------------------------------------------------
    # TrueNAS-specific read API (normalized)
    # ------------------------------------------------------------------

    async def get_system_info_model(self) -> SystemInfo:
        """Strongly-typed ``/system/info``."""
        return SystemInfo(**await self._api.get_system_info())

    async def get_pools(self) -> list[Pool]:
        """List ZFS pools with usage + health, normalized."""
        return [parse_pool(p) for p in await self._api.list_pools()]

    async def get_datasets(self) -> list[Dataset]:
        """List ZFS datasets, normalized."""
        return [parse_dataset(d) for d in await self._api.list_datasets()]

    async def get_snapshots(self) -> list[Snapshot]:
        """List ZFS snapshots, normalized."""
        return [parse_snapshot(s) for s in await self._api.list_snapshots()]

    async def get_disks(self) -> list[Disk]:
        """List physical disks, normalized."""
        return [parse_disk(d) for d in await self._api.list_disks()]

    # ------------------------------------------------------------------
    # Richer health surface (WS API 25.x). Each wrapper degrades to an
    # empty result if the active transport doesn't expose it (e.g. the
    # REST fallback for legacy boxes) or the call fails transiently — a
    # missing alert feed must never fail the whole storage view.
    # ------------------------------------------------------------------

    async def get_alerts(self) -> list[dict[str, Any]]:
        """Active (non-dismissed) appliance alerts, normalized.

        ``datetime`` arrives as a ``{"$date": ms}`` wrapper; we flatten it
        to epoch ms so the FE can format it.
        """
        fn = getattr(self._api, "list_alerts", None)
        if fn is None:
            return []
        try:
            raw = await fn()
        except Exception as exc:  # noqa: BLE001 — never fail the view on alerts
            logger.debug("TrueNAS get_alerts failed: %s", exc)
            return []

        out: list[dict[str, Any]] = []
        for a in raw:
            if not isinstance(a, dict) or a.get("dismissed"):
                continue
            dt = a.get("datetime")
            at_ms = dt.get("$date") if isinstance(dt, dict) else dt
            out.append(
                {
                    "level": str(a.get("level") or "INFO"),
                    "klass": str(a.get("klass") or ""),
                    "message": str(a.get("formatted") or a.get("text") or ""),
                    "at_ms": int(at_ms) if isinstance(at_ms, (int, float)) else None,
                    "one_shot": bool(a.get("one_shot", False)),
                }
            )
        return out

    async def get_disk_temperatures(self) -> dict[str, float]:
        """Per-disk temperatures in °C, keyed by device name."""
        fn = getattr(self._api, "disk_temperatures", None)
        if fn is None:
            return {}
        try:
            data = await fn()
        except Exception as exc:  # noqa: BLE001
            logger.debug("TrueNAS get_disk_temperatures failed: %s", exc)
            return {}
        return {str(k): float(v) for k, v in (data or {}).items() if isinstance(v, (int, float))}

    async def get_services(self) -> list[dict[str, Any]]:
        """Service state (SMB/NFS/iSCSI/SSH/…), normalized."""
        fn = getattr(self._api, "list_services", None)
        if fn is None:
            return []
        try:
            raw = await fn()
        except Exception as exc:  # noqa: BLE001
            logger.debug("TrueNAS get_services failed: %s", exc)
            return []
        return [
            {
                "service": str(s.get("service") or ""),
                "state": str(s.get("state") or ""),
                "enabled": bool(s.get("enable", False)),
            }
            for s in raw
            if isinstance(s, dict)
        ]

    async def get_data_protection(self) -> dict[str, int]:
        """Configured data-protection task counts (coverage signal)."""
        fn = getattr(self._api, "data_protection_counts", None)
        if fn is None:
            return {"snapshot_tasks": 0, "replication": 0, "cloudsync": 0}
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001
            logger.debug("TrueNAS get_data_protection failed: %s", exc)
            return {"snapshot_tasks": 0, "replication": 0, "cloudsync": 0}

    # ------------------------------------------------------------------
    # Write surface (v2) — reached ONLY through the staged-change apply
    # path (dual-gate + operator sign-off). The ``force`` gate is a
    # client-side backstop so no non-staged code path can ever write.
    # ------------------------------------------------------------------

    async def upload_file(
        self,
        *,
        dataset_path: str,
        filename: str,
        blob: bytes,
        force: bool = False,
        mode: int | None = None,
    ) -> dict[str, Any]:
        """Upload ``blob`` as ``filename`` into ``dataset_path`` on the appliance.

        Writes only happen when ``force=True`` (passed exclusively by the
        staged-apply path after the dual-gate). Validates the destination is a
        ``/mnt`` path with safe segments (no traversal) and a separator-free
        filename, then drives the two-channel ``filesystem.put`` job and waits
        for it to settle. Raises :class:`AdapterError` on a refused gate, an
        unsafe path, a non-WS transport, or a failed job.
        """
        if not force:
            raise AdapterError("TrueNAS write refused: staging force-gate not set")
        if self._transport != "ws" or not hasattr(self._api, "upload_blob"):
            raise AdapterError("TrueNAS upload requires the WS JSON-RPC transport (25.04+)")

        dest_dir = _validate_mnt_path(dataset_path)
        safe_name = _validate_filename(filename)
        if not blob:
            raise AdapterError("refusing to upload an empty blob")

        dest = f"{dest_dir}/{safe_name}"
        job_id = await self._api.upload_blob(dest_path=dest, blob=blob, mode=mode)
        status = await self._api.job_wait(job_id)
        state = str(status.get("state") or "").upper()
        if state != "SUCCESS":
            err = status.get("error") or status.get("exception") or state
            raise AdapterError(f"TrueNAS upload job {job_id} did not succeed: {err}")
        return {"job_id": job_id, "path": dest, "size": len(blob), "state": state}
