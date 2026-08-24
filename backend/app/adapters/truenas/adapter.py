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

    # ------------------------------------------------------------------
    # Data plane — TrueNAS as a backup destination
    # ------------------------------------------------------------------
    #
    # These deliberately do NOT carry the ``force`` gate that ``upload_file``
    # does, and the distinction is the whole point rather than a shortcut.
    #
    # ``upload_file`` is reached from the Fabric staged-apply path: an
    # automation or a connection decides to write to an appliance, and the
    # operator has not necessarily seen it. The dual gate exists so that class
    # of write cannot happen unreviewed.
    #
    # These are reached only when an operator has explicitly created a
    # StorageLocation pointing at this appliance and a dataset -- the same act
    # of authorisation as configuring an S3 bucket or an SFTP host, which no
    # one routes through device staging either. Nothing here mutates appliance
    # CONFIGURATION; they read, size, write and remove files inside a dataset
    # the operator nominated.
    #
    # Keeping them separate is what preserves the invariant. ``force=True``
    # still arrives at ``upload_file`` from exactly one place, and a test
    # asserts it.

    async def put_data_file(
        self, *, dataset_path: str, filename: str, blob: bytes
    ) -> dict[str, Any]:
        """Write a backup artifact into an operator-nominated dataset."""
        return await self._data_plane_write(dataset_path, filename, blob)

    async def get_data_file(self, *, dataset_path: str, filename: str) -> bytes:
        """Read a backup artifact back. The half that makes this a destination."""
        api = self._require_ws()
        return await api.download_blob(self._safe_join(dataset_path, filename))

    async def stat_data_file(self, *, dataset_path: str, filename: str) -> dict[str, Any] | None:
        """Size and metadata, or None when it is not there."""
        api = self._require_ws()
        return await api.stat_path(self._safe_join(dataset_path, filename))

    async def delete_data_file(self, *, dataset_path: str, filename: str) -> bool:
        """Remove an artifact. False when there was nothing to remove."""
        api = self._require_ws()
        return await api.unlink_path(self._safe_join(dataset_path, filename))

    def _require_ws(self) -> Any:
        """The data plane is WS-only, and says so rather than half-working.

        ``filesystem.get`` / ``stat`` / ``unlink`` are middleware calls that the
        retired REST v2.0 surface never exposed the same way. A legacy box
        (<=24.10 / CORE 13.x) can still be MONITORED over REST -- it just
        cannot be a backup destination, and an operator needs that as a clear
        refusal at configuration time rather than a restore that fails later.
        """
        if self._transport != "ws" or self._api is None:
            raise AdapterError(
                "TrueNAS backup storage requires the WS JSON-RPC API (SCALE 25.04+); "
                "this appliance answered on the legacy REST surface"
            )
        return self._api

    @staticmethod
    def _safe_join(dataset_path: str, filename: str) -> str:
        """Join and validate, with the same rules the staged upload uses.

        Backup filenames are generated, not typed -- but they are built from a
        backup id and a date prefix, and "generated" is exactly what people say
        about the input right before it turns out to be operator-controlled
        somewhere upstream.
        """
        from app.services.adapter_truenas_storage import (
            _validate_dataset_path,
            _validate_filename,
        )

        base = _validate_dataset_path(dataset_path)
        # A date prefix is a path, not a name: validate each segment, then the
        # leaf as a filename.
        *dirs, leaf = filename.split("/")
        for segment in dirs:
            if not segment or segment in (".", "..") or "\\" in segment:
                raise AdapterError(f"TrueNAS: unsafe path segment {segment!r}")
        return f"{base.rstrip('/')}/{'/'.join([*dirs, _validate_filename(leaf)])}"

    async def ensure_data_dir(self, *, dataset_path: str, subdir: str) -> bool:
        """Create the date-prefixed directory a backup lands in."""
        api = self._require_ws()
        from app.services.adapter_truenas_storage import _validate_dataset_path

        base = _validate_dataset_path(dataset_path).rstrip("/")
        created = False
        parts = [p for p in subdir.split("/") if p]
        for i in range(len(parts)):
            segment = "/".join(parts[: i + 1])
            if any(p in (".", "..") for p in parts):
                raise AdapterError(f"TrueNAS: unsafe directory {subdir!r}")
            created = await api.mkdir_path(f"{base}/{segment}") or created
        return created

    async def ensure_backup_dataset(self, *, base_dataset_path: str, backup_id: str) -> str:
        """Create the per-backup child dataset and return its ZFS name.

        Each backup gets its own dataset so it can be pruned by destroying the
        dataset -- the TrueNAS middleware has no file-delete, but
        ``pool.dataset.delete`` exists. Verified live on 26.0.

        Returns the ZFS name (``s4_hdd/freesdn_test/<id>``); the file goes into
        its auto-mount at ``/mnt/<that>``.
        """
        api = self._require_ws()
        child = self._backup_child_name(base_dataset_path, backup_id)
        from app.adapters.truenas.client import TrueNASAPIError

        try:
            await api.create_dataset(child, comments="FreeSDN backup")
        except TrueNASAPIError as exc:
            # Re-running a backup with the same id finds the dataset already
            # there, which is fine -- the file inside is overwritten by put.
            if "already exists" not in str(exc).lower():
                raise
        return child

    async def remove_backup_dataset(self, *, base_dataset_path: str, backup_id: str) -> bool:
        """Destroy one backup's dataset. The only recursive delete in the code.

        The name is rebuilt from the SAME validated base + a single-token id, so
        it can only ever name a direct child of the operator-nominated backup
        dataset. ``pool.dataset.delete`` on a pool root would destroy everything,
        so the guard in :meth:`_backup_child_name` is the safety boundary.
        """
        api = self._require_ws()
        child = self._backup_child_name(base_dataset_path, backup_id)
        return await api.delete_dataset(child, recursive=True, force=True)

    @staticmethod
    def _backup_child_name(base_dataset_path: str, backup_id: str) -> str:
        """``<zfs-base>/<safe-id>``, refusing anything that could escape the base.

        The single most dangerous string in the storage code: it feeds a
        recursive dataset delete. Every failure mode here is catastrophic, so
        the checks are deliberately strict and paranoid.
        """
        base = base_dataset_path.strip()
        # Accept both the mount form (/mnt/pool/ds) and the ZFS form (pool/ds).
        if base.startswith("/mnt/"):
            base = base[len("/mnt/") :]
        base = base.strip("/")
        if not base or "/" not in base:
            # A ZFS name with no "/" is a pool ROOT. Refusing it is what stops a
            # recursive delete ever reaching an entire pool.
            raise AdapterError(f"TrueNAS backup base must be a dataset under a pool, got {base!r}")
        if ".." in base.split("/"):
            raise AdapterError(f"TrueNAS backup base has an unsafe segment: {base!r}")

        token = "".join(c for c in str(backup_id) if c.isalnum() or c in "-_")
        if not token:
            raise AdapterError(f"backup id yields no safe dataset segment: {backup_id!r}")
        return f"{base}/{token}"

    def backup_mount_path(self, *, base_dataset_path: str, backup_id: str, filename: str) -> str:
        """Absolute mount path a backup file lives at, inside its own dataset."""
        child = self._backup_child_name(base_dataset_path, backup_id)
        leaf = self._safe_join_leaf(filename)
        return f"/mnt/{child}/{leaf}"

    @staticmethod
    def _safe_join_leaf(filename: str) -> str:
        from app.services.adapter_truenas_storage import _validate_filename

        *dirs, leaf = filename.split("/")
        for segment in dirs:
            if not segment or segment in (".", "..") or "\\" in segment:
                raise AdapterError(f"TrueNAS: unsafe path segment {segment!r}")
        return "/".join([*dirs, _validate_filename(leaf)])

    async def _data_plane_write(
        self, dataset_path: str, filename: str, blob: bytes
    ) -> dict[str, Any]:
        api = self._require_ws()
        dest = self._safe_join(dataset_path, filename)
        job_id = await api.upload_blob(dest_path=dest, blob=blob)
        job = await api.job_wait(job_id)
        state = str(job.get("state", "")).upper()
        if state != "SUCCESS":
            raise AdapterError(f"TrueNAS write to {dest} ended {state}: {job.get('error')}")
        return {"path": dest, "job_id": job_id, "size": len(blob)}

    # ------------------------------------------------------------------
    # Management writes — staged, dual-gated, config not data
    # ------------------------------------------------------------------
    #
    # These DO carry the force gate. They change appliance configuration, which
    # is exactly what the staged-write chokepoint exists to hold: an operator
    # reviews the pending change and applies it. That is the opposite of the
    # data-plane methods above, and the line between them is "does this alter
    # what the appliance IS, or does it put a file in a dataset the operator
    # already nominated".

    async def create_dataset(
        self, *, name: str, comments: str | None = None, force: bool = False
    ) -> dict[str, Any]:
        """Create a filesystem dataset (``tank/backups``, pool-relative)."""
        self._require_gate(force)
        api = self._require_ws()
        row = await api.create_dataset(name, comments=comments)
        return {"dataset": row.get("id") or name, "created": True}

    async def create_snapshot(
        self, *, dataset: str, name: str, recursive: bool = False, force: bool = False
    ) -> dict[str, Any]:
        """Take a snapshot. Additive: it creates a restore point, destroys nothing."""
        self._require_gate(force)
        api = self._require_ws()
        row = await api.create_snapshot(dataset, name, recursive=recursive)
        return {"snapshot": row.get("id") or f"{dataset}@{name}", "created": True}

    async def delete_snapshot(self, *, snapshot_id: str, force: bool = False) -> dict[str, Any]:
        """Delete one snapshot by ``dataset@name``.

        Destroys a restore point, which is why it is staged like any other
        config change rather than exposed as a convenience.
        """
        self._require_gate(force)
        api = self._require_ws()
        await api.delete_snapshot(snapshot_id)
        return {"snapshot": snapshot_id, "deleted": True}

    async def start_scrub(self, *, pool_name: str, force: bool = False) -> dict[str, Any]:
        """Queue a scrub on ``pool_name``.

        Returns as soon as it is queued. A scrub runs for hours and the Storage
        dashboard already shows scrub state per pool, so progress belongs there
        rather than in a request held open.
        """
        self._require_gate(force)
        api = self._require_ws()
        job_id = await api.start_scrub(pool_name)
        return {"pool": pool_name, "scrub_started": True, "job_id": job_id}

    @staticmethod
    def _require_gate(force: bool) -> None:
        """One spelling of the refusal, so all four cannot drift apart.

        ``upload_file`` grew its own copy of this check first; a second, third
        and fourth hand-written copy is how one of them eventually ends up
        missing, and the missing one is not discovered until something writes
        to an appliance nobody approved.
        """
        if not force:
            raise AdapterError("TrueNAS write refused: staging force-gate not set")
