# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""TrueNAS Pydantic models for normalized read responses.

The TrueNAS REST API returns deeply-nested JSON with many vendor
fields the FreeSDN UI doesn't render. These models pick the
subset we surface and normalize the shapes so downstream code
doesn't carry vendor field names through to the FE.

Models intentionally use ``model_config = ConfigDict(extra="ignore")``
so a TrueNAS version bump that adds new fields doesn't break parsing.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Base(BaseModel):
    model_config = ConfigDict(
        extra="ignore",  # tolerate new vendor fields
        populate_by_name=True,
        str_strip_whitespace=True,
    )


# ---------------------------------------------------------------------------
# /system/info
# ---------------------------------------------------------------------------


class SystemInfo(_Base):
    """High-level system identity + uptime.

    Mapped from TrueNAS ``GET /api/v2.0/system/info`` response.
    """

    version: str = ""
    hostname: str = ""
    system_product: str = Field(default="", alias="system_product")
    system_serial: str = Field(default="", alias="system_serial")
    physmem: int = 0  # bytes
    uptime_seconds: float = Field(default=0.0, alias="uptime_seconds")
    boottime: int | None = None  # epoch seconds
    timezone: str = ""

    @field_validator("boottime", mode="before")
    @classmethod
    def _coerce_boottime(cls, v: Any) -> int | None:
        """Normalize ``boottime`` to epoch seconds.

        REST returns a plain int (epoch seconds); the WS JSON-RPC API
        returns a Mongo-style ``{"$date": <epoch_ms>}`` wrapper. Accept
        both, plus a bare ms int, and fall back to None on anything odd.
        """
        if v is None:
            return None
        if isinstance(v, dict):
            ms = v.get("$date")
            return int(ms) // 1000 if isinstance(ms, (int, float)) else None
        if isinstance(v, (int, float)):
            return int(v)
        return None


# ---------------------------------------------------------------------------
# /pool
# ---------------------------------------------------------------------------


class PoolUsage(_Base):
    """Capacity rollup for a ZFS pool."""

    size: int = 0  # total bytes
    allocated: int = 0  # used bytes
    free: int = 0  # free bytes
    fragmentation: str = ""  # e.g. "12%"


class Pool(_Base):
    """ZFS pool inventory entry.

    The TrueNAS pool object is huge (topology, vdevs, scrub state,
    autotrim, encryption, dedupe …). We surface the fields the FE
    dashboard needs and let the raw payload survive in ``raw`` for
    advanced consumers.
    """

    id: int = 0
    name: str = ""
    status: str = "UNKNOWN"  # ONLINE / DEGRADED / FAULTED / UNKNOWN
    healthy: bool = False
    is_decrypted: bool = True
    autotrim: dict[str, Any] = Field(default_factory=dict)
    usage: PoolUsage = Field(default_factory=PoolUsage)
    scan: dict[str, Any] = Field(default_factory=dict)
    # Raw vdev tree (data/cache/log/spare/special/dedup → vdevs → disk
    # leaves). Carries redundancy type + per-disk status/errors; the
    # endpoint derives the redundancy label and disk→pool map from it.
    topology: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# /pool/dataset
# ---------------------------------------------------------------------------


class DatasetUsage(_Base):
    used_bytes: int = 0
    available_bytes: int = 0
    quota_bytes: int = 0  # 0 = no quota


class Dataset(_Base):
    """ZFS dataset (filesystem or volume).

    TrueNAS represents each ZFS property as ``{value, source,
    rawvalue, parsed}`` — we flatten to ``used / available / quota``
    bytes for the FE and to a flat ``properties`` map for power users.
    """

    id: str = ""  # dataset path, e.g. tank/share
    name: str = ""
    pool: str = ""
    type: str = "FILESYSTEM"  # FILESYSTEM or VOLUME
    mountpoint: str | None = None
    encrypted: bool = False
    locked: bool = False
    usage: DatasetUsage = Field(default_factory=DatasetUsage)


# ---------------------------------------------------------------------------
# /zfs/snapshot
# ---------------------------------------------------------------------------


class Snapshot(_Base):
    """ZFS snapshot inventory entry.

    ``id`` matches TrueNAS' canonical ``{dataset}@{name}`` notation.
    """

    id: str = ""  # tank/data@daily-2026-05-24
    name: str = ""  # daily-2026-05-24
    dataset: str = ""  # tank/data
    snapshot_name: str = ""
    created_at: str | None = None  # ISO8601 if available
    properties: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# /disk
# ---------------------------------------------------------------------------


class Disk(_Base):
    """Physical disk metadata.

    TrueNAS reports per-disk SMART state, temperature, serial, and
    model. We surface the fields the FE inventory page needs.
    """

    identifier: str = ""  # GPTID/UUID
    name: str = ""  # da0, sda, nvme0n1
    serial: str = ""
    model: str = ""
    size: int = 0  # bytes
    pool: str | None = None  # owning pool name, if any
    transfermode: str = ""  # Auto / SATA300 / SATA600 / ...
    type: str = ""  # HDD / SSD / NVME


# ---------------------------------------------------------------------------
# Helpers — convert raw vendor dicts to our normalized models
# ---------------------------------------------------------------------------


def parse_pool(raw: dict[str, Any]) -> Pool:
    """Convert a raw TrueNAS pool dict into a Pool model.

    The vendor surface is a moving target between TrueNAS CORE and
    SCALE — for example, SCALE 23.10 added ``healthy`` as a top-level
    bool, while CORE still derives it from ``status``. This helper
    handles both shapes.
    """
    status = (raw.get("status") or "UNKNOWN").upper()
    healthy = bool(raw.get("healthy")) if "healthy" in raw else status == "ONLINE"

    pool = Pool(
        id=int(raw.get("id") or 0),
        name=str(raw.get("name") or ""),
        status=status,
        healthy=healthy,
        is_decrypted=bool(raw.get("is_decrypted", True)),
        autotrim=raw.get("autotrim") or {},
        scan=raw.get("scan") or {},
        topology=raw.get("topology") or {},
    )

    # Usage often lives inside ``topology`` rollups or directly under
    # ``size/allocated/free``. Prefer the direct keys when present.
    usage_src = raw.get("usage") or {}
    pool.usage = PoolUsage(
        size=int(raw.get("size") or usage_src.get("size") or 0),
        allocated=int(raw.get("allocated") or usage_src.get("allocated") or 0),
        free=int(raw.get("free") or usage_src.get("free") or 0),
        fragmentation=str(raw.get("fragmentation") or usage_src.get("fragmentation") or ""),
    )
    return pool


def parse_dataset(raw: dict[str, Any]) -> Dataset:
    """Convert a raw TrueNAS dataset dict into a Dataset model.

    ZFS properties on TrueNAS arrive as
    ``{"used": {"parsed": 123, "value": "120K", "rawvalue": "120000"}}``.
    The ``parsed`` key is the integer byte count; we read that and
    fall back to ``rawvalue`` (string of bytes) so version drift
    doesn't break parsing.
    """

    def _bytes_prop(key: str) -> int:
        node = raw.get(key)
        if isinstance(node, dict):
            parsed = node.get("parsed")
            if isinstance(parsed, (int, float)):
                return int(parsed)
            raw_val = node.get("rawvalue")
            if isinstance(raw_val, str) and raw_val.isdigit():
                return int(raw_val)
        if isinstance(node, (int, float)):
            return int(node)
        return 0

    ds = Dataset(
        id=str(raw.get("id") or raw.get("name") or ""),
        name=str(raw.get("name") or ""),
        pool=str(raw.get("pool") or ""),
        type=str(raw.get("type") or "FILESYSTEM").upper(),
        mountpoint=raw.get("mountpoint"),
        encrypted=bool(raw.get("encrypted") or False),
        locked=bool(raw.get("locked") or False),
    )
    ds.usage = DatasetUsage(
        used_bytes=_bytes_prop("used"),
        available_bytes=_bytes_prop("available"),
        quota_bytes=_bytes_prop("quota"),
    )
    return ds


def parse_snapshot(raw: dict[str, Any]) -> Snapshot:
    """Convert a raw TrueNAS snapshot dict into a Snapshot model."""
    snap_id = str(raw.get("id") or raw.get("name") or "")
    dataset = str(raw.get("dataset") or "")
    snapshot_name = str(raw.get("snapshot_name") or raw.get("name") or "")

    # If only ``id`` is present, split tank/data@daily into parts.
    if not dataset and "@" in snap_id:
        dataset, snapshot_name = snap_id.split("@", 1)

    created = raw.get("created") or raw.get("created_at")
    created_iso: str | None
    if isinstance(created, dict):
        # TrueNAS sometimes returns {"$date": ...} or {"value": ...}.
        created_iso = str(created.get("value") or created.get("$date") or "")
        created_iso = created_iso or None
    elif isinstance(created, (int, float)):
        created_iso = None  # epoch — caller can format if needed
    elif isinstance(created, str):
        created_iso = created
    else:
        created_iso = None

    return Snapshot(
        id=snap_id,
        name=snap_id,
        dataset=dataset,
        snapshot_name=snapshot_name,
        created_at=created_iso,
        properties=raw.get("properties") or {},
    )


def parse_disk(raw: dict[str, Any]) -> Disk:
    """Convert a raw TrueNAS disk dict into a Disk model."""
    return Disk(
        identifier=str(raw.get("identifier") or ""),
        name=str(raw.get("name") or raw.get("devname") or ""),
        serial=str(raw.get("serial") or ""),
        model=str(raw.get("model") or ""),
        size=int(raw.get("size") or 0),
        pool=raw.get("pool"),
        transfermode=str(raw.get("transfermode") or ""),
        type=str(raw.get("type") or "").upper(),
    )
