# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Parser tests for ``app.adapters.truenas.models``.

The TrueNAS REST API has shape drift between CORE (13.x) and SCALE
(22.x → 24.x): SCALE 23.10 added top-level ``healthy`` booleans,
SCALE 24.04 reshaped ``used / available / quota`` on datasets,
and snapshot ``created`` switched representation more than once.

These tests pin the parsers to both shapes so a routine version
bump on the appliance side can't silently corrupt the FE inventory.
"""
from __future__ import annotations

from app.adapters.truenas.models import (
    parse_dataset,
    parse_disk,
    parse_pool,
    parse_snapshot,
)


# ---------------------------------------------------------------------------
# parse_pool
# ---------------------------------------------------------------------------

class TestParsePool:
    def test_scale_shape_with_top_level_healthy(self) -> None:
        raw = {
            "id": 1,
            "name": "tank",
            "status": "ONLINE",
            "healthy": True,
            "size": 1024 * 1024 * 1024,
            "allocated": 512 * 1024 * 1024,
            "free": 512 * 1024 * 1024,
            "fragmentation": "5%",
            "is_decrypted": True,
        }
        out = parse_pool(raw)
        assert out.name == "tank"
        assert out.status == "ONLINE"
        assert out.healthy is True
        assert out.usage.size == 1024 * 1024 * 1024
        assert out.usage.allocated == 512 * 1024 * 1024
        assert out.usage.fragmentation == "5%"

    def test_core_shape_without_healthy_derives_from_status(self) -> None:
        """CORE 13 doesn't expose ``healthy`` — fall back to status."""
        raw = {"id": 2, "name": "backup", "status": "DEGRADED"}
        out = parse_pool(raw)
        assert out.status == "DEGRADED"
        assert out.healthy is False  # derived from non-ONLINE status

    def test_status_lowercase_normalized_to_upper(self) -> None:
        raw = {"name": "p", "status": "online"}
        assert parse_pool(raw).status == "ONLINE"

    def test_missing_status_becomes_unknown(self) -> None:
        out = parse_pool({"name": "p"})
        assert out.status == "UNKNOWN"
        assert out.healthy is False

    def test_usage_under_nested_key(self) -> None:
        """Some TrueNAS minor versions nest size/allocated under usage."""
        raw = {
            "name": "p", "status": "ONLINE",
            "usage": {"size": 100, "allocated": 40, "free": 60,
                      "fragmentation": "1%"},
        }
        out = parse_pool(raw)
        assert out.usage.size == 100
        assert out.usage.allocated == 40
        assert out.usage.free == 60


# ---------------------------------------------------------------------------
# parse_dataset — ZFS property unwrapping
# ---------------------------------------------------------------------------

class TestParseDataset:
    def test_flattens_parsed_byte_props(self) -> None:
        raw = {
            "id": "tank/share",
            "name": "tank/share",
            "pool": "tank",
            "type": "FILESYSTEM",
            "mountpoint": "/mnt/tank/share",
            "encrypted": False,
            "used": {"parsed": 1024, "rawvalue": "1024", "value": "1K"},
            "available": {"parsed": 4096, "rawvalue": "4096"},
            "quota": {"parsed": 0, "rawvalue": "0"},
        }
        out = parse_dataset(raw)
        assert out.id == "tank/share"
        assert out.pool == "tank"
        assert out.type == "FILESYSTEM"
        assert out.usage.used_bytes == 1024
        assert out.usage.available_bytes == 4096
        assert out.usage.quota_bytes == 0

    def test_falls_back_to_rawvalue_when_parsed_missing(self) -> None:
        """Some versions only ship rawvalue (string-of-bytes); we
        parse it as int."""
        raw = {
            "id": "tank/x", "name": "tank/x", "pool": "tank",
            "used": {"rawvalue": "2048"},
        }
        assert parse_dataset(raw).usage.used_bytes == 2048

    def test_int_property_short_form(self) -> None:
        """If a future TrueNAS flattens used→int, still works."""
        raw = {"id": "p/x", "pool": "p", "used": 999}
        assert parse_dataset(raw).usage.used_bytes == 999

    def test_volume_type_normalized_to_upper(self) -> None:
        raw = {"id": "tank/zvol", "type": "volume"}
        assert parse_dataset(raw).type == "VOLUME"

    def test_encrypted_and_locked_passthrough(self) -> None:
        raw = {"id": "x", "encrypted": True, "locked": True}
        out = parse_dataset(raw)
        assert out.encrypted is True
        assert out.locked is True


# ---------------------------------------------------------------------------
# parse_snapshot
# ---------------------------------------------------------------------------

class TestParseSnapshot:
    def test_full_shape(self) -> None:
        raw = {
            "id": "tank/data@auto-2026-05-24-0300",
            "name": "tank/data@auto-2026-05-24-0300",
            "dataset": "tank/data",
            "snapshot_name": "auto-2026-05-24-0300",
            "created": "2026-05-24T03:00:00Z",
        }
        out = parse_snapshot(raw)
        assert out.id == "tank/data@auto-2026-05-24-0300"
        assert out.dataset == "tank/data"
        assert out.snapshot_name == "auto-2026-05-24-0300"
        assert out.created_at == "2026-05-24T03:00:00Z"

    def test_splits_dataset_from_compound_id(self) -> None:
        """Older TrueNAS only ships the compound ``{dataset}@{name}``
        — derive both halves from that."""
        raw = {"id": "tank/data@daily-1", "name": "tank/data@daily-1"}
        out = parse_snapshot(raw)
        assert out.dataset == "tank/data"
        assert out.snapshot_name == "daily-1"

    def test_created_as_dict_with_value(self) -> None:
        """Some shapes wrap created as ``{"$date": ...}`` or
        ``{"value": ...}``."""
        raw = {"id": "p@s", "created": {"value": "2026-01-01T00:00:00Z"}}
        out = parse_snapshot(raw)
        assert out.created_at == "2026-01-01T00:00:00Z"

    def test_created_as_epoch_int_becomes_none(self) -> None:
        """Epoch-int created stays None until a formatter lifts it —
        we don't want to silently render the raw epoch as ISO."""
        raw = {"id": "p@s", "created": 1700000000}
        assert parse_snapshot(raw).created_at is None


# ---------------------------------------------------------------------------
# parse_disk
# ---------------------------------------------------------------------------

class TestParseDisk:
    def test_full_shape(self) -> None:
        raw = {
            "identifier": "{serial}_ABC123",
            "name": "sda",
            "serial": "ABC123",
            "model": "WDC WD20EFRX",
            "size": 2_000_398_934_016,
            "pool": "tank",
            "transfermode": "SATA600",
            "type": "HDD",
        }
        out = parse_disk(raw)
        assert out.name == "sda"
        assert out.serial == "ABC123"
        assert out.size == 2_000_398_934_016
        assert out.pool == "tank"
        assert out.type == "HDD"

    def test_devname_fallback_for_name(self) -> None:
        raw = {"devname": "da0", "serial": "X"}
        assert parse_disk(raw).name == "da0"

    def test_unpooled_disk_has_no_pool(self) -> None:
        raw = {"name": "nvme0n1", "type": "nvme"}
        out = parse_disk(raw)
        assert out.pool is None
        assert out.type == "NVME"
