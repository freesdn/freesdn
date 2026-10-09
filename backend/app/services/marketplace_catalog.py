# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Catalog freshness, transaction ordering and install authorization.

Signatures are checked by the caller before these helpers. The serial floor is
only as current as this database; restore operators must supply an independently
retained minimum serial. An accurate UTC clock is required for expiry checks.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.marketplace import MarketplaceCatalogState, MarketplacePlugin

MAX_SERIAL = 2**63 - 1
MAX_FUTURE_SKEW = timedelta(minutes=5)


def utc_now() -> datetime:
    return datetime.now(UTC)


def minimum_serial(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if not 0 <= value <= MAX_SERIAL:
        raise HTTPException(503, "Invalid MARKETPLACE_MIN_SERIAL; marketplace writes are disabled.")
    return value


def publisher_identity(url: str, key: str) -> str:
    # The endpoint verifies that a configured key is well formed before ingest.
    payload = json.dumps([url, key.lower().replace(" ", "") or "unsigned-development"])
    return hashlib.sha256(payload.encode()).hexdigest()


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or "T" not in value:
        raise HTTPException(400, "Catalog timestamps must be timezone-aware ISO-8601 strings.")
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("naive timestamp")
        return result.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(
            400, "Catalog timestamps must be timezone-aware ISO-8601 strings."
        ) from exc


@dataclass(frozen=True)
class CatalogEnvelope:
    serial: int
    digest: str
    generated_at: datetime
    expires_at: datetime

    def require_current(self, floor: int) -> None:
        now = utc_now()
        if self.serial < floor:
            raise HTTPException(
                409, "Catalog serial is below the independently configured minimum."
            )
        if self.generated_at > now + MAX_FUTURE_SKEW:
            raise HTTPException(
                409, "Catalog was generated in the future; check publisher and local clocks."
            )
        if self.expires_at <= now:
            raise HTTPException(
                409, "Marketplace catalog has expired. Sync a newly signed catalog."
            )


def validate_envelope(catalog: dict[str, Any], floor: int) -> CatalogEnvelope:
    serial = catalog.get("serial")
    if type(serial) is not int or not 1 <= serial <= MAX_SERIAL:
        raise HTTPException(400, "Catalog requires a positive signed 64-bit integer serial.")
    generated = _timestamp(catalog.get("generated_at"))
    expires = _timestamp(catalog.get("expires_at"))
    if expires <= generated:
        raise HTTPException(400, "Catalog expiry must be later than its generation time.")
    payload = {k: v for k, v in catalog.items() if k != "signature"}
    try:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Catalog contains invalid JSON values.") from exc
    envelope = CatalogEnvelope(
        serial, hashlib.sha256(canonical.encode()).hexdigest(), generated, expires
    )
    envelope.require_current(floor)
    return envelope


def validate_entries(entries: Any) -> list[dict[str, Any]]:
    """Reject partial snapshots: every entry must be usable before any write."""
    if not isinstance(entries, list) or len(entries) > 10000:
        raise HTTPException(400, "Catalog plugins must be a bounded array.")
    required = {
        "plugin_id": 100,
        "slug": 100,
        "name": 200,
        "short_description": 500,
        "author_name": 200,
        "category": 50,
        "latest_version": 20,
        "min_core_version": 20,
        "download_url": 512,
        "checksum_sha256": 64,
    }
    optional = {"description": 100000, "author_url": 512, "icon_url": 512, "banner_url": 512}
    ids: set[str] = set()
    slugs: set[str] = set()
    validated = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise HTTPException(400, "Every catalog entry must be an object.")
        # Compatibility aliases remain descriptive; trust/status fields never enter this map.
        row = {k: entry[k] for k in (*required, *optional, "tags", "screenshots") if k in entry}
        for source, target in (
            ("version", "latest_version"),
            ("min_freesdn_version", "min_core_version"),
            ("homepage_url", "author_url"),
        ):
            if source in entry and target not in row:
                row[target] = entry[source]
        for key, length in required.items():
            value = row.get(key)
            if not isinstance(value, str) or not value.strip() or len(value) > length:
                raise HTTPException(400, f"Catalog entry has an invalid {key}.")
        for key, length in optional.items():
            value = row.get(key)
            if value is not None and (not isinstance(value, str) or len(value) > length):
                raise HTTPException(400, f"Catalog entry has an invalid {key}.")
        for key in ("tags", "screenshots"):
            values = row.setdefault(key, [])
            if (
                not isinstance(values, list)
                or len(values) > 128
                or any(not isinstance(v, str) or len(v) > 512 for v in values)
            ):
                raise HTTPException(400, f"Catalog entry has an invalid {key}.")
        checksum = row["checksum_sha256"]
        if len(checksum) != 64 or any(c not in "0123456789abcdefABCDEF" for c in checksum):
            raise HTTPException(400, "Catalog checksum must be a SHA-256 hex digest.")
        row["checksum_sha256"] = checksum.lower()
        try:
            url = urlsplit(row["download_url"])
            valid_url = (
                url.scheme == "https"
                and bool(url.hostname)
                and not url.username
                and not url.password
                and not url.fragment
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            raise HTTPException(
                400, "Catalog downloads require HTTPS URLs without embedded credentials."
            )
        if row["plugin_id"] in ids or row["slug"] in slugs:
            raise HTTPException(400, "Catalog contains duplicate plugin IDs or slugs.")
        ids.add(row["plugin_id"])
        slugs.add(row["slug"])
        validated.append(row)
    return validated


async def lock_catalog(session: AsyncSession) -> MarketplaceCatalogState:
    # INSERT also serializes the first-ever sync across processes. Do not commit
    # here: the floor and all catalog mutations must commit or roll back together.
    await session.execute(
        insert(MarketplaceCatalogState)
        .values(scope="global", identity="", serial=0, payload_sha256="")
        .on_conflict_do_nothing(index_elements=["scope"])
    )
    return (
        await session.execute(
            select(MarketplaceCatalogState)
            .where(MarketplaceCatalogState.scope == "global")
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


def accept_envelope(
    state: MarketplaceCatalogState, envelope: CatalogEnvelope, identity: str, floor: int
) -> None:
    # Recheck after waiting for a concurrent sync's lock, including wall-clock expiry.
    envelope.require_current(floor)
    if state.serial and state.identity != identity:
        raise HTTPException(
            409,
            "Marketplace publisher/feed changed. Preserve the serial floor and review this trust change before migrating it.",
        )
    if envelope.serial < state.serial:
        raise HTTPException(
            409, "Marketplace catalog rollback refused: serial is older than the accepted catalog."
        )
    if envelope.serial == state.serial and envelope.digest != state.payload_sha256:
        raise HTTPException(409, "Marketplace catalog serial was reused for different content.")
    state.identity = identity
    state.serial = envelope.serial
    state.payload_sha256 = envelope.digest
    state.generated_at = envelope.generated_at
    state.expires_at = envelope.expires_at


async def require_installable(
    session: AsyncSession, plugin: MarketplacePlugin, identity: str, floor: int
) -> None:
    state = (
        await session.execute(
            select(MarketplaceCatalogState)
            .where(MarketplaceCatalogState.scope == "global")
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if (
        state is None
        or not state.serial
        or state.identity != identity
        or plugin.catalog_identity != identity
        or plugin.catalog_serial != state.serial
    ):
        raise HTTPException(
            409,
            "Plugin lacks a current accepted catalog. Sync the signed registry before installing or updating.",
        )
    if state.generated_at is None or state.expires_at is None:
        raise HTTPException(409, "Catalog freshness evidence is missing; sync the signed registry.")
    CatalogEnvelope(
        state.serial, state.payload_sha256, state.generated_at, state.expires_at
    ).require_current(floor)


@dataclass(frozen=True)
class CatalogOffer:
    """The catalog offer whose archive the initiating request downloaded."""

    row_id: UUID
    plugin_id: str
    slug: str
    identity: str | None
    serial: int | None
    version: str
    download_url: str
    checksum: str

    @classmethod
    def from_plugin(cls, plugin: MarketplacePlugin) -> CatalogOffer:
        return cls(
            plugin.id,
            plugin.plugin_id,
            plugin.slug,
            plugin.catalog_identity,
            plugin.catalog_serial,
            plugin.latest_version,
            plugin.download_url,
            plugin.checksum_sha256,
        )


async def require_current_offer(
    session: AsyncSession,
    offer: CatalogOffer,
    identity: str,
    floor: int,
) -> CatalogEnvelope:
    """Fresh committed catalog/offer snapshot at the lifecycle boundary.

    The earlier download checks retain their existing catalog-reader locks.
    Upgrade commits its marker, releasing those locks before waiting for the
    plugin mutex. Use one scalar SELECT here, not a cached ORM record or a new
    blocking row lock under that mutex: another catalog reader can already be
    waiting for the same mutex while a catalog writer waits for that reader.

    This checks the boundary snapshot. It does not serialize a withdrawal that
    commits after this read, trusted hooks, or cross-process filesystem writes.
    """
    row = (
        await session.execute(
            select(
                MarketplaceCatalogState.identity,
                MarketplaceCatalogState.serial,
                MarketplaceCatalogState.payload_sha256,
                MarketplaceCatalogState.generated_at,
                MarketplaceCatalogState.expires_at,
            )
            .select_from(MarketplacePlugin)
            .join(MarketplaceCatalogState, MarketplaceCatalogState.scope == "global")
            .where(
                MarketplacePlugin.id == offer.row_id,
                MarketplacePlugin.plugin_id == offer.plugin_id,
                MarketplacePlugin.slug == offer.slug,
                MarketplacePlugin.status == "published",
                MarketplacePlugin.catalog_identity == offer.identity,
                MarketplacePlugin.catalog_serial == offer.serial,
                MarketplacePlugin.latest_version == offer.version,
                MarketplacePlugin.download_url == offer.download_url,
                MarketplacePlugin.checksum_sha256 == offer.checksum,
            )
        )
    ).one_or_none()
    if (
        row is None
        or not row.serial
        or row.identity != identity
        or offer.identity != identity
        or offer.serial != row.serial
        or row.generated_at is None
        or row.expires_at is None
    ):
        raise HTTPException(
            409, "Marketplace authorization changed; sync and retry the plugin operation."
        )
    envelope = CatalogEnvelope(row.serial, row.payload_sha256, row.generated_at, row.expires_at)
    envelope.require_current(floor)
    return envelope
