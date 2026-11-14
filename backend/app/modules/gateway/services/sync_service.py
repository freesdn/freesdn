# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Sync Service
====================================

Periodic data synchronisation from brain devices.
Refreshes the imported-cache tables (firewall rules, NAT,
VPN, IDS, DHCP leases, interfaces) without modifying anything
on the device.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import io_policy
from app.core.device_slot import device_slots, gateway_slot_key
from app.core.events import Event, EventCategory, get_event_bus
from app.modules.firewall.models import (
    GatewayConnection,
    GatewaySyncLog,
    GatewaySyncStatus,
)
from app.modules.gateway.adapter_helpers import build_adapter
from app.modules.gateway.models import (
    ImportedDHCPLease,
    ImportedFirewallRule,
    ImportedInterface,
    ImportedNATRule,
    ImportedVPNTunnel,
)

logger = logging.getLogger(__name__)

#: The device reads of a full sync, in order: (imported-cache section, adapter method).
_SECTIONS: tuple[tuple[str, str], ...] = (
    ("firewall_rules", "get_firewall_rules"),
    ("nat_rules", "get_nat_rules"),
    ("vpn_tunnels", "get_vpn_status"),
    ("interfaces", "get_interfaces"),
    ("dhcp_leases", "get_dhcp_leases"),
)

#: Ceiling for one section. Each request is already bounded by the adapter's
#: read timeout; a section may make several (OPNsense VPN status makes six).
_SECTION_DEADLINE = 90.0


def _is_device_failure_text(error: str) -> bool:
    return io_policy.is_device_failure_text(error)


def _is_device_failure_exc(exc: BaseException) -> bool:
    return io_policy.is_device_failure(exc)


_CONFIG_XML_KEY = "freesdn:gateway:config-xml:{}"


def _accepts(call: Any, parameter: str) -> bool:
    try:
        return parameter in inspect.signature(call).parameters
    except (TypeError, ValueError):
        return False


def _config_xml_due(gateway_id: UUID) -> bool:
    """May this sync download the full config.xml for legacy firewall rules?

    At most once per GATEWAY_CONFIG_XML_REFRESH_SECONDS (6 h by default) per
    gateway. On a box whose rules all live in config.xml the MVC rule API is
    always empty, so the adapter's fallback downloaded the WHOLE configuration
    on every sync (every 5 minutes on the 2026-11 soak). Redis trouble allows
    the download: the sync interval still bounds it.
    """
    try:
        from app.core.celery_app import _get_solo_redis

        return not _get_solo_redis().exists(_CONFIG_XML_KEY.format(gateway_id))
    except Exception:  # noqa: BLE001
        return True


def _mark_config_xml_fetched(gateway_id: UUID) -> None:
    try:
        from app.core.celery_app import _get_solo_redis
        from app.core.config import settings

        _get_solo_redis().set(
            _CONFIG_XML_KEY.format(gateway_id),
            "1",
            ex=int(settings.GATEWAY_CONFIG_XML_REFRESH_SECONDS),
        )
    except Exception:  # noqa: BLE001
        logger.debug("could not record the config.xml download time", exc_info=True)


@dataclass
class _DeviceReads:
    """What one sync read from the device, before anything is written."""

    connected: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    #: Why the sync stopped early because the device itself was in trouble.
    device_failure: str | None = None
    #: Safe-to-publish form of the same: an exception class name, or
    #: ``DeviceError`` when the device answered with an error text (which can
    #: carry vendor output and is never published).
    failure_kind: str | None = None


def _normalize_vpn_tunnels(data: Any) -> list[dict[str, Any]]:
    """Flatten a vendor's ``get_vpn_status`` payload into tunnel dicts.

    This used to be ``data.get("tunnels", [])``, and NO supported brain
    firewall returns a top-level ``tunnels`` list:

      OPNsense  {"wireguard": {...}, "openvpn": {...}, "ipsec": ...}
      pfSense   {"openvpn": ..., "wireguard": {"tunnels": [...], ...}, ...}
      MikroTik  {"ipsec": {...}, "wireguard": {...}, "l2tp": ..., "pptp": ...}
      OpenWrt   {"tunnels": {"wireguard": [...], "openvpn": [...]}}

    So three vendors yielded ``[]`` and the Gateway VPN Tunnels table stayed
    permanently empty, while OpenWrt yielded a DICT -- truthy, so it reached
    ``_upsert_vpn_tunnels``, whose ``for t in tunnels`` then iterated the KEYS
    and produced rows from the strings "wireguard" and "openvpn" before failing
    into the except above. Either way nobody ever saw a tunnel.

    Deliberately conservative: this walks the shapes those four adapters
    actually return and tags each tunnel with the protocol it came from. It
    does not try to guess at unknown shapes -- an unrecognised payload yields
    nothing, which is the same as today rather than a table of garbage.
    """
    if not isinstance(data, dict):
        return []

    out: list[dict[str, Any]] = []

    def _add(items: Any, vpn_type: str) -> None:
        if isinstance(items, dict):
            # A mapping of name -> tunnel, or a single tunnel object.
            items = list(items.values()) if all(isinstance(v, dict) for v in items.values()) else []
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            out.append({**item, "type": item.get("type") or vpn_type})

    # OpenWrt nests everything under "tunnels"; the others are top-level.
    root = data.get("tunnels") if isinstance(data.get("tunnels"), dict) else data

    for vpn_type in ("wireguard", "openvpn", "ipsec", "l2tp", "pptp"):
        section = root.get(vpn_type)
        if section is None:
            continue
        if isinstance(section, list):
            _add(section, vpn_type)
        elif isinstance(section, dict):
            # pfSense: {"tunnels": [...]}; OPNsense: {"status": ..., "peers": [...]};
            # MikroTik: {"interfaces": [...], "peers": [...]}.
            for key in ("tunnels", "interfaces", "instances", "providers", "peers", "status"):
                if key in section:
                    _add(section[key], vpn_type)

    return out


# ── Vendor values -> typed columns ───────────────────────────────────────────
# The imported tables have Integer and Boolean columns, and the brains answer in
# three dialects: OPNsense's adapter normalises (bool, int), pfSense and its own
# raw API answer "1"/"0", and RouterOS answers every value as a string
# ("mtu": "1500", "disabled": "false"). asyncpg refuses a str for an int/bool
# parameter, so a RouterOS interface table rolled its whole section back on every
# sync. These parse what they can and store no value for what they cannot.

_TRUE = frozenset({"1", "true", "yes", "on", "enable", "enabled"})
_FALSE = frozenset({"0", "false", "no", "off", "disable", "disabled", ""})


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return default


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(float(str(value).strip()))
    except (ValueError, OverflowError):
        return None


def _enabled(row: dict[str, Any], default: bool = True) -> bool:
    """``enabled`` (OPNsense / pfSense) or RouterOS's inverted ``disabled``."""
    for key in ("enabled", "enable"):
        if key in row:
            return _as_bool(row[key], default)
    if "disabled" in row:
        return not _as_bool(row["disabled"], not default)
    return default


def _as_text(value: Any) -> str | None:
    return None if value is None else str(value)


def _first(row: dict[str, Any], *keys: str) -> Any:
    """The first non-empty value among a row's vendor spellings of one field."""
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _rows(data: Any, *keys: str) -> list[dict[str, Any]]:
    """The list of row dicts inside a vendor payload.

    The section readers used to take ``data.get("rules")`` only. OPNsense's NAT
    API answers ``{"rows": [...]}`` (so NAT was never imported), pfSense wraps
    lists in ``{"data": [...]}``, and RouterOS returns a bare list.
    """
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
            if isinstance(value, dict) and isinstance(value.get("data"), list):
                return [r for r in value["data"] if isinstance(r, dict)]
    return []


class SyncService:
    """Refreshes imported-cache tables from brain devices."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def sync_gateway(
        self,
        gateway_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Full sync of read-only data from a single gateway device.

        When called from an API endpoint, pass org_id to scope the query.
        Background tasks may omit org_id for internal sync operations.

        Three phases, and NO database transaction is open during the second:

        1. read the gateway row and build the adapter, then COMMIT -- this
           service owns its transactions;
        2. read every section from the device;
        3. write what was read in one short transaction.

        This used to read the row, then keep that transaction (and, behind
        PgBouncer, a server connection) open across every device call. Against
        a struggling OPNsense on the 2026-11 soak one sync held it for 7+
        minutes while each request timed out.
        """
        q = select(GatewayConnection).where(
            GatewayConnection.id == gateway_id,
            GatewayConnection.deleted_at.is_(None),
        )
        if org_id is not None:
            q = q.where(GatewayConnection.org_id == org_id)
        result = await self.db.execute(q)
        gw = result.scalar_one_or_none()
        if gw is None:
            logger.warning("Gateway %s not found for sync", gateway_id)
            return {"status": "not_found"}

        if not gw.sync_enabled:
            return {"status": "sync_disabled"}

        adapter = build_adapter(gw)
        slot_key = gateway_slot_key(gw)
        # End the read transaction before the first byte goes to the device.
        await self.db.commit()

        # One request group per device across every poller: while the health
        # poll, a drift check, a config backup or a UI read is talking to this
        # box, the full sync waits for the next cycle instead of piling on.
        lease = await device_slots.acquire(slot_key, "gateway full sync")
        if lease is None:
            reason = await device_slots.abusy_reason(slot_key)
            logger.info("Gateway %s sync skipped: %s", gateway_id, reason)
            return {"status": "skipped", "reason": reason, "device_busy": True}
        t0 = datetime.now(UTC)
        try:
            reads = await self._read_device(adapter, gw.id)
        finally:
            await device_slots.arelease(lease)

        # ── write phase: one short transaction ───────────────────────────
        await self.db.refresh(gw)
        if gw.deleted_at is not None:
            await self.db.commit()
            return {"status": "not_found"}

        synced: dict[str, int] = {}
        if reads.connected:
            # Resilience (audit): every _upsert_* below does a delete-all-then-
            # insert "replace". A device that is reachable but momentarily
            # returns an EMPTY list (a fetch glitch, an oversize-config fallback,
            # an MVC plugin hiccup) would otherwise WIPE the configured device's
            # imported rules/NAT/VPN/interfaces/leases to zero — a dangerously
            # misleading view of a security device until the next good sync. So
            # SKIP the replace whenever the incoming list is empty; keep the
            # last-known data instead. A genuinely-emptied set self-corrects on
            # the next non-empty sync (or a manual re-import).
            #
            # Each replace runs in its own SAVEPOINT, so a failed flush in one
            # section (a lease time asyncpg refused) rolls back only that
            # section, to its last-known rows, and the rest still land.
            sections = {
                "firewall_rules": (self._upsert_firewall_rules, "rules"),
                "nat_rules": (self._upsert_nat_rules, "rules"),
                "interfaces": (self._upsert_interfaces, "interfaces"),
                "dhcp_leases": (self._upsert_dhcp_leases, "leases"),
            }
            for name, (upsert, key) in sections.items():
                # _rows, not data.get(key): OPNsense's NAT API answers
                # {"rows": [...]} (so NAT was never imported), pfSense wraps
                # lists in {"data": [...]} and RouterOS returns a bare list.
                rows = _rows(reads.data.get(name), key, "rows", "data")
                if rows:
                    try:
                        async with self.db.begin_nested():
                            synced[name] = await upsert(gw, rows)
                    except Exception as exc:
                        reads.errors[name] = type(exc).__name__
                        logger.warning("Failed to store %s for %s: %s", name, gateway_id, exc)
            tunnels = _normalize_vpn_tunnels(reads.data.get("vpn_tunnels"))
            if tunnels:
                try:
                    async with self.db.begin_nested():
                        synced["vpn_tunnels"] = await self._upsert_vpn_tunnels(gw, tunnels)
                except Exception as exc:
                    reads.errors["vpn_tunnels"] = type(exc).__name__
                    logger.warning("Failed to store vpn_tunnels for %s: %s", gateway_id, exc)

        finished = datetime.now(UTC)
        elapsed = int((finished - t0).total_seconds() * 1000)
        gw.last_sync_duration_ms = elapsed
        failed = not reads.connected or reads.device_failure is not None
        if failed:
            # The device did not answer (connect failed, or it stopped
            # answering part-way). Say so: this used to stamp SUCCESS and
            # is_online=True whatever the reads returned, because the adapter
            # turns every timeout into a failed AdapterResult rather than an
            # exception, so a firewall that timed out on everything looked
            # healthy and freshly synced.
            gw.sync_status = GatewaySyncStatus.FAILED
            gw.last_sync_error = (reads.device_failure or "device unreachable")[:500]
            if not reads.connected:
                gw.is_online = False
        else:
            gw.sync_status = GatewaySyncStatus.SUCCESS
            gw.last_sync_at = finished
            gw.last_sync_error = None
        if reads.connected:
            gw.is_online = True
            gw.last_seen_at = finished
        log_status = "failed" if not synced and failed else ("partial" if failed else "success")
        details: dict[str, Any] = dict(synced)
        if reads.errors:
            details["errors"] = dict(reads.errors)
        self.db.add(
            GatewaySyncLog(
                gateway_id=gw.id,
                started_at=t0,
                finished_at=finished,
                duration_ms=elapsed,
                status=log_status,
                # The model has ``error``, an int ``items_synced`` and a
                # ``details`` JSONB. This passed ``error_message=`` and the
                # per-section dict as ``items_synced``, so the constructor
                # raised TypeError and EVERY periodic sync ended as failed
                # after doing its work.
                items_synced=sum(n for n in synced.values() if isinstance(n, int)),
                error=gw.last_sync_error if failed else None,
                details=details,
            )
        )
        await self.db.commit()

        if failed:
            # A failed periodic sync was visible only in the worker log and the
            # gateway row; nothing could alert on it.
            try:
                await get_event_bus().publish(
                    Event(
                        event_type="gateway.sync.failed",
                        category=EventCategory.SYSTEM,
                        source="gateway.sync_service",
                        organization_id=str(gw.org_id),
                        payload={
                            "gateway_id": str(gateway_id),
                            "site_id": str(gw.site_id) if gw.site_id else None,
                            # Class name only; the failure text can carry
                            # vendor output.
                            "error": reads.failure_kind or "Unreachable",
                        },
                    )
                )
            except Exception:
                logger.debug("Failed to emit sync-failed event", exc_info=True)
            return {
                "status": "failed",
                "error": gw.last_sync_error,
                "device_failure": True,
                "synced": synced,
            }
        # Emit sync-complete event so drift detection can run
        try:
            bus = get_event_bus()
            await bus.publish(
                Event(
                    event_type="gateway.sync.completed",
                    category=EventCategory.SYSTEM,
                    source="gateway.sync_service",
                    # Without it the Fabric drops the event (an org-less
                    # event can never fire a Connection) and the WS router
                    # cannot route it: the advertised trigger was dead.
                    organization_id=str(gw.org_id),
                    payload={
                        "gateway_id": str(gateway_id),
                        "site_id": str(gw.site_id) if gw.site_id else None,
                        "synced": synced,
                        "duration_ms": elapsed,
                    },
                )
            )
        except Exception:
            logger.debug("Failed to emit sync event", exc_info=True)
        return {"status": "success", "synced": synced}

    async def _read_device(self, adapter: Any, gateway_id: UUID) -> _DeviceReads:
        """Read every section from the device. Touches no database state.

        Stops at the first sign the device itself is in trouble (connect
        failed, a read timed out or the connection dropped) instead of sending
        the remaining sections to a box that is not answering.
        """
        reads = _DeviceReads()
        try:
            async with adapter:
                reads.connected = True
                for name, method in _SECTIONS:
                    call = getattr(adapter, method, None)
                    if call is None:
                        continue
                    kwargs: dict[str, Any] = {}
                    if name == "firewall_rules" and _accepts(call, "legacy_fallback"):
                        kwargs["legacy_fallback"] = _config_xml_due(gateway_id)
                    try:
                        res = await asyncio.wait_for(call(**kwargs), timeout=_SECTION_DEADLINE)
                    except Exception as exc:
                        if _is_device_failure_exc(exc):
                            reads.device_failure = f"{name}: {type(exc).__name__}"
                            reads.failure_kind = type(exc).__name__
                            break
                        reads.errors[name] = type(exc).__name__
                        logger.warning("Failed to sync %s: %s", name, exc)
                        continue
                    if getattr(res, "success", False) and getattr(res, "data", None):
                        reads.data[name] = res.data
                        if isinstance(res.data, dict) and res.data.get("source") == "config_xml":
                            _mark_config_xml_fetched(gateway_id)
                    elif not getattr(res, "success", False):
                        error = str(getattr(res, "error", "") or "unavailable")
                        reads.errors[name] = error[:200]
                        if _is_device_failure_text(error):
                            reads.device_failure = f"{name}: {error[:200]}"
                            reads.failure_kind = "DeviceError"
                            break
        except Exception as exc:
            if reads.connected:
                # Raised while disconnecting: the reads are already in hand.
                logger.debug("Gateway adapter disconnect failed: %s", exc)
            else:
                # Raised by connect(): the device did not answer at all.
                reads.device_failure = f"connect: {type(exc).__name__}"
                reads.failure_kind = type(exc).__name__
                logger.warning("Gateway sync could not reach the device: %s", exc)
        return reads

    # ── Upsert Helpers ───────────────────────────────────────────────────

    async def _upsert_firewall_rules(
        self, gw: GatewayConnection, rules: list[dict[str, Any]]
    ) -> int:
        """Replace-all approach: delete existing, insert fresh."""
        now = datetime.now(UTC)
        await self.db.execute(
            delete(ImportedFirewallRule).where(
                ImportedFirewallRule.device_id == gw.id,
            )
        )
        for idx, r in enumerate(rules):
            row = ImportedFirewallRule(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=r.get("uuid", r.get("id", str(idx))),
                name=r.get("description", r.get("name", f"rule-{idx}")),
                description=r.get("description"),
                rule_index=idx,
                direction=r.get("direction", "in"),
                action=r.get("action", "pass"),
                protocol=r.get("protocol", "any"),
                source=r.get("source", {}),
                destination=r.get("destination", {}),
                is_enabled=_enabled(r),
                hit_count=_as_int(_first(r, "evaluations", "packets")) or 0,
                last_synced_at=now,
                raw_data=r,
            )
            self.db.add(row)
        await self.db.flush()
        return len(rules)

    async def _upsert_nat_rules(self, gw: GatewayConnection, rules: list[dict[str, Any]]) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedNATRule).where(ImportedNATRule.device_id == gw.id))
        for r in rules:
            row = ImportedNATRule(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=r.get("uuid", r.get("id", "")),
                name=r.get("description", ""),
                nat_type=r.get("type", "dnat"),
                source=r.get("source", {}),
                destination=r.get("destination", {}),
                translation=r.get("target", {}),
                is_enabled=_enabled(r),
                last_synced_at=now,
                raw_data=r,
            )
            self.db.add(row)
        await self.db.flush()
        return len(rules)

    async def _upsert_vpn_tunnels(
        self, gw: GatewayConnection, tunnels: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedVPNTunnel).where(ImportedVPNTunnel.device_id == gw.id))
        for t in tunnels:
            row = ImportedVPNTunnel(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=t.get("uuid", t.get("id", "")),
                name=t.get("description", t.get("name", "")),
                vpn_type=t.get("type", "ipsec"),
                status=t.get("status", "down"),
                local_config=t.get("local", {}),
                remote_config=t.get("remote", {}),
                stats=t.get("stats", {}),
                last_synced_at=now,
                raw_data=t,
            )
            self.db.add(row)
        await self.db.flush()
        return len(tunnels)

    async def _upsert_interfaces(
        self, gw: GatewayConnection, interfaces: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedInterface).where(ImportedInterface.device_id == gw.id))
        for iface in interfaces:
            row = ImportedInterface(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                # Normalised (OPNsense adapter), pfSense raw and RouterOS raw
                # spellings of each field, in that order. This read only the
                # pfSense names, so OPNsense interfaces landed with no MAC,
                # address, subnet, VLAN tag or type.
                external_id=str(_first(iface, "identifier", "if", "name", ".id") or ""),
                name=iface.get("description", iface.get("name", "")),
                description=iface.get("description"),
                if_type=_first(iface, "link_type", "type"),
                mac_address=_first(iface, "mac_address", "macaddr", "mac", "mac-address"),
                mtu=_as_int(_first(iface, "mtu", "actual-mtu")),
                is_enabled=_enabled(iface),
                is_up=str(iface.get("status", "")).lower() == "up"
                or _as_bool(iface.get("running"), False),
                ipv4_address=_first(iface, "ipv4_address", "ipaddr"),
                ipv4_subnet=_as_text(_first(iface, "ipv4_subnet", "subnet")),
                ipv6_address=_first(iface, "ipv6_address", "ipaddrv6"),
                vlan_tag=_as_int(_first(iface, "vlan_id", "vlan_tag", "vlan-id", "vlan")),
                parent_interface=_first(iface, "parent_interface", "if"),
                stats=iface.get("statistics") if isinstance(iface.get("statistics"), dict) else {},
                last_synced_at=now,
                raw_data=iface,
            )
            self.db.add(row)
        await self.db.flush()
        return len(interfaces)

    @staticmethod
    def _lease_time(value: Any) -> datetime | None:
        """A lease start/end as an aware datetime, or None if it cannot be read.

        OPNsense's ISC DHCP lease API reports ``"2026/11/12 22:18:13"``, the
        dhcpd.leases format, whose times dhcpd writes in UTC; Kea reports epoch
        seconds; others send ISO 8601. The raw string used to be bound straight
        to the timestamp column, asyncpg refused it, and the failed flush left
        the session rolled back, so the WHOLE gateway sync failed (found on the
        2026-11 soak VM). An unreadable value now stores no time rather than
        sinking the sync.
        """
        if value is None or value == "" or isinstance(value, bool):
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        text = str(value).strip()
        if isinstance(value, int | float) or text.isdigit():
            try:
                return datetime.fromtimestamp(float(text), UTC)
            except (OverflowError, OSError, ValueError):
                return None
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=UTC)
            except ValueError:
                pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    async def _upsert_dhcp_leases(self, gw: GatewayConnection, leases: list[dict[str, Any]]) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedDHCPLease).where(ImportedDHCPLease.device_id == gw.id))
        for l in leases:
            row = ImportedDHCPLease(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                ip_address=l.get("address", ""),
                mac_address=l.get("mac", ""),
                hostname=l.get("hostname"),
                interface=l.get("if"),
                status=l.get("state", l.get("binding_state")),
                starts=self._lease_time(l.get("starts")),
                ends=self._lease_time(l.get("ends")),
                last_synced_at=now,
            )
            self.db.add(row)
        await self.db.flush()
        return len(leases)
