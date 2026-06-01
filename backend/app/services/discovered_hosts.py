# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Service layer for ``devices.discovered_hosts`` upsert + merge.

Single chokepoint that takes a discovery report (from any source — HTTP
``POST /discovery/results``, WS ``scan_result``, or the daemon's
scheduler) and either:

- creates a new ``DiscoveredHost`` row, or
- merges new attributes into an existing one (matched by site+MAC,
  falling back to site+IP when MAC unknown).

Multi-source merge contract:

- ``discovered_via`` is a set — each scanner name (arp, mdns, lldp, …)
  is appended exactly once.
- ``open_ports`` is unioned across sources.
- ``services`` / ``mdns_services`` / ``ssdp_info`` / ``lldp_*`` /
  ``http_*`` are SET WHEN the new payload has a non-None value;
  otherwise the existing value is preserved.
- ``last_seen`` always advances to now().
- ``first_seen`` is preserved from the original creation.
- ``vendor`` / ``device_type`` / ``hostname`` are taken from the latest
  non-empty observation (LLDP > mDNS > NetBIOS > MAC OUI lookup, but
  the service is naive and just takes whatever it last saw — the
  callers are responsible for source ordering if they care).

Adoption flow lives elsewhere (``app/api/v1/endpoints/discovery.py``
``adopt_device`` already exists); this service stops at the
"discovered" state.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import Site
from app.models.devices import DiscoveredHost

logger = logging.getLogger(__name__)


def _norm_mac(mac: str | None) -> str:
    if not mac:
        return ""
    return mac.replace(":", "").replace("-", "").replace(".", "").upper()


async def build_known_entity_index(
    session: AsyncSession,
    *,
    organization_id: UUID | None,
    site_id: UUID | None = None,
    allowed_site_ids: list[UUID] | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Build an index of every IP/MAC FreeSDN already knows about.

    The whole point: an agent scanning the wire shouldn't present a
    MikroTik gateway, a UniFi UDM, or an Omada-managed AP as a brand-new
    "discovered" host when FreeSDN already manages it. This index lets
    the discovered-hosts list tag each row with what we already know.

    Sources:
    - ``core.controllers`` — the controller APPLIANCES themselves
      (MikroTik / UniFi / Omada / OPNsense / OpenWrt / Proxmox /
      Hikvision / FreePBX / Grandstream / …). These have a host IP but
      no MAC, and they are NOT in core.devices — so without this they'd
      always look "discovered".
    - ``core.devices`` — every managed + module-synced device (cameras,
      phones, NVRs, hypervisors, and controller-managed APs/switches all
      sync here). Carries ip + mac. ``controller_id`` tells us whether
      the device came from a controller (so we can say "managed via
      Omada") vs. a standalone adoption.

    Returns ``{"by_ip": {ip: entity}, "by_mac": {normalized_mac: entity}}``
    where entity = ``{kind, name, detail, ref_type, ref_id}``. ``kind``
    is one of ``controller`` | ``controller_device`` | ``device``.
    """
    from app.models.core import Controller
    from app.models.devices import Device

    by_ip: dict[str, dict[str, Any]] = {}
    by_mac: dict[str, dict[str, Any]] = {}

    # --- Controllers (appliance hosts) -------------------------------
    cq = (
        select(Controller)
        .join(Site, Controller.site_id == Site.id)
        .where(Controller.deleted_at.is_(None), Site.deleted_at.is_(None))
    )
    if organization_id is not None:
        cq = cq.where(Site.organization_id == organization_id)
    if site_id is not None:
        cq = cq.where(Controller.site_id == site_id)
    # confine the enrichment index to the caller's granted sites so a
    # site-limited viewer cannot learn a sibling-site controller's name/ref id
    # through an IP/MAC collision. None = unrestricted (admin) no-op; empty list
    # = site-limited with no grants -> matches nothing (fail-closed).
    if allowed_site_ids is not None:
        cq = cq.where(Controller.site_id.in_(allowed_site_ids))
    for c in (await session.execute(cq)).scalars().all():
        host = (c.host or "").strip()
        if not host:
            continue
        ctype = str(getattr(c.controller_type, "value", c.controller_type) or "")
        entity = {
            "kind": "controller",
            "name": c.name,
            "detail": f"{ctype} controller" if ctype else "controller",
            "ref_type": "controller",
            "ref_id": str(c.id),
            "controller_type": ctype,
        }
        # host may be an IP or FQDN; index by IP key (FQDNs simply won't
        # match a discovered IP, which is fine).
        by_ip.setdefault(host, entity)

    # --- Devices (managed + module-synced) ---------------------------
    dq = (
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(Device.deleted_at.is_(None), Site.deleted_at.is_(None))
    )
    if organization_id is not None:
        dq = dq.where(Site.organization_id == organization_id)
    if site_id is not None:
        dq = dq.where(Device.site_id == site_id)
    # same per-user site-grant confinement as the controller index above.
    if allowed_site_ids is not None:
        dq = dq.where(Device.site_id.in_(allowed_site_ids))
    for d in (await session.execute(dq)).scalars().all():
        kind = "controller_device" if d.controller_id else "device"
        dtype = str(getattr(d.device_type, "value", d.device_type) or "")
        detail = dtype.replace("_", " ") if dtype else "managed device"
        entity = {
            "kind": kind,
            "name": d.name,
            "detail": detail,
            "ref_type": "device",
            "ref_id": str(d.id),
            "device_type": dtype,
        }
        ip = (d.ip_address or "").strip()
        mac = _norm_mac(d.mac_address)
        # Devices are higher-signal than controllers when both match an
        # IP, so let them overwrite a controller entry on the same IP.
        if ip:
            by_ip[ip] = entity
        if mac:
            by_mac[mac] = entity

    return {"by_ip": by_ip, "by_mac": by_mac}


def match_known_entity(
    index: dict[str, dict[str, dict[str, Any]]],
    *,
    ip_address: str | None,
    mac_address: str | None,
) -> dict[str, Any] | None:
    """Look up a discovered host against the known-entity index.

    MAC is the stronger key (survives DHCP), checked first; IP is the
    fallback. Returns the entity dict or None when FreeSDN has never
    seen this host.
    """
    mac = _norm_mac(mac_address)
    if mac and mac in index["by_mac"]:
        return index["by_mac"][mac]
    ip = (ip_address or "").strip()
    if ip and ip in index["by_ip"]:
        return index["by_ip"][ip]
    return None


async def resolve_site_for_host(
    session: AsyncSession,
    *,
    organization_id: UUID,
    ip_address: str,
) -> UUID | None:
    """Return the site_id whose `subnets` JSONB contains the host IP.

    A site row's ``subnets`` is a list of {cidr, name, vlan_id, ...}. We
    pull every site in the org (small N — typical orgs have <50 sites)
    and check IP-in-CIDR membership in Python. This avoids a
    JSONB-aware SQL query that PostgreSQL doesn't support natively for
    CIDR containment.

    Returns the first match (sites should not overlap in subnets, but
    if they do we prefer the most-specific match by smallest prefix
    size). Returns None when no site claims the IP — callers should
    fall back to a default ``site_id`` so the discovery still lands
    somewhere.

    Cheap to call per-host inside ``upsert_batch`` (~20 sites × IP-in-CIDR
    each is microseconds). For very large orgs the caller can hoist the
    list-sites query out of the loop.
    """
    try:
        target_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    result = await session.execute(
        select(Site).where(
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
    )
    sites = result.scalars().all()

    best_site: UUID | None = None
    best_prefix = -1  # larger prefix = more specific match
    for site in sites:
        for sub in site.subnets or []:
            cidr = (sub or {}).get("cidr")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if target_ip in network and network.prefixlen > best_prefix:
                best_site = site.id
                best_prefix = network.prefixlen
    return best_site


# Fields on DiscoveredHost that we update when a new observation
# arrives. ``discovered_via`` / ``open_ports`` / ``services`` /
# ``mdns_services`` have custom merge semantics handled below.
_REPLACE_IF_PRESENT_FIELDS = (
    "hostname",
    "vendor",
    "device_type",
    "manufacturer_confidence",
    "ssdp_info",
    "http_title",
    "http_server",
    "lldp_chassis_id",
    "lldp_port_id",
    "lldp_system_name",
    "lldp_capabilities",
    "recommended_driver",
)


async def upsert_discovered_host(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    ip_address: str,
    mac_address: str | None = None,
    hostname: str | None = None,
    vendor: str | None = None,
    device_type: str | None = None,
    manufacturer_confidence: int | None = None,
    discovered_by_agent_id: UUID | None = None,
    discovered_via: list[str] | None = None,
    open_ports: list[int] | None = None,
    services: dict[str, Any] | None = None,
    mdns_services: list[str] | None = None,
    ssdp_info: dict[str, Any] | None = None,
    http_title: str | None = None,
    http_server: str | None = None,
    lldp_chassis_id: str | None = None,
    lldp_port_id: str | None = None,
    lldp_system_name: str | None = None,
    lldp_capabilities: list[str] | None = None,
    likely_device_types: list[str] | None = None,
    recommended_driver: str | None = None,
) -> DiscoveredHost:
    """Upsert a single discovered host.

    Returns the (possibly new) DiscoveredHost row. Does NOT commit —
    caller is responsible for committing the transaction so the upsert
    can be part of a batch.
    """
    # Lookup priority: site + MAC if MAC is known, else site + IP.
    existing: DiscoveredHost | None = None

    if mac_address:
        # Normalize MAC: uppercase + colon-separated
        mac_normalized = mac_address.upper().replace("-", ":")
        result = await session.execute(
            select(DiscoveredHost).where(
                and_(
                    DiscoveredHost.site_id == site_id,
                    DiscoveredHost.mac_address == mac_normalized,
                    DiscoveredHost.deleted_at.is_(None),
                )
            )
        )
        existing = result.scalar_one_or_none()
        mac_address = mac_normalized

        # If we found a MAC-keyed row for this site, we're done with lookup.
        # Otherwise, also check for any prior IP-only row at the same IP —
        # if one exists, we want to MERGE it into the MAC-keyed row (and
        # mark the orphan deleted) so the operator doesn't see two rows
        # for the same host.
        if existing is None:
            ip_only_result = await session.execute(
                select(DiscoveredHost).where(
                    and_(
                        DiscoveredHost.site_id == site_id,
                        DiscoveredHost.mac_address.is_(None),
                        DiscoveredHost.ip_address == ip_address,
                        DiscoveredHost.deleted_at.is_(None),
                    )
                )
            )
            orphan = ip_only_result.scalar_one_or_none()
            if orphan is not None:
                # Promote the orphan to a MAC-keyed row instead of
                # creating a duplicate.
                orphan.mac_address = mac_normalized
                existing = orphan
    else:
        # No MAC — match by site + IP. Note: if a row for this IP later
        # gets a MAC, the block above will promote this row.
        result = await session.execute(
            select(DiscoveredHost).where(
                and_(
                    DiscoveredHost.site_id == site_id,
                    DiscoveredHost.mac_address.is_(None),
                    DiscoveredHost.ip_address == ip_address,
                    DiscoveredHost.deleted_at.is_(None),
                )
            )
        )
        existing = result.scalar_one_or_none()

    now = datetime.now(UTC)

    if existing is None:
        # Fresh discovery
        row = DiscoveredHost(
            site_id=site_id,
            organization_id=organization_id,
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname,
            vendor=vendor,
            device_type=device_type,
            manufacturer_confidence=manufacturer_confidence,
            discovered_by_agent_id=discovered_by_agent_id,
            discovered_via=list(dict.fromkeys(discovered_via or [])),  # dedup
            open_ports=sorted(set(open_ports or [])),
            services=dict(services or {}),
            mdns_services=list(dict.fromkeys(mdns_services or [])),
            ssdp_info=ssdp_info,
            http_title=http_title,
            http_server=http_server,
            lldp_chassis_id=lldp_chassis_id,
            lldp_port_id=lldp_port_id,
            lldp_system_name=lldp_system_name,
            lldp_capabilities=lldp_capabilities,
            likely_device_types=list(dict.fromkeys(likely_device_types or [])),
            recommended_driver=recommended_driver,
            first_seen=now,
            last_seen=now,
        )
        session.add(row)
        # Flush so the caller can read row.id without re-querying.
        await session.flush()
        return row

    # Merge into existing row
    # ip_address: latest observation wins (helps when DHCP leases roll)
    if ip_address and existing.ip_address != ip_address:
        existing.ip_address = ip_address

    # Simple "replace if non-None" fields
    for field in _REPLACE_IF_PRESENT_FIELDS:
        new_val = locals().get(field)
        if new_val is not None and new_val != "":
            setattr(existing, field, new_val)

    # Multi-value merges
    if discovered_via:
        merged = list(dict.fromkeys((existing.discovered_via or []) + list(discovered_via)))
        existing.discovered_via = merged
    if open_ports:
        merged_ports = sorted(set((existing.open_ports or []) + list(open_ports)))
        existing.open_ports = merged_ports
    if services:
        merged_services = dict(existing.services or {})
        merged_services.update(services)
        existing.services = merged_services
    if mdns_services:
        merged_mdns = list(dict.fromkeys((existing.mdns_services or []) + list(mdns_services)))
        existing.mdns_services = merged_mdns
    if likely_device_types:
        merged_dts = list(
            dict.fromkeys((existing.likely_device_types or []) + list(likely_device_types))
        )
        existing.likely_device_types = merged_dts

    # Source attribution: keep the most-recent agent that saw the host.
    if discovered_by_agent_id is not None:
        existing.discovered_by_agent_id = discovered_by_agent_id

    existing.last_seen = now
    existing.updated_at = now

    # Agent-observation heartbeat for adopted standalone devices.
    # A device adopted from agent discovery has no controller to poll
    # it, so the controller-sync task never touches it and it would
    # rot to OFFLINE after the stale window. Instead, every time the
    # agent re-observes the host we bump the linked Device's last_seen
    # and keep it ONLINE — agent observation IS the liveness signal
    # for controller-less devices. Controller-managed devices are left
    # alone (their controller_id != None) so the controller stays the
    # authority for those.
    if existing.is_adopted and existing.adopted_device_id is not None:
        await _touch_adopted_device_liveness(
            session,
            existing.adopted_device_id,
            now,
        )

    await session.flush()
    return existing


async def _touch_adopted_device_liveness(
    session: AsyncSession,
    device_id: UUID,
    now: datetime,
) -> None:
    """Bump last_seen + flip ONLINE for an agent-tracked managed device.

    Only acts on devices WITHOUT a controller — those are the ones the
    controller-sync task can't reach. A device that has a controller
    keeps the controller as its liveness authority and is left
    untouched here. Status transitions ADOPTING/OFFLINE/UNKNOWN →
    ONLINE; we never downgrade a device that's already in some other
    deliberate state (e.g. MAINTENANCE).
    """
    from app.models.devices import Device, DeviceStatus

    dev = (
        await session.execute(
            select(Device).where(
                Device.id == device_id,
                Device.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if dev is None or dev.controller_id is not None:
        return

    dev.last_seen = now
    if dev.status in (
        DeviceStatus.ADOPTING,
        DeviceStatus.OFFLINE,
        DeviceStatus.UNKNOWN,
        DeviceStatus.PROVISIONING,
    ):
        dev.status = DeviceStatus.ONLINE


async def upsert_batch(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    discovered_by_agent_id: UUID | None,
    hosts: list[dict[str, Any]],
    auto_route: bool = True,
    allowed_site_ids: set[UUID] | None = None,
) -> dict[str, Any]:
    """Upsert many hosts in one transaction.

    ``hosts`` is a list of dicts using the same key names as the
    ``upsert_discovered_host`` kwargs. Returns a summary dict:
    ``{"created": N, "updated": M, "skipped": K, "routed": {site_id: count}}``.

    When ``auto_route`` is True (default), every host's IP is checked
    against every site in the org's ``subnets`` field. If a site claims
    the IP, the row lands there instead of the request's ``site_id``.
    Hosts whose IP doesn't match any site's subnets fall back to the
    request ``site_id`` (treated as the default bucket).

    A row is skipped if ip_address is missing.

    Why auto-route exists: the agent's "current site" picker in the GUI
    is a user choice, but the agent is physically on one subnet. An
    operator scanning from a Site A machine with Site B selected used
    to pollute Site B's discovered_hosts. With
    routing on, each host lands in the site whose subnet contains it.
    """
    created = 0
    updated = 0
    skipped = 0
    routed: dict[str, int] = {}

    # Hoist the site list query out of the per-host loop. Build a
    # (network, site_id) list once.
    site_cidrs: list[tuple[ipaddress._BaseNetwork, UUID]] = []
    if auto_route:
        _site_stmt = select(Site).where(
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
        if allowed_site_ids is not None:
            # a site-limited caller's auto-routing may only
            # land hosts in their granted sites. Non-matching IPs fall back to
            # the (already grant-checked) request ``site_id``, so a sibling-site
            # subnet can never claim a write.
            _site_stmt = _site_stmt.where(Site.id.in_(allowed_site_ids))
        site_rows = (await session.execute(_site_stmt)).scalars().all()
        for site in site_rows:
            for sub in site.subnets or []:
                cidr = (sub or {}).get("cidr")
                if not cidr:
                    continue
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                site_cidrs.append((network, site.id))
        # Sort by descending prefix so the most-specific match wins.
        site_cidrs.sort(key=lambda t: -t[0].prefixlen)

    def _resolve_target_site(ip: str) -> UUID:
        if not auto_route:
            return site_id
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return site_id
        for network, sid in site_cidrs:
            if target in network:
                return sid
        return site_id  # default bucket

    for h in hosts:
        ip = h.get("ip_address") or h.get("ip")
        if not ip:
            skipped += 1
            continue

        # Allow either 'mac_address' or 'mac' key shape from the agent.
        mac = h.get("mac_address") or h.get("mac")

        # Resolve the target site (subnet-claim wins, else fallback)
        target_site = _resolve_target_site(ip)

        # Discovery-via list normalization: agent may send
        # ``discovered_via`` as a single string or list.
        via = h.get("discovered_via")
        if isinstance(via, str):
            via = [via]

        check = await session.execute(
            select(DiscoveredHost.id).where(
                and_(
                    DiscoveredHost.site_id == target_site,
                    DiscoveredHost.mac_address == (mac.upper().replace("-", ":") if mac else None),
                    DiscoveredHost.deleted_at.is_(None),
                )
            )
        )
        already = check.scalar_one_or_none() is not None

        try:
            await upsert_discovered_host(
                session,
                site_id=target_site,
                organization_id=organization_id,
                ip_address=ip,
                mac_address=mac,
                hostname=h.get("hostname"),
                vendor=h.get("vendor"),
                device_type=h.get("device_type"),
                manufacturer_confidence=h.get("vendor_confidence")
                or h.get("manufacturer_confidence"),
                discovered_by_agent_id=discovered_by_agent_id,
                discovered_via=via,
                open_ports=h.get("open_ports") or [],
                services=h.get("services") or {},
                mdns_services=h.get("mdns_services") or [],
                ssdp_info=h.get("ssdp_info"),
                http_title=h.get("http_title"),
                http_server=h.get("http_server"),
                lldp_chassis_id=h.get("lldp_chassis_id"),
                lldp_port_id=h.get("lldp_port_id"),
                lldp_system_name=h.get("lldp_system_name"),
                lldp_capabilities=h.get("lldp_capabilities"),
                likely_device_types=h.get("likely_device_types") or [],
                recommended_driver=h.get("recommended_driver"),
            )
            if already:
                updated += 1
            else:
                created += 1
            sid_str = str(target_site)
            routed[sid_str] = routed.get(sid_str, 0) + 1
        except Exception:
            logger.exception(
                "Failed to upsert discovered host (ip=%s, mac=%s)",
                ip,
                mac,
            )
            skipped += 1

    summary = {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "routed": routed,
    }

    # Opt-in auto-adopt: when a site has ``settings.auto_adopt_known_vendors``
    # set, every freshly-upserted discovery whose recommended_driver +
    # vendor + MAC clear the confidence bar is promoted directly into
    # devices.devices. Keeps the operator out of the loop for the
    # obvious cases (a switch advertising NETGEAR / a Sangoma VoIP
    # phone responding on SIP) while leaving "unknown" rows in the
    # discovered queue for manual review.
    try:
        promoted = await _maybe_auto_adopt_for_site(
            session,
            site_id=site_id,
            organization_id=organization_id,
            hosts=hosts,
        )
        if promoted:
            summary["auto_adopted"] = promoted
    except Exception:
        logger.exception(
            "auto-adopt path failed for site %s — continuing without it",
            site_id,
        )

    return summary


async def _maybe_auto_adopt_for_site(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    hosts: list[dict[str, Any]],
) -> int:
    """Promote high-confidence discoveries to managed devices.

    No-op when the site's ``settings.auto_adopt_known_vendors`` is
    falsy (default). When enabled, each host is checked for:
    - MAC address present (required for device dedup)
    - ``recommended_driver`` is not None / not "generic"
    - manufacturer_confidence >= 0.7 (or vendor_confidence)
    - No existing ``devices.devices`` row with the same MAC at this site

    Devices land in ``status=ADOPTING`` (the same state the bulk-adopt
    endpoint uses), which the controller-sync task will resolve to
    online/offline on the next pass. ``adopted_by`` is left NULL since
    no human triggered it — audit logs key off ``discovery_method=
    "auto_adopt"`` for these rows.
    """
    from app.models.core import Site
    from app.models.devices import Device, DeviceStatus, DiscoveredHost

    site_row = (
        await session.execute(
            select(Site).where(
                Site.id == site_id,
                Site.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if site_row is None:
        return 0

    settings = site_row.settings or {}
    if not settings.get("auto_adopt_known_vendors"):
        return 0

    min_conf = float(settings.get("auto_adopt_min_confidence", 0.7))
    promoted = 0

    for h in hosts:
        mac = h.get("mac_address") or h.get("mac")
        if not mac:
            continue
        recommended = h.get("recommended_driver")
        if not recommended or recommended == "generic":
            continue
        conf = h.get("vendor_confidence") or h.get("manufacturer_confidence") or 0.0
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0
        if conf < min_conf:
            continue

        mac_norm = mac.upper().replace("-", ":")
        ip = h.get("ip_address") or h.get("ip")
        if not ip:
            continue

        # Skip if already adopted within THIS org. We don't dedup
        # globally because a MAC can legitimately appear in multiple
        # tenants (different physical devices in different orgs that
        # happen to share an OUI-vendor pattern), and the test
        # fixtures rely on per-org isolation.
        from app.models.core import Site as _SiteAlias

        dup = await session.execute(
            select(Device.id)
            .join(_SiteAlias, Device.site_id == _SiteAlias.id)
            .where(
                Device.mac_address == mac_norm,
                Device.deleted_at.is_(None),
                _SiteAlias.organization_id == organization_id,
            )
            .limit(1)
        )
        if dup.scalar_one_or_none() is not None:
            continue

        now = datetime.now(UTC)
        # Land standalone agent-adopted devices ONLINE, not ADOPTING.
        # The agent literally just observed this host, so it IS online.
        # ADOPTING implies a controller handshake in progress — there's
        # no controller here, so that state would never resolve and the
        # device would look permanently stuck. last_seen is set so the
        # stale-detection task has a baseline to age against.
        device = Device(
            name=h.get("hostname") or f"auto-{ip}",
            ip_address=ip,
            mac_address=mac_norm,
            device_type=h.get("device_type") or "other",
            site_id=site_id,
            driver_id=recommended,
            status=DeviceStatus.ONLINE,
            last_seen=now,
            is_adopted=True,
            adopted_at=now,
            adopted_by=None,
            manufacturer=h.get("vendor"),
            discovery_method="auto_adopt",
        )
        session.add(device)
        await session.flush()

        # Close the loop on the discovered_host row so the UI shows
        # "adopted" + links to the managed device.
        dh_row = (
            await session.execute(
                select(DiscoveredHost)
                .where(
                    DiscoveredHost.site_id == site_id,
                    DiscoveredHost.mac_address == mac_norm,
                    DiscoveredHost.deleted_at.is_(None),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if dh_row is not None:
            dh_row.is_adopted = True
            dh_row.adopted_device_id = device.id
            dh_row.adopted_at = now

        promoted += 1

    if promoted:
        logger.info(
            "Auto-adopted %d discovered host(s) for site %s",
            promoted,
            site_id,
        )
    return promoted
