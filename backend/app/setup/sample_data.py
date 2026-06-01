# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Sample Data Generator
====================================

Generates realistic sample/demo data so a fresh install already looks
populated.  Used by the setup wizard when the user checks
"Install sample data".

The volumes here are intentionally generous so that *every* DB-backed page
(devices, clients, VLANs, WiFi, ports, alerts, events, audit logs,
incidents, backups, firmware, topology) is richly populated and there is
plenty of data to safely exercise full CRUD (delete a device, clear logs,
resolve alerts/incidents, delete backups, …) on a fresh install with no
live hardware.

All data is inserted via ORM — no raw SQL.

Determinism
-----------
``random`` is seeded at the top of ``install_sample_data`` so repeated
installs on a fresh DB produce the same shape of data.  ``_NOW`` is
captured once per call so every timestamp is consistent relative to "now".
MAC addresses come from a monotonic counter (``_next_mac``) so the
``uq_devices_mac_alive`` partial-unique index is never violated even across
~50 devices and ~150 clients.
"""

import logging
import random
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_credential
from app.models.alert_rules import Alert, AlertRule
from app.models.core import (
    Controller,
    ControllerStatus,
    ControllerType,
    Site,
)
from app.models.correlation import Incident, IncidentEvent
from app.models.devices import (
    ConnectionType,
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    DeviceType,
    PortStatus,
    PortType,
)
from app.models.events import EventCategory, EventPriority, EventRecord
from app.models.firmware import DeviceFirmwareStatus, FirmwareImage
from app.models.security_audit import AuditLogRecord
from app.modules.backup.models import Backup, BackupSchedule
from app.modules.network.models import (
    Network,
    TopologyLink,
    WifiBand,
    WifiNetwork,
    WifiSecurityType,
)
from app.setup.schemas import SampleDataResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants for realistic data
# ---------------------------------------------------------------------------

_NOW: datetime = datetime.now(UTC)  # populated at call time so every row is consistent

# Monotonic MAC counter — guarantees globally-unique MACs (the devices table
# has a partial-unique index ``uq_devices_mac_alive`` on alive rows). Reset at
# the start of every install so a fresh DB is deterministic.
_MAC_COUNTER: int = 0

# (model, vendor, port_count)
SWITCH_MODELS = [
    ("TL-SG3428XMP", "TP-Link", 28),
    ("TL-SG2210MP", "TP-Link", 10),
    ("TL-SG3452XP", "TP-Link", 52),
    ("TL-SG2428P", "TP-Link", 28),
    ("TL-SG3210XHP-M2", "TP-Link", 10),
    ("Catalyst 9200L-24P", "Cisco", 24),
    ("Catalyst 9300-48P", "Cisco", 48),
    ("ICX 7150-48ZP", "Ruckus", 48),
    ("USW-Pro-24-PoE", "Ubiquiti", 24),
    ("USW-Aggregation", "Ubiquiti", 8),
    ("GS748T", "Netgear", 48),
    ("EX3300-24P", "Juniper", 24),
]

# (model, vendor)
AP_MODELS = [
    ("EAP670", "TP-Link"),
    ("EAP660 HD", "TP-Link"),
    ("EAP620 HD", "TP-Link"),
    ("EAP610", "TP-Link"),
    ("EAP245", "TP-Link"),
    ("EAP650", "TP-Link"),
    ("U6-Pro", "Ubiquiti"),
    ("U6-Lite", "Ubiquiti"),
    ("U7-Pro", "Ubiquiti"),
    ("Catalyst 9120AXI", "Cisco"),
    ("R750", "Ruckus"),
    ("AX3000", "Aruba"),
]

# (model, vendor)
GATEWAY_MODELS = [
    ("ER8411", "TP-Link"),
    ("ER7206", "TP-Link"),
    ("UDM-Pro", "Ubiquiti"),
    ("UXG-Pro", "Ubiquiti"),
    ("FortiGate 60F", "Fortinet"),
    ("MX67", "Cisco Meraki"),
]

# (model, vendor)
CAMERA_MODELS = [
    ("DS-2CD2143G2-I", "Hikvision"),
    ("DS-2CD2386G2-IU", "Hikvision"),
    ("DS-2DE4A425IW-DE", "Hikvision"),
    ("P3245-LVE", "Axis"),
    ("M3085-V", "Axis"),
    ("G4 Pro", "Ubiquiti"),
    ("G5 Bullet", "Ubiquiti"),
]

# (model, vendor, channels)
NVR_MODELS = [
    ("DS-7616NI-K2", "Hikvision", 16),
    ("DS-9664NI-I8", "Hikvision", 64),
    ("UNVR-Pro", "Ubiquiti", 20),
]

# (model, vendor)
VOIP_MODELS = [
    ("GXP2170", "Grandstream"),
    ("GRP2614", "Grandstream"),
    ("GXV3370", "Grandstream"),
    ("T54W", "Yealink"),
]

FLOOR_NAMES = ["Basement", "Ground Floor", "1st Floor", "2nd Floor", "3rd Floor"]
ROOM_NAMES = [
    "Server Room",
    "Conference Room A",
    "Conference Room B",
    "Open Office",
    "Reception",
    "IT Office",
    "CEO Office",
    "Finance Office",
    "Meeting Room 1",
    "Meeting Room 2",
    "Cafeteria",
    "Storage Room",
    "Lab 1",
    "Lab 2",
    "Warehouse",
    "Lobby",
    "Loading Dock",
    "Break Room",
    "Sales Floor",
    "Parking Garage",
]
NET_CLOSETS = ["IDF Closet", "MDF", "Server Room", "Network Closet", "Comms Room"]

# Client hostname fragments → built into many varied client names.
CLIENT_NAME_PARTS = [
    "iphone",
    "macbook-pro",
    "macbook-air",
    "pixel",
    "galaxy-s24",
    "galaxy-tab",
    "ipad",
    "thinkpad",
    "dell-latitude",
    "dell-optiplex",
    "hp-elitebook",
    "surface-pro",
    "surface-laptop",
    "chromebook",
    "desktop",
    "workstation",
    "nuc",
]
CLIENT_PEOPLE = [
    "john",
    "sarah",
    "mike",
    "emma",
    "raj",
    "li",
    "carlos",
    "anna",
    "dev01",
    "dev02",
    "cfo",
    "ceo",
    "it",
    "finance",
    "sales",
    "hr",
    "guest",
    "marketing",
    "ops",
    "qa",
]
# IoT / fixed-function clients (hostname, os/kind)
IOT_CLIENTS = [
    ("hp-printer-finance", "Printer"),
    ("brother-printer-it", "Printer"),
    ("xerox-mfp-lobby", "Printer"),
    ("apple-tv-conf", "tvOS"),
    ("chromecast-mr2", "Android"),
    ("roku-breakroom", "Roku"),
    ("thermostat-hvac", "IoT"),
    ("nest-thermostat-2", "IoT"),
    ("security-cam-lobby", "Linux"),
    ("ring-doorbell", "IoT"),
    ("sonos-speaker-cafe", "Linux"),
    ("echo-dot-kitchen", "FireOS"),
    ("zoom-room-conf-a", "Android"),
    ("polycom-phone-1", "VoIP"),
    ("grandstream-phone-3", "VoIP"),
    ("smart-tv-lobby", "Tizen"),
    ("hvac-controller", "IoT"),
    ("door-access-main", "Linux"),
    ("ups-monitor-srv", "Linux"),
    ("nas-backup", "Linux"),
]

CLIENT_OS = ["iOS", "macOS", "Windows", "Android", "Linux", "ChromeOS"]

# ---------------------------------------------------------------------------
# Deterministic helpers (preserved + extended)
# ---------------------------------------------------------------------------


def _next_mac() -> str:
    """Return a globally-unique MAC address.

    Uses a locally-administered OUI (02:…) plus a monotonic counter so that
    no two devices/clients ever collide — important because the devices
    table enforces ``uq_devices_mac_alive``.
    """
    global _MAC_COUNTER
    _MAC_COUNTER += 1
    n = _MAC_COUNTER
    octets = [(n >> shift) & 0xFF for shift in (32, 24, 16, 8, 0)]
    return "02:" + ":".join(f"{o:02X}" for o in octets)


def _mac() -> str:
    """Generate a random MAC address (used for non-unique client/uplink macs)."""
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def _ip(base: str = "10.10") -> str:
    """Generate a random internal IPv4 address."""
    return f"{base}.{random.randint(1, 254)}.{random.randint(2, 254)}"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def install_sample_data(
    db: AsyncSession,
    organization_id: UUID,
    site_id: UUID,
) -> SampleDataResponse:
    """Insert a realistic set of demo data into the database.

    Returns a summary of what was created.
    """
    global _NOW, _MAC_COUNTER
    _NOW = datetime.now(UTC)
    _MAC_COUNTER = 0
    # Deterministic-ish: seed so a fresh install is reproducible while the
    # individual rows still look varied.
    random.seed(1337)

    try:
        # ── Additional Sites ──────────────────────────────────────────────
        extra_sites = await _create_extra_sites(db, organization_id)
        all_site_ids = [site_id] + [s.id for s in extra_sites]

        # ── One controller per site ───────────────────────────────────────
        controllers = await _create_sample_controllers(db, all_site_ids)

        # ── VLANs / Networks (per site) ───────────────────────────────────
        vlans = await _create_vlans(db, controllers, all_site_ids)

        # ── WiFi Networks (per site) ──────────────────────────────────────
        wifi_nets = await _create_wifi_networks(db, controllers, all_site_ids, vlans)

        # ── Devices: switches, APs, gateways, cameras, NVRs, phones ───────
        devices = await _create_devices(db, controllers, all_site_ids)

        # ── Ports on switches ─────────────────────────────────────────────
        await _create_ports(db, devices)

        # ── Topology links (uplinks + L2 edges) ──────────────────────────
        await _create_topology(db, devices)

        # ── Wired + wireless clients on switches/APs ──────────────────────
        clients = await _create_clients(db, devices, wifi_nets)

        # ── Alert rules + fired alerts ────────────────────────────────────
        rules, alerts = await _create_alert_rules_and_alerts(
            db,
            organization_id,
            all_site_ids,
            devices,
        )

        # ── Event records (activity feed; written to the LogDB) ───────────
        events = await _create_event_records(
            organization_id,
            all_site_ids,
            devices,
        )

        # ── Audit log records ─────────────────────────────────────────────
        audit_logs = await _create_audit_logs(db, organization_id, all_site_ids)

        # ── Incidents (correlated events) ─────────────────────────────────
        incidents = await _create_incidents(
            db,
            organization_id,
            all_site_ids,
            events,
        )

        # ── Backup history ────────────────────────────────────────────────
        backups = await _create_backup_history(db, organization_id, all_site_ids, len(devices))

        # ── Firmware images + device status ───────────────────────────────
        fw_images = await _create_firmware_data(
            db,
            organization_id,
            devices,
        )

        await db.flush()
        logger.info(
            "Sample data installed: %d devices, %d VLANs, %d WiFi, %d clients, "
            "%d alerts, %d events, %d audit logs, %d incidents, %d backups, %d firmware",
            len(devices),
            len(vlans),
            len(wifi_nets),
            len(clients),
            len(alerts),
            len(events),
            len(audit_logs),
            len(incidents),
            len(backups),
            len(fw_images),
        )

        return SampleDataResponse(
            success=True,
            devices_created=len(devices),
            vlans_created=len(vlans),
            wifi_networks_created=len(wifi_nets),
            clients_created=len(clients),
            alerts_created=len(alerts),
            events_created=len(events),
            audit_logs_created=len(audit_logs),
            incidents_created=len(incidents),
            backups_created=len(backups),
            firmware_images_created=len(fw_images),
            message=(
                f"Installed {len(devices)} devices, {len(vlans)} VLANs, "
                f"{len(wifi_nets)} WiFi networks, {len(clients)} clients, "
                f"{len(alerts)} alerts, {len(events)} events, "
                f"{len(audit_logs)} audit logs, and {len(incidents)} incidents."
            ),
        )
    except Exception as exc:
        logger.exception("Sample data installation failed")
        await db.rollback()
        return SampleDataResponse(success=False, error=str(exc))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


async def _create_extra_sites(db: AsyncSession, org_id: UUID) -> list[Site]:
    """Create additional sites so the multi-site UI looks realistic."""
    sites_data = [
        (
            "Data Center",
            "dc1",
            "Primary data center",
            "100 Congress Ave",
            "Austin",
            "USA",
            "America/Chicago",
        ),
        (
            "Branch Office",
            "branch-1",
            "Regional branch office",
            "350 5th Ave",
            "New York",
            "USA",
            "America/New_York",
        ),
    ]
    sites: list[Site] = []
    for name, slug, desc, address, city, country, tz in sites_data:
        s = Site(
            id=uuid4(),
            organization_id=org_id,
            name=name,
            slug=slug,
            description=desc,
            address=address,
            city=city,
            country=country,
            timezone=tz,
            is_active=True,
        )
        db.add(s)
        sites.append(s)
    await db.flush()
    return sites


async def _create_sample_controllers(
    db: AsyncSession,
    site_ids: list[UUID],
) -> list[Controller]:
    """Create one controller per site, with a mix of vendors/statuses."""
    # (name, type, host, port, status, sync_enabled)
    ctrl_defs = [
        (
            "HQ Omada Controller",
            ControllerType.OMADA,
            "198.51.100.1",
            443,
            ControllerStatus.CONNECTED,
            True,
        ),
        (
            "DC UniFi Controller",
            ControllerType.UNIFI,
            "198.51.100.2",
            8443,
            ControllerStatus.CONNECTED,
            True,
        ),
        (
            "Branch OPNsense Firewall",
            ControllerType.OPNSENSE,
            "198.51.100.3",
            443,
            ControllerStatus.CONNECTED,
            True,
        ),
    ]

    controllers: list[Controller] = []
    for i, sid in enumerate(site_ids):
        name, ctype, host, port, status, sync = ctrl_defs[i % len(ctrl_defs)]
        ctrl = Controller(
            id=uuid4(),
            site_id=sid,
            name=name,
            description=f"Sample controller for {name}",
            controller_type=ctype,
            host=host,
            port=port,
            use_ssl=True,
            verify_ssl=False,
            status=status,
            config={
                "username": encrypt_credential("demo-admin"),
                "password": encrypt_credential("demo-sample-data-only"),
            },
            sync_enabled=sync,
            sync_interval_seconds=300,
            is_active=True,
            last_sync=_NOW - timedelta(minutes=random.randint(1, 30)),
        )
        db.add(ctrl)
        controllers.append(ctrl)
    await db.flush()
    return controllers


# Canonical VLAN catalog reused per-site.
_VLAN_DEFS = [
    (1, "Default", "Default untagged network", "192.168.{o}.1", "192.168.{o}.0/24", True),
    (10, "Management", "Network management VLAN", "10.{o}.10.1", "10.{o}.10.0/24", True),
    (20, "Staff", "Employee workstations", "10.{o}.20.1", "10.{o}.20.0/24", True),
    (30, "Guest", "Guest WiFi network", "10.{o}.30.1", "10.{o}.30.0/24", True),
    (40, "IoT", "Internet of Things devices", "10.{o}.40.1", "10.{o}.40.0/24", True),
    (50, "VoIP", "Voice over IP phones", "10.{o}.50.1", "10.{o}.50.0/24", True),
    (60, "Security", "Cameras and access control", "10.{o}.60.1", "10.{o}.60.0/24", True),
    (70, "BYOD", "Bring-your-own-device", "10.{o}.70.1", "10.{o}.70.0/24", True),
    (80, "Printers", "Printers and MFPs", "10.{o}.80.1", "10.{o}.80.0/24", True),
    (90, "Lab", "Engineering lab network", "10.{o}.90.1", "10.{o}.90.0/24", True),
    (100, "Servers", "Server infrastructure", "10.{o}.100.1", "10.{o}.100.0/24", False),
    (110, "DMZ", "Demilitarized zone", "10.{o}.110.1", "10.{o}.110.0/24", False),
    (120, "Storage", "SAN / NAS storage network", "10.{o}.120.1", "10.{o}.120.0/24", False),
    (200, "Quarantine", "Isolated / quarantined hosts", "10.{o}.200.1", "10.{o}.200.0/24", False),
]


async def _create_vlans(
    db: AsyncSession,
    controllers: list[Controller],
    site_ids: list[UUID],
) -> list[Network]:
    """Create a realistic set of VLANs spread across all sites."""
    vlans: list[Network] = []
    for site_idx, sid in enumerate(site_ids):
        ctrl = controllers[site_idx % len(controllers)]
        octet = 10 * (site_idx + 1)  # different L3 space per site
        # Each site gets a varied subset so totals add up to ~40 across 3 sites.
        if site_idx == 0:
            chosen = _VLAN_DEFS  # HQ gets all 14
        elif site_idx == 1:
            chosen = _VLAN_DEFS[:14]  # DC also full
        else:
            chosen = _VLAN_DEFS[:12]  # Branch slightly fewer
        for vid, name, desc, gw_tpl, cidr_tpl, dhcp in chosen:
            cidr = cidr_tpl.format(o=octet)
            gw = gw_tpl.format(o=octet)
            subnet = cidr.split("/")[0]
            base3 = ".".join(subnet.split(".")[:3])
            v = Network(
                id=uuid4(),
                controller_id=ctrl.id,
                site_id=sid,
                external_id=f"vlan_{site_idx}_{vid}",
                name=name,
                vlan_id=vid,
                description=desc,
                gateway=gw,
                subnet=subnet,
                cidr=cidr,
                dhcp_enabled=dhcp,
                dhcp_start=f"{base3}.100" if dhcp else None,
                dhcp_end=f"{base3}.254" if dhcp else None,
                is_active=vid != 200,  # quarantine VLAN inactive
                purpose="lan" if vid not in (110,) else "wan",
                network_metadata={"site_index": site_idx},
            )
            db.add(v)
            vlans.append(v)
    await db.flush()
    return vlans


_WIFI_DEFS = [
    ("{site}-Staff", WifiSecurityType.WPA2_WPA3_PERSONAL, WifiBand.BOTH, 20, True),
    ("{site}-Guest", WifiSecurityType.WPA2_PERSONAL, WifiBand.BOTH, 30, True),
    ("{site}-IoT", WifiSecurityType.WPA2_PERSONAL, WifiBand.BAND_2_4, 40, True),
    ("{site}-BYOD", WifiSecurityType.WPA2_WPA3_PERSONAL, WifiBand.BOTH, 70, True),
    ("{site}-Admin", WifiSecurityType.WPA3_PERSONAL, WifiBand.BAND_5, 10, False),
]


async def _create_wifi_networks(
    db: AsyncSession,
    controllers: list[Controller],
    site_ids: list[UUID],
    vlans: list[Network],
) -> list[WifiNetwork]:
    """Create WiFi SSIDs linked to VLANs, per site (~12 total)."""
    site_prefixes = ["FreeSDN", "DC", "Branch"]
    nets: list[WifiNetwork] = []
    for site_idx, sid in enumerate(site_ids):
        ctrl = controllers[site_idx % len(controllers)]
        prefix = site_prefixes[site_idx % len(site_prefixes)]
        # HQ gets all 5; DC 4; Branch 3 → 12 total.
        count = [5, 4, 3][site_idx] if site_idx < 3 else 3
        for ssid_tpl, sec, band, vid, enabled in _WIFI_DEFS[:count]:
            ssid = ssid_tpl.format(site=prefix)
            w = WifiNetwork(
                id=uuid4(),
                controller_id=ctrl.id,
                site_id=sid,
                external_id=f"wifi_{site_idx}_{ssid.lower().replace('-', '_')}",
                ssid=ssid,
                security=sec,
                band=band,
                vlan_id=vid,
                enabled=enabled,
                hidden=not enabled,
                band_steering=band == WifiBand.BOTH,
                fast_roaming=vid in (10, 20),
                client_isolation=vid in (30, 40),
                wifi_metadata={"site_index": site_idx},
            )
            db.add(w)
            nets.append(w)
    await db.flush()
    return nets


def _make_device(**kwargs) -> Device:
    """Construct a Device with sane shared defaults."""
    return Device(id=uuid4(), is_active=True, is_managed=True, **kwargs)


async def _create_devices(
    db: AsyncSession,
    controllers: list[Controller],
    site_ids: list[UUID],
) -> list[Device]:
    """Create ~50 devices spread across sites: gateways, switches, APs,
    cameras, NVRs, and VoIP phones, with varied vendors/models/status."""
    devices: list[Device] = []
    ext_seq = 0

    # Per-site device plan: (#switches, #aps, #cameras, #nvrs, #phones)
    # Site 0 (HQ): big.  Site 1 (DC): infra-heavy.  Site 2 (Branch): small.
    site_plans = [
        {"switches": 4, "aps": 6, "cameras": 5, "nvrs": 1, "phones": 4},
        {"switches": 4, "aps": 4, "cameras": 4, "nvrs": 1, "phones": 2},
        {"switches": 2, "aps": 3, "cameras": 2, "nvrs": 1, "phones": 2},
    ]

    for site_idx, sid in enumerate(site_ids):
        ctrl = controllers[site_idx % len(controllers)]
        plan = site_plans[site_idx % len(site_plans)]
        mgmt_octet = 10 * (site_idx + 1)

        def _next_ext(prefix: str) -> str:
            nonlocal ext_seq
            ext_seq += 1
            return f"{prefix}_{ext_seq}"

        # ── Gateway ──
        gw_model, gw_vendor = GATEWAY_MODELS[site_idx % len(GATEWAY_MODELS)]
        gw = _make_device(
            controller_id=ctrl.id,
            site_id=sid,
            name=f"GW-{['HQ', 'DC', 'BR'][site_idx % 3]}-01",
            mac_address=_next_mac(),
            serial_number=f"GW{random.randint(100000, 999999)}",
            external_id=_next_ext("gw"),
            device_type=DeviceType.GATEWAY,
            model=gw_model,
            manufacturer=gw_vendor,
            firmware_version=random.choice(["2.3.0", "2.2.6", "3.1.1"]),
            ip_address=f"192.168.{mgmt_octet}.1",
            connection_type=ConnectionType.WIRED,
            vlan_id=1,
            location="Server Room",
            floor="Ground Floor",
            room="Server Room",
            status=DeviceStatus.ONLINE,
            last_seen=_NOW,
            uptime_seconds=random.randint(100_000, 8_000_000),
            cpu_usage_percent=round(random.uniform(5, 35), 1),
            memory_usage_percent=round(random.uniform(20, 60), 1),
            temperature_celsius=round(random.uniform(35, 55), 1),
            is_adopted=True,
            adopted_at=_NOW - timedelta(days=random.randint(30, 400)),
            lifecycle_state="managed",
            lifecycle_changed_at=_NOW - timedelta(days=random.randint(30, 400)),
            device_metadata={
                "wan_ip": f"203.0.113.{40 + site_idx}",
                "wan_gateway": "203.0.113.1",
            },
            capabilities={"firewall": True, "vpn": True, "load_balance": True},
        )
        db.add(gw)
        devices.append(gw)

        # ── Switches ──
        for i in range(plan["switches"]):
            model, vendor, port_count = SWITCH_MODELS[(site_idx * 3 + i) % len(SWITCH_MODELS)]
            floor = FLOOR_NAMES[i % len(FLOOR_NAMES)]
            # ~10% offline, ~10% degraded, rest online
            roll = random.random()
            status = (
                DeviceStatus.OFFLINE
                if roll < 0.08
                else (DeviceStatus.DEGRADED if roll < 0.18 else DeviceStatus.ONLINE)
            )
            sw = _make_device(
                controller_id=ctrl.id,
                site_id=sid,
                name=f"SW-{['HQ', 'DC', 'BR'][site_idx % 3]}-{floor.replace(' ', '')}-{i + 1}",
                mac_address=_next_mac(),
                serial_number=f"SW{random.randint(100000, 999999)}",
                external_id=_next_ext("sw"),
                device_type=DeviceType.SWITCH,
                model=model,
                manufacturer=vendor,
                firmware_version=random.choice(["1.6.3", "1.6.1", "2.0.4", "16.12.5"]),
                ip_address=f"10.{mgmt_octet}.10.{10 + i}",
                connection_type=ConnectionType.WIRED,
                vlan_id=10,
                location=floor,
                floor=floor,
                room=random.choice(NET_CLOSETS),
                status=status,
                last_seen=_NOW
                if status == DeviceStatus.ONLINE
                else _NOW - timedelta(minutes=random.randint(5, 240)),
                uptime_seconds=0
                if status == DeviceStatus.OFFLINE
                else random.randint(200_000, 9_000_000),
                cpu_usage_percent=round(random.uniform(3, 30), 1),
                memory_usage_percent=round(random.uniform(15, 55), 1),
                temperature_celsius=round(random.uniform(30, 52), 1),
                is_adopted=True,
                adopted_at=_NOW - timedelta(days=random.randint(5, 300)),
                lifecycle_state="offline" if status == DeviceStatus.OFFLINE else "managed",
                lifecycle_changed_at=_NOW - timedelta(days=random.randint(5, 300)),
                device_metadata={
                    "port_count": port_count,
                    "poe_budget_watts": port_count * 15,
                },
                capabilities={"poe": True, "vlan": True, "stp": True, "lacp": True},
            )
            db.add(sw)
            devices.append(sw)

        # ── Access Points ──
        for i in range(plan["aps"]):
            model, vendor = AP_MODELS[(site_idx * 4 + i) % len(AP_MODELS)]
            floor = FLOOR_NAMES[i % len(FLOOR_NAMES)]
            room = ROOM_NAMES[i % len(ROOM_NAMES)]
            roll = random.random()
            status = (
                DeviceStatus.OFFLINE
                if roll < 0.05
                else (DeviceStatus.DEGRADED if roll < 0.15 else DeviceStatus.ONLINE)
            )
            ap = _make_device(
                controller_id=ctrl.id,
                site_id=sid,
                name=f"AP-{['HQ', 'DC', 'BR'][site_idx % 3]}-{floor.replace(' ', '')}-{i + 1}",
                mac_address=_next_mac(),
                serial_number=f"AP{random.randint(100000, 999999)}",
                external_id=_next_ext("ap"),
                device_type=DeviceType.ACCESS_POINT,
                model=model,
                manufacturer=vendor,
                firmware_version=random.choice(["1.4.2", "1.5.0", "6.5.28", "1.3.7"]),
                ip_address=f"10.{mgmt_octet}.10.{100 + i}",
                connection_type=ConnectionType.POE,
                vlan_id=10,
                location=f"{floor}, {room}",
                floor=floor,
                room=room,
                status=status,
                last_seen=_NOW
                if status == DeviceStatus.ONLINE
                else _NOW - timedelta(minutes=random.randint(5, 120)),
                uptime_seconds=0
                if status == DeviceStatus.OFFLINE
                else random.randint(50_000, 4_000_000),
                cpu_usage_percent=round(random.uniform(5, 45), 1),
                memory_usage_percent=round(random.uniform(20, 75), 1),
                temperature_celsius=round(random.uniform(30, 62), 1),
                is_adopted=True,
                adopted_at=_NOW - timedelta(days=random.randint(1, 250)),
                lifecycle_state="offline" if status == DeviceStatus.OFFLINE else "managed",
                lifecycle_changed_at=_NOW - timedelta(days=random.randint(1, 250)),
                device_metadata={
                    "clients_2g": random.randint(2, 18),
                    "clients_5g": random.randint(5, 35),
                },
                capabilities={
                    "wifi6": "670" in model or "660" in model or "U6" in model or "U7" in model,
                    "mesh": True,
                    "band_steering": True,
                },
            )
            db.add(ap)
            devices.append(ap)

        # ── Cameras ──
        for i in range(plan["cameras"]):
            model, vendor = CAMERA_MODELS[(site_idx * 2 + i) % len(CAMERA_MODELS)]
            room = ROOM_NAMES[(i + 5) % len(ROOM_NAMES)]
            roll = random.random()
            status = DeviceStatus.OFFLINE if roll < 0.06 else DeviceStatus.ONLINE
            cam = _make_device(
                controller_id=ctrl.id,
                site_id=sid,
                name=f"CAM-{['HQ', 'DC', 'BR'][site_idx % 3]}-{room.replace(' ', '')}-{i + 1}",
                mac_address=_next_mac(),
                serial_number=f"CAM{random.randint(1000000, 9999999)}",
                external_id=_next_ext("cam"),
                device_type=DeviceType.CAMERA,
                model=model,
                manufacturer=vendor,
                firmware_version=random.choice(["5.7.3", "5.6.820", "11.9.55", "1.2.4"]),
                ip_address=f"10.{mgmt_octet}.60.{20 + i}",
                connection_type=ConnectionType.POE,
                vlan_id=60,
                location=room,
                floor=FLOOR_NAMES[i % len(FLOOR_NAMES)],
                room=room,
                status=status,
                last_seen=_NOW
                if status == DeviceStatus.ONLINE
                else _NOW - timedelta(minutes=random.randint(5, 60)),
                uptime_seconds=0
                if status == DeviceStatus.OFFLINE
                else random.randint(50_000, 5_000_000),
                cpu_usage_percent=round(random.uniform(10, 40), 1),
                memory_usage_percent=round(random.uniform(30, 70), 1),
                temperature_celsius=round(random.uniform(35, 58), 1),
                is_adopted=True,
                adopted_at=_NOW - timedelta(days=random.randint(10, 300)),
                lifecycle_state="offline" if status == DeviceStatus.OFFLINE else "managed",
                lifecycle_changed_at=_NOW - timedelta(days=random.randint(10, 300)),
                device_metadata={
                    "resolution": random.choice(["4MP", "8MP", "4K"]),
                    "fps": random.choice([15, 20, 25, 30]),
                    "ir_enabled": True,
                },
                capabilities={"ptz": "DE" in model, "motion_detection": True, "onvif": True},
            )
            db.add(cam)
            devices.append(cam)

        # ── NVRs ──
        for i in range(plan["nvrs"]):
            model, vendor, channels = NVR_MODELS[(site_idx + i) % len(NVR_MODELS)]
            nvr = _make_device(
                controller_id=ctrl.id,
                site_id=sid,
                name=f"NVR-{['HQ', 'DC', 'BR'][site_idx % 3]}-{i + 1}",
                mac_address=_next_mac(),
                serial_number=f"NVR{random.randint(1000000, 9999999)}",
                external_id=_next_ext("nvr"),
                device_type=DeviceType.NVR,
                model=model,
                manufacturer=vendor,
                firmware_version=random.choice(["4.62.005", "4.30.000", "3.1.16"]),
                ip_address=f"10.{mgmt_octet}.60.{10 + i}",
                connection_type=ConnectionType.WIRED,
                vlan_id=60,
                location="Server Room",
                floor="Ground Floor",
                room="Server Room",
                status=DeviceStatus.ONLINE,
                last_seen=_NOW,
                uptime_seconds=random.randint(200_000, 7_000_000),
                cpu_usage_percent=round(random.uniform(15, 55), 1),
                memory_usage_percent=round(random.uniform(40, 80), 1),
                temperature_celsius=round(random.uniform(38, 60), 1),
                is_adopted=True,
                adopted_at=_NOW - timedelta(days=random.randint(20, 400)),
                lifecycle_state="managed",
                lifecycle_changed_at=_NOW - timedelta(days=random.randint(20, 400)),
                device_metadata={
                    "channels": channels,
                    "storage_tb": random.choice([8, 16, 32, 64]),
                    "recording": True,
                },
                capabilities={"recording": True, "playback": True, "onvif": True},
            )
            db.add(nvr)
            devices.append(nvr)

        # ── VoIP phones ──
        for i in range(plan["phones"]):
            model, vendor = VOIP_MODELS[(site_idx + i) % len(VOIP_MODELS)]
            room = ROOM_NAMES[(i + 2) % len(ROOM_NAMES)]
            roll = random.random()
            status = DeviceStatus.OFFLINE if roll < 0.1 else DeviceStatus.ONLINE
            phone = _make_device(
                controller_id=ctrl.id,
                site_id=sid,
                name=f"PHONE-{['HQ', 'DC', 'BR'][site_idx % 3]}-{1000 + i}",
                mac_address=_next_mac(),
                serial_number=f"PH{random.randint(1000000, 9999999)}",
                external_id=_next_ext("phone"),
                device_type=DeviceType.VOIP_PHONE,
                model=model,
                manufacturer=vendor,
                firmware_version=random.choice(["1.0.11.79", "1.0.3.37", "84.0.0.95"]),
                ip_address=f"10.{mgmt_octet}.50.{50 + i}",
                connection_type=ConnectionType.POE,
                vlan_id=50,
                location=room,
                floor=FLOOR_NAMES[i % len(FLOOR_NAMES)],
                room=room,
                status=status,
                last_seen=_NOW
                if status == DeviceStatus.ONLINE
                else _NOW - timedelta(hours=random.randint(1, 12)),
                uptime_seconds=0
                if status == DeviceStatus.OFFLINE
                else random.randint(20_000, 3_000_000),
                cpu_usage_percent=round(random.uniform(2, 20), 1),
                memory_usage_percent=round(random.uniform(20, 55), 1),
                temperature_celsius=round(random.uniform(28, 45), 1),
                is_adopted=True,
                adopted_at=_NOW - timedelta(days=random.randint(5, 200)),
                lifecycle_state="offline" if status == DeviceStatus.OFFLINE else "managed",
                lifecycle_changed_at=_NOW - timedelta(days=random.randint(5, 200)),
                device_metadata={
                    "extension": str(1000 + i + site_idx * 100),
                    "registered": status == DeviceStatus.ONLINE,
                },
                capabilities={"hd_voice": True, "poe": True},
            )
            db.add(phone)
            devices.append(phone)

    await db.flush()
    return devices


async def _create_ports(db: AsyncSession, devices: list[Device]) -> int:
    """Create ports for switches.  Returns total port count."""
    total = 0
    switches = [d for d in devices if d.device_type == DeviceType.SWITCH]

    vlan_options = [1, 10, 20, 30, 40, 50, 60, 70, 80, 100]

    for sw in switches:
        sw_offline = sw.status == DeviceStatus.OFFLINE
        port_count = sw.device_metadata.get("port_count", 24) if sw.device_metadata else 24
        for pn in range(1, port_count + 1):
            is_uplink = pn >= port_count - 1  # last 2 ports = SFP+ uplinks
            if sw_offline:
                status = PortStatus.DOWN
            else:
                status = random.choice(
                    [PortStatus.UP, PortStatus.UP, PortStatus.UP, PortStatus.DOWN]
                )
            has_client = status == PortStatus.UP and not is_uplink

            port = DevicePort(
                id=uuid4(),
                device_id=sw.id,
                port_number=pn,
                name=f"GE{pn}" if not is_uplink else f"SFP+{pn - port_count + 2}",
                port_type=PortType.ETHERNET if not is_uplink else PortType.SFP_PLUS,
                status=status,
                is_enabled=not (status == PortStatus.DOWN and random.random() < 0.1),
                is_poe_enabled=not is_uplink,
                vlan_id=random.choice(vlan_options),
                speed_mbps=1000 if not is_uplink else 10000,
                duplex="full",
                poe_power_watts=round(random.uniform(2, 25), 1)
                if (not is_uplink and status == PortStatus.UP)
                else None,
                poe_class=random.choice([0, 2, 3, 4]) if not is_uplink else None,
                tx_bytes=random.randint(100_000, 50_000_000_000) if status == PortStatus.UP else 0,
                rx_bytes=random.randint(100_000, 50_000_000_000) if status == PortStatus.UP else 0,
                tx_packets=random.randint(1000, 100_000_000) if status == PortStatus.UP else 0,
                rx_packets=random.randint(1000, 100_000_000) if status == PortStatus.UP else 0,
                errors=random.randint(0, 50),
                connected_mac=_mac() if has_client else None,
                port_metadata={},
            )
            db.add(port)
            total += 1

    await db.flush()
    return total


async def _create_topology(db: AsyncSession, devices: list[Device]) -> int:
    """Create topology links: gateway↔switches and switches↔APs/cameras
    within each site so the topology view has edges to render."""
    total = 0
    # Group devices by site.
    by_site: dict[UUID, list[Device]] = {}
    for d in devices:
        by_site.setdefault(d.site_id, []).append(d)

    for site_devices in by_site.values():
        gws = [d for d in site_devices if d.device_type == DeviceType.GATEWAY]
        switches = [d for d in site_devices if d.device_type == DeviceType.SWITCH]
        leaves = [
            d
            for d in site_devices
            if d.device_type
            in (DeviceType.ACCESS_POINT, DeviceType.CAMERA, DeviceType.NVR, DeviceType.VOIP_PHONE)
        ]
        if not switches:
            continue
        core_sw = switches[0]

        # Gateway → core switch
        for gw in gws:
            db.add(
                TopologyLink(
                    id=uuid4(),
                    source_device_id=gw.id,
                    target_device_id=core_sw.id,
                    source_port="LAN1",
                    target_port="SFP+1",
                    speed="10G",
                    status="up",
                    link_type="fiber",
                    discovered_via="lldp",
                    link_metadata={},
                )
            )
            total += 1

        # Core switch → other switches
        for sw in switches[1:]:
            db.add(
                TopologyLink(
                    id=uuid4(),
                    source_device_id=core_sw.id,
                    target_device_id=sw.id,
                    source_port=f"GE{random.randint(1, 24)}",
                    target_port="SFP+1",
                    speed="10G",
                    status="up" if sw.status != DeviceStatus.OFFLINE else "down",
                    link_type="fiber",
                    discovered_via="lldp",
                    link_metadata={},
                )
            )
            total += 1

        # Leaf devices → a switch
        for leaf in leaves:
            parent = random.choice(switches)
            db.add(
                TopologyLink(
                    id=uuid4(),
                    source_device_id=parent.id,
                    target_device_id=leaf.id,
                    source_port=f"GE{random.randint(1, 24)}",
                    target_port="eth0",
                    speed="1G",
                    status="up" if leaf.status != DeviceStatus.OFFLINE else "down",
                    link_type="ethernet",
                    discovered_via="lldp",
                    link_metadata={},
                )
            )
            total += 1

    await db.flush()
    return total


async def _create_clients(
    db: AsyncSession,
    devices: list[Device],
    wifi_networks: list[WifiNetwork],
) -> list[DeviceClient]:
    """Create ~150 clients (wired + wireless) attached to APs and switches."""
    aps = [d for d in devices if d.device_type == DeviceType.ACCESS_POINT]
    switches = [d for d in devices if d.device_type == DeviceType.SWITCH]
    clients: list[DeviceClient] = []

    if not aps and not switches:
        return clients

    # Build a large pool of varied hostnames.
    hostnames: list[str] = []
    for part in CLIENT_NAME_PARTS:
        for person in CLIENT_PEOPLE:
            hostnames.append(f"{part}-{person}")
    random.shuffle(hostnames)
    wireless_names = hostnames[:130]
    wired_iot = list(IOT_CLIENTS)

    # ── Wireless clients on APs ──
    for hostname in wireless_names:
        if not aps:
            break
        ap = random.choice(aps)
        # Prefer a wifi net on the same site as the AP.
        site_wifi = [w for w in wifi_networks if w.site_id == ap.site_id] or wifi_networks
        wifi = random.choice(site_wifi)
        band = random.choices(["2.4GHz", "5GHz", "6GHz"], weights=[3, 6, 1])[0]
        if band == "2.4GHz":
            channel = random.choice([1, 6, 11])
        elif band == "5GHz":
            channel = random.choice([36, 44, 52, 100, 149, 157])
        else:
            channel = random.choice([37, 53, 117, 213])

        ap_offline = ap.status == DeviceStatus.OFFLINE
        is_online = (random.random() > 0.12) and not ap_offline
        connected_ago = timedelta(
            hours=random.randint(0, 72),
            minutes=random.randint(0, 59),
        )

        c = DeviceClient(
            id=uuid4(),
            device_id=ap.id,
            mac_address=_next_mac(),
            hostname=hostname,
            ip_address=f"10.10.{wifi.vlan_id}.{random.randint(100, 254)}",
            ssid=wifi.ssid,
            band=band,
            channel=channel,
            signal_dbm=random.randint(-82, -32),
            noise_dbm=random.randint(-96, -85),
            connected_at=_NOW - connected_ago,
            last_seen=_NOW - timedelta(seconds=random.randint(0, 600)),
            is_online=is_online,
            tx_bytes=random.randint(1_000_000, 5_000_000_000),
            rx_bytes=random.randint(1_000_000, 8_000_000_000),
            tx_rate_mbps=round(random.uniform(50, 1200), 1),
            rx_rate_mbps=round(random.uniform(50, 1200), 1),
            client_metadata={
                "os": random.choice(CLIENT_OS),
                "connection": "wireless",
            },
        )
        db.add(c)
        clients.append(c)

    # ── Wired clients (printers, IoT, fixed-function) on switches ──
    for hostname, kind in wired_iot:
        if not switches:
            break
        sw = random.choice(switches)
        vlan = random.choice([20, 50, 60, 80, 100])
        c = DeviceClient(
            id=uuid4(),
            device_id=sw.id,
            mac_address=_next_mac(),
            hostname=hostname,
            ip_address=f"10.10.{vlan}.{random.randint(10, 99)}",
            ssid=None,
            band=None,
            channel=None,
            signal_dbm=None,
            noise_dbm=None,
            connected_at=_NOW - timedelta(days=random.randint(1, 60)),
            last_seen=_NOW - timedelta(seconds=random.randint(0, 300)),
            is_online=random.random() > 0.05,
            tx_bytes=random.randint(100_000, 1_000_000_000),
            rx_bytes=random.randint(100_000, 1_000_000_000),
            tx_rate_mbps=round(random.uniform(10, 1000), 1),
            rx_rate_mbps=round(random.uniform(10, 1000), 1),
            client_metadata={"os": kind, "connection": "wired"},
        )
        db.add(c)
        clients.append(c)

    await db.flush()
    return clients


# ---------------------------------------------------------------------------
# Observability & operational data builders
# ---------------------------------------------------------------------------


async def _create_alert_rules_and_alerts(
    db: AsyncSession,
    organization_id: UUID,
    site_ids: list[UUID],
    devices: list[Device],
) -> tuple[list[AlertRule], list[Alert]]:
    """Create sample alert rules and ~60 fired alerts across statuses/ages."""
    rule_defs = [
        (
            "High CPU Usage",
            "critical",
            "threshold",
            {"metric": "cpu_usage_percent", "operator": ">", "threshold": 80},
        ),
        (
            "Device Offline",
            "critical",
            "pattern",
            {"metric": "device.status", "operator": "==", "value": "offline"},
        ),
        (
            "High Memory Usage",
            "warning",
            "threshold",
            {"metric": "memory_usage_percent", "operator": ">", "threshold": 85},
        ),
        (
            "High Temperature",
            "warning",
            "threshold",
            {"metric": "temperature_celsius", "operator": ">", "threshold": 60},
        ),
        (
            "Port Errors Spike",
            "warning",
            "threshold",
            {"metric": "port.errors", "operator": ">", "threshold": 100},
        ),
        (
            "WiFi Client Capacity",
            "info",
            "threshold",
            {"metric": "wifi.client_count", "operator": ">", "threshold": 50},
        ),
        (
            "PoE Budget Exceeded",
            "warning",
            "threshold",
            {"metric": "poe.budget_percent", "operator": ">", "threshold": 90},
        ),
        (
            "Camera Stream Lost",
            "critical",
            "pattern",
            {"metric": "camera.stream", "operator": "==", "value": "lost"},
        ),
        (
            "Firmware Update Available",
            "info",
            "pattern",
            {"metric": "firmware.update_available", "operator": "==", "value": True},
        ),
        (
            "WAN Latency High",
            "warning",
            "threshold",
            {"metric": "wan.latency_ms", "operator": ">", "threshold": 150},
        ),
    ]

    rules: list[AlertRule] = []
    for name, severity, rule_type, conditions in rule_defs:
        rule = AlertRule(
            id=uuid4(),
            organization_id=organization_id,
            name=name,
            description=f"Auto-generated rule: {name}",
            rule_type=rule_type,
            status="active",
            severity=severity,
            conditions=conditions,
            check_interval_seconds=300,
            cooldown_seconds=300,
            auto_resolve=True,
            fire_count=random.randint(0, 40),
            last_fired_at=_NOW - timedelta(hours=random.uniform(0.2, 72)),
        )
        db.add(rule)
        rules.append(rule)
    await db.flush()

    # ~60 fired alerts: weighted toward "resolved" (history) with a steady
    # stream of firing/acknowledged, spread over the last ~14 days.
    titles_by_rule = {
        "High CPU Usage": "CPU at {pct}% on {device}",
        "Device Offline": "{device} is offline",
        "High Memory Usage": "Memory at {pct}% on {device}",
        "High Temperature": "Temperature at {pct}°C on {device}",
        "Port Errors Spike": "Port errors exceeded threshold on {device}",
        "WiFi Client Capacity": "WiFi client count at {pct} on {device}",
        "PoE Budget Exceeded": "PoE budget at {pct}% on {device}",
        "Camera Stream Lost": "Stream lost on {device}",
        "Firmware Update Available": "Firmware update available for {device}",
        "WAN Latency High": "WAN latency at {pct}ms on {device}",
    }

    alerts: list[Alert] = []
    statuses = ["firing"] * 12 + ["acknowledged"] * 13 + ["resolved"] * 33 + ["suppressed"] * 2
    random.shuffle(statuses)
    for status in statuses:
        rule = random.choice(rules)
        device = random.choice(devices)
        pct = random.randint(60, 99)
        title = titles_by_rule[rule.name].format(device=device.name, pct=pct)
        # Spread fired_at over ~14 days; firing alerts skew recent.
        if status == "firing":
            hours_ago = random.uniform(0.05, 12)
        elif status == "acknowledged":
            hours_ago = random.uniform(1, 72)
        else:
            hours_ago = random.uniform(2, 336)
        fired_at = _NOW - timedelta(hours=hours_ago)
        ack_at = (
            fired_at + timedelta(minutes=random.randint(5, 90))
            if status in ("acknowledged", "resolved")
            else None
        )
        resolved_at = (
            fired_at + timedelta(hours=random.uniform(0.5, 6)) if status == "resolved" else None
        )
        occ = random.randint(1, 12)
        alert = Alert(
            id=uuid4(),
            organization_id=organization_id,
            rule_id=rule.id,
            site_id=device.site_id,
            device_id=device.id,
            severity=rule.severity,
            title=title,
            message=f"Alert triggered by rule '{rule.name}': {title}",
            details={"device_name": device.name, "device_ip": device.ip_address},
            status=status,
            fired_at=fired_at,
            acknowledged_at=ack_at,
            resolved_at=resolved_at,
            suppressed=status == "suppressed",
            suppressed_until=_NOW + timedelta(hours=random.randint(1, 24))
            if status == "suppressed"
            else None,
            suppression_reason="Maintenance window" if status == "suppressed" else None,
            fingerprint=f"{rule.id}:{device.id}:{int(fired_at.timestamp())}",
            occurrence_count=occ,
            last_occurrence_at=fired_at + timedelta(minutes=random.randint(0, 120)),
            notifications_sent=random.randint(0, 3),
            source="sample_data",
        )
        db.add(alert)
        alerts.append(alert)
    await db.flush()
    return rules, alerts


async def _create_event_records(
    organization_id: UUID,
    site_ids: list[UUID],
    devices: list[Device],
) -> list[EventRecord]:
    """Create ~200 event records for the activity feed (written to LogDB).

    ``EventRecord`` is a ``LogBase`` model — it lives in the separate LogDB
    (TimescaleDB) instance, NOT the primary database. Writing it through the
    primary session raises ``UndefinedTableError`` which rolls back the entire
    sample-data install. So it goes through a dedicated LogDB session.
    Best-effort: if LogDB is unconfigured/unreachable, skip the activity feed
    rather than fail the whole install (devices, alerts, etc. are unaffected).
    """
    event_templates = [
        (
            "device.online",
            EventCategory.DEVICE,
            EventPriority.NORMAL,
            "Device {device} came online",
        ),
        (
            "device.offline",
            EventCategory.DEVICE,
            EventPriority.HIGH,
            "Device {device} went offline",
        ),
        (
            "device.degraded",
            EventCategory.DEVICE,
            EventPriority.HIGH,
            "Device {device} is degraded",
        ),
        (
            "device.adopted",
            EventCategory.DEVICE,
            EventPriority.NORMAL,
            "Device {device} was adopted",
        ),
        (
            "device.firmware_updated",
            EventCategory.DEVICE,
            EventPriority.NORMAL,
            "Firmware updated on {device}",
        ),
        (
            "controller.sync_complete",
            EventCategory.CONTROLLER,
            EventPriority.LOW,
            "Controller sync completed successfully",
        ),
        (
            "controller.sync_failed",
            EventCategory.CONTROLLER,
            EventPriority.HIGH,
            "Controller sync failed — retrying in 60s",
        ),
        (
            "network.client_connected",
            EventCategory.NETWORK,
            EventPriority.LOW,
            "New client connected to {device}",
        ),
        (
            "network.client_disconnected",
            EventCategory.NETWORK,
            EventPriority.LOW,
            "Client disconnected from {device}",
        ),
        (
            "network.client_roamed",
            EventCategory.NETWORK,
            EventPriority.LOW,
            "Client roamed from {device} to another AP",
        ),
        (
            "network.vlan_changed",
            EventCategory.NETWORK,
            EventPriority.NORMAL,
            "VLAN membership changed on {device}",
        ),
        (
            "system.backup_completed",
            EventCategory.SYSTEM,
            EventPriority.NORMAL,
            "Scheduled backup completed",
        ),
        (
            "system.backup_failed",
            EventCategory.SYSTEM,
            EventPriority.HIGH,
            "Scheduled backup failed",
        ),
        (
            "system.config_changed",
            EventCategory.SYSTEM,
            EventPriority.NORMAL,
            "Configuration updated by admin",
        ),
        (
            "security.login_success",
            EventCategory.SECURITY,
            EventPriority.LOW,
            "Admin login from 192.168.1.100",
        ),
        (
            "security.login_failed",
            EventCategory.SECURITY,
            EventPriority.HIGH,
            "Failed login attempt from 203.0.113.55",
        ),
        (
            "security.ip_blocked",
            EventCategory.SECURITY,
            EventPriority.HIGH,
            "IP 203.0.113.55 blocked after repeated failures",
        ),
        (
            "automation.rule_fired",
            EventCategory.AUTOMATION,
            EventPriority.NORMAL,
            "Automation rule fired for {device}",
        ),
    ]

    try:
        from app.db.session import get_logdb_factory

        logdb_factory = get_logdb_factory()
    except RuntimeError:
        logger.warning(
            "Sample data: LogDB not configured — skipping the event-record "
            "activity feed (devices, alerts, etc. are unaffected)."
        )
        return []

    events: list[EventRecord] = []
    try:
        # LogDBSessionLocal uses expire_on_commit=False, so returned objects
        # keep their attributes after commit — _create_incidents reads ev.id.
        async with logdb_factory() as logdb:
            for _i in range(200):
                tpl = random.choice(event_templates)
                event_type, category, priority, msg_tpl = tpl
                device = random.choice(devices)
                msg = msg_tpl.format(device=device.name)
                # Spread over the last ~21 days.
                hours_ago = random.uniform(0, 504)

                event = EventRecord(
                    id=uuid4(),
                    event_type=event_type,
                    category=category,
                    priority=priority,
                    payload={"message": msg, "device_name": device.name},
                    event_meta={"source": "sample_data"},
                    source="freesdn",
                    organization_id=organization_id,
                    site_id=device.site_id,
                    timestamp=_NOW - timedelta(hours=hours_ago),
                )
                logdb.add(event)
                events.append(event)
            await logdb.commit()
    except Exception:
        logger.exception(
            "Sample data: failed to seed event records into LogDB — "
            "continuing without the activity feed."
        )
        return []
    return events


async def _create_audit_logs(
    db: AsyncSession,
    organization_id: UUID,
    site_ids: list[UUID],
) -> list[AuditLogRecord]:
    """Create ~120 realistic audit log records with varied actors/actions."""
    # (action, resource_type, resource_name)
    action_defs = [
        ("login", "session", "Admin Session"),
        ("logout", "session", "Admin Session"),
        ("create", "device", "Switch-Ground-Floor"),
        ("create", "device", "AP-1st-Floor"),
        ("update", "device", "Main Gateway"),
        ("delete", "device", "Decommissioned AP"),
        ("create", "network", "Staff VLAN"),
        ("update", "network", "Guest VLAN"),
        ("delete", "network", "Legacy VLAN"),
        ("create", "controller", "Demo Omada Controller"),
        ("update", "setting", "SMTP Configuration"),
        ("update", "setting", "Backup Schedule"),
        ("configure", "module", "Network Module"),
        ("read", "device", "Device Inventory"),
        ("read", "setting", "Dashboard Overview"),
        ("read", "network", "Network Topology"),
        ("export", "device", "Device Report CSV"),
        ("export", "alert", "Alert History CSV"),
        ("read", "setting", "Security Audit Log"),
        ("backup", "backup", "Manual Backup"),
        ("restore", "backup", "Config Restore"),
        ("enable", "alert", "High CPU Usage"),
        ("disable", "alert", "WiFi Client Capacity"),
        ("approve", "device", "Device Adoption"),
        ("scan", "site", "Network Discovery"),
        ("deploy", "device", "Firmware Upgrade"),
        ("create", "api_key", "CI Integration Key"),
        ("revoke", "api_key", "Old Integration Key"),
        ("update", "user", "User Role Change"),
        ("create", "user", "New Operator Account"),
    ]

    actors = [
        ("admin", "admin@freesdn.local", "user"),
        ("jdoe", "jdoe@example.com", "user"),
        ("operator1", "operator1@example.com", "user"),
        ("netadmin", "netadmin@example.com", "user"),
        ("security", "security@example.com", "user"),
        ("scheduler", "system@freesdn.local", "system"),
        ("api-client", "ci@example.com", "service"),
    ]
    user_agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "FreeSDN-Scheduler/1.0",
        "python-httpx/0.27",
    ]
    methods = {
        "create": "POST",
        "update": "PUT",
        "delete": "DELETE",
        "read": "GET",
        "export": "GET",
        "login": "POST",
        "logout": "POST",
        "configure": "POST",
        "backup": "POST",
        "restore": "POST",
        "enable": "PATCH",
        "disable": "PATCH",
        "approve": "POST",
        "scan": "POST",
        "deploy": "POST",
        "revoke": "DELETE",
    }
    ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.105",
        "10.10.10.50",
        "10.20.10.42",
        "203.0.113.55",
    ]

    logs: list[AuditLogRecord] = []
    for _i in range(120):
        action, resource_type, resource_name = random.choice(action_defs)
        actor_name, actor_email, actor_type = random.choice(actors)
        # ~8% failures (heavily weighted toward login).
        if action == "login":
            status = "failure" if random.random() < 0.2 else "success"
        else:
            status = "failure" if random.random() < 0.05 else "success"
        # Spread over the last ~10 days.
        hours_ago = random.uniform(0, 240)
        log = AuditLogRecord(
            id=uuid4(),
            timestamp=_NOW - timedelta(hours=hours_ago),
            action=action,
            resource_type=resource_type,
            resource_name=resource_name,
            actor_type=actor_type,
            actor_name=actor_name,
            actor_email=actor_email,
            organization_id=organization_id,
            site_id=random.choice(site_ids),
            ip_address=random.choice(ips),
            user_agent=random.choice(user_agents),
            request_method=methods.get(action, "GET"),
            request_path=f"/api/v1/{resource_type}s",
            status=status,
            response_code=200 if status == "success" else random.choice([400, 401, 403, 500]),
            response_time_ms=round(random.uniform(8, 480), 1),
        )
        db.add(log)
        logs.append(log)
    await db.flush()
    return logs


async def _create_incidents(
    db: AsyncSession,
    organization_id: UUID,
    site_ids: list[UUID],
    events: list[EventRecord],
) -> list[Incident]:
    """Create ~15 correlated incidents across open/investigating/resolved."""
    # (title, description, severity, status, hours_ago)
    incident_defs = [
        (
            "AP offline — clients roamed to nearby APs",
            "An access point went offline causing several wireless clients to roam.",
            "high",
            "resolved",
            48.0,
        ),
        (
            "High CPU on core switch",
            "Core switch CPU exceeded 80% for over 10 minutes.",
            "medium",
            "investigating",
            2.0,
        ),
        (
            "Multiple failed login attempts detected",
            "Repeated failed login attempts from external IP 203.0.113.55.",
            "high",
            "open",
            0.5,
        ),
        (
            "Camera stream loss in lobby",
            "Two lobby cameras stopped streaming within the same minute.",
            "high",
            "investigating",
            5.0,
        ),
        (
            "WAN latency spike on branch link",
            "Branch WAN latency exceeded 150ms for 15 minutes.",
            "medium",
            "resolved",
            72.0,
        ),
        (
            "PoE budget exceeded on access switch",
            "PoE draw exceeded the switch budget; lowest-priority ports cut.",
            "medium",
            "resolved",
            120.0,
        ),
        (
            "Controller sync failures",
            "The UniFi controller failed to sync 3 times in a row.",
            "medium",
            "open",
            1.2,
        ),
        (
            "Memory pressure on NVR",
            "NVR memory utilization sustained above 90%.",
            "low",
            "mitigating",
            8.0,
        ),
        (
            "Rogue AP detected",
            "An unmanaged SSID was observed broadcasting near the office.",
            "high",
            "investigating",
            3.5,
        ),
        (
            "VoIP phones de-registered",
            "A batch of VoIP phones lost SIP registration after a VLAN change.",
            "medium",
            "resolved",
            96.0,
        ),
        (
            "Backup job failed",
            "Nightly backup failed due to a storage backend timeout.",
            "low",
            "resolved",
            18.0,
        ),
        (
            "Switch uplink flapping",
            "A switch uplink flapped repeatedly over a 20-minute window.",
            "medium",
            "open",
            0.9,
        ),
        (
            "Guest network DHCP exhaustion",
            "The guest VLAN DHCP pool reached capacity at peak hours.",
            "low",
            "resolved",
            150.0,
        ),
        (
            "Impossible-travel login anomaly",
            "Admin login observed from two distant geos within minutes.",
            "critical",
            "investigating",
            4.0,
        ),
        (
            "Firmware rollout partially failed",
            "A scheduled firmware rollout failed on 2 of 12 devices.",
            "medium",
            "mitigating",
            6.0,
        ),
    ]

    incidents: list[Incident] = []
    for title, desc, severity, status, hours_ago in incident_defs:
        opened_at = _NOW - timedelta(hours=hours_ago)
        ack_at = opened_at + timedelta(minutes=random.randint(5, 30)) if status != "open" else None
        resolved_at = (
            opened_at + timedelta(hours=random.uniform(0.5, 8))
            if status in ("resolved", "closed")
            else None
        )
        inc = Incident(
            id=uuid4(),
            organization_id=organization_id,
            site_id=random.choice(site_ids),
            title=title,
            description=desc,
            severity=severity,
            status=status,
            opened_at=opened_at,
            acknowledged_at=ack_at,
            resolved_at=resolved_at,
            event_count=random.randint(2, 12),
            affected_devices=[],
            root_cause="Identified during triage" if status in ("resolved", "mitigating") else None,
            resolution_notes="Resolved by operator" if status == "resolved" else None,
            tags=["sample-data"],
            context={"generated": True},
        )
        db.add(inc)
        incidents.append(inc)
    await db.flush()

    # Link some events to incidents (event_id is a plain UUID across DBs).
    if events:
        for inc in incidents:
            linked = random.sample(events, min(random.randint(2, 5), len(events)))
            for ev in linked:
                ie = IncidentEvent(
                    id=uuid4(),
                    incident_id=inc.id,
                    event_id=ev.id,
                    matched_pattern="sample_data",
                    added_at=_NOW,
                )
                db.add(ie)
        await db.flush()
    return incidents


async def _create_backup_history(
    db: AsyncSession,
    organization_id: UUID,
    site_ids: list[UUID],
    device_count: int,
) -> list[Backup]:
    """Create backup schedules and ~20 backup records (mixed statuses)."""
    primary_site = site_ids[0]

    schedules: list[BackupSchedule] = []
    sched_defs = [
        ("Daily Full Backup", "daily", "0 2 * * *", "02:00", "full", primary_site),
        ("Weekly Config Backup", "weekly", "0 3 * * 0", "03:00", "site_config", primary_site),
        (
            "DC Database Backup",
            "daily",
            "0 1 * * *",
            "01:00",
            "database",
            site_ids[1] if len(site_ids) > 1 else primary_site,
        ),
    ]
    for name, stype, cron, run_time, btype, sid in sched_defs:
        schedule = BackupSchedule(
            id=uuid4(),
            name=name,
            description=f"Automatic {stype} backup",
            schedule_type=stype,
            cron_expression=cron,
            run_time=run_time,
            backup_type=btype,
            retention_days=30,
            max_backups=14,
            is_encrypted=True,
            storage_type="local",
            is_enabled=True,
            last_run_at=_NOW - timedelta(hours=random.randint(2, 24)),
            next_run_at=_NOW + timedelta(hours=random.randint(2, 24)),
            organization_id=organization_id,
            site_id=sid,
        )
        db.add(schedule)
        schedules.append(schedule)
    await db.flush()

    backups: list[Backup] = []
    # 20 backups over ~20 days: mostly completed, a few failed, one in_progress,
    # one pending, one cancelled.
    statuses = ["completed"] * 15 + ["failed"] * 2 + ["in_progress"] + ["pending"] + ["cancelled"]
    for idx, status in enumerate(statuses):
        days_ago = idx if status != "in_progress" else 0
        schedule = schedules[idx % len(schedules)]
        started = _NOW - timedelta(days=days_ago, hours=2)
        size = random.randint(20_000_000, 250_000_000) if status == "completed" else None
        completed_at = (
            started + timedelta(minutes=random.randint(3, 18)) if status == "completed" else None
        )
        progress = {
            "completed": 100,
            "in_progress": random.randint(20, 80),
            "failed": random.randint(10, 70),
            "pending": 0,
            "cancelled": random.randint(0, 50),
        }[status]
        b = Backup(
            id=uuid4(),
            name=f"backup-{(_NOW - timedelta(days=days_ago)).strftime('%Y%m%d')}-{idx:02d}",
            description=f"{schedule.backup_type} backup ({status})",
            backup_type=schedule.backup_type,
            status=status,
            progress=progress,
            started_at=started if status != "pending" else None,
            completed_at=completed_at,
            storage_type="local",
            storage_path=(
                f"/data/backups/backup-{(_NOW - timedelta(days=days_ago)).strftime('%Y%m%d')}-{idx:02d}.tar.gz"
                if status == "completed"
                else None
            ),
            file_size=size,
            checksum=(f"{random.getrandbits(256):064x}") if status == "completed" else None,
            is_encrypted=True,
            include_devices=True,
            include_vlans=True,
            include_ssids=True,
            include_users=True,
            device_count=device_count if status == "completed" else 0,
            error_message=(
                "Connection timeout to storage backend"
                if status == "failed"
                else ("Cancelled by operator" if status == "cancelled" else None)
            ),
            retention_days=30,
            expires_at=started + timedelta(days=30) if status == "completed" else None,
            organization_id=organization_id,
            site_id=schedule.site_id,
            schedule_id=schedule.id,
        )
        db.add(b)
        backups.append(b)
    await db.flush()
    return backups


async def _create_firmware_data(
    db: AsyncSession,
    organization_id: UUID,
    devices: list[Device],
) -> list[FirmwareImage]:
    """Create firmware images (one 'latest' per model) and per-device status."""
    # Collect unique model/vendor pairs from devices + remember device type.
    model_versions: dict[tuple[str, str], str] = {}
    model_type: dict[tuple[str, str], str] = {}
    for d in devices:
        key = (d.manufacturer or "TP-Link", d.model or "Unknown")
        if key not in model_versions:
            model_versions[key] = d.firmware_version or "1.0.0"
            model_type[key] = (
                d.device_type.value if hasattr(d.device_type, "value") else str(d.device_type)
            )

    images: list[FirmwareImage] = []
    image_map: dict[tuple[str, str], FirmwareImage] = {}
    for (vendor, model), current_ver in model_versions.items():
        # Bump the last numeric component for the "latest" version.
        parts = current_ver.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except (ValueError, IndexError):
            parts = ["2", "0", "0"]
        latest_ver = ".".join(parts)
        is_critical = random.random() < 0.2

        img = FirmwareImage(
            id=uuid4(),
            vendor=vendor,
            model=model,
            device_type=model_type.get((vendor, model)),
            version=latest_ver,
            release_type=random.choice(["stable", "stable", "stable", "beta"]),
            display_name=f"{vendor} {model} v{latest_ver}",
            description=f"Stability improvements and security patches for {model}",
            release_notes=f"- Security hardening\n- Bug fixes for {model}\n- Performance tuning",
            release_date=_NOW - timedelta(days=random.randint(3, 90)),
            file_size_bytes=random.randint(8_000_000, 120_000_000),
            checksum_sha256=f"{random.getrandbits(256):064x}",
            is_latest=True,
            is_critical=is_critical,
            is_recommended=True,
            organization_id=organization_id,
        )
        db.add(img)
        images.append(img)
        image_map[(vendor, model)] = img
    await db.flush()

    # Per-device firmware status — ~25% have an update available.
    up_to_date_counts: dict[tuple[str, str], int] = {}
    device_counts: dict[tuple[str, str], int] = {}
    for device in devices:
        key = (device.manufacturer or "TP-Link", device.model or "Unknown")
        fw_img = image_map.get(key)
        if not fw_img:
            continue
        needs_update = random.random() < 0.25
        device_counts[key] = device_counts.get(key, 0) + 1
        if not needs_update:
            up_to_date_counts[key] = up_to_date_counts.get(key, 0) + 1
        fw_status = DeviceFirmwareStatus(
            id=uuid4(),
            device_id=device.id,
            site_id=device.site_id,
            current_version=device.firmware_version if needs_update else fw_img.version,
            latest_version=fw_img.version,
            recommended_version=fw_img.version,
            is_up_to_date=not needs_update,
            update_available=needs_update,
            critical_update_available=needs_update and fw_img.is_critical,
            can_upgrade=True,
            device_name=device.name,
            device_type=device.device_type.value
            if hasattr(device.device_type, "value")
            else str(device.device_type),
            vendor=device.manufacturer,
            model=device.model,
            last_checked_at=_NOW - timedelta(hours=random.randint(0, 24)),
        )
        db.add(fw_status)

    # Backfill the denormalized device counts on each image.
    for key, img in image_map.items():
        img.device_count = device_counts.get(key, 0)
        img.devices_up_to_date = up_to_date_counts.get(key, 0)

    await db.flush()
    return images
