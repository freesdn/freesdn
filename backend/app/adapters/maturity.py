# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Adapter maturity — the project's honest live-validation record.
================================================================

THE single source of truth for "have we actually proven this adapter against
real hardware?" It drives the UI maturity badges (Verified / Experimental) and
the docs, so a user never sees an integration presented as supported when it has
only ever been *assumed* to work.

Honesty rules (mirrors the feature-readiness rubric):

* An adapter is **VERIFIED only with real-hardware evidence.** Never on protocol
  similarity alone ("pfSense is like OPNsense", "Dahua is like Hikvision") — that
  assumption is exactly the oversell this record exists to prevent.
* **VERIFIED can only be granted here**, by the project's validation record — an
  adapter (or a third-party plugin) can never self-declare verified.
* Anything **not listed defaults to EXPERIMENTAL** — the safe, non-overselling
  default.

Owner-reviewed: edit this one table when an adapter is genuinely live-validated.
"""

from dataclasses import dataclass

from app.adapters.base import AdapterMaturity, WriteMaturity


@dataclass(frozen=True)
class MaturityInfo:
    """An adapter's honest maturity + a short human note explaining it.

    ``maturity`` grades the READ surface (live monitoring/discovery), which is
    what the owner's real 2-site fleet + lab exercise daily. ``write_maturity``
    grades the WRITE surface SEPARATELY — a release-honesty audit found that most
    adapters' writes are code-complete + unit-tested but NOT yet proven on real
    hardware, so a single "Verified" badge oversold them. The two grades drive a
    split UI badge ("Reads: Verified · Writes: …") and honest public docs.
    """

    maturity: AdapterMaturity
    notes: str = ""
    write_maturity: WriteMaturity = WriteMaturity.MOCK_TESTED
    write_note: str = ""


_VERIFIED = AdapterMaturity.VERIFIED
_EXPERIMENTAL = AdapterMaturity.EXPERIMENTAL
_W_LIVE = WriteMaturity.LIVE_VALIDATED
_W_PARTIAL = WriteMaturity.PARTIAL
_W_MOCK = WriteMaturity.MOCK_TESTED
_W_DISABLED = WriteMaturity.DISABLED
_W_EXPERIMENTAL = WriteMaturity.EXPERIMENTAL

# adapter id -> honest maturity. Absent ⇒ EXPERIMENTAL (see ``get_maturity``).
# Keep this list HONEST: move an adapter up to VERIFIED only after it has been
# proven against real hardware, never on assumption.
ADAPTER_MATURITY: dict[str, MaturityInfo] = {
    # ── 🟢 READS VERIFIED — proven live on real hardware (maintainer's 2-site
    # fleet / lab). WRITES are graded SEPARATELY below: most are code-complete +
    # gated + unit-tested but NOT yet proven on hardware (a release-honesty audit
    # found the single "Verified" badge oversold them). Reads stay Verified — they
    # run live daily; mock-CI is a regression caveat, not a read-validation claim.
    "omada": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="Config writes (VLAN/SSID/firewall/route/port-profile, ~70 methods) "
        "are gated + unit-tested, but no real-device write is persisted yet — treat writes "
        "as unproven on hardware.",
    ),
    "hikvision": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="PTZ / reboot / motion-recording-privacy config writes are gated + "
        "mock-tested; not yet proven on real hardware.",
    ),
    "grandstream": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="Phone config / provision / reboot writes are unit-tested; no persisted "
        "real-device write yet (the one live attempt was an intentional no-op).",
    ),
    "opnsense": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="~60 staged + dual-gated + pre-flighted write methods, mock-tested. ONE "
        "firewall-alias create was run live on a 26.1 box historically (not persisted; alias "
        "delete was broken on 26.1) — treat the write surface as unproven.",
    ),
    "truenas": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="The blob-upload (filesystem.put) write path is implemented + mock-tested; "
        "no real-device write validated yet.",
    ),
    "mikrotik": MaturityInfo(
        _VERIFIED,
        write_maturity=_W_MOCK,
        write_note="RouterOS write paths are implemented + unit-tested + exercised by a "
        "developer CHR (container) harness, but have no persisted real-hardware write proof.",
    ),
    "freepbx": MaturityInfo(
        _VERIFIED,
        "Monitoring and reads are live-validated on a real PBX.",
        write_maturity=_W_PARTIAL,
        # CORRECTED: the prior note said the write transport was "not yet implemented" —
        # it IS implemented (GraphQL/REST), and extension/ring-group/inbound-route
        # create->read->delete were proven live historically (not persisted as a cassette).
        write_note="Write transport IS implemented; extension / ring-group / inbound-route "
        "create was proven live historically (not persisted); other entities mock-tested.",
    ),
    "proxmox": MaturityInfo(
        _VERIFIED,
        "Read-only monitoring is live-validated on a real cluster.",
        write_maturity=_W_DISABLED,
        write_note="Write code exists but is DISABLED by design (the owner runs Proxmox "
        "read-only); ceph / replication appliers are intentionally stubbed.",
    ),
    "unifi": MaturityInfo(
        _VERIFIED,
        "Reads + device discovery live-validated on a real UCG Fiber (UniFi OS "
        "5.1.19 / Network 10.4.57) over Tailscale — both the v1 classic and v2 "
        "modern (zone-based-firewall) API lanes.",
        write_maturity=_W_PARTIAL,
        # HONEST split (post release-honesty audit): only ONE write domain has
        # PERSISTED real-device proof; the broad surface was live-exercised this
        # session via ephemeral scripts that left NO persisted artifact — so it is
        # NOT LIVE_VALIDATED, it is partial.
        write_note="VLAN/network create+delete is proven on the real UCG with a "
        "PERSISTED cassette (freesdn-cassettes/unifi/networkconf_vlan_networkgroup.json). "
        "A broad write surface — clients (block/unblock/forget/reconnect), devices "
        "(restart/disable/locate/PoE), WLAN/SSID, firewall groups + legacy rules, "
        "RADIUS, hotspot vouchers, NAT/QoS/static-DNS, and the cross-vendor "
        "distribution targets (create_vlan_interface/dhcp_scope/alias) — was "
        "create->read->delete EXERCISED live this session but NOT persisted as "
        "cassettes (so treat as provisional). ZBF zone create/delete is unexercised "
        "(this controller isn't ZBF-migrated). VLAN-create constraint: the VLAN-ID "
        "range (reserved-high ~>4000 rejected); 'networkgroup' is OPTIONAL (sent as "
        "a default).",
    ),
    # ── 🟡 EXPERIMENTAL — real adapter, NOT yet verified on real hardware ──
    # Listed explicitly to carry an honest note; EXPERIMENTAL is also the default
    # for anything absent, so new/plugin adapters are never oversold.
    "unifi_protect": MaturityInfo(
        _EXPERIMENTAL,
        "Adapter implemented; not yet verified on real hardware.",
        write_maturity=_W_EXPERIMENTAL,
    ),
    "pfsense": MaturityInfo(
        _EXPERIMENTAL,
        "Assumed compatible with the OPNsense API surface; not yet verified on a real pfSense box.",
        write_maturity=_W_EXPERIMENTAL,
    ),
    "openwrt": MaturityInfo(
        _EXPERIMENTAL,
        "Adapter implemented; not yet verified on real hardware.",
        write_maturity=_W_EXPERIMENTAL,
    ),
    "onvif": MaturityInfo(
        _EXPERIMENTAL,
        "Generic ONVIF — works in principle for Dahua / Axis / Reolink / Uniview "
        "and other ONVIF cameras, but not verified per vendor.",
        write_maturity=_W_EXPERIMENTAL,
    ),
}


def get_maturity(adapter_id: str) -> MaturityInfo:
    """Honest maturity for an adapter id.

    The project validation record (this table) is authoritative. Anything not
    listed — including third-party plugins — is EXPERIMENTAL: VERIFIED is never
    assumed and can never be self-claimed.
    """
    return ADAPTER_MATURITY.get(adapter_id, MaturityInfo(_EXPERIMENTAL))
