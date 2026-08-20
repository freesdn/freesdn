# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two features that were wired to keys nothing produced.

1. CUSTOM DPI RULES CLASSIFIED NOTHING
   ``ApplicationClassifier.load_rules(session, organization_id=None)`` takes an
   ``else`` branch that filters to ``is_system`` rules only. The NetFlow
   receiver -- one process-wide UDP listener serving every organization, so it
   has no single org to load for -- called it exactly that way.

   So every rule an operator created through the API was filtered out at load
   time. The rule appeared in the list, said "enabled", and did not exist as
   far as traffic was concerned: no flow was ever tagged with it, and the
   Observability views built on ``app_name`` never showed it.

   Fixed with a per-org map rather than by loading everything flat, so one
   shared listener can honour an org's rules without letting org A's naming
   land on org B's flows.

2. THE GATEWAY VPN TUNNELS TABLE COULD NEVER POPULATE
   The sync read ``vpn_result.data.get("tunnels", [])``. No supported brain
   firewall returns a top-level ``tunnels`` list::

       OPNsense  {"wireguard": {...}, "openvpn": {...}, "ipsec": ...}
       pfSense   {"openvpn": ..., "wireguard": {"tunnels": [...], ...}, ...}
       MikroTik  {"ipsec": {...}, "wireguard": {...}, "l2tp": ..., "pptp": ...}
       OpenWrt   {"tunnels": {"wireguard": [...], "openvpn": [...]}}

   Three vendors yielded ``[]`` and the table stayed permanently empty.
   OpenWrt yielded a DICT -- truthy, so it reached ``_upsert_vpn_tunnels``,
   whose ``for t in tunnels`` iterated the KEYS and tried to build rows from
   the strings "wireguard" and "openvpn" before failing into the surrounding
   except. Either way nobody ever saw a tunnel.

NOT REPRODUCED, recorded here so it is not re-filed: the report that ring-group
"Ring Time" is stored and displayed but never sent. ``create_ring_group``
does send it (``"grptime": data.get("ring_time", 20)``), the staged
``pbx.ring_group.update`` applier forwards whatever payload it is given, and
there is no ring-group UPDATE route in the VoIP API or update mutation in the
UI at all -- only create. There is no path on which the value is dropped.
"""

from __future__ import annotations

import inspect
from uuid import uuid4

import pytest

from app.modules.collector.services.classifier import ApplicationClassifier
from app.modules.gateway.services.sync_service import _normalize_vpn_tunnels

ORG_A = uuid4()
ORG_B = uuid4()


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. custom DPI rules ──────────────────────────────────────────


def _classifier_with(org_rules: dict, system: dict | None = None) -> ApplicationClassifier:
    c = ApplicationClassifier()
    c._port_map = dict(system or {(6, 443): ("HTTPS", "web")})
    c._org_port_maps = {org: dict(rules) for org, rules in org_rules.items()}
    return c


def test_an_orgs_own_rule_classifies_its_traffic() -> None:
    """
    The regression. An operator maps port 8443 to "Internal App"; before the
    fix the rule was filtered out at load and every such flow stayed unnamed.
    """
    c = _classifier_with({ORG_A: {(6, 8443): ("Internal App", "business")}})
    assert c.classify(6, 8443, organization_id=ORG_A) == ("Internal App", "business")


def test_one_orgs_rule_does_not_rename_anothers_traffic() -> None:
    """
    The reason for a per-org map rather than one flat one: the listener is
    shared, so loading every org's rules into a single map would have let one
    tenant's naming land on another's flows.
    """
    c = _classifier_with({ORG_A: {(6, 8443): ("Internal App", "business")}})
    assert c.classify(6, 8443, organization_id=ORG_B) == (None, None)


def test_an_orgs_rule_overrides_the_builtin() -> None:
    """Overriding a built-in is the main reason to write a custom rule."""
    c = _classifier_with({ORG_A: {(6, 443): ("Corporate Portal", "internal")}})
    assert c.classify(6, 443, organization_id=ORG_A) == ("Corporate Portal", "internal")
    assert c.classify(6, 443, organization_id=ORG_B) == ("HTTPS", "web")


def test_builtins_still_apply_where_an_org_has_no_rule() -> None:
    c = _classifier_with({ORG_A: {(6, 8443): ("Internal App", "business")}})
    assert c.classify(6, 443, organization_id=ORG_A) == ("HTTPS", "web")


def test_classifying_without_an_org_is_unchanged() -> None:
    """Existing callers pass no org and must keep the old behaviour exactly."""
    c = _classifier_with({ORG_A: {(6, 8443): ("Internal App", "business")}})
    assert c.classify(6, 443) == ("HTTPS", "web")
    assert c.classify(6, 8443) == (None, None)


def test_a_missing_port_is_still_unclassified() -> None:
    c = _classifier_with({})
    assert c.classify(6, None) == (None, None)
    assert c.classify(6, 9999, organization_id=ORG_A) == (None, None)


def test_the_loader_no_longer_drops_non_system_rules() -> None:
    """
    The mechanism. ``else: query.where(is_system)`` is what made every
    operator-created rule invisible.
    """
    code = _code(ApplicationClassifier.load_rules)
    assert "query = query.where(ApplicationClassificationRule.is_system)" not in code, (
        "the loader still filters custom rules out when no org is given"
    )
    assert "_org_port_maps.setdefault" in code


def test_the_receiver_passes_the_exporters_org() -> None:
    """
    A per-org map is useless if the call site does not say which org. The
    receiver resolves org_id from the exporter's source IP already.
    """
    from app.modules.collector.services import netflow

    code = _code(netflow.NetFlowReceiver._handle)
    assert "organization_id=org_id" in code


def test_the_rule_count_includes_the_per_org_rules() -> None:
    """The startup log line reported 0 custom rules, which looked correct."""
    c = _classifier_with({ORG_A: {(6, 8443): ("x", "y")}, ORG_B: {(17, 53): ("z", "w")}})
    assert c.rule_count() == 3


# ── 2. the gateway VPN tunnels ───────────────────────────────────


OPNSENSE = {
    "wireguard": {
        "status": [{"id": "wg0", "name": "wg0", "status": "up"}],
        "peers": [{"id": "peer1", "name": "branch"}],
        "servers": [],
    },
    "openvpn": {"instances": [{"id": "ovpn1", "description": "road-warrior"}], "providers": []},
    "ipsec": [{"id": "con1", "description": "site-b", "status": "up"}],
}

PFSENSE = {
    "openvpn": [{"id": "ovpn1", "name": "branch-vpn"}],
    "wireguard": {"tunnels": [{"id": "wg0", "name": "wg0"}], "peers": []},
    "ipsec": [{"id": "ike1", "description": "hq"}],
}

MIKROTIK = {
    "ipsec": {"policies": [{"id": "*1", "name": "policy1"}], "peers": [], "active": []},
    "wireguard": {"interfaces": [{"id": "*2", "name": "wg-hq"}], "peers": []},
    "l2tp": None,
    "pptp": None,
}

OPENWRT = {
    "tunnels": {
        "wireguard": [{"id": "wg0", "uci_name": "wg0"}],
        "openvpn": [{"id": "ovpn0", "uci_name": "vpn"}],
    }
}


@pytest.mark.parametrize(
    ("name", "payload"),
    [("opnsense", OPNSENSE), ("pfsense", PFSENSE), ("mikrotik", MIKROTIK), ("openwrt", OPENWRT)],
)
def test_every_supported_vendor_yields_tunnels(name: str, payload: dict) -> None:
    """
    The regression, one vendor at a time. Three of these produced an empty
    list and the fourth produced a dict that broke the upsert loop.
    """
    tunnels = _normalize_vpn_tunnels(payload)
    assert tunnels, f"{name} still yields no tunnels"
    assert all(isinstance(t, dict) for t in tunnels)


@pytest.mark.parametrize(
    ("name", "payload"),
    [("opnsense", OPNSENSE), ("pfsense", PFSENSE), ("mikrotik", MIKROTIK), ("openwrt", OPENWRT)],
)
def test_the_old_read_really_did_come_up_empty(name: str, payload: dict) -> None:
    """
    Negative control: the exact expression that shipped, against the exact
    payloads. Three return [], and OpenWrt returns a dict whose iteration
    yields strings rather than tunnel dicts.
    """
    old = payload.get("tunnels", [])
    if name == "openwrt":
        assert isinstance(old, dict)
        assert all(isinstance(k, str) for k in old), "iterating this yields strings, not tunnels"
    else:
        assert old == []


def test_each_tunnel_is_tagged_with_its_protocol() -> None:
    """
    ``_upsert_vpn_tunnels`` reads ``t.get("type", "ipsec")``. Without a tag
    every WireGuard tunnel would be filed as IPsec.
    """
    types = {t["type"] for t in _normalize_vpn_tunnels(OPNSENSE)}
    assert "wireguard" in types
    assert "openvpn" in types
    assert "ipsec" in types


def test_an_explicit_type_on_the_item_wins() -> None:
    """A vendor that already labels its tunnels must not be relabelled."""
    payload = {"wireguard": [{"id": "x", "type": "wireguard-p2p"}]}
    assert _normalize_vpn_tunnels(payload)[0]["type"] == "wireguard-p2p"


def test_the_upsert_can_consume_what_the_normalizer_produces() -> None:
    """
    Pin the two together: the normalizer's output shape has to match the keys
    the upsert reads, or this is just a differently-shaped empty table.
    """
    from app.modules.gateway.services.sync_service import SyncService

    code = _code(SyncService._upsert_vpn_tunnels)
    for tunnel in _normalize_vpn_tunnels(PFSENSE):
        # Every key the upsert reaches for must be safe on these dicts.
        assert tunnel.get("uuid", tunnel.get("id", "")) != ""
        assert isinstance(tunnel.get("local", {}), dict)
    assert 't.get("type", "ipsec")' in code


@pytest.mark.parametrize("payload", [None, {}, [], "nonsense", {"wireguard": "not-a-list"}])
def test_an_unrecognised_payload_yields_nothing_rather_than_garbage(payload) -> None:
    """
    Deliberately conservative. An unknown shape produces no rows -- the same
    as today -- rather than a table of strings, which is what the OpenWrt path
    was heading toward.
    """
    assert _normalize_vpn_tunnels(payload) == []


def test_the_sync_uses_the_normalizer() -> None:
    from app.modules.gateway.services.sync_service import SyncService

    code = _code(SyncService.sync_gateway)
    assert "_normalize_vpn_tunnels(" in code
    assert 'vpn_result.data.get("tunnels", [])' not in code
