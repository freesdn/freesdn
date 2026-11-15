# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Every firewall gateway API write goes through the staging chokepoint.

``GatewayService`` (``modules/firewall/gateway_service.py``) is what the
firewall gateway API calls straight from the request: rules, NAT, DNS, DHCP,
aliases, WireGuard, OpenVPN, IPsec, routes, the traffic shaper, IDS, backups,
firmware, service control, reboot and halt. It wrote to the device with no
staged row and no force flag, and in read-only mode it still logged in to the
gateway before the adapter's own gate refused the write.

Now, per STAGING-MIGRATION options 2 and 3:

* a configuration write is staged and applied in the same request (a
  ``direct.gateway.<feature>`` ledger row with who, what, when and the result);
* an operational action is audited (``device_action:<action>``) once the
  gateway accepts it;
* read-only mode refuses every one of them before the gateway is contacted;
* the response is built from the adapter's answer exactly as before.

The adapter is a fake built through the adapter registry; nothing is contacted.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterError
from app.core.config import settings
from app.core.crypto import encrypt_dict
from app.core.device_slot import DeviceWriteBusyError, device_slots, gateway_slot_key
from app.models.core import Organization, Site
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.modules.firewall.gateway_service import GatewayService, adapter_registry
from app.modules.firewall.models import GatewayConnection


class _Gateway:
    """A fake OPNsense: records every call, answers AdapterResult.ok."""

    def __init__(self, box: SimpleNamespace) -> None:
        self._box = box

    async def connect(self) -> bool:
        self._box.connected += 1
        return True

    async def disconnect(self) -> None:
        return None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        async def _call(*args: Any, **kwargs: Any) -> Any:
            self._box.calls.append((name, args, kwargs))
            return self._box.answer

        return _call


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    monkeypatch.setattr(settings, "DEVICE_WRITE_SLOT_WAIT_SECONDS", 0.2)
    return state


@pytest_asyncio.fixture
async def gw(db_session, monkeypatch: pytest.MonkeyPatch):
    org = Organization(name="gateway writes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    row = GatewayConnection(
        org_id=org.id,
        site_id=site.id,
        name="edge",
        vendor="opnsense",
        host="192.0.2.1",
        port=443,
        verify_ssl=True,
        credentials=encrypt_dict({"api_key": "k", "api_secret": "s"}),
        settings={},
        sync_enabled=False,
    )
    db_session.add(row)
    await db_session.commit()
    box = SimpleNamespace(
        built=0, connected=0, calls=[], answer=AdapterResult.ok({"uuid": "v-1"}, message="done")
    )

    def _create(**_kwargs: Any) -> _Gateway:
        box.built += 1
        return _Gateway(box)

    monkeypatch.setattr(adapter_registry, "create_adapter", _create)
    # The request's user, as the API dependency records it for the write.
    user = SimpleNamespace(id=uuid4())
    monkeypatch.setattr("app.services.device_writes.request_actor_id", lambda: user.id)
    return SimpleNamespace(
        svc=GatewayService(db_session), row=row, org=org, site=site, box=box, user=user
    )


async def _ledger(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


async def _actions(db_session) -> list[AuditLogRecord]:
    return list(
        (
            await db_session.execute(
                select(AuditLogRecord).where(AuditLogRecord.action.like("device_action:%"))
            )
        ).scalars()
    )


P = {"description": "lan"}

#: (service method, extra args, adapter method, ledger feature, operation)
CONFIG_WRITES = [
    ("create_live_dns_override", (P,), "create_dns_override", "dns.override", "create"),
    ("update_live_dns_override", ("v-1", P), "update_dns_override", "dns.override", "update"),
    ("delete_live_dns_override", ("v-1",), "delete_dns_override", "dns.override", "delete"),
    (
        "create_live_dns_domain_override",
        (P,),
        "create_dns_domain_override",
        "dns.domain_override",
        "create",
    ),
    (
        "update_live_dns_domain_override",
        ("v-1", P),
        "update_dns_domain_override",
        "dns.domain_override",
        "update",
    ),
    (
        "delete_live_dns_domain_override",
        ("v-1",),
        "delete_dns_domain_override",
        "dns.domain_override",
        "delete",
    ),
    (
        "create_live_dhcp_static_mapping",
        (P,),
        "create_dhcp_static_mapping",
        "dhcp.static_mapping",
        "create",
    ),
    (
        "update_live_dhcp_static_mapping",
        ("v-1", P),
        "update_dhcp_static_mapping",
        "dhcp.static_mapping",
        "update",
    ),
    (
        "delete_live_dhcp_static_mapping",
        ("v-1",),
        "delete_dhcp_static_mapping",
        "dhcp.static_mapping",
        "delete",
    ),
    ("create_live_port_forward", (P,), "create_port_forward", "nat.port_forward", "create"),
    (
        "update_live_port_forward",
        ("v-1", P),
        "update_port_forward",
        "nat.port_forward",
        "update",
    ),
    ("delete_live_port_forward", ("v-1",), "delete_port_forward", "nat.port_forward", "delete"),
    ("create_live_source_nat_rule", (P,), "create_source_nat_rule", "nat.source", "create"),
    (
        "update_live_source_nat_rule",
        ("v-1", P),
        "update_source_nat_rule",
        "nat.source",
        "update",
    ),
    ("delete_live_source_nat_rule", ("v-1",), "delete_source_nat_rule", "nat.source", "delete"),
    ("create_live_alias", (P,), "create_alias", "alias", "create"),
    ("update_live_alias", ("v-1", P), "update_alias", "alias", "update"),
    ("delete_live_alias", ("v-1",), "delete_alias", "alias", "delete"),
    (
        "create_live_wireguard_server",
        (P,),
        "create_wireguard_server",
        "wireguard.server",
        "create",
    ),
    (
        "update_live_wireguard_server",
        ("v-1", P),
        "update_wireguard_server",
        "wireguard.server",
        "update",
    ),
    (
        "delete_live_wireguard_server",
        ("v-1",),
        "delete_wireguard_server",
        "wireguard.server",
        "delete",
    ),
    ("create_live_wireguard_peer", (P,), "create_wireguard_peer", "wireguard.peer", "create"),
    (
        "update_live_wireguard_peer",
        ("v-1", P),
        "update_wireguard_peer",
        "wireguard.peer",
        "update",
    ),
    ("delete_live_wireguard_peer", ("v-1",), "delete_wireguard_peer", "wireguard.peer", "delete"),
    (
        "create_live_openvpn_instance",
        (P,),
        "create_openvpn_instance",
        "openvpn.instance",
        "create",
    ),
    (
        "update_live_openvpn_instance",
        ("v-1", P),
        "update_openvpn_instance",
        "openvpn.instance",
        "update",
    ),
    (
        "delete_live_openvpn_instance",
        ("v-1",),
        "delete_openvpn_instance",
        "openvpn.instance",
        "delete",
    ),
    ("create_live_static_route", (P,), "create_static_route", "route.static", "create"),
    ("update_live_static_route", ("v-1", P), "update_static_route", "route.static", "update"),
    ("delete_live_static_route", ("v-1",), "delete_static_route", "route.static", "delete"),
    ("update_live_ids_settings", (P,), "update_ids_settings", "ids.settings", "update"),
    ("create_live_shaper_pipe", (P,), "create_shaper_pipe", "shaper.pipe", "create"),
    ("update_live_shaper_pipe", ("v-1", P), "update_shaper_pipe", "shaper.pipe", "update"),
    ("delete_live_shaper_pipe", ("v-1",), "delete_shaper_pipe", "shaper.pipe", "delete"),
    ("create_live_shaper_queue", (P,), "create_shaper_queue", "shaper.queue", "create"),
    ("update_live_shaper_queue", ("v-1", P), "update_shaper_queue", "shaper.queue", "update"),
    ("delete_live_shaper_queue", ("v-1",), "delete_shaper_queue", "shaper.queue", "delete"),
    ("create_live_shaper_rule", (P,), "create_shaper_rule", "shaper.rule", "create"),
    ("update_live_shaper_rule", ("v-1", P), "update_shaper_rule", "shaper.rule", "update"),
    ("delete_live_shaper_rule", ("v-1",), "delete_shaper_rule", "shaper.rule", "delete"),
    ("revert_live_backup", ("config-1.xml",), "revert_backup", "backup.revert", "update"),
    ("delete_live_backup", ("config-1.xml",), "delete_backup", "backup", "delete"),
    ("firmware_update", (), "firmware_update", "firmware", "update"),
    (
        "toggle_live_firewall_rule",
        ("r-1",),
        "toggle_firewall_rule",
        "firewall_rule",
        "update",
    ),
    (
        "update_live_firewall_rule",
        ("r-1", {"action": "pass"}),
        "update_firewall_rule",
        "firewall_rule",
        "update",
    ),
    ("apply_live_ipsec_changes", (), "apply_ipsec_changes", "ipsec.apply", "update"),
    ("toggle_live_ids_rule", ("2010935",), "toggle_ids_rule", "ids.rule", "update"),
    ("control_live_ids", ("update-rules",), "update_ids_rules", "ids.rules_update", "update"),
    (
        "push_firewall_rule",
        ({"action": "pass"},),
        "create_firewall_rule",
        "firewall_rule",
        "create",
    ),
    ("delete_vendor_rule", ("r-1",), "delete_firewall_rule", "firewall_rule", "delete"),
]

#: (service method, extra args, adapter method == audited action)
ACTIONS = [
    ("kill_live_openvpn_session", ("s-1",), "kill_openvpn_session"),
    ("connect_live_ipsec_tunnel", ("p1",), "connect_ipsec_tunnel"),
    ("disconnect_live_ipsec_tunnel", ("p1",), "disconnect_ipsec_tunnel"),
    ("create_live_backup", (), "create_backup"),
    ("reboot_live_gateway", (), "reboot_device"),
    ("halt_live_gateway", (), "halt_device"),
    ("flush_live_arp", (), "flush_arp"),
    ("drop_live_ids_alert_log", (), "drop_ids_alert_log"),
    ("control_live_service", ("unbound", "start"), "start_service"),
    ("control_live_service", ("unbound", "stop"), "stop_service"),
    ("control_live_service", ("unbound", "restart"), "restart_service"),
    ("control_live_ids", ("start",), "start_ids"),
    ("control_live_ids", ("stop",), "stop_ids"),
    ("control_live_ids", ("restart",), "restart_ids"),
]


def _call(f, method: str, args: tuple[Any, ...]) -> Any:
    return getattr(f.svc, method)(f.row.id, f.org.id, *args)


@pytest.mark.parametrize(
    ("method", "args", "adapter_method", "feature", "operation"),
    CONFIG_WRITES,
    ids=[c[0] + ":" + c[2] for c in CONFIG_WRITES],
)
async def test_a_configuration_write_is_staged_and_applied(
    db_session, gw, mode, method, args, adapter_method, feature, operation
) -> None:
    out = await _call(gw, method, args)

    assert [c[0] for c in gw.box.calls] == [adapter_method]
    assert out["success"] is True
    (row,) = await _ledger(db_session)
    assert row.feature == f"direct.gateway.{feature}"
    assert row.operation == operation
    assert row.status == "applied"
    assert row.controller_id is None
    assert row.organization_id == gw.org.id
    assert row.site_id == gw.site.id
    assert row.created_by == gw.user.id
    assert row.payload["gateway_id"] == str(gw.row.id)
    assert await _actions(db_session) == []


@pytest.mark.parametrize(
    ("method", "args", "adapter_method"), ACTIONS, ids=[a[0] + ":" + a[2] for a in ACTIONS]
)
async def test_an_operational_action_is_audited(
    db_session, gw, mode, method, args, adapter_method
) -> None:
    out = await _call(gw, method, args)

    assert [c[0] for c in gw.box.calls] == [adapter_method]
    assert out["success"] is True
    assert await _ledger(db_session) == []
    (record,) = await _actions(db_session)
    assert record.action == f"device_action:{adapter_method}"
    assert record.organization_id == gw.org.id
    assert record.actor_id == str(gw.user.id)
    assert record.new_state["target_id"] == str(gw.row.id)


ALL = [(c[0], c[1]) for c in CONFIG_WRITES] + [(a[0], a[1]) for a in ACTIONS]


@pytest.mark.parametrize(("method", "args"), ALL, ids=[f"{m}:{i}" for i, (m, _a) in enumerate(ALL)])
async def test_read_only_mode_refuses_before_the_gateway_is_contacted(
    db_session, gw, mode, method, args
) -> None:
    mode["read_only"] = True

    with pytest.raises(HTTPException) as refused:
        await _call(gw, method, args)

    assert refused.value.status_code == 403
    assert "Read-only mode is on" in str(refused.value.detail)
    assert gw.box.built == 0, "the adapter was built: the gateway would have been contacted"
    assert gw.box.calls == []
    assert await _ledger(db_session) == []
    assert await _actions(db_session) == []


async def test_a_refused_write_raises_as_before_and_is_recorded_failed(
    db_session, gw, mode
) -> None:
    gw.box.answer = AdapterResult.fail("the gateway rejected the alias")

    with pytest.raises(AdapterError):
        await gw.svc.create_live_alias(gw.row.id, gw.org.id, P)

    (row,) = await _ledger(db_session)
    assert row.status == "failed"
    assert "rejected the alias" in (row.failure_reason or "")


async def test_a_refused_action_is_not_audited(db_session, gw, mode) -> None:
    gw.box.answer = AdapterResult.fail("service not found")

    with pytest.raises(AdapterError):
        await gw.svc.control_live_service(gw.row.id, gw.org.id, "unbound", "restart")

    assert await _actions(db_session) == []


async def test_secrets_in_a_write_never_reach_the_ledger(db_session, gw, mode) -> None:
    peer = {"name": "laptop", "pubkey": "pub", "private_key": "wg-private-material", "psk": "x1"}
    await gw.svc.create_live_wireguard_peer(gw.row.id, gw.org.id, peer)

    sent = gw.box.calls[0][1][0]
    assert sent["private_key"] == "wg-private-material", "the device must get the real key"
    (row,) = await _ledger(db_session)
    assert "wg-private-material" not in str(row.payload)
    assert row.payload["name"] == "laptop"


async def test_a_busy_gateway_refuses_the_write(db_session, gw, mode) -> None:
    poller = device_slots.try_acquire(gateway_slot_key(gw.row), "gateway full sync", ttl=30)
    assert poller is not None
    try:
        with pytest.raises(DeviceWriteBusyError):
            await gw.svc.create_live_alias(gw.row.id, gw.org.id, P)
        with pytest.raises(DeviceWriteBusyError):
            await gw.svc.reboot_live_gateway(gw.row.id, gw.org.id)
    finally:
        device_slots.release(poller)
    assert gw.box.calls == []
    (row,) = await _ledger(db_session)
    assert row.status == "failed"
    assert "gateway full sync" in (row.failure_reason or "")


async def test_a_bulk_rule_change_is_one_staged_row(db_session, gw, mode) -> None:
    out = await gw.svc.bulk_rule_operation(gw.row.id, gw.org.id, "disable", ["r-1", "r-2"])

    assert out["succeeded"] == 2 and out["failed"] == 0
    assert [c[0] for c in gw.box.calls] == [
        "toggle_firewall_rule",
        "toggle_firewall_rule",
        "apply_firewall_changes",
    ]
    assert gw.box.connected == 1, "the batch must use one connection"
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.gateway.firewall_rule.bulk"
    assert row.payload["rule_uuids"] == ["r-1", "r-2"]
    assert row.applied_response["succeeded"] == 2


async def test_a_bulk_rule_change_is_refused_in_read_only_mode(db_session, gw, mode) -> None:
    mode["read_only"] = True
    with pytest.raises(HTTPException) as refused:
        await gw.svc.bulk_rule_operation(gw.row.id, gw.org.id, "delete", ["r-1"])
    assert refused.value.status_code == 403
    assert gw.box.built == 0


async def test_an_unknown_ids_action_contacts_nothing(db_session, gw, mode) -> None:
    out = await gw.svc.control_live_ids(gw.row.id, gw.org.id, "explode")
    assert out == {"success": False, "message": "Unknown IDS action: explode"}
    assert gw.box.built == 0
