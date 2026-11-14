# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
VoIP and hypervisor writes made from a request go through the chokepoint.

``modules/voip/service.py`` created, updated and deleted PBX extensions and
ring groups by calling the FreePBX adapter straight from the request, a second
path beside the staged ``pbx.*`` features, and rebooted, factory-reset and
provisioned phones through the Grandstream client. ``modules/hypervisor/
service.py`` updated and regenerated a guest's cloud-init the same way. None of
them left a ledger row; a PBX write in read-only mode logged in to the PBX
before the adapter refused it.

Now: configuration writes are staged and applied in the request
(``direct.pbx.*``, ``direct.phone.sip_config``, ``direct.hypervisor.*``),
phone reboot and factory reset are audited actions, read-only mode refuses
before the device is contacted, and FreeSDN's own record changes only when the
device accepted the write. Adapters are fakes; nothing is contacted.
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
from app.core.crypto import encrypt_credential
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.modules.voip.models import PBX, Extension, Phone, RingGroup
from app.modules.voip.service import VoIPError, VoIPService


class _Device:
    """Records every call; every write answers ``box.answer``."""

    def __init__(self, box: SimpleNamespace) -> None:
        self._box = box

    async def connect(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def __aenter__(self) -> _Device:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        async def _call(*args: Any, **_kwargs: Any) -> Any:
            self._box.calls.append((name, args))
            return self._box.answer

        return _call


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def voip(db_session, monkeypatch: pytest.MonkeyPatch):
    org = Organization(name="voip writes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    pbx = PBX(
        site_id=site.id,
        name="pbx",
        pbx_type="freepbx",
        ip_address="192.0.2.30",
        settings={"api_username": "admin"},
        web_password_enc=encrypt_credential("web"),
    )
    db_session.add(pbx)
    await db_session.flush()
    ext = Extension(pbx_id=pbx.id, extension_number="201", display_name="Front desk")
    rg = RingGroup(pbx_id=pbx.id, group_number="600", name="Sales", members=["201"])
    phone = Phone(
        site_id=site.id,
        name="lobby",
        ip_address="192.0.2.40",
        mac_address="aa:bb:cc:00:00:40",
        status="online",
        lifecycle_state="managed",
        sip_registered=True,
        settings={},
        tags=[],
        pbx_id=pbx.id,
    )
    db_session.add_all([ext, rg, phone])
    await db_session.flush()
    phone.extension_id = ext.id
    await db_session.commit()

    box = SimpleNamespace(built=0, calls=[], answer=AdapterResult.ok({"ok": True}))

    def _adapter(_self: Any, _pbx: Any) -> _Device:
        box.built += 1
        return _Device(box)

    async def _client(_self: Any, _phone: Any) -> _Device:
        box.built += 1
        return _Device(box)

    monkeypatch.setattr(VoIPService, "_adapter_from_pbx", _adapter)
    monkeypatch.setattr(VoIPService, "_grandstream_client_for_phone", _client)
    actor = uuid4()
    monkeypatch.setattr("app.services.device_writes.request_actor_id", lambda: actor)
    return SimpleNamespace(
        svc=VoIPService(db_session, organization_id=org.id),
        org=org,
        site=site,
        pbx=pbx,
        ext=ext,
        rg=rg,
        phone=phone,
        box=box,
        actor=actor,
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


# ── PBX extensions and ring groups ───────────────────────────────────────────


def _pbx_writes(v):
    return [
        (
            lambda: v.svc.create_pbx_extension(
                v.pbx.id, {"extension_number": "202", "display_name": "Back office"}
            ),
            "create_extension",
            "direct.pbx.extension",
            "create",
        ),
        (
            lambda: v.svc.update_pbx_extension(v.pbx.id, "201", {"display_name": "Reception"}),
            "update_extension",
            "direct.pbx.extension",
            "update",
        ),
        (
            lambda: v.svc.delete_pbx_extension(v.pbx.id, "201"),
            "delete_extension",
            "direct.pbx.extension",
            "delete",
        ),
        (
            lambda: v.svc.create_ring_group(
                {"pbx_id": v.pbx.id, "group_number": "601", "members": ["201"]}
            ),
            "create_ring_group",
            "direct.pbx.ring_group",
            "create",
        ),
        (
            lambda: v.svc.delete_ring_group(v.rg.id),
            "delete_ring_group",
            "direct.pbx.ring_group",
            "delete",
        ),
    ]


@pytest.mark.parametrize("index", range(5))
async def test_a_pbx_write_is_staged_and_applied(db_session, voip, mode, index) -> None:
    call, adapter_method, feature, operation = _pbx_writes(voip)[index]

    await call()

    assert [c[0] for c in voip.box.calls] == [adapter_method]
    (row,) = await _ledger(db_session)
    assert (row.feature, row.operation, row.status) == (feature, operation, "applied")
    assert row.organization_id == voip.org.id
    assert row.site_id == voip.site.id
    assert row.created_by == voip.actor
    assert row.payload["pbx_id"] == str(voip.pbx.id)


@pytest.mark.parametrize("index", range(5))
async def test_read_only_mode_refuses_a_pbx_write_before_the_pbx_is_contacted(
    db_session, voip, mode, index
) -> None:
    mode["read_only"] = True
    call, *_ = _pbx_writes(voip)[index]

    with pytest.raises(HTTPException) as refused:
        await call()

    assert refused.value.status_code == 403
    assert voip.box.built == 0
    assert await _ledger(db_session) == []


async def test_a_refused_extension_delete_keeps_freesdns_record(db_session, voip, mode) -> None:
    voip.box.answer = AdapterResult.fail("extension is in use by a queue")

    with pytest.raises(VoIPError):
        await voip.svc.delete_pbx_extension(voip.pbx.id, "201")

    await db_session.refresh(voip.ext)
    assert voip.ext.deleted_at is None, "the PBX kept the extension, so FreeSDN must too"
    (row,) = await _ledger(db_session)
    assert row.status == "failed"
    assert "in use by a queue" in (row.failure_reason or "")


async def test_a_refused_ring_group_delete_keeps_freesdns_record(db_session, voip, mode) -> None:
    voip.box.answer = AdapterResult.fail("no such ring group")

    with pytest.raises(VoIPError):
        await voip.svc.delete_ring_group(voip.rg.id)

    await db_session.refresh(voip.rg)
    assert voip.rg.deleted_at is None


# ── phones ───────────────────────────────────────────────────────────────────


async def test_a_phone_reboot_is_audited(db_session, voip, mode) -> None:
    voip.box.answer = True

    out = await voip.svc.reboot_phone(voip.phone.id)

    assert out["status"] == "success"
    assert [c[0] for c in voip.box.calls] == ["reboot"]
    assert await _ledger(db_session) == []
    (record,) = await _actions(db_session)
    assert record.action == "device_action:reboot"
    assert record.organization_id == voip.org.id
    assert record.new_state["parameters"]["phone_ip"] == "192.0.2.40"


async def test_a_phone_that_refuses_the_reboot_leaves_no_action_record(
    db_session, voip, mode
) -> None:
    voip.box.answer = False

    out = await voip.svc.reboot_phone(voip.phone.id)

    assert out["status"] == "failed"
    assert await _actions(db_session) == []


async def test_a_factory_reset_is_audited(db_session, voip, mode) -> None:
    voip.box.answer = True

    out = await voip.svc.factory_reset_phone(voip.phone.id)

    assert out["status"] == "success"
    (record,) = await _actions(db_session)
    assert record.action == "device_action:factory_reset"


async def test_a_sip_push_is_staged_and_the_secret_never_reaches_the_ledger(
    db_session, voip, mode
) -> None:
    voip.box.answer = True

    out = await voip.svc.push_sip_config_to_phone(voip.phone.id, sip_password="sip-secret-77")

    assert out["status"] == "success"
    ((name, args),) = voip.box.calls
    assert name == "set_config" and args[0]["P34"] == "sip-secret-77"
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.phone.sip_config"
    assert row.status == "applied"
    assert "sip-secret-77" not in str(row.payload)
    assert row.payload["P35"] == "201"


async def test_read_only_mode_refuses_phone_writes_before_the_phone_is_contacted(
    db_session, voip, mode
) -> None:
    mode["read_only"] = True
    for call in (
        lambda: voip.svc.reboot_phone(voip.phone.id),
        lambda: voip.svc.factory_reset_phone(voip.phone.id),
        lambda: voip.svc.push_sip_config_to_phone(voip.phone.id, sip_password="x"),
    ):
        with pytest.raises(VoIPError):
            await call()
    assert voip.box.built == 0
    assert await _ledger(db_session) == []
    assert await _actions(db_session) == []


# ── hypervisor cloud-init ────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxmox(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.modules.hypervisor.service import HypervisorService

    org = Organization(name="hypervisor writes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="pve", site_id=site.id, controller_type="proxmox", host="192.0.2.50", port=8006
    )
    db_session.add(ctrl)
    await db_session.commit()
    box = SimpleNamespace(built=0, calls=[], answer=AdapterResult.ok({"ok": True}))

    async def _get_adapter(_controller: Any) -> _Device:
        box.built += 1
        return _Device(box)

    monkeypatch.setattr(HypervisorService, "_get_adapter", staticmethod(_get_adapter))
    return SimpleNamespace(svc=HypervisorService(db_session), ctrl=ctrl, org=org, box=box)


async def test_a_cloudinit_update_is_staged_with_its_secrets_masked(
    db_session, proxmox, mode
) -> None:
    await proxmox.svc.update_cloudinit_config(
        proxmox.ctrl, "pve1", 101, {"ciuser": "ops", "cipassword": "guest-root-pw"}
    )

    assert [c[0] for c in proxmox.box.calls] == ["update_guest_cloudinit"]
    (row,) = await _ledger(db_session)
    assert row.feature == "direct.hypervisor.cloudinit"
    assert row.controller_id == proxmox.ctrl.id
    assert row.status == "applied"
    assert "guest-root-pw" not in str(row.payload)


async def test_a_cloudinit_regenerate_is_staged(db_session, proxmox, mode) -> None:
    await proxmox.svc.regenerate_cloudinit(proxmox.ctrl, "pve1", 101)

    (row,) = await _ledger(db_session)
    assert row.feature == "direct.hypervisor.cloudinit.regenerate"
    assert row.status == "applied"


async def test_read_only_mode_refuses_cloudinit_before_proxmox_is_contacted(
    db_session, proxmox, mode
) -> None:
    mode["read_only"] = True
    with pytest.raises(HTTPException) as refused:
        await proxmox.svc.update_cloudinit_config(proxmox.ctrl, "pve1", 101, {"ciuser": "x"})
    assert refused.value.status_code == 403
    with pytest.raises(HTTPException):
        await proxmox.svc.regenerate_cloudinit(proxmox.ctrl, "pve1", 101)
    assert proxmox.box.built == 0
    assert await _ledger(db_session) == []


async def test_the_direct_backup_restore_never_reaches_proxmox(db_session, proxmox, mode) -> None:
    with pytest.raises(ValueError, match="cannot be applied on the direct path"):
        await proxmox.svc.restore_backup(proxmox.ctrl, "pve1", "qemu", "local:backup/x", 101)
    assert proxmox.box.built == 0
