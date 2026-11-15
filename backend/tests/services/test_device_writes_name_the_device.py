"""Every device write and audited action names the device it reaches, so it
waits for that device's turn (``app/core/device_slot.acquire_write_turn``).

``acquire_write_turn(None, ...)`` returns at once without a lease, so a write
that names no device ran alongside a poll of the same device. A write with a
controller row gets the controller's slot from the chokepoint; one without
(camera, NVR, phone, gateway) and every audited action must pass
``slot_key``. ``write_device_config`` / ``device_action`` derive it from the
device row themselves.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.config import settings
from app.core.device_slot import DeviceWriteBusyError, device_slots, host_slot_key

APP = Path(__file__).resolve().parents[2] / "app"

#: Calls that hand their keywords over as ``**mapping``; the mapping is checked
#: to carry a ``slot_key`` entry instead.
_MAPPING_CALLERS = {
    # staged_camera_write's ledger dict, built from its slot_key parameter.
    "modules/cameras/config_write.py",
}


def _name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_none(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _unnamed_writes() -> list[str]:
    missing: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        rel = path.relative_to(APP).as_posix()
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func)
            kw = {k.arg: k.value for k in node.keywords}
            if name == "audited_device_action":
                needs = True
            elif name in ("write_through_staging", "apply_now"):
                # A controller row names its own slot in the chokepoint.
                needs = "controller_id" in kw and _is_none(kw["controller_id"])
            else:
                continue
            if not needs:
                continue
            if None in kw:
                if rel in _MAPPING_CALLERS and '"slot_key": slot_key' in source:
                    continue
                missing.append(f"{rel}:{node.lineno} {name}(**...)")
            elif "slot_key" not in kw or _is_none(kw["slot_key"]):
                missing.append(f"{rel}:{node.lineno} {name}")
    return missing


def test_every_write_without_a_controller_row_names_its_device() -> None:
    missing = _unnamed_writes()
    assert not missing, (
        "These device writes / audited actions pass no slot_key, so they take no "
        "device turn and can run alongside a poll of the same device. Pass the "
        "device's key (camera / NVR / phone / gateway / controller helpers in "
        "app/core/device_slot.py):\n  " + "\n  ".join(missing)
    )


def test_the_scan_sees_a_missing_key() -> None:
    tree = ast.parse(
        "async def f():\n"
        "    await audited_device_action(db, action='x', perform=p)\n"
        "    await audited_device_action(db, action='x', perform=p, slot_key=None)\n"
        "    await write_through_staging(db, controller_id=None, perform=p)\n"
        "    await write_through_staging(db, controller_id=ctrl.id, perform=p)\n"
    )
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _name(n.func) != "f"]
    flagged = 0
    for node in calls:
        kw = {k.arg: k.value for k in node.keywords}
        name = _name(node.func)
        if name == "audited_device_action" or (
            name == "write_through_staging" and _is_none(kw.get("controller_id"))
        ):
            flagged += "slot_key" not in kw or _is_none(kw["slot_key"])
    assert flagged == 3


# ── the device-row wrappers derive the key ───────────────────────────────────


@pytest.fixture
def writes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.core.runtime_flags as rf

    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    monkeypatch.setattr(settings, "DEVICE_WRITE_SLOT_WAIT_SECONDS", 0.2)


async def test_a_device_without_a_controller_waits_for_its_own_turn(
    db_session, writes_on
) -> None:
    from app.models.core import Organization, Site
    from app.models.devices import Device
    from app.services.device_writes import device_action, write_device_config

    org = Organization(name="device turns", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    device = Device(
        name="sw-standalone",
        site_id=site.id,
        device_type="switch",
        mac_address="aa:bb:cc:00:00:61",
        ip_address="192.0.2.61",
        status="online",
    )
    db_session.add(device)
    await db_session.commit()
    sent: list[str] = []

    async def _send() -> SimpleNamespace:
        sent.append("sent")
        return SimpleNamespace(success=True, data=None, error=None)

    lease = device_slots.try_acquire(host_slot_key("192.0.2.61", fallback="-"), "poll", ttl=30)
    assert lease is not None
    try:
        with pytest.raises(DeviceWriteBusyError):
            await write_device_config(
                db_session,
                device,
                actor_id=None,
                feature="test.turn",
                operation="update",
                payload={},
                perform=_send,
            )
        with pytest.raises(DeviceWriteBusyError):
            await device_action(
                db_session,
                device,
                actor_id=None,
                action="reboot_device",
                parameters={},
                perform=_send,
            )
    finally:
        device_slots.release(lease)
    assert sent == [], "nothing is sent while the device is busy"
