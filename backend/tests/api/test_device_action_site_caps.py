"""Site caps reject device mutation before any synthetic adapter is constructed.

Real PostgreSQL and HTTP routes; authentication and controller adapters are
synthetic. No vendor hardware or concurrent grant-revocation proof.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.adapters.base import AdapterResult
from app.api.v1.endpoints import devices as endpoint
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Controller, Organization, Site, User
from app.models.devices import Device

ACTIONS = {
    "delete": ("DELETE", "", "device:delete", None),
    "reboot": ("POST", "/reboot", "device:reboot", "reboot_device"),
    "locate": ("POST", "/locate", "device:action", "locate_device"),
    "led": ("PATCH", "/led", "device:action", "set_device_led"),
    "adopt": ("POST", "/adopt", "device:admin", "adopt_device"),
    "forget": ("POST", "/forget", "device:admin", "forget_device"),
    "upgrade": ("POST", "/upgrade", "firmware:upgrade", "upgrade_firmware"),
    "batch-reboot": ("POST", "/batch/reboot", "device:admin", "reboot_device"),
    "batch-upgrade": ("POST", "/batch/upgrade", "firmware:upgrade", "upgrade_firmware"),
}


def action_cases():
    cases = []
    for action in ACTIONS:
        for level in ["read", "write", "admin", None, "invalid"]:
            denied = level in {"read", "invalid"} or (
                level == "write" and ACTIONS[action][2] in {"device:admin", "device:delete"}
            )
            cases.append(
                {
                    "label": f"{action}-{level}",
                    "action": action,
                    "level": level,
                    "denied": denied,
                    "old_denied": False,
                }
            )
    for action in ACTIONS:
        for control in ["org-admin", "scoped-read-key", "outside-grant", "grantless"]:
            denied = control in {"scoped-read-key", "outside-grant"}
            cases.append(
                {
                    "label": f"{action}-{control}",
                    "action": action,
                    "level": "read",
                    "control": control,
                    "denied": denied,
                    "old_denied": denied,
                }
            )
    for action in ["reboot", "forget", "upgrade", "batch-reboot", "batch-upgrade"]:
        cases.append(
            {
                "label": f"{action}-unconfirmed",
                "action": action,
                "level": "admin",
                "control": "unconfirmed",
                "denied": True,
                "old_denied": True,
            }
        )
    for action in ["batch-reboot", "batch-upgrade"]:
        cases.append(
            {
                "label": f"{action}-mixed",
                "action": action,
                "level": "admin",
                "control": "mixed",
                "denied": False,
                "old_denied": False,
            }
        )
    return cases


async def make_action_fixture(db, case):
    org = Organization(name="Owned device action", slug=uuid4().hex)
    foreign = Organization(name="Owned foreign action", slug=uuid4().hex)
    db.add_all([org, foreign])
    await db.flush()
    sites = {}
    devices = {}
    for name in ["a", "read", "write", "ungranted", "foreign", "deleted"]:
        site = Site(
            name=name, slug=uuid4().hex, organization_id=foreign.id if name == "foreign" else org.id
        )
        db.add(site)
        sites[name] = site
    await db.flush()
    ctrl = Controller(
        name="Owned synthetic controller",
        site_id=sites["a"].id,
        controller_type="unifi",
        host="127.0.0.1",
        port=443,
    )
    db.add(ctrl)
    await db.flush()
    for name, site in sites.items():
        raw = uuid4().hex[:12]
        device = Device(
            name=name,
            site_id=site.id,
            controller_id=ctrl.id,
            device_type="switch",
            mac_address=":".join(raw[i : i + 2] for i in range(0, 12, 2)),
            is_adopted=case["action"] == "forget",
            status="online",
            deleted_at=datetime.now(UTC) if name == "deleted" else None,
        )
        db.add(device)
        devices[name] = device
    user = User(
        username=uuid4().hex,
        email=uuid4().hex + "@owned.example.test",
        hashed_password="owned-synthetic",
        role="org_admin" if case.get("control") == "org-admin" else "operator",
        organization_id=org.id,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    control = case.get("control")
    granted = {sites[n].id for n in (["a", "read", "write"] if control == "mixed" else ["a"])}
    if control == "grantless":
        granted = set()
    levels = {sites["a"].id: case["level"], sites["read"].id: "read", sites["write"].id: "write"}
    permissions = ["device:read"] if control == "scoped-read-key" else [ACTIONS[case["action"]][2]]
    principal = CurrentUser(
        user,
        permissions,
        accessible_site_ids=granted,
        site_access_levels={} if control == "grantless" else levels,
        scoped=control == "scoped-read-key",
    )
    f = SimpleNamespace(
        db=db,
        case=case,
        devices=devices,
        ids={n: d.id for n, d in devices.items()},
        macs={n: d.mac_address for n, d in devices.items()},
        calls=[],
        created=0,
        closed=0,
    )
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/devices")
    app.dependency_overrides[get_current_active_user] = lambda: principal

    async def session():
        try:
            yield db
            await db.commit()
        except BaseException:
            await db.rollback()
            raise

    app.dependency_overrides[get_session] = session
    f.app = app
    method, suffix, _, _ = ACTIONS[case["action"]]
    target = "ungranted" if control == "outside-grant" else "a"
    f.target = target
    f.method = method
    f.path = (
        "/devices" + suffix
        if case["action"].startswith("batch-")
        else f"/devices/{f.ids[target]}" + suffix
    )
    f.path += "?confirm=" + ("false" if control == "unconfirmed" else "true")
    f.payload = {"setting": 1} if case["action"] == "led" else None
    if case["action"].startswith("batch-"):
        f.requested = (
            [f.ids[n] for n in devices] + [uuid4()] if control == "mixed" else [f.ids[target]]
        )
        f.payload = {"device_ids": [str(i) for i in f.requested]}
    await db.commit()
    return f


def action_adapter_patch(f):
    class Adapter:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            f.closed += 1

        def __getattr__(self, method):
            assert method in {a[3] for a in ACTIONS.values() if a[3]}

            async def action(mac, *args):
                f.calls.append((method, mac))
                return AdapterResult.ok(message="Owned synthetic action")

            return action

    async def factory(device):
        f.created += 1
        return Adapter()

    return patch.object(endpoint, "_get_adapter_for_device", factory)


async def inspect_action_response(f, response, *, after=True):
    case = f.case
    denied = case["denied"] if after else case["old_denied"]
    action = case["action"]
    control = case.get("control")
    batch = action.startswith("batch-")
    if control == "unconfirmed":
        status = 409 if action in {"upgrade", "batch-upgrade"} else 400
    elif control == "scoped-read-key":
        status = 403
    elif batch:
        status = 200
    elif control == "outside-grant":
        status = 404
    else:
        status = 403 if denied else 204 if action == "delete" else 200
    assert response.status_code == status, response.text
    expected_names = [] if denied or action == "delete" else [f.target]
    if control == "mixed":
        expected_names = ["a"]
        if not after:
            expected_names += ["read", "write"]
        elif action == "batch-upgrade":
            expected_names += ["write"]
    expected_calls = sorted((ACTIONS[action][3], f.macs[n]) for n in expected_names)
    assert sorted(f.calls) == expected_calls
    assert f.created == f.closed == (1 if expected_calls else 0)
    if batch and status == 200:
        results = response.json()["results"]
        assert len(results) == len(f.requested)
        assert {r["device_id"] for r in results if r["success"]} == {
            str(f.ids[n]) for n in expected_names
        }
    rows = (
        (
            await f.db.execute(
                select(Device)
                .where(Device.id.in_(list(f.ids.values())))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == len(f.ids)
    for row in rows:
        selected = row.id == f.ids[f.target]
        allowed = selected and not denied
        assert (row.deleted_at is not None) == (
            row.id == f.ids["deleted"] or allowed and action == "delete"
        )
        assert row.is_adopted == (
            allowed if action == "adopt" else not allowed if action == "forget" else False
        )
        assert row.status == (
            "adopting"
            if allowed and action == "adopt"
            else "unknown"
            if allowed and action == "forget"
            else "online"
        )
    return {
        "status": status,
        "adapter_constructions": f.created,
        "adapter_closures": f.closed,
        "adapter_calls": len(f.calls),
        "denied": denied,
        "database_state_verified": True,
        "no_adapter_on_denial": not denied or f.created == 0,
    }


@pytest.mark.parametrize("case", action_cases(), ids=lambda c: c["label"])
async def test_device_action_caps(db_session, case):
    f = await make_action_fixture(db_session, case)
    with action_adapter_patch(f):
        async with AsyncClient(
            transport=ASGITransport(app=f.app, raise_app_exceptions=False),
            base_url="http://owned-fixture",
        ) as client:
            response = await client.request(f.method, f.path, json=f.payload)
    await inspect_action_response(f, response)
