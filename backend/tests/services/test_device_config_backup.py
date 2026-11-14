# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Network device config backup over PostgreSQL, with synthetic adapters only.

No test contacts a device: GatewayService builds its adapter through
``adapter_registry.create_adapter``, which is replaced by a recorder.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import logging
import tarfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_dict
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Organization, User
from app.modules.backup.models import DeviceConfigBackupTarget, DeviceConfigSnapshot
from app.modules.firewall.gateway_service import adapter_registry
from app.modules.firewall.models import GatewayConnection
from app.services import device_config_backup as backup_module
from app.services.device_config_backup import (
    Claim,
    DeviceConfigBackupService,
    ExportFailed,
    unseal,
)

SECRET = "SECRET-firewall-root-password"


def xml(password: str = SECRET, hostname: str = "fw1") -> str:
    return (
        '<?xml version="1.0"?>\n<opnsense><system>'
        f"<hostname>{hostname}</hostname><user><name>root</name>"
        f"<password>{password}</password></user></system></opnsense>\n"
    )


def sysupgrade(key: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        data = f"config wifi-iface 'x'\n\toption key '{key}'\n".encode()
        info = tarfile.TarInfo("etc/config/wireless")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


@pytest_asyncio.fixture
async def fleet(db_session, monkeypatch):
    org = Organization(name="Config backup fixture", slug="cfgbak-" + uuid4().hex)
    other = Organization(name="Other tenant", slug="cfgbak-other-" + uuid4().hex)
    db_session.add_all([org, other])
    await db_session.flush()

    def gateway(owner, vendor, name, **kwargs):
        return GatewayConnection(
            org_id=owner.id,
            name=name,
            vendor=vendor,
            host="192.0.2.10",
            port=443,
            verify_ssl=True,
            credentials=encrypt_dict({"api_key": "k", "api_secret": "s"}),
            settings={},
            sync_enabled=kwargs.get("sync_enabled", True),
        )

    gws = SimpleNamespace(
        opnsense=gateway(org, "opnsense", "fw-opnsense"),
        openwrt=gateway(org, "openwrt", "ap-openwrt"),
        mikrotik=gateway(org, "mikrotik", "rt-mikrotik"),
        foreign=gateway(other, "opnsense", "fw-foreign"),
    )
    db_session.add_all(vars(gws).values())
    await db_session.flush()

    f = SimpleNamespace(
        db=db_session, org=org, other=other, gws=gws, calls=[], results={}, closed=0
    )

    class Adapter:
        def __init__(self, host):
            self.host = host

        async def connect(self):
            f.calls.append("connect")

        async def disconnect(self):
            f.closed += 1

        async def download_config(self):
            f.calls.append("download")
            result = f.results.get("next", AdapterResult.ok({"config_xml": xml()}))
            if isinstance(result, BaseException):
                raise result
            if callable(result):
                return await result()
            return result

    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **kw: Adapter(kw["host"]))
    return f


async def _targets(f):
    rows = await f.db.execute(
        select(DeviceConfigBackupTarget).where(
            DeviceConfigBackupTarget.organization_id.in_([f.org.id, f.other.id])
        )
    )
    return {t.source_id: t for t in rows.scalars()}


async def _claim(f, gw):
    service = DeviceConfigBackupService(f.db)
    await service.sync_targets()
    target = (await _targets(f))[gw.id]
    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    claims = [c for c in await service.claim_due() if c.target_id == target.id]
    assert len(claims) == 1
    return service, target, claims[0]


async def _snapshots(f, target_id):
    rows = await f.db.execute(
        select(DeviceConfigSnapshot)
        .where(DeviceConfigSnapshot.target_id == target_id)
        .order_by(DeviceConfigSnapshot.version)
    )
    return list(rows.scalars())


# ── discovery and scheduling ────────────────────────────────────────────────


async def test_only_exportable_gateways_become_targets_spread_over_the_first_hour(fleet):
    f = fleet
    now = datetime.now(UTC)
    first = await DeviceConfigBackupService(f.db).sync_targets(now)
    targets = await _targets(f)
    assert set(targets) == {f.gws.opnsense.id, f.gws.openwrt.id, f.gws.foreign.id}
    assert first["added"] >= 3
    for target in targets.values():
        assert target.enabled and target.interval_hours == 24
        delay = (target.next_due_at - now).total_seconds()
        assert 600 <= delay < 4200, "first export is spread 10-70 minutes out, not at once"
    again = await DeviceConfigBackupService(f.db).sync_targets(now)
    assert again["added"] == 0
    assert set(await _targets(f)) == set(targets)


async def test_a_lease_allows_one_export_per_device_at_a_time(fleet):
    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    # Nothing else may claim it while leased, even though it is "due" again.
    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    assert target.id not in [c.target_id for c in await service.claim_due()]
    await f.db.refresh(target)
    with pytest.raises(backup_module.CaptureRefused) as busy:
        await service.claim_manual(target)
    assert busy.value.status_code == 409
    # A stale token (a duplicate task) never touches the device.
    assert await service.capture(Claim(target.id, uuid4())) == "lease_lost"
    assert f.calls == []
    assert await service.capture(claim) == "changed"
    assert f.calls == ["connect", "download"] and f.closed == 1


async def test_claiming_pushes_the_next_run_an_hour_out_in_case_the_worker_dies(fleet):
    f = fleet
    _, target, _ = await _claim(f, f.gws.opnsense)
    await f.db.refresh(target)
    ahead = (target.next_due_at - datetime.now(UTC)).total_seconds()
    assert 3500 < ahead <= 3600
    assert target.lease_until > datetime.now(UTC)


# ── capture outcomes ───────────────────────────────────────────────────────


async def test_versions_are_stored_only_on_change_encrypted_and_pruned(fleet, caplog):
    f = fleet
    caplog.set_level(logging.DEBUG)
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "changed"
    [v1] = await _snapshots(f, target.id)
    assert v1.version == 1 and v1.format == "opnsense-config-xml"
    assert SECRET.encode() not in bytes(v1.ciphertext)
    assert unseal(v1.ciphertext) == xml().encode()
    assert len(v1.content_digest) == 64
    await f.db.refresh(target)
    assert target.last_status == "changed" and target.lease_until is None
    # Next run is a day out, plus at most 10 % jitter.
    ahead = (target.next_due_at - datetime.now(UTC)).total_seconds()
    assert 86400 - 60 < ahead <= 86400 * 1.1

    async def recapture(result):
        f.results["next"] = result
        await f.db.execute(
            update(DeviceConfigBackupTarget)
            .where(DeviceConfigBackupTarget.id == target.id)
            .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        [c] = [c for c in await service.claim_due() if c.target_id == target.id]
        return await service.capture(c)

    assert await recapture(AdapterResult.ok({"config_xml": xml()})) == "unchanged"
    assert len(await _snapshots(f, target.id)) == 1
    assert await recapture(AdapterResult.ok({"config_xml": xml(hostname="fw2")})) == "changed"
    v2 = (await _snapshots(f, target.id))[-1]
    assert v2.version == 2 and v2.summary == {"added": 1, "removed": 1}

    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(retention_versions=2)
    )
    assert await recapture(AdapterResult.ok({"config_xml": xml(hostname="fw3")})) == "changed"
    assert [s.version for s in await _snapshots(f, target.id)] == [2, 3]
    assert SECRET not in caplog.text


async def test_openwrt_archive_rebuilds_do_not_create_versions(fleet):
    f = fleet
    service, target, claim = await _claim(f, f.gws.openwrt)

    def archive(key):
        return AdapterResult.ok(
            {"backup_data": sysupgrade(key), "format": "tar.gz", "scope": "sysupgrade"}
        )

    f.results["next"] = archive("SECRET-wifi")
    assert await service.capture(claim) == "changed"
    await asyncio.sleep(1.1)  # a new gzip timestamp / tar mtime
    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    [again] = [c for c in await service.claim_due() if c.target_id == target.id]
    assert await service.capture(again) == "unchanged"
    [only] = await _snapshots(f, target.id)
    text = DeviceConfigBackupService.redacted(only)
    assert "SECRET" not in text and "option key [redacted:" in text


async def test_a_paused_gateway_is_never_contacted(fleet):
    f = fleet
    f.gws.opnsense.sync_enabled = False
    await f.db.flush()
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "paused"
    assert f.calls == []
    await f.db.refresh(target)
    assert target.last_status == "paused" and target.lease_until is None
    assert target.next_due_at > datetime.now(UTC) + timedelta(hours=23)


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (ExportFailed("auth_failed"), "auth_failed"),
        (RuntimeError(SECRET), "export_failed"),
        (AdapterResult.fail(SECRET, error_code="DOWNLOAD_FAILED"), "export_failed"),
        (AdapterResult.fail("no", error_code="NOT_SUPPORTED"), "unsupported"),
        (AdapterResult.ok({"config_xml": "<pfsense/>"}), "invalid_content"),
        (AdapterResult.ok({"note": SECRET}), "invalid_content"),
    ],
)
async def test_failures_record_a_fixed_code_and_back_off(fleet, caplog, result, code):
    f = fleet
    caplog.set_level(logging.DEBUG)
    service, target, claim = await _claim(f, f.gws.opnsense)
    f.results["next"] = result
    assert await service.capture(claim) == "failed"
    await f.db.refresh(target)
    assert (target.last_status, target.last_error_code) == ("failed", code)
    assert target.consecutive_failures == 1 and target.lease_until is None
    ahead = (target.next_due_at - datetime.now(UTC)).total_seconds()
    assert 3500 < ahead <= 3600, "first retry an hour out, not a loop"
    assert await _snapshots(f, target.id) == []
    assert SECRET not in caplog.text
    assert SECRET not in (target.last_error_code or "")


async def test_backoff_doubles_and_is_capped_by_the_interval(fleet):
    now = datetime.now(UTC)
    delays = [
        (backup_module.next_failure_due(now, 24, n) - now).total_seconds() for n in (1, 2, 3, 6)
    ]
    assert delays == [3600, 7200, 14400, 86400]


async def test_a_hung_device_is_cut_off_at_the_budget(fleet, monkeypatch):
    f = fleet
    monkeypatch.setattr(backup_module, "CAPTURE_TIMEOUT_SECONDS", 0.2)
    service, target, claim = await _claim(f, f.gws.opnsense)

    async def hang():
        await asyncio.sleep(30)

    f.results["next"] = hang
    assert await service.capture(claim) == "failed"
    await f.db.refresh(target)
    assert target.last_error_code == "timeout"
    assert f.closed == 1, "the adapter is closed even when the export is cut off"


async def test_manual_capture_is_refused_soon_after_an_attempt(fleet):
    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "changed"
    await f.db.refresh(target)
    with pytest.raises(backup_module.CaptureRefused) as early:
        await service.claim_manual(target)
    assert early.value.status_code == 429
    target.last_attempt_at = datetime.now(UTC) - timedelta(minutes=11)
    manual = await service.claim_manual(target)
    assert manual.target_id == target.id


async def test_a_deleted_gateway_keeps_its_history_but_is_not_scheduled(fleet):
    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "changed"
    f.gws.opnsense.deleted_at = datetime.now(UTC)
    await f.db.flush()
    await service.sync_targets()
    await f.db.refresh(target)
    assert target.last_status == "source_removed" and target.next_due_at is None
    assert len(await _snapshots(f, target.id)) == 1


# ── API ────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def api(fleet, monkeypatch):
    from app.api.v1.endpoints.device_config_backups import router
    from app.tasks import config_backup

    f = fleet
    app = FastAPI()
    app.include_router(router, prefix="/config-backups")
    f.user = User(
        id=uuid4(),
        organization_id=f.org.id,
        email="cfgbak@example.test",
        username="cfgbak-" + uuid4().hex,
        hashed_password="synthetic",
        role="super_admin",
        is_active=True,
    )
    f.db.add(f.user)
    await f.db.flush()
    f.permissions = ["firewall.view", "firewall.manage_rules", "controller:write"]
    f.role = "super_admin"
    f.scoped = False
    f.queued = []
    monkeypatch.setattr(config_backup.capture, "delay", lambda *a: f.queued.append(a))

    def principal():
        f.user.role = f.role
        return CurrentUser(f.user, f.permissions, scoped=f.scoped)

    app.dependency_overrides[get_current_active_user] = principal

    async def session():
        yield f.db

    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://cfgbak"
    ) as client:
        f.client = client
        try:
            yield f
        finally:
            f.client = None


async def test_api_lists_own_tenant_and_shows_only_redacted_content(api):
    f = api
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "changed"
    f.results["next"] = AdapterResult.ok({"config_xml": xml(password="SECRET-rotated")})
    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    [again] = [c for c in await service.claim_due() if c.target_id == target.id]
    assert await service.capture(again) == "changed"
    f.user.role = "org_admin"
    f.role = "org_admin"

    listed = await f.client.get("/config-backups/")
    assert listed.status_code == 200, listed.text
    names = {row["display_name"] for row in listed.json()}
    assert "fw-opnsense" in names and "fw-foreign" not in names
    row = next(r for r in listed.json() if r["id"] == str(target.id))
    assert row["latest_version"] == 2 and row["last_status"] == "changed"

    versions = await f.client.get(f"/config-backups/{target.id}/versions/")
    assert [v["version"] for v in versions.json()] == [2, 1]

    content = await f.client.get(f"/config-backups/{target.id}/versions/2")
    assert content.status_code == 200
    assert content.json()["redacted"] is True
    assert "SECRET" not in content.text and "<hostname>fw1</hostname>" in content.json()["content"]

    diff = await f.client.get(f"/config-backups/{target.id}/versions/2/diff")
    body = diff.json()
    assert diff.status_code == 200 and (body["from_version"], body["to_version"]) == (1, 2)
    assert "SECRET" not in diff.text
    assert body["added"] == 1 and body["removed"] == 1

    foreign = (await _targets(f))[f.gws.foreign.id]
    assert (await f.client.get(f"/config-backups/{foreign.id}/versions/")).status_code == 404


def _openwrt_archive(secret: str) -> bytes:
    files = {
        "etc/config/ddns": (
            "config service 'home'\n"
            f"\toption update_url 'http://admin:{secret}@ddns.example.invalid/update'\n"
        ).encode(),
        "etc/openvpn/client.auth": f"vpnuser\n{secret}\n".encode(),
        "etc/ppp/chap-secrets": f'"dsluser" * "{secret}" *\n'.encode(),
    }
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


async def test_api_openwrt_version_and_diff_never_show_non_uci_files_or_url_passwords(api):
    f = api
    service, target, claim = await _claim(f, f.gws.openwrt)

    def archive(secret):
        return AdapterResult.ok(
            {"backup_data": _openwrt_archive(secret), "format": "tar.gz", "scope": "sysupgrade"}
        )

    f.results["next"] = archive("SECRET-first")
    assert await service.capture(claim) == "changed"
    f.results["next"] = archive("SECRET-rotated")
    await f.db.execute(
        update(DeviceConfigBackupTarget)
        .where(DeviceConfigBackupTarget.id == target.id)
        .values(next_due_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    [again] = [c for c in await service.claim_due() if c.target_id == target.id]
    assert await service.capture(again) == "changed"
    f.user.role = "org_admin"
    f.role = "org_admin"

    content = await f.client.get(f"/config-backups/{target.id}/versions/2")
    assert content.status_code == 200, content.text
    assert "SECRET" not in content.text
    body = content.json()["content"]
    assert "### /etc/openvpn/client.auth\n[file:" in body
    assert "### /etc/ppp/chap-secrets\n[file:" in body
    assert "@ddns.example.invalid/update'" in body

    diff = await f.client.get(f"/config-backups/{target.id}/versions/2/diff")
    assert diff.status_code == 200, diff.text
    assert "SECRET" not in diff.text
    # Every rotation still shows as a changed fingerprint (ddns, auth, chap).
    assert diff.json()["added"] == 3 and diff.json()["removed"] == 3


async def test_api_raw_download_needs_super_admin_and_is_audited(api):
    from app.models.security_audit import AuditLogRecord

    f = api
    service, target, claim = await _claim(f, f.gws.opnsense)
    assert await service.capture(claim) == "changed"
    # An org admin holding controller:write still lacks the super_admin role.
    f.role = "org_admin"
    denied = await f.client.get(f"/config-backups/{target.id}/versions/1/download")
    assert denied.status_code == 403
    # A super_admin's key scoped to read-only never satisfies the gate.
    f.role, f.scoped, f.permissions = "super_admin", True, ["firewall.view"]
    assert (
        await f.client.get(f"/config-backups/{target.id}/versions/1/download")
    ).status_code == 403
    f.scoped, f.permissions = False, ["firewall.view", "controller:write"]
    raw = await f.client.get(f"/config-backups/{target.id}/versions/1/download")
    assert raw.status_code == 200
    assert raw.content == xml().encode()
    assert raw.headers["cache-control"] == "no-store"
    audited = await f.db.execute(
        select(AuditLogRecord).where(AuditLogRecord.actor_id == str(f.user.id))
    )
    assert any(
        (r.extra_metadata or {}).get("source") == "device-config-backup" for r in audited.scalars()
    )


async def test_api_capture_is_gentle_and_settings_are_bounded(api):
    f = api
    await DeviceConfigBackupService(f.db).sync_targets()
    target = (await _targets(f))[f.gws.opnsense.id]
    first = await f.client.post(f"/config-backups/{target.id}/capture")
    assert first.status_code == 202, first.text
    assert len(f.queued) == 1 and f.queued[0][2] == "manual"
    busy = await f.client.post(f"/config-backups/{target.id}/capture")
    assert busy.status_code == 409 and len(f.queued) == 1
    f.role, f.permissions = "org_admin", ["firewall.view"]
    assert (await f.client.post(f"/config-backups/{target.id}/capture")).status_code == 403
    f.permissions = ["firewall.view", "firewall.manage_rules"]
    for bad in ({"interval_hours": 1}, {"interval_hours": 1000}, {"retention_versions": 0}):
        assert (await f.client.patch(f"/config-backups/{target.id}", json=bad)).status_code == 422
    ok = await f.client.patch(
        f"/config-backups/{target.id}", json={"interval_hours": 168, "enabled": False}
    )
    assert ok.status_code == 200 and ok.json()["interval_hours"] == 168
    assert ok.json()["enabled"] is False


async def test_a_deactivated_organization_is_never_exported(fleet):
    f = fleet
    service, target, claim = await _claim(f, f.gws.opnsense)
    f.org.is_active = False
    await f.db.flush()
    assert await service.capture(claim) == "source_removed"
    assert f.calls == []
