"""A device list narrows a selected site's backup instead of overriding it.

Actual PostgreSQL and core contributor archives; no HTTP, hardware or complete
multi-contributor recovery qualification is implied.
"""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.core import Organization, Site
from app.models.devices import Device
from app.modules.backup.models import BackupStatus, StorageLocation
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)


def selection_cases():
    return [
        {"label": label, "site": site, "devices": devices, "expected": expected}
        for label, site, devices, expected in [
            ("organization", None, None, {"a1", "a2", "b1", "b2"}),
            ("site-a", "a", None, {"a1", "a2"}),
            ("site-b", "b", None, {"b1", "b2"}),
            ("site-empty-list", "a", [], {"a1", "a2"}),
            ("org-empty-list", None, [], {"a1", "a2", "b1", "b2"}),
            ("same-site", "a", ["a1"], {"a1"}),
            ("outside-site", "a", ["b1"], set()),
            ("mixed-a", "a", ["a1", "b1"], {"a1"}),
            ("mixed-b", "b", ["a1", "b1"], {"b1"}),
            ("empty-site", "empty", ["a1"], set()),
            ("missing-site", "missing", ["a1"], set()),
            ("foreign-site", "foreign", ["a1"], set()),
            ("deleted-site-other-device", "deleted", ["a1"], set()),
            ("org-selected", None, ["a1", "b1"], {"a1", "b1"}),
            ("foreign-device", "a", ["foreign"], set()),
            ("unknown-device", "a", ["missing"], set()),
            ("deleted-device", "a", ["removed"], set()),
            ("duplicate-same", "a", ["a1", "a1"], {"a1"}),
            ("org-foreign", None, ["foreign"], set()),
            ("duplicate-outside", "a", ["b1", "b1"], set()),
        ]
    ]


async def make_devices(db):
    org = Organization(name="Owned backup device scope", slug=uuid4().hex)
    other = Organization(name="Owned foreign backup scope", slug=uuid4().hex)
    db.add_all([org, other])
    await db.flush()
    sites = {}
    for name in ["a", "b", "empty", "deleted", "foreign"]:
        site = Site(
            name=name,
            slug=uuid4().hex,
            organization_id=other.id if name == "foreign" else org.id,
            deleted_at=datetime.now(UTC) if name == "deleted" else None,
        )
        db.add(site)
        sites[name] = site
    await db.flush()
    devices = {}
    for name, site in [
        ("a1", "a"),
        ("a2", "a"),
        ("b1", "b"),
        ("b2", "b"),
        ("foreign", "foreign"),
        ("removed", "a"),
    ]:
        mac = uuid4().hex[:12]
        device = Device(
            name="owned-backup-device-" + name,
            site_id=sites[site].id,
            device_type="switch",
            mac_address=":".join(mac[i : i + 2] for i in range(0, 12, 2)),
            deleted_at=datetime.now(UTC) if name == "removed" else None,
        )
        db.add(device)
        devices[name] = device
    await db.flush()
    return SimpleNamespace(db=db, org=org, sites=sites, devices=devices, missing=uuid4())


def selection_options(f, case, secrets, include_devices=True):
    return {
        "site_id": f.sites[case["site"]].id
        if case["site"] in f.sites
        else f.missing
        if case["site"]
        else None,
        "device_ids": [f.devices[n].id if n in f.devices else f.missing for n in case["devices"]]
        if case["devices"] is not None
        else None,
        "include_devices": include_devices,
        "include_users": False,
        "include_automation": False,
        "include_secrets": secrets,
    }


def expected_device_ids(f, case, *, before=False):
    if before and case["devices"]:
        names = set(case["devices"]) & {"a1", "a2", "b1", "b2"}
    else:
        names = case["expected"]
    return {str(f.devices[n].id) for n in names}


@pytest.mark.parametrize("case", selection_cases(), ids=lambda c: c["label"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_device_selection_intersects_site(db_session, case, secrets):
    f = await make_devices(db_session)
    payload = await CoreBackupContributor().collect(
        f.db, f.org.id, selection_options(f, case, secrets)
    )
    rows = payload.data["devices"]
    assert {r["id"] for r in rows} == expected_device_ids(f, case)
    assert payload.counts["devices"] == len(rows)
    if case["site"]:
        assert all(
            r["site_id"] == str(selection_options(f, case, secrets)["site_id"]) for r in rows
        )
    assert all("config" not in r and "password" not in r for r in rows)


@pytest.mark.parametrize(
    "case", [selection_cases()[i] for i in [0, 1, 7]], ids=lambda c: c["label"]
)
@pytest.mark.parametrize("secrets", [False, True])
async def test_device_exclusion_overrides_selection(db_session, case, secrets):
    f = await make_devices(db_session)
    payload = await CoreBackupContributor().collect(
        f.db, f.org.id, selection_options(f, case, secrets, include_devices=False)
    )
    assert "devices" not in payload.data and "devices" not in payload.counts


async def create_device_archive(f, root, case, secrets):
    storage = StorageLocation(
        name="Owned device scope archive",
        organization_id=f.org.id,
        storage_type="local",
        config={"path": str(root)},
        is_active=True,
    )
    f.db.add(storage)
    await f.db.flush()
    service = BackupService(f.db)
    phrase = "owned-disposable-device-selection-passphrase"
    backup = await service.create_backup(
        name="Owned device selection",
        organization_id=f.org.id,
        **selection_options(f, case, secrets),
        passphrase=phrase if secrets else None,
        storage_location_id=storage.id,
        is_encrypted=True,
    )
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    raw = await LocalStorageBackend({"path": str(root)}).load(backup.storage_path)
    n = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4 : 4 + n])
    encrypted = raw[4 + n :]
    assert header["encrypted"] is True and header["secrets"] is secrets
    assert hashlib.sha256(encrypted).hexdigest() == header["checksum"]
    assert b"owned-backup-device-" not in raw
    encryption = BackupEncryption(master_key=phrase) if secrets else service.encryption
    archive = BackupArchive.model_validate_json(
        gzip.decompress(encryption.decrypt(encrypted, header["key_id"]))
    )
    return backup, archive


@pytest.mark.parametrize("case", [selection_cases()[i] for i in [7, 13]], ids=lambda c: c["label"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_encrypted_archive_preserves_device_site_selection(
    db_session, tmp_path, monkeypatch, case, secrets
):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    f = await make_devices(db_session)
    backup, archive = await create_device_archive(f, tmp_path, case, secrets)
    rows = archive.contributors["core"]["devices"]
    assert {r["id"] for r in rows} == expected_device_ids(f, case)
    assert archive.manifest.contributors[0].counts["devices"] == len(rows)
    assert backup.site_id == selection_options(f, case, secrets)["site_id"]
