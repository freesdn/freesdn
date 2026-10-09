"""Real PostgreSQL collection and encrypted local archives; no device I/O."""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio

from app.core.crypto import encrypt_dict
from app.models.core import Organization, Site
from app.modules.backup.models import BackupStatus, StorageLocation
from app.modules.firewall.backup import FirewallBackupContributor
from app.modules.firewall.models import (
    FirewallDevice,
    FirewallRule,
    GatewayConnection,
    NATRule,
    VPNTunnel,
)
from app.services.backup import BackupEncryption, BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    CoreBackupContributor,
)


async def make_scope(db):
    org = Organization(name="Owned scope", slug=uuid4().hex)
    other = Organization(name="Owned other", slug=uuid4().hex)
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
    gateways = {}
    for name, site_name, foreign_org, deleted in [
        ("a", "a", False, False),
        ("b", "b", False, False),
        ("global", None, False, False),
        ("deleted-site", "deleted", False, False),
        ("foreign-site", "foreign", False, False),
        ("foreign-org", "a", True, False),
        ("deleted-gateway", "a", False, True),
    ]:
        gateway = GatewayConnection(
            org_id=other.id if foreign_org else org.id,
            site_id=sites[site_name].id if site_name else None,
            name=name,
            vendor="opnsense",
            host="owned.example.test",
            credentials=encrypt_dict({"api_key": "owned-key-" + name}),
            settings={"port_hint": 443, "nested": {"password": "owned-setting-" + name}},
            deleted_at=datetime.now(UTC) if deleted else None,
        )
        db.add(gateway)
        gateways[name] = gateway
    await db.flush()
    return SimpleNamespace(db=db, org=org, other=other, sites=sites, gateways=gateways)


@pytest_asyncio.fixture
async def scope(db_session):
    return await make_scope(db_session)


def expected_names(target):
    if target is None:
        # Existing organization-wide behavior is deliberately unchanged.
        return {"a", "b", "global", "deleted-site", "foreign-site"}
    return {target} if target in {"a", "b"} else set()


def options_for(f, target, secrets):
    site_id = f.sites[target].id if target in f.sites else uuid4() if target else None
    return {"site_id": site_id, "include_secrets": secrets}


@pytest.mark.parametrize("target", ["a", "b", "empty", "deleted", "foreign", "missing", None])
@pytest.mark.parametrize("secrets", [False, True])
async def test_gateway_collection_honors_requested_active_site(scope, target, secrets):
    f = scope
    payload = await FirewallBackupContributor().collect(
        f.db, f.org.id, options_for(f, target, secrets)
    )
    rows = payload.data["gateway_connections"]
    assert {r["name"] for r in rows} == expected_names(target)
    assert payload.counts["gateway_connections"] == len(rows)
    for row in rows:
        assert row["org_id"] == str(f.org.id)
        assert ("credentials" in row) is secrets
        assert ("password" in row["settings"]["nested"]) is secrets
        if secrets:
            assert row["credentials"] == {"api_key": "owned-key-" + row["name"]}
        assert row["settings"]["port_hint"] == 443


@pytest.mark.parametrize("secrets", [False, True])
async def test_manifest_reports_actual_secret_policy(scope, secrets):
    payload = await FirewallBackupContributor().collect(
        scope.db, scope.org.id, {"include_secrets": secrets}
    )
    assert payload.metadata["secrets_excluded"] is (not secrets)


@pytest.mark.parametrize("outside", ["b", "global"])
async def test_unselected_credentials_are_never_decrypted(scope, outside):
    f = scope
    f.gateways[outside].credentials = {"_encrypted": "deliberately-invalid-owned-token"}
    await f.db.flush()
    payload = await FirewallBackupContributor().collect(f.db, f.org.id, options_for(f, "a", True))
    assert [r["name"] for r in payload.data["gateway_connections"]] == ["a"]


@pytest.mark.parametrize("target", ["a", "b"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_existing_device_and_child_scope_is_preserved(scope, target, secrets):
    f = scope
    for site_name in ["a", "b"]:
        device = FirewallDevice(
            name=site_name, site_id=f.sites[site_name].id, ip_address="192.0.2.1"
        )
        f.db.add(device)
        await f.db.flush()
        f.db.add_all(
            [
                FirewallRule(device_id=device.id, name=site_name, action="allow"),
                NATRule(device_id=device.id, name=site_name, nat_type="port_forward"),
                VPNTunnel(
                    device_id=device.id,
                    name=site_name,
                    vpn_type="ipsec",
                    settings={"psk": "owned-psk", "ike": "v2"},
                ),
            ]
        )
    await f.db.flush()
    payload = await FirewallBackupContributor().collect(
        f.db, f.org.id, options_for(f, target, secrets)
    )
    for key in ["devices", "rules", "nat_rules", "vpn_tunnels"]:
        assert [r["name"] for r in payload.data[key]] == [target]
        assert payload.counts[key] == 1
    assert ("psk" in payload.data["vpn_tunnels"][0]["settings"]) is secrets


async def create_archive(f, root, target, secrets):
    storage = StorageLocation(
        name="Owned local archive",
        organization_id=f.org.id,
        storage_type="local",
        config={"path": str(root)},
        is_active=True,
    )
    f.db.add(storage)
    await f.db.flush()
    service = BackupService(f.db)
    passphrase = "owned-disposable-archive-passphrase"
    backup = await service.create_backup(
        name="Owned scope archive",
        organization_id=f.org.id,
        site_id=options_for(f, target, secrets)["site_id"],
        include_users=False,
        include_automation=False,
        include_secrets=secrets,
        passphrase=passphrase if secrets else None,
        storage_location_id=storage.id,
        is_encrypted=True,
    )
    assert backup.status == BackupStatus.COMPLETED and not backup.error_message
    raw = await LocalStorageBackend({"path": str(root)}).load(backup.storage_path)
    assert len(raw) == backup.file_size
    header_len = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4 : 4 + header_len])
    encrypted = raw[4 + header_len :]
    assert header["encrypted"] is True and header["secrets"] is secrets
    assert hashlib.sha256(encrypted).hexdigest() == header["checksum"]
    assert b"owned-key-" not in raw and b"owned-setting-" not in raw
    decryptor = BackupEncryption(master_key=passphrase) if secrets else service.encryption
    decoded = decryptor.decrypt(encrypted, header["key_id"])
    archive = BackupArchive.model_validate_json(gzip.decompress(decoded))
    return backup, archive


@pytest.mark.parametrize("target", ["a", None])
@pytest.mark.parametrize("secrets", [False, True])
async def test_persisted_encrypted_archive_keeps_gateway_scope(
    scope, tmp_path, monkeypatch, target, secrets
):
    # Use the real core + firewall contributors, not a fake collected payload.
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    registry.register(FirewallBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    backup, archive = await create_archive(scope, tmp_path, target, secrets)
    rows = archive.contributors["firewall"]["gateway_connections"]
    assert {r["name"] for r in rows} == expected_names(target)
    entry = next(e for e in archive.manifest.contributors if e.id == "firewall")
    assert entry.counts["gateway_connections"] == len(rows)
    assert all(("credentials" in row) is secrets for row in rows)
    assert backup.site_id == (scope.sites[target].id if target else None)
    assert set(archive.contributors) == {"core", "firewall"}
