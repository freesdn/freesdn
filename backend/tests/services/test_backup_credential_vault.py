# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A `.fsdnvault` must actually contain the credential vault it promises.

Background
----------
The docs are unambiguous about what a vault carries::

    modules/backup.md:11   "Carries **every credential** (controller passwords,
                            PBX/camera/firewall secrets, VPN configs, user
                            password hashes)"
    modules/backup.md:97   "It contains every credential in the deployment"
    deploy/backups-and-restore.md:16  "config **plus every credential**"

``core.credentials`` -- the Credentials page, and the rows every
``Device.credential_id`` points at -- was never collected. ``BackupService`` did
not reference the ``Credential`` model at all.

So after a bare-metal recovery from a vault, Settings -> Credentials was empty
and every device's credential link dangled, while the restore reported success
and said nothing. The operator re-entered every stored device password, SSH key,
API key and SNMP community by hand, having been told at backup time that they
would not have to.

What hid it: controller secrets and user logins WERE included, so the vault was
partly true and the promise looked kept.

The secret handling mirrors what controller config secrets already get:
decrypted into the payload (which is itself sealed by the operator passphrase)
and re-encrypted under the DESTINATION instance's SECRET_KEY on restore, so
plaintext never reaches a database. A config-only ``.fsdn`` omits the secrets
entirely rather than carrying ciphertext that the destination key could not
decrypt anyway.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.services.backup import CREDENTIAL_SECRET_FIELDS, BackupService

ORG = uuid.uuid4()
PASSWORD = "sup3r-secret-device-password"
SSH_KEY = "-----BEGIN KEY-----body-----END KEY-----"
COMMUNITY = "public-ro"


class _Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _Session:
    """Returns the credential row only for the credentials query."""

    def __init__(self, cred) -> None:
        self.cred = cred

    async def execute(self, query):
        return _Result([self.cred] if "core.credentials" in str(query) else [])


def _credential():
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=ORG,
        site_id=None,
        name="Core switch admin",
        description="used by the switch adapter",
        credential_type="ssh",
        scope="organization",
        vendor="cisco",
        username="admin",
        encrypted_password=encrypt_credential(PASSWORD),
        api_key=None,
        token=None,
        ssh_private_key=encrypt_credential(SSH_KEY),
        certificate=None,
        snmp_community=encrypt_credential(COMMUNITY),
        options={"port": 22},
        is_default=True,
        is_active=True,
    )


async def _collect(*, include_secrets: bool) -> dict:
    svc = BackupService.__new__(BackupService)
    svc.db = _Session(_credential())
    svc.org_id = ORG
    payload = await BackupService.collect_backup_data(
        svc, organization_id=ORG, include_secrets=include_secrets
    )
    return payload.get("data", payload)


def _reencrypt_like_restore(record: dict) -> dict:
    """Mirror the re-encryption the restore loop performs."""
    out = dict(record)
    for field in CREDENTIAL_SECRET_FIELDS:
        value = out.get(field)
        if isinstance(value, str) and value and not is_encrypted(value):
            out[field] = encrypt_credential(value)
    return out


# ── The regression ───────────────────────────────────────────────


async def test_vault_contains_a_credentials_section() -> None:
    """The section did not exist at all; this is the whole bug in one assert."""
    data = await _collect(include_secrets=True)
    assert "credentials" in data, "a .fsdnvault still omits the credential vault"
    assert len(data["credentials"]) == 1


async def test_vault_carries_the_secrets_decrypted_inside_the_sealed_payload() -> None:
    """
    The vault is sealed by the operator passphrase, so secrets travel decrypted
    inside it -- that is what makes it portable to an instance with a different
    SECRET_KEY. Same treatment controller config secrets already get.
    """
    rec = (await _collect(include_secrets=True))["credentials"][0]
    assert rec["encrypted_password"] == PASSWORD
    assert rec["ssh_private_key"] == SSH_KEY
    assert rec["snmp_community"] == COMMUNITY


async def test_secrets_are_re_encrypted_on_restore_and_still_decrypt() -> None:
    """
    The round trip that matters: what leaves the vault must land in the database
    encrypted under THIS instance's key, and must decrypt back to the original.
    """
    rec = (await _collect(include_secrets=True))["credentials"][0]
    restored = _reencrypt_like_restore(rec)

    assert is_encrypted(restored["encrypted_password"]), "plaintext would reach the DB"
    assert decrypt_credential(restored["encrypted_password"]) == PASSWORD
    assert decrypt_credential(restored["ssh_private_key"]) == SSH_KEY
    assert decrypt_credential(restored["snmp_community"]) == COMMUNITY


async def test_non_secret_fields_survive() -> None:
    """A credential with no name or type is useless even if the secret restored."""
    rec = (await _collect(include_secrets=True))["credentials"][0]
    assert rec["name"] == "Core switch admin"
    assert rec["username"] == "admin"
    assert rec["credential_type"] == "ssh"
    assert rec["vendor"] == "cisco"
    assert rec["options"] == {"port": 22}
    assert rec["is_default"] is True


# ── The config-only backup must stay secret-free ─────────────────


async def test_config_only_backup_omits_every_secret() -> None:
    """
    A `.fsdn` is the secret-FREE snapshot. Carrying ciphertext there would be
    both a secrets leak by a different name and useless -- the destination has a
    different SECRET_KEY and could not decrypt it.
    """
    rec = (await _collect(include_secrets=False))["credentials"][0]
    for field in CREDENTIAL_SECRET_FIELDS:
        assert rec[field] is None, f"{field} leaked into a config-only backup"


async def test_config_only_backup_still_carries_the_credential_metadata() -> None:
    """
    The rows must still exist so Device.credential_id resolves after a config
    restore; only the secrets are withheld.
    """
    rec = (await _collect(include_secrets=False))["credentials"][0]
    assert rec["name"] == "Core switch admin"
    assert rec["credential_type"] == "ssh"


# ── Restore ordering ─────────────────────────────────────────────


def test_credentials_are_restored_before_devices() -> None:
    """
    Device.credential_id references these rows. Restoring devices first would
    leave every link dangling -- the exact symptom being fixed.
    """
    import inspect

    src = inspect.getsource(BackupService)
    start = src.index("restore_map = [")
    block = src[start : start + 700]
    assert '("credentials", Credential)' in block
    assert block.index('("credentials"') < block.index('"devices"'), (
        "credentials must be restored before devices"
    )


def test_every_secret_column_is_covered() -> None:
    """
    A secret column added to the model later but missed here would silently ship
    plaintext into the database on restore.
    """
    assert set(CREDENTIAL_SECRET_FIELDS) == {
        "encrypted_password",
        "api_key",
        "token",
        "ssh_private_key",
        "certificate",
        "snmp_community",
    }
