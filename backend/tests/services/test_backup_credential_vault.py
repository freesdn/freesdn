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


# ── Restoring a config-only backup must not destroy live secrets ──────────
#
# A .fsdn config snapshot exports every credential row with its secret columns
# set to literal None, on purpose, so Device.credential_id still resolves --
# test_config_only_backup_omits_every_secret above asserts exactly that.
#
# _restore_data's overwrite branch then does setattr(existing, k, v) for every
# key not in _BLOCKED_FIELDS. Those six columns were not in it, so restoring
# yesterday's config snapshot with "Overwrite existing" -- the only option the
# restore dialog exposes -- wrote those Nones over the live ciphertext for every
# credential in the org, reported credentials: {updated: N}, and completed green.
# SSH private keys, API keys, tokens, certificates and SNMP communities, gone and
# unrecoverable, with the operator's next device poll failing everywhere.
#
# Every module contributor already guarded this (firewall passes {"credentials"},
# voip {"voicemail_pin"}, cameras and network their own sets). The core restore,
# which owns the credentials table itself, did not.


def _blocked_fields_source() -> str:
    import inspect

    from app.services.backup import BackupService

    return inspect.getsource(BackupService._restore_data)


def test_a_config_only_restore_blocks_every_credential_secret_column() -> None:
    """The core regression.

    Asserted on the real source: _BLOCKED_FIELDS is a local, so there is nothing
    importable to compare against. The behaviour it produces was verified by
    reproducing the filter against the live schema.
    """
    src = _blocked_fields_source()
    assert "*CREDENTIAL_SECRET_FIELDS" in src, (
        "the non-secret restore path no longer blocks the credential secret "
        "columns. A config-only backup carries them as None by construction, so "
        "an overwrite restore will NULL every live device credential in the org."
    )


def test_the_blocklist_is_derived_not_copied() -> None:
    """A second hand-written copy would rot the moment a column is added.

    CREDENTIAL_SECRET_FIELDS is already pinned against the model by
    test_every_secret_column_is_covered, so deriving from it means a new secret
    column is blocked on restore the moment it is declared.
    """
    src = _blocked_fields_source()
    for column in CREDENTIAL_SECRET_FIELDS:
        assert f'"{column}"' not in src.split("_BLOCKED_FIELDS")[1][:600], (
            f"{column} looks hard-coded into _BLOCKED_FIELDS; derive the set from "
            "CREDENTIAL_SECRET_FIELDS instead so it cannot drift from the model"
        )


def test_a_vault_restore_still_writes_secrets() -> None:
    """The fix must not block the path that is SUPPOSED to write them.

    A .fsdnvault carries real secrets and include_secrets is True, which selects
    the narrow {id, organization_id} blocklist. Blocking the secret columns there
    would silently turn a full restore into a config-only one.
    """
    src = _blocked_fields_source()
    head = src[src.index("_BLOCKED_FIELDS = (") :][:400]
    assert '{"id", "organization_id"}' in head, (
        "the include_secrets branch must stay narrow, or a vault restore would "
        "no longer restore the secrets it exists to carry"
    )
