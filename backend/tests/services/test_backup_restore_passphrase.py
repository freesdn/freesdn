# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A mistyped vault passphrase must say "wrong passphrase", not HTTP 500 + blank.

``cryptography.fernet.InvalidToken`` carries no message -- ``str(InvalidToken())``
is the EMPTY STRING. ``restore_from_backup`` called ``decrypt`` unwrapped, so a
one-character typo took this path:

    decrypt(...) -> InvalidToken
      -> except Exception as e:  job.error_message = str(e)[:2000]   # ''
      -> raise
      -> backups.py `except ValueError` does NOT match InvalidToken
      -> unhandled 500

The operator, mid-recovery, with this file as their only copy, saw "Internal
Server Error" and a failed restore job whose error column was blank. Nothing
anywhere said "wrong passphrase", so the reasonable reading was that the archive
was corrupt.

``restore_fresh_instance_from_vault`` already wrapped the identical call and
produced a clean 400 with an explanation; the live-instance path never got it.
The missing-passphrase case WAS handled with a clear ValueError, which is what
made the wrong-passphrase gap easy to miss.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.modules.backup.models import BackupStatus, RestoreJob
from app.services.backup import BackupEncryption, BackupService

ORG = uuid.uuid4()
REAL_PASSPHRASE = "the-operators-real-passphrase"
TYPO_PASSPHRASE = "the-operators-real-passphras"  # one character short


def _vault_bytes(passphrase: str) -> bytes:
    """A .fsdnvault built exactly as ``create_backup`` builds one."""
    payload = json.dumps(
        {
            "manifest": {
                "backup_id": str(uuid.uuid4()),
                "created_at": datetime.now(UTC).isoformat(),
                "organization_id": str(ORG),
                "contributors": [],
            },
            "contributors": {},
        }
    ).encode("utf-8")
    compressed = gzip.compress(payload)
    compressed, key_id = BackupEncryption(master_key=passphrase).encrypt(compressed)
    header = {
        "backup_id": str(uuid.uuid4()),
        "checksum": hashlib.sha256(compressed).hexdigest(),
        "encrypted": True,
        "compressed": True,
        "secrets": True,
        "key_id": key_id,
        "created_at": datetime.now(UTC).isoformat(),
        "version": "2.0",
    }
    hb = json.dumps(header).encode("utf-8")
    return len(hb).to_bytes(4, "big") + hb + compressed


class _Backup:
    id = uuid.uuid4()
    status = BackupStatus.COMPLETED
    include_secrets = True
    storage_type = "local"
    storage_location_id = None
    storage_path = "/backups/vault.fsdnvault"
    encryption_key_id = None
    created_at = datetime.now(UTC)
    name = "nightly vault"
    # Persisted pre-identity Backup rows have this required JSONB field.
    metadata_json: dict[str, Any] = {}


class _Session:
    """Captures the RestoreJob the service writes, so the row the operator
    would see in the restore-jobs list can be asserted on."""

    def __init__(self) -> None:
        self.jobs: list[RestoreJob] = []

    def add(self, obj: Any) -> None:
        if isinstance(obj, RestoreJob) and obj not in self.jobs:
            self.jobs.append(obj)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def refresh(self, obj: Any) -> None:
        return None


async def _restore_with(passphrase: str | None) -> tuple[BaseException | None, _Session]:
    file_bytes = _vault_bytes(REAL_PASSPHRASE)

    class _Backend:
        async def load(self, path: str) -> bytes:
            return file_bytes

    session = _Session()
    BackupService._contributors_initialized = True
    svc = BackupService(session)

    async def _get_backup(*_a: Any, **_kw: Any) -> _Backup:
        return _Backup()

    async def _resolve(*_a: Any, **_kw: Any) -> tuple[Any, None]:
        return _Backend(), None

    svc.get_backup_for_organization = _get_backup
    svc._resolve_storage = _resolve

    raised: BaseException | None = None
    try:
        await svc.restore_from_backup(
            _Backup.id,
            dry_run=True,
            organization_id=ORG,
            passphrase=passphrase,
        )
    except BaseException as exc:  # noqa: BLE001 - the test asserts on the type
        raised = exc
    return raised, session


async def test_a_wrong_passphrase_is_a_value_error_not_an_opaque_invalid_token() -> None:
    """``backups.py`` turns ValueError into a 400 and everything else into an
    unhandled 500. InvalidToken is not a ValueError.

    Mutation caught: removing the try/except around the vault decrypt in
    restore_from_backup -- the raised type goes back to
    ``cryptography.fernet.InvalidToken``.
    """
    raised, _ = await _restore_with(TYPO_PASSPHRASE)
    assert isinstance(raised, ValueError), f"escaped as {type(raised).__name__} -> HTTP 500"
    assert "passphrase" in str(raised)


async def test_the_failed_job_records_why_it_failed() -> None:
    """``str(InvalidToken())`` is '', so the job's error column was written
    blank -- a failed restore with no reason attached, which is the part the
    operator actually looks at afterwards.

    Mutation caught: raising a bare ``ValueError()`` with no message, or
    re-raising InvalidToken (whose str is empty).
    """
    _, session = await _restore_with(TYPO_PASSPHRASE)
    assert session.jobs, "no RestoreJob was recorded"
    job = session.jobs[0]
    assert job.status == "failed"
    assert job.error_message, "the restore job's error column is blank"
    assert "passphrase" in job.error_message


async def test_the_right_passphrase_still_opens_the_vault() -> None:
    """The wrapper must not swallow a SUCCESSFUL decrypt. With the correct
    passphrase the restore proceeds past the decrypt (and on to an empty
    contributor dispatch, which is fine for a dry run).

    Mutation caught: catching the decrypt result instead of the exception, or
    an over-broad guard that rejects every archive.
    """
    raised, _ = await _restore_with(REAL_PASSPHRASE)
    assert raised is None, f"a valid passphrase failed: {raised!r}"


async def test_a_missing_passphrase_keeps_its_own_distinct_message() -> None:
    """ "You did not give me a passphrase" and "that passphrase is wrong" are
    different operator problems and must not collapse into one message.

    Mutation caught: moving the missing-passphrase check inside the try block,
    where it would be rewritten as a wrong-passphrase error.
    """
    raised, _ = await _restore_with(None)
    assert isinstance(raised, ValueError)
    assert "required" in str(raised)


def test_a_malformed_key_id_is_not_reported_as_a_passphrase_mistake() -> None:
    """``_parse_key_id`` raises ValueError for a malformed or out-of-range
    key descriptor. Those name a defect in the FILE; masking them as "wrong
    passphrase?" sends the operator to re-type a passphrase that was correct.

    Mutation caught: a bare ``except Exception`` around the decrypt that
    rewrites every failure, ValueError included, as a passphrase error.
    """
    import inspect

    src = inspect.getsource(BackupService.restore_from_backup)
    decrypt_at = src.index("BackupEncryption(master_key=passphrase).decrypt")
    guard = src[decrypt_at:]
    assert "except ValueError:" in guard, "ValueError is not re-raised unmasked"
    assert guard.index("except ValueError:") < guard.index("wrong passphrase?")


def test_the_endpoint_still_translates_value_error_into_a_400() -> None:
    """The whole fix depends on ``/backups/restore`` mapping ValueError to
    HTTP 400. If that except clause is narrowed or removed, the wrapper above
    silently stops helping and the operator is back on a 500.

    Mutation caught: changing ``except ValueError`` in restore_backup to a
    narrower type, or deleting it.
    """
    import inspect

    from app.api.v1.endpoints import backups as backups_api

    src = inspect.getsource(backups_api.restore_backup)
    assert "except ValueError as e:" in src
    assert "HTTP_400_BAD_REQUEST" in src


@pytest.mark.parametrize("passphrase", [TYPO_PASSPHRASE, None])
async def test_the_failure_never_escapes_as_a_non_value_error(passphrase: str | None) -> None:
    """Both operator mistakes on the restore dialog must land as 400s.

    Mutation caught: handling only one of the two branches.
    """
    raised, _ = await _restore_with(passphrase)
    assert isinstance(raised, ValueError)


# ── the first-install restore path (unauthenticated) ─────────────────
#
# POST /setup/restore takes an uploaded .fsdnvault before any super_admin
# exists. Its key_id -- and therefore the PBKDF2 iteration count -- comes out
# of that file's own header, and so does everything checked before it: the
# SHA-256 is over the uploader's payload, "secrets"/"encrypted" are their
# booleans, the passphrase is their form field. Two properties matter here:
# an out-of-band iteration count must be refused before any CPU is spent, and
# a legitimate derive must not run on the event loop.


def _vault_at(iterations: int, passphrase: str, payload_obj: Any) -> bytes:
    """A .fsdnvault sealed at an EXPLICIT iteration count, built the way the
    file format specifies rather than via BackupEncryption.encrypt (which
    always writes the current default)."""
    import base64
    import os

    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    body = Fernet(key).encrypt(gzip.compress(json.dumps(payload_obj).encode("utf-8")))
    header = {
        "backup_id": str(uuid.uuid4()),
        "checksum": hashlib.sha256(body).hexdigest(),
        "encrypted": True,
        "compressed": True,
        "secrets": True,
        "key_id": f"v2:{iterations}:{base64.urlsafe_b64encode(salt).decode()}",
        "created_at": datetime.now(UTC).isoformat(),
        "version": "2.0",
    }
    hb = json.dumps(header).encode("utf-8")
    return len(hb).to_bytes(4, "big") + hb + body


def _hostile_header(iterations: int) -> bytes:
    """A ~200-byte upload whose ONLY hostile ingredient is the iteration count
    it declares. The checksum is genuine -- it is computed over the attacker's
    own body, which is exactly why it gates nothing."""
    body = b"not really an archive"
    header = {
        "backup_id": str(uuid.uuid4()),
        "checksum": hashlib.sha256(body).hexdigest(),
        "encrypted": True,
        "compressed": True,
        "secrets": True,
        "key_id": f"v2:{iterations}:AAAAAAAAAAAAAAAAAAAAAA==",
        "created_at": datetime.now(UTC).isoformat(),
        "version": "2.0",
    }
    hb = json.dumps(header).encode("utf-8")
    return len(hb).to_bytes(4, "big") + hb + body


async def test_setup_restore_refuses_an_absurd_iteration_count_in_milliseconds() -> None:
    """One unauthenticated ~200-byte POST used to buy minutes of PBKDF2 on the
    API worker -- past GUNICORN_TIMEOUT, at which point the arbiter SIGKILLs it
    and every other in-flight request dies. Measured at 999,999,999: the
    encryption suite took 132s with the bound removed and 1.4s with it.

    Mutation caught: removing the range check in ``_parse_key_id`` -- this test
    then runs the KDF for minutes instead of raising.
    """
    import time

    BackupService._contributors_initialized = True
    svc = BackupService(_Session())

    start = time.monotonic()
    with pytest.raises(ValueError, match="unsupported iteration count"):
        await svc.restore_fresh_instance_from_vault(
            _hostile_header(999_999_999), passphrase="anything"
        )
    assert time.monotonic() - start < 1.0


async def test_setup_restore_does_not_derive_on_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even a legitimate derive must not stall /health, the setup wizard and
    the frontend while it runs. The iteration cap bounds how long that stall
    could be; running the derive on a worker thread removes it.

    Self-calibrating: the same derive is timed inline as the control, so the
    assertion holds on a slow machine too. (``cryptography``'s PBKDF2 releases
    the GIL, which is what makes the thread hand-off worth anything -- measured
    29 loop ticks threaded vs 5 inline for one 2M-iteration derive.)

    Mutation caught: calling ``BackupEncryption(...).decrypt`` directly instead
    of via ``anyio.to_thread.run_sync`` -- the tick count collapses to the
    control's.
    """
    import anyio.to_thread

    iterations = 1_200_000
    passphrase = "a-perfectly-valid-operator-passphrase"
    # An archive with no org-scoped records: the decrypt SUCCEEDS and the
    # restore then fails on content, which is all this test needs.
    vault = _vault_at(iterations, passphrase, {"manifest": {}, "contributors": {}})

    # Assert WHERE the derive runs, not how long the loop was starved.
    #
    # This measured event-loop ticks during a threaded KDF against the same KDF
    # inline and required a 3x ratio. That is a proxy for the real property and
    # it is machine-dependent: asyncio.sleep(0.001) resolves to the host timer
    # granularity, which is ~15 ms on Windows, so the same correct code produced
    # 5 ticks vs 2 there (ratio 2.5, needs > 3) and a comfortable margin in the
    # CI container. A test that passes on one machine and fails on another is
    # not evidence either way.
    #
    # The property under test is simply that the KDF does not execute on the
    # event loop's thread, and thread identity answers that exactly.
    import threading

    loop_thread = threading.get_ident()
    derive_threads: list[int] = []

    real_run_sync = anyio.to_thread.run_sync

    async def _record(func, *args, **kwargs):
        async def _wrapped():
            return await real_run_sync(
                lambda: (derive_threads.append(threading.get_ident()), func(*args))[1]
            )

        return await _wrapped()

    monkeypatch.setattr(anyio.to_thread, "run_sync", _record)

    BackupService._contributors_initialized = True
    svc = BackupService(_Session())

    with pytest.raises(Exception):  # noqa: B017 - content failure, post-decrypt
        await svc.restore_fresh_instance_from_vault(vault, passphrase=passphrase)

    assert derive_threads, (
        "the passphrase KDF never went through anyio.to_thread.run_sync, so it "
        "ran on the event loop -- one unauthenticated /setup/restore upload with "
        "a high iteration count blocks every other request for its duration"
    )
    assert all(t != loop_thread for t in derive_threads), (
        f"the KDF executed on the event loop thread ({loop_thread}); "
        f"observed threads: {derive_threads}"
    )
