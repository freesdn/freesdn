# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The pre-restore "undo" slot must not promise more than it captures.

``capture_rollback_slot`` calls ``BackupService.create_backup`` with no
``include_secrets=`` and no ``passphrase=``, so the slot is a CONFIG snapshot
(``.fsdn``) sealed with the instance ``SECRET_KEY``. Three claims around that
call said otherwise:

  * the module docstring said the capture ran in a REPEATABLE READ transaction.
    Nothing in ``app/`` sets an isolation level -- the claim only ever existed
    in that docstring.
  * the comment on the include_* flags said "Capture everything ... a complete
    representation of the pre-restore state". Credential secrets, user password
    hashes and MFA secrets are not in it.
  * "Same encryption posture as user backups" -- a user can choose a
    passphrase-sealed ``.fsdnvault``; the slot cannot be one, because there is
    no operator to prompt on an already-authorised restore.

Why this matters and is not merely untidy: an operator reaching for "undo"
after a bad restore reads that description in the catalog and decides whether
they still have a problem. The slot returns CONFIGURATION to its pre-restore
shape; it leaves the credential vault and logins as the restore left them, and
it cannot remove rows the restore CREATED (``_restore_data`` only INSERTs and
UPDATEs).

It is safe rather than destructive only because ``_BLOCKED_FIELDS`` derives the
credential secret columns from ``CREDENTIAL_SECRET_FIELDS``, so restoring the
config-only slot cannot write its ``None`` placeholders over live ciphertext.
That guard is pinned by ``test_backup_credential_vault.py``; this file pins the
honesty of what the slot claims.

Pure-unit: ``BackupService.create_backup`` is replaced by a recorder, so no
database, no storage and no encryption keys are required.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.backup_contributors import rollback as rollback_mod


class _Session:
    """Just enough session for capture_rollback_slot."""

    def __init__(self, source_name: str | None = "Nightly config") -> None:
        self._source = SimpleNamespace(id=uuid4(), name=source_name)
        self.flushed = 0

    async def get(self, _model, _pk):
        return self._source

    async def flush(self) -> None:
        self.flushed += 1


async def _capture(monkeypatch, **overrides):
    """Run capture_rollback_slot and return (recorded kwargs, slot)."""
    recorded: dict = {}

    class _Recorder:
        def __init__(self, session):
            self.session = session

        async def create_backup(self, **kwargs):
            recorded.update(kwargs)
            # Mirror what create_backup would persist for these two flags, so
            # the assertions below read the ROW the operator sees, not just the
            # call.
            return SimpleNamespace(
                id=uuid4(),
                name=kwargs["name"],
                description=kwargs["description"],
                include_secrets=kwargs.get("include_secrets", False),
                is_encrypted=kwargs.get("is_encrypted", False),
                rollback_for_restore_job_id=None,
            )

    import app.services.backup as backup_mod

    monkeypatch.setattr(backup_mod, "BackupService", _Recorder)

    session = _Session(**overrides)
    job = SimpleNamespace(id=uuid4(), backup_id=uuid4())
    slot = await rollback_mod.capture_rollback_slot(
        session,
        organization_id=uuid4(),
        restore_job=job,
        created_by_id=uuid4(),
    )
    return recorded, slot


# ---------------------------------------------------------------------------
# What the slot actually is
# ---------------------------------------------------------------------------


async def test_the_slot_is_a_config_snapshot_and_says_so_explicitly(monkeypatch):
    """``include_secrets`` is passed, not left to the default.

    Leaving it defaulted is how the "Capture everything" comment survived three
    audits sitting directly above a call that captured no secrets.
    """
    recorded, slot = await _capture(monkeypatch)

    assert "include_secrets" in recorded, (
        "include_secrets is defaulted rather than stated; the reader has to "
        "open create_backup to learn what the undo slot contains"
    )
    assert recorded["include_secrets"] is False
    assert slot.include_secrets is False


async def test_the_operator_visible_description_names_the_limitation(monkeypatch):
    """``description`` is on BackupResponse and is what the catalog renders.

    A limitation that lives only in a docstring is invisible at the moment the
    operator clicks "undo".
    """
    _recorded, slot = await _capture(monkeypatch)

    text = slot.description.lower()
    assert "credential" in text
    assert "not in this snapshot" in text or "are not" in text
    assert "password hash" in text
    # It must also say the undo cannot delete what the restore created.
    assert "created" in text


async def test_the_name_still_fits_the_column(monkeypatch):
    """Backup.name is String(128). A status/name string too long for its column
    is a failure mode this repo has shipped before."""
    from app.modules.backup.models import Backup

    long_source = "x" * 400
    recorded, _slot = await _capture(monkeypatch, source_name=long_source)

    limit = Backup.__table__.c.name.type.length
    assert len(recorded["name"]) <= limit, f"name is {len(recorded['name'])} > {limit}"


async def test_the_slot_is_still_linked_to_the_restore_job_it_precedes(monkeypatch):
    """The behaviour the UI depends on must survive the honesty edit."""
    recorded, slot = await _capture(monkeypatch)

    assert recorded["backup_type"] == rollback_mod.ROLLBACK_BACKUP_TYPE
    assert slot.rollback_for_restore_job_id is not None
    assert recorded["is_encrypted"] is True


# ---------------------------------------------------------------------------
# The three false claims
# ---------------------------------------------------------------------------


def test_no_docstring_claims_a_repeatable_read_snapshot():
    """Nothing in app/ sets a transaction isolation level."""
    doc = rollback_mod.__doc__ or ""
    src = inspect.getsource(rollback_mod.capture_rollback_slot)
    combined = f"{doc}\n{src}"

    # Collapse wrapping first: the disclaimer legitimately lands on the next
    # source line, and a per-line scan would read that as a bare claim.
    flat = " ".join(combined.lower().split())
    at = flat.find("repeatable read")
    while at != -1:
        window = flat[at : at + 200]
        assert "never did" in window, f"REPEATABLE READ is claimed here: ...{window}..."
        at = flat.find("repeatable read", at + 1)


def test_the_tree_really_has_no_isolation_level_to_back_that_claim():
    """The premise. If someone later implements it, this fails and the
    docstring can honestly say so again."""
    app_dir = Path(rollback_mod.__file__).resolve().parents[2]
    hits = [
        f"{path.relative_to(app_dir)}:{n}"
        for path in app_dir.rglob("*.py")
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "isolation_level" in line
    ]
    assert not hits, f"an isolation level exists after all: {hits}"


def test_no_comment_claims_the_slot_captures_everything():
    src = inspect.getsource(rollback_mod.capture_rollback_slot)
    assert "Capture everything" not in src
    assert "Same encryption posture as user backups" not in src


def test_the_restore_path_still_only_inserts_and_updates():
    """Backs the "cannot undo what the restore created" sentence in the
    description. If restore ever learns to delete, this fails and the copy has
    to be revisited."""
    from app.services.backup import BackupService

    src = inspect.getsource(BackupService._restore_data)
    assert "self.db.delete" not in src
    assert "delete(" not in src


@pytest.mark.parametrize(
    "phrase",
    ["config snapshot", "include_secrets=False"],
)
def test_the_function_docstring_leads_with_what_undo_means(phrase: str):
    doc = rollback_mod.capture_rollback_slot.__doc__ or ""
    assert phrase.lower() in doc.lower()
