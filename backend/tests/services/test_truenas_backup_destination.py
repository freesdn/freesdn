# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN could not back up to the NAS it monitors.

The Storage page shows an operator their TrueNAS in detail -- pool capacity and
redundancy, scrub state, per-disk SMART temperature and error counts, active
alerts, snapshot and replication coverage. Then the backup page offered them
``local, s3, sftp, ftp, google_drive, dropbox, webdav``: seven destinations, and
not one of them the appliance in the same rack that FreeSDN already holds
working credentials for.

The adapter was close to able. ``filesystem.put`` was implemented, path
validated and force-gated, for the Fabric ``storage.store_blob`` operation --
26 read methods against that single write. What was missing was everything on
the other side of a write: reading a backup back, checking one is there, sizing
it, deleting it when retention expires. An appliance you can only write to is
the one thing a backup target must never be.

Two design decisions are load-bearing here and both are tested below.

**It names a controller, not a host.** Every other remote backend takes an
address and its own credentials. Re-entering the NAS's address and API key
would duplicate a secret that FreeSDN already stores and rotate-tracks. It also
avoids a real conflict: ``_ssrf_validate_storage_cfg`` pins ftp/sftp hosts with
``allow_private=False`` because an operator-supplied hostname is an SSRF
vector -- and a NAS lives on a private LAN, so that rule would refuse every
legitimate appliance.

**The data plane does not carry the staging force-gate, deliberately.**
``upload_file`` refuses unless ``force=True``, which arrives from exactly one
place: the staged-apply path after the dual gate. That gate exists to stop
unreviewed changes to device CONFIGURATION. Writing a backup file into a
dataset an operator explicitly nominated is not configuration, and routing it
through staging would mean every scheduled backup waited for a human. The data
plane is therefore separate -- and separate is what keeps the invariant
provable, which the last test in this file asserts.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.adapters.exceptions import AdapterError
from app.services.backup import (
    SUPPORTED_STORAGE_TYPES,
    BackupStorageBackend,
    TrueNASStorageBackend,
    get_storage_backend,
)

ORG = uuid4()
OTHER_ORG = uuid4()
CONTROLLER = uuid4()
DATASET = "/mnt/tank/freesdn-backups"


def _config(**over):
    cfg = {
        "controller_id": str(CONTROLLER),
        "dataset_path": DATASET,
        "_organization_id": str(ORG),
    }
    cfg.update(over)
    return cfg


# ── it is offered at all ────────────────────────────────────────


def test_truenas_is_an_offered_destination():
    """
    The gap in one assertion: the platform monitors these appliances and did
    not let you write a backup to one.
    """
    ids = [t["id"] for t in SUPPORTED_STORAGE_TYPES]

    assert "truenas" in ids


def test_the_form_asks_for_a_controller_not_a_hostname():
    """
    An address field here would mean a second copy of a credential FreeSDN
    already holds, and would run into the ftp/sftp SSRF rule that refuses
    private addresses -- which is every real NAS.
    """
    spec = next(t for t in SUPPORTED_STORAGE_TYPES if t["id"] == "truenas")
    fields = {f["name"]: f for f in spec["fields"]}

    assert "controller_id" in fields
    assert fields["controller_id"]["controller_type"] == "truenas"
    assert "dataset_path" in fields
    assert not any(f in fields for f in ("host", "url", "password", "api_key")), (
        "the form is asking for credentials the platform already has"
    )


def test_the_factory_builds_it():
    backend = get_storage_backend("truenas", _config())

    assert isinstance(backend, TrueNASStorageBackend)
    assert isinstance(backend, BackupStorageBackend)


def test_it_implements_the_whole_backend_contract():
    """
    Every method is present and concrete, including delete -- which works via
    ``pool.dataset.delete`` rather than a file unlink the middleware lacks.
    """
    for method in ("save", "load", "delete", "exists", "get_size"):
        assert callable(getattr(TrueNASStorageBackend, method, None)), f"missing {method}"

    assert not getattr(TrueNASStorageBackend, "__abstractmethods__", set())


def test_the_backend_can_delete():
    """
    Delete works -- via ``pool.dataset.delete``, not a file unlink.

    The middleware has no file-delete on any version (found live on
    26.0.0-BETA.3: unlink/remove/rmdir/move/rename all absent). So each backup
    is its own child dataset, and pruning a backup destroys that dataset. The
    full save/load/verify/delete cycle plus dataset reclamation was validated
    against a real appliance.

    The SUPPORTS_DELETE=False infrastructure remains in the ABC and the
    retention path for any FUTURE delete-incapable backend, but TrueNAS is not
    one any more.
    """
    from app.services.backup import LocalStorageBackend, S3StorageBackend

    assert TrueNASStorageBackend.SUPPORTS_DELETE is True
    assert LocalStorageBackend.SUPPORTS_DELETE is True
    assert S3StorageBackend.SUPPORTS_DELETE is True


def test_delete_never_names_a_dataset_outside_the_configured_base():
    """
    The single most dangerous string in the storage code: delete feeds a
    RECURSIVE ``pool.dataset.delete``, and naming a pool root would destroy
    everything. The child name is rebuilt from the validated base plus one
    sanitised id token, so it can only ever be a direct child of the
    operator-nominated dataset.
    """
    from app.adapters.truenas.adapter import TrueNASAdapter

    child = TrueNASAdapter._backup_child_name("/mnt/s4_hdd/freesdn_test", "abc-123")
    assert child == "s4_hdd/freesdn_test/abc-123"

    # a base that is a pool ROOT (no "/") must be refused -- a recursive delete
    # there would take the whole pool
    with pytest.raises(AdapterError):
        TrueNASAdapter._backup_child_name("/mnt/s4_hdd", "abc-123")

    # traversal in the id cannot escape the base
    escaped = TrueNASAdapter._backup_child_name("/mnt/s4_hdd/freesdn_test", "../../evil")
    assert escaped.startswith("s4_hdd/freesdn_test/")
    assert ".." not in escaped


@pytest.mark.parametrize("base", ["/mnt/tank/../etc", "/mnt/tank/../../pool", "tank/../root"])
def test_a_base_with_traversal_is_refused(base):
    """
    A ``..`` in the base could climb out of the nominated dataset toward the
    pool root before the recursive delete runs. Refused outright.
    """
    from app.adapters.truenas.adapter import TrueNASAdapter

    with pytest.raises(AdapterError):
        TrueNASAdapter._backup_child_name(base, "abc-123")


@pytest.mark.parametrize("bad_id", ["", "   ", "...", "/", "@@@"])
def test_an_id_yielding_no_safe_token_is_refused(bad_id):
    """
    If the sanitised id is empty, the child name collapses to the base itself,
    and a recursive delete would then take the whole nominated dataset. That is
    not "delete this backup", it is "delete every backup", so it is refused.
    """
    from app.adapters.truenas.adapter import TrueNASAdapter

    with pytest.raises(AdapterError):
        TrueNASAdapter._backup_child_name("/mnt/s4_hdd/freesdn_test", bad_id)


def test_the_offered_type_advertises_working_retention():
    """
    Retention prunes by destroying the per-backup dataset, so the form no
    longer warns that pruning is the operator's problem.
    """
    spec = next(t for t in SUPPORTED_STORAGE_TYPES if t["id"] == "truenas")

    assert spec.get("supports_delete") is True
    assert "dataset" in spec["description"].lower()


class _RecordingDB:
    """A DB session that records whether the backup row was deleted."""

    def __init__(self, backup):
        self._backup = backup
        self.deleted = False
        self.committed = False

    async def get(self, _model, _pk):
        return self._backup

    async def delete(self, _obj):
        self.deleted = True

    async def commit(self):
        self.committed = True


class _NoDeleteBackend:
    SUPPORTS_DELETE = False

    async def delete(self, _path):  # pragma: no cover - must never be reached
        raise AssertionError("delete() called on a SUPPORTS_DELETE=False backend")


async def test_a_delete_incapable_backend_does_not_orphan_its_file(monkeypatch):
    """
    The call site that matters, driven rather than grepped.

    ``delete_backup`` used to catch every delete error, log it, and remove the
    DB record anyway -- so on a delete-incapable backend the file was orphaned
    on the appliance with nothing pointing at it. A source-order assertion could
    not tell that apart from a version that swallows the exception and deletes
    the record; a mutation doing exactly that survived one.

    So: call it, and assert the record SURVIVES and a 409 is raised.
    """
    from fastapi import HTTPException

    from app.services.backup import BackupService

    backup = SimpleNamespace(
        id=uuid4(),
        storage_path="2026/08/24/bkp_config.fsdn",
        # Not TrueNAS any more -- it can delete. This guards the GENERIC
        # infrastructure for any future backend that cannot, using a fake.
        storage_type="somefutureappliance",
        storage_location_id=uuid4(),
    )
    db = _RecordingDB(backup)
    svc = BackupService.__new__(BackupService)
    svc.db = db
    svc.org_id = None

    async def _resolve(_type, _loc):
        return _NoDeleteBackend(), None

    monkeypatch.setattr(svc, "_resolve_storage", _resolve)

    with pytest.raises(HTTPException) as exc:
        await svc.delete_backup(backup.id)

    assert exc.value.status_code == 409
    assert not db.deleted, "the record was removed, orphaning the file on the appliance"
    assert not db.committed


async def test_deleting_a_normal_backup_still_removes_the_record(monkeypatch):
    """
    Guards the fix from breaking every OTHER backend: a delete-capable
    destination must still prune and remove the record.
    """
    from app.services.backup import BackupService

    class _DeletingBackend:
        SUPPORTS_DELETE = True
        deleted_path = None

        async def delete(self, path):
            self.deleted_path = path
            return True

    backup = SimpleNamespace(
        id=uuid4(),
        storage_path="2026/08/24/bkp_config.fsdn",
        storage_type="s3",
        storage_location_id=uuid4(),
    )
    db = _RecordingDB(backup)
    svc = BackupService.__new__(BackupService)
    svc.db = db
    svc.org_id = None
    backend = _DeletingBackend()

    async def _resolve(_type, _loc):
        return backend, None

    monkeypatch.setattr(svc, "_resolve_storage", _resolve)

    result = await svc.delete_backup(backup.id)

    assert result is True
    assert backend.deleted_path == backup.storage_path
    assert db.deleted and db.committed


# ── configuration is refused rather than half-accepted ──────────


@pytest.mark.parametrize(
    "config,reason",
    [
        ({"dataset_path": DATASET}, "no controller named"),
        ({"controller_id": "not-a-uuid", "dataset_path": DATASET}, "controller id unparseable"),
        ({"controller_id": str(CONTROLLER)}, "no dataset named"),
        ({"controller_id": str(CONTROLLER), "dataset_path": "   "}, "blank dataset"),
    ],
)
def test_an_incomplete_configuration_is_refused_at_creation(config, reason):
    """
    At configuration time, not at 3am when the first scheduled backup runs.
    """
    with pytest.raises(ValueError):
        get_storage_backend("truenas", config)


# ── the cross-tenant question ───────────────────────────────────


class _FakeSession:
    """Answers via execute(), matching the soft-delete-filtered lookup.

    It used to implement ``get()``. That is exactly what the real code stopped
    doing -- ``db.get`` ignores soft deletes -- so a double that still offered
    it would keep testing an implementation the product no longer has.
    """

    def __init__(self, controller):
        self._controller = controller

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, _stmt):
        controller = self._controller

        class _Result:
            def scalar_one_or_none(self):
                return controller

        return _Result()


def _patch_lookup(monkeypatch, controller):
    import app.db.session as session_mod

    monkeypatch.setattr(
        session_mod, "AsyncSessionLocal", lambda: _FakeSession(controller), raising=False
    )


async def test_a_controller_from_another_org_is_refused(monkeypatch):
    """
    ``controller_id`` is caller-supplied, exactly as ``storage_location_id``
    was when V3 found that org A could write into org B's storage and
    exercise org B's decrypted credentials -- re-fired by the Celery scheduler
    on every run.

    This is the same shape one level down: without the check, org A points a
    backup at org B's appliance and writes through org B's stored API key.
    """
    foreign = SimpleNamespace(id=CONTROLLER, organization_id=OTHER_ORG)
    _patch_lookup(monkeypatch, foreign)

    backend = get_storage_backend("truenas", _config())

    with pytest.raises(ValueError) as exc:
        await backend._adapter()

    assert "not found" in str(exc.value), (
        "the error distinguishes 'wrong org' from 'no such controller', which "
        "confirms another tenant's controller id exists"
    )


async def test_a_missing_controller_is_refused(monkeypatch):
    _patch_lookup(monkeypatch, None)
    backend = get_storage_backend("truenas", _config())

    with pytest.raises(ValueError):
        await backend._adapter()


def test_the_resolver_threads_the_org_into_the_config():
    """
    The backend can only enforce the org check if it is told the org. This is
    the wiring: ``_resolve_storage`` has already proved the StorageLocation
    belongs to the caller, and passes that down.
    """
    import inspect

    from app.services.backup import BackupService

    src = inspect.getsource(BackupService._resolve_storage)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    assert 'config["_organization_id"] = str(loc.organization_id)' in body


def test_an_unscoped_backend_still_refuses_nothing_silently():
    """
    ``_organization_id`` absent means the caller did not scope the lookup. That
    happens on the default-local path, which never builds this backend -- but
    if it ever did, the field being None must not read as "any org is fine"
    without someone having decided that.
    """
    backend = get_storage_backend("truenas", {"controller_id": str(CONTROLLER), "dataset_path": DATASET})

    assert backend._organization_id is None


# ── the staging invariant ───────────────────────────────────────


def test_the_data_plane_does_not_use_the_staging_force_gate():
    """
    The decision, asserted so it cannot drift into a bypass.

    ``upload_file`` is the Fabric/staged path and refuses without
    ``force=True``. The data-plane methods are a separate door, taken only
    after an operator has explicitly nominated this appliance and dataset as a
    backup destination -- the same act of authorisation as configuring an S3
    bucket, which nobody routes through device staging either.

    What must stay true is that the CONFIG path's gate is not weakened, so
    ``force=True`` must not appear in the data-plane methods.
    """
    import inspect

    from app.adapters.truenas.adapter import TrueNASAdapter

    for name in ("put_data_file", "get_data_file", "delete_data_file", "stat_data_file"):
        src = inspect.getsource(getattr(TrueNASAdapter, name))
        assert "force" not in src, f"{name} reaches for the staging gate"


def test_the_config_path_still_refuses_without_the_gate():
    """
    The other half: adding a data plane must not have loosened
    ``upload_file``. If this ever passes without the refusal, the dual gate has
    been quietly removed from the Fabric write path.
    """
    import inspect

    from app.adapters.truenas.adapter import TrueNASAdapter

    src = inspect.getsource(TrueNASAdapter.upload_file)

    assert "if not force:" in src
    assert "staging force-gate not set" in src


def test_the_data_plane_refuses_a_legacy_rest_appliance():
    """
    A REST-only box (<=24.10 / CORE 13.x) can still be monitored, but cannot be
    a destination -- ``filesystem.get``/``stat``/``unlink`` are middleware calls
    the retired REST v2.0 surface did not expose. The operator has to learn
    that when configuring, not when restoring.
    """
    import inspect

    from app.adapters.truenas.adapter import TrueNASAdapter

    src = inspect.getsource(TrueNASAdapter._require_ws)

    assert 'self._transport != "ws"' in src
    assert "25.04" in src


# ── path handling ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename",
    ["../../etc/shadow", "a/../../../etc/passwd", "x/./../../y", "../escape"],
)
def test_a_traversing_key_is_refused(filename):
    """
    Backup keys are generated from an id and a date prefix, so they contain
    slashes by design -- which means the leaf-only validation the staged upload
    uses is not enough here, and each segment has to be checked.
    """
    from app.adapters.exceptions import AdapterError
    from app.adapters.truenas.adapter import TrueNASAdapter

    with pytest.raises((AdapterError, ValueError)):
        TrueNASAdapter._safe_join(DATASET, filename)


def test_a_normal_dated_key_is_accepted():
    from app.adapters.truenas.adapter import TrueNASAdapter

    joined = TrueNASAdapter._safe_join(DATASET, "2026/08/23/abc123_config.fsdn")

    assert joined == f"{DATASET}/2026/08/23/abc123_config.fsdn"


def test_the_key_encodes_the_backup_id_so_delete_can_find_the_dataset():
    """
    Each backup is its own child dataset, so the storage key is
    ``<safe-id>/<filename>`` -- the id half is what delete uses to name the
    dataset to destroy. It round-trips through ``_split_key``.
    """
    backend = get_storage_backend("truenas", _config())

    backup_id, filename = backend._split_key("abc123/config.fsdn")
    assert backup_id == "abc123"
    assert filename == "config.fsdn"

    # the id is sanitised into a single safe dataset segment
    assert backend._child_mount("abc123").endswith("/abc123")
    assert "/" not in backend._child_mount("abc123").rsplit("/", 1)[1]


def test_truenas_is_exempt_from_the_hostname_ssrf_check_on_purpose():
    """
    Not an oversight. The type accepts no address, so there is nothing for the
    check to validate -- and the ftp/sftp rule it would otherwise inherit
    (allow_private=False) refuses every appliance on a private LAN.
    """
    from app.services.backup import _ssrf_validate_storage_cfg

    _ssrf_validate_storage_cfg("truenas", _config())

    import inspect

    src = inspect.getsource(_ssrf_validate_storage_cfg)
    assert 'elif st == "truenas":' in src, "the exemption is implicit; make it explicit"


async def test_a_removed_appliance_is_no_longer_a_destination(monkeypatch):
    """
    An operator deleting a controller expects it gone. Without a soft-delete
    filter the lookup still found it, so backups kept writing to an appliance
    that had disappeared from the UI -- or failed nightly citing a controller
    nobody could find.

    Caught by the repo's soft-delete guard, which is the ratchet for exactly
    this class.
    """
    import inspect

    from app.services.backup import TrueNASStorageBackend

    src = inspect.getsource(TrueNASStorageBackend._adapter)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    assert "Controller.deleted_at.is_(None)" in body, "a deleted appliance still resolves"
    assert "db.get(Controller" not in body, "db.get ignores soft deletes"
