# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A storage failure writing a phone config must be typed, logged, and loud.

``_write_config_file`` let ``mkdir``/``write_text`` raise a bare ``OSError``.
Every caller catches ``ProvisioningError`` only, so a full disk, a root-owned
volume or a read-only bind mount escaped as an unhandled exception:

  * ``POST /voip/phones/{id}/provision`` — anonymous 500, and the log carried a
    traceback that never named the provisioning directory.
  * ``GET /voip/provisioning/cfg{MAC}.xml`` (the unauthenticated handset route)
    — the same, on the path a phone hits every time it boots.

Translating it to a plain ``ProvisioningError`` would be worse, not better:
``get_config_for_mac`` answers ``ProvisioningError`` with ``None`` and the route
turns that into a 404 "No config for this device". An operator would go hunting
for a missing phone record while the real fault was the volume. Hence the
``ProvisioningStorageError`` subclass and the explicit re-raise.

Pure-unit: the DB session is mocked and the sink is a tmp_path, so no database
and no real provisioning volume are required.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

MAC = "00:0b:82:12:34:56"
CFG_NAME = "cfg000b82123456.xml"


def _service(provision_dir):
    from app.modules.voip.provisioning import ProvisioningService

    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    return ProvisioningService(db, provision_dir=provision_dir)


# ---------------------------------------------------------------------------
# The write sink
# ---------------------------------------------------------------------------


async def test_an_unwritable_provisioning_dir_raises_a_typed_error(tmp_path):
    """A FILE where the provisioning directory should be produces the same
    OSError shape as a wrong mount, and must not escape as a bare OSError."""
    from app.modules.voip.provisioning import ProvisioningStorageError

    blocker = tmp_path / "voip"
    blocker.write_text("not a directory")

    svc = _service(blocker)
    with pytest.raises(ProvisioningStorageError) as excinfo:
        await svc._write_config_file(MAC, "grandstream", "<x/>")

    assert CFG_NAME in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, OSError)


async def test_a_full_disk_is_logged_with_the_errno_and_the_path(tmp_path, caplog, monkeypatch):
    """The operator needs the path and the errno, not an anonymous 500."""
    from app.modules.voip.provisioning import ProvisioningStorageError

    svc = _service(tmp_path / "voip")

    def _enospc(self, *args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_text", _enospc)

    with caplog.at_level(logging.ERROR, logger="app.modules.voip.provisioning"):
        with pytest.raises(ProvisioningStorageError):
            await svc._write_config_file(MAC, "grandstream", "<x/>")

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "a storage failure produced no ERROR log line"
    logged = errors[0].getMessage()
    assert CFG_NAME in logged
    assert "No space left on device" in logged


async def test_a_writable_dir_still_writes_the_config(tmp_path):
    """The guard must not break the happy path."""
    svc = _service(tmp_path / "voip")
    path = await svc._write_config_file(MAC, "grandstream", "<gs_provision/>")

    assert Path(path).read_text(encoding="utf-8") == "<gs_provision/>"
    assert Path(path).name == CFG_NAME


async def test_an_oversized_config_is_still_a_plain_provisioning_error(tmp_path):
    """Only STORAGE failures get the new subclass; the size refusal is a real
    "there is no servable config" and keeps its 404."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningStorageError

    svc = _service(tmp_path / "voip")
    with pytest.raises(ProvisioningError) as excinfo:
        await svc._write_config_file(MAC, "grandstream", "x" * (128 * 1024 + 1))

    assert not isinstance(excinfo.value, ProvisioningStorageError)


# ---------------------------------------------------------------------------
# The unauthenticated handset route must not read a broken volume as "unknown"
# ---------------------------------------------------------------------------


def _phone():
    """A Phone row good enough for get_config_for_mac's on-the-fly branch."""
    return SimpleNamespace(
        id=uuid4(),
        mac_address=MAC,
        vendor="grandstream",
        deleted_at=None,
        last_seen=None,
        status="offline",
        provision_status="pending",
        config_checksum=None,
        config_template_id=None,
        provisioning_url=None,
        last_provisioned_at=None,
    )


async def _get_config(svc, phone, raiser):
    """Drive get_config_for_mac with the phone lookup satisfied."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = phone
    svc.db.execute = AsyncMock(return_value=result)
    svc.generate_phone_config = raiser
    return await svc.get_config_for_mac(MAC)


async def test_a_storage_failure_is_not_answered_as_no_config_for_this_device(tmp_path):
    """The regression this subclass exists for.

    The route maps ``None`` to a 404 "No config for this device". Returning that
    for a full disk sends the operator after a phantom missing phone record.
    """
    from app.modules.voip.provisioning import ProvisioningStorageError

    svc = _service(tmp_path / "voip")

    async def _storage_failure(*args, **kwargs):
        raise ProvisioningStorageError("could not write provisioning config to /x: ENOSPC")

    with pytest.raises(ProvisioningStorageError):
        await _get_config(svc, _phone(), _storage_failure)


async def test_a_genuine_not_found_still_answers_none(tmp_path):
    """The no-oracle 404 is preserved for the case it was written for: a phone
    we genuinely cannot render a config for."""
    from app.modules.voip.provisioning import ProvisioningError

    svc = _service(tmp_path / "voip")

    async def _not_found(*args, **kwargs):
        raise ProvisioningError("Phone not found: x")

    assert await _get_config(svc, _phone(), _not_found) is None


def test_the_storage_error_is_still_a_provisioning_error():
    """Existing ``except ProvisioningError`` handlers must keep catching it, so
    this change introduces no NEW unhandled exception class."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningStorageError

    assert issubclass(ProvisioningStorageError, ProvisioningError)
