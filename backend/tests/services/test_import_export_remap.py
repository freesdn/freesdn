# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN-native import FK-remapping regression tests.

REGRESSION (correctness review — data integrity):

``_import_freesdn`` used to construct ``Controller(...)`` / ``Device(...)`` with
NO ``site_id`` (and no ``controller_id``). Both FKs are ``NOT NULL`` /
relationship-critical, so:

* controllers and devices silently failed to import (``site_id`` is NOT NULL ->
  every row raised an IntegrityError, caught and counted as ``failed``), and
* even had they inserted, they'd have been orphaned — the export emits the
  ORIGINAL ids but sites are minted fresh on insert, so old ids don't line up.

The fix builds org-scoped old->new id maps during the sites/controllers passes
and re-links children through them. Resolving FKs ONLY through those maps is
also a tenant-isolation guarantee: an exported ``site_id`` that isn't part of
this import (e.g. a raw cross-tenant UUID) is unmappable, so the child is
rejected rather than attached to an arbitrary site.

No live database: a fake session assigns ids on ``flush`` exactly as the DB
would, so the remap logic can be exercised in isolation.
"""
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.core import Controller, Site
from app.models.devices import Device
from app.services.import_export import DataImportExportService


class _FakeImportSession:
    """Async session stand-in: assigns a UUID id to added rows on flush (as a
    real DB would) and reports 'no existing row' for the conflict lookup."""

    def __init__(self) -> None:
        self._pending: list = []
        self.added: list = []

    def add(self, obj) -> None:  # noqa: ANN001
        self._pending.append(obj)
        self.added.append(obj)

    async def flush(self) -> None:
        for obj in self._pending:
            if getattr(obj, "id", None) is None:
                obj.id = uuid4()
        self._pending.clear()

    async def execute(self, stmt):  # noqa: ANN001
        # The only SELECT _import_freesdn issues is the per-site conflict lookup.
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit(self) -> None:
        pass

    async def refresh(self, obj) -> None:  # noqa: ANN001
        pass


def _added(session: _FakeImportSession, cls):  # noqa: ANN001
    return [o for o in session.added if isinstance(o, cls)]


@pytest.mark.asyncio
async def test_import_relinks_controller_and_device_to_new_site_ids() -> None:
    old_site, old_ctrl, old_dev = str(uuid4()), str(uuid4()), str(uuid4())
    data = {
        "entities": {
            "sites": [{"id": old_site, "name": "HQ"}],
            "controllers": [
                {
                    "id": old_ctrl,
                    "name": "ctrl-1",
                    "controller_type": "omada",
                    "host": "h",
                    "port": 443,
                    "site_id": old_site,
                }
            ],
            "devices": [
                {
                    "id": old_dev,
                    "name": "ap-1",
                    "device_type": "ap",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "site_id": old_site,
                    "controller_id": old_ctrl,
                }
            ],
        }
    }
    session = _FakeImportSession()
    result = await DataImportExportService._import_freesdn(  # type: ignore[arg-type]
        session, data, "skip", uuid4()
    )

    assert result["imported"] == 3
    assert result["failed"] == 0

    site = _added(session, Site)[0]
    ctrl = _added(session, Controller)[0]
    dev = _added(session, Device)[0]

    # The whole point: children point at the NEWLY-minted site id, not the old
    # exported one (which no longer exists), and the device links to the new
    # controller id.
    assert ctrl.site_id == site.id
    assert ctrl.site_id != old_site
    assert dev.site_id == site.id
    assert dev.controller_id == ctrl.id


@pytest.mark.asyncio
async def test_device_with_unmappable_site_is_rejected_not_orphaned() -> None:
    """Tenant-isolation + fail-closed: a device whose site_id isn't part of this
    import (could be a raw cross-tenant UUID) must be REFUSED — never attached
    to an arbitrary site, never created org-less."""
    data = {
        "entities": {
            "sites": [],  # the referenced site is NOT imported
            "devices": [
                {
                    "id": str(uuid4()),
                    "name": "orphan",
                    "device_type": "ap",
                    "site_id": str(uuid4()),  # unmappable
                }
            ],
        }
    }
    session = _FakeImportSession()
    result = await DataImportExportService._import_freesdn(  # type: ignore[arg-type]
        session, data, "skip", uuid4()
    )

    assert result["imported"] == 0
    assert result["failed"] == 1
    assert _added(session, Device) == []  # nothing inserted
