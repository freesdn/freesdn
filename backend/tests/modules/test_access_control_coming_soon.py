# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Access Control ships as a non-enableable preview.

The module exposes a data model and CRUD surface but has no shipping
door-controller adapter yet, so it is surfaced as "coming soon": the
manifest carries the ``coming_soon`` flag and the enablement service
refuses to turn it on for an organization.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.modules.access_control.module import AccessControlModule
from app.modules.service import ModuleService


def test_access_control_manifest_is_coming_soon() -> None:
    manifest = AccessControlModule.get_manifest()
    assert manifest.coming_soon is True
    # The flag must survive serialization so the admin UI can render the
    # non-enableable "Coming soon" treatment.
    assert manifest.to_dict()["coming_soon"] is True


def test_manifest_coming_soon_defaults_false() -> None:
    from app.modules.manifest import ModuleManifest

    manifest = ModuleManifest(id="demo", name="Demo", version="1.0.0", description="x")
    assert manifest.coming_soon is False
    assert manifest.to_dict()["coming_soon"] is False


async def test_enable_module_refuses_coming_soon() -> None:
    """The enablement guard rejects preview modules before any DB access."""
    fake_module = SimpleNamespace(manifest=SimpleNamespace(coming_soon=True))
    fake_registry = SimpleNamespace(get_module=lambda _mid: fake_module)
    # db is intentionally None: the guard raises before it is touched.
    service = ModuleService(db=None, registry=fake_registry)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="preview"):
        await service.enable_module(uuid.uuid4(), "access_control")
