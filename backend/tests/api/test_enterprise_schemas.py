# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Schema-level tests for the Enterprise API surface.

These pin contracts that the FE depends on. Catching a drift here
fires far earlier than the FE typecheck would.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.enterprise import ReconcileRequest


class TestReconcileRequest:
    def test_org_scope_omits_scope_id(self) -> None:
        """``scope=organization`` must accept a missing scope_id —
        the backend ignores it for org-wide and uses the caller's
        own org. Previously the schema required scope_id, forcing
        the FE to send an all-zeros placeholder."""
        req = ReconcileRequest(scope="organization")
        assert req.scope == "organization"
        assert req.scope_id is None

    def test_site_scope_accepts_scope_id(self) -> None:
        sid = uuid4()
        req = ReconcileRequest(scope="site", scope_id=sid)
        assert req.scope_id == sid

    def test_device_scope_accepts_scope_id(self) -> None:
        did = uuid4()
        req = ReconcileRequest(scope="device", scope_id=did)
        assert req.scope_id == did

    def test_unknown_scope_rejected(self) -> None:
        """Pattern is ``device|site|organization`` — anything else 422s."""
        with pytest.raises(ValidationError):
            ReconcileRequest(scope="planet")

    def test_invalid_uuid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ReconcileRequest(scope="site", scope_id="not-a-uuid")  # type: ignore[arg-type]
