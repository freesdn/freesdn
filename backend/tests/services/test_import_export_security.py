# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression guards for cross-tenant isolation in data import/export.

Background: ``DataImportExportService._collect_export_data`` used to issue bare
``select(Model).limit(...)`` queries with NO organization predicate, so any
org_admin could export every other tenant's organizations, controllers,
devices, users, agents and VPN connections in a single API call (a P0
cross-tenant data breach). These tests pin the fix WITHOUT requiring a live
database by capturing the statements the service builds and asserting each one
is tenant-scoped (carries a WHERE clause).
"""
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.import_export import DataImportExportService


class _EmptyResult:
    def scalars(self):  # noqa: ANN001
        return self

    def all(self):  # noqa: ANN001
        return []


class _CapturingSession:
    """Minimal AsyncSession stand-in that records every executed statement."""

    def __init__(self) -> None:
        self.statements: list = []

    async def execute(self, stmt):  # noqa: ANN001
        self.statements.append(stmt)
        return _EmptyResult()


@pytest.mark.asyncio
async def test_full_export_scopes_every_query_to_the_job_organization():
    session = _CapturingSession()
    job = SimpleNamespace(
        scope="full",
        entity_types=[],
        site_ids=None,
        organization_id=uuid4(),
    )

    await DataImportExportService._collect_export_data(session, job)  # type: ignore[arg-type]

    # scope="full" exercises all entity branches: orgs, sites, controllers,
    # devices, device_ports, users, agents, vpn.
    assert len(session.statements) >= 8, "expected every entity branch to run"

    for stmt in session.statements:
        sql = str(stmt.compile()).upper()
        # The original cross-tenant leak was exactly the absence of WHERE on
        # these selects. Every export query MUST be filtered now — either by
        # organization_id directly, or via the org-scoped sites/devices
        # subquery (which itself references organization_id).
        assert "WHERE" in sql, f"unscoped (cross-tenant) export query: {sql}"
        assert ("ORGANIZATION_ID" in sql) or ("ORGANIZATIONS.ID" in sql), (
            f"export query not tied to the job organization: {sql}"
        )
