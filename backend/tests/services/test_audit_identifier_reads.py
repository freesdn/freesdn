"""Committed string identifiers survive reads without enabling CSV formulas.

The route handler is called directly with an explicit org-admin principal;
this checks its response conversion and org predicate, not HTTP authentication.
"""
from __future__ import annotations

import csv
import io
import json
import os
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.endpoints.audit import get_audit_logs
from app.models.core import Organization
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditQuery, AuditService
from app.services.security_audit import PersistentSecurityAuditService
from tests.security.audit_integrity.conftest import (
    isolated_audit_module_database as isolated_audit_module_database,
)
from tests.security.audit_integrity.conftest import (
    maintenance_engine as maintenance_engine,
)
from tests.security.audit_integrity.conftest import (
    reset_owned_audit_state_after_case as reset_owned_audit_state_after_case,
)

pytestmark = pytest.mark.usefixtures("isolated_audit_module_database")

IDENTIFIERS = [
    pytest.param("e5d659e1-8319-45c6-b4ac-c4817ca91728", id="uuid"),
    pytest.param("e5d659e1831945c6b4acc4817ca91728", id="compact-uuid"),
    pytest.param("owned-vendor/service-101", id="vendor"),
    pytest.param("=1+1", id="equals"),
    pytest.param("+1+1", id="plus"),
    pytest.param("-1+1", id="minus"),
    pytest.param("@SUM(1,1)", id="at"),
    pytest.param("\t=1+1", id="tab"),
    pytest.param("\r=1+1", id="cr"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
]



@pytest.mark.parametrize("value", IDENTIFIERS)
@pytest.mark.parametrize("field", ["resource_id", "actor_id"])
async def test_committed_identifier_query_json_csv_and_list(field, value, record_property):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_id, outside_org = uuid4(), uuid4()
    uuid_value = value in {
        "e5d659e1-8319-45c6-b4ac-c4817ca91728", "e5d659e1831945c6b4acc4817ca91728",
    }
    expected = UUID(value) if uuid_value else value
    output = str(expected) if expected is not None else None
    csv_output = output or ""
    if csv_output and csv_output[0] in "=+-@\t\r":
        csv_output = "'" + csv_output
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for oid in (org_id, outside_org):
                session.add(Organization(id=oid, name="Owned identifier read",
                                         slug="owned-identifier-read-" + oid.hex))
            await session.commit()
            for oid in (org_id, outside_org):
                await PersistentSecurityAuditService.create_audit_log(
                    session, action="owned_identifier_read", resource_type="device",
                    organization_id=oid, **{field: value},
                )
            await session.commit()

        async with AsyncSession(engine, expire_on_commit=False) as reader:
            row = (await reader.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org_id,
            ))).one()
            original = (row.timestamp, row.resource_id, row.actor_id, row.row_hmac, row.prev_hash)
            assert getattr(row, field) == value
            record_property("durable_original_identifier", json.dumps(value))
            service = AuditService(reader)
            query = AuditQuery(organization_id=org_id)
            entries, total = await service.query(query)
            assert total == len(entries) == 1
            assert entries[0].organization_id == org_id
            assert getattr(entries[0], field) == expected
            assert isinstance(getattr(entries[0], field), UUID) is uuid_value
            record_property("query_preserved_identifier", True)

            exported = json.loads(await service.export(query, format="json"))
            assert len(exported) == 1 and exported[0][field] == output
            record_property("json_preserved_identifier", True)
            cells = list(csv.DictReader(io.StringIO((await service.export(query, format="csv")).decode())))
            assert len(cells) == 1 and cells[0][field] == csv_output
            record_property("csv_cell_correct_and_formula_safe", True)

            result = await get_audit_logs(
                session=reader,
                current_user=SimpleNamespace(role="org_admin", organization_id=org_id),
                status=None, search=None, site_id=None, page=1, per_page=50,
            )
            assert result["total"] == len(result["items"]) == 1
            assert result["items"][0].model_dump(mode="json")[field] == output
            record_property("direct_list_handler_preserved_identifier_and_scope", True)
            await reader.refresh(row)
            assert original == (row.timestamp, row.resource_id, row.actor_id, row.row_hmac, row.prev_hash)
            record_property("reads_did_not_rewrite_stored_history", True)
    finally:
        async with engine.begin() as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(
                AuditLogRecord.organization_id.in_((org_id, outside_org)),
            ))
            await cleanup.execute(delete(Organization).where(Organization.id.in_((org_id, outside_org))))
        await engine.dispose()
