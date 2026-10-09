"""Real committed gateway audit/savepoint checks with owned adapter boundaries.

No hardware, external gateway or HTTP authentication is exercised. PostgreSQL
sessions and the staging/audit/vendor dispatch services are real. Only adapter
acquisition returns a synthetic, recording transport in a loopback-only runner.
"""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.base import AdapterResult
from app.models.core import Controller, Organization, Site
from app.models.security_audit import AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.modules.voip.models import PBX
from app.services.adapter_freepbx_extensions import FreePBXExtensionsService
from app.services.adapter_freepbx_inbound_routes import FreePBXInboundRoutesService
from app.services.adapter_staging import AdapterStagingService
from app.services.adapter_unifi_clients import GatewayUniFiClientsService
from app.services.audit import AuditService
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


@pytest.mark.parametrize("kind", ["inbound", "extension", "unifi"])
@pytest.mark.parametrize("mode", ["genesis", "existing_tail", "sql_rejection"])
async def test_committed_gateway_apply_audit_and_savepoint(
    kind, mode, monkeypatch, caplog, record_property,
):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    org_id, site_id, controller_id, change_id = [uuid4() for _ in range(4)]
    constraint = "owned_audit_rejection_" + uuid4().hex
    constraint_installed = False
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
    calls = []
    observed_claims = []
    connections = []
    expected_previous = None
    feature, operation, target, payload = {
        "inbound": ("pbx.inbound_route.create", "create", None,
                    {"extension": "15551234", "destination": "app-blackhole,hangup,1"}),
        "extension": ("pbx.extension.update", "update", "1001",
                      {"name": "Owned Front Desk", "ring_timer": 25}),
        "unifi": ("unifi.clients.forget", "delete", "02:00:00:00:00:01", {"site": "default"}),
    }[kind]
    try:
        async with AsyncSession(engine, expire_on_commit=False) as seed:
            assert await seed.scalar(select(func.count()).select_from(AuditLogRecord)) == 0
            seed.add(Organization(id=org_id, name="Owned audit", slug="owned-audit-" + org_id.hex))
            await seed.flush()
            seed.add(Site(id=site_id, organization_id=org_id, name="Owned site", slug="owned-site"))
            await seed.flush()
            seed.add(Controller(id=controller_id, site_id=site_id, name="Owned controller",
                                controller_type="unifi" if kind == "unifi" else "freepbx",
                                host="192.0.2.20", port=443))
            if kind != "unifi":
                seed.add(PBX(id=controller_id, site_id=site_id, name="Owned PBX",
                             pbx_type="freepbx", ip_address="192.0.2.20", api_port=443))
            await seed.flush()
            seed.add(AdapterPendingChange(id=change_id, organization_id=org_id,
                                          controller_id=controller_id, site_id=site_id,
                                          feature=feature, operation=operation,
                                          target_id=target, payload=payload, status="pending"))
            await seed.commit()
            if mode == "existing_tail":
                await AuditService(seed).log(action="owned_prior", resource_type="controller",
                                             resource_id=controller_id, organization_id=org_id,
                                             site_id=site_id)
                await seed.commit()
                previous = (await seed.execute(select(AuditLogRecord))).scalar_one()
                assert previous.row_hmac and len(previous.row_hmac) == 64
                expected_previous = previous.row_hmac
        if mode == "sql_rejection":
            # Actual PostgreSQL23514 inside the audit SAVEPOINT, scoped to this
            # owned organization's apply row. No app method/flush is mocked.
            async with engine.begin() as setup:
                await setup.execute(text(
                    f"ALTER TABLE audit.audit_logs ADD CONSTRAINT {constraint} "
                    f"CHECK (organization_id IS DISTINCT FROM '{org_id}'::uuid "
                    "OR action NOT LIKE 'apply:%')"
                ))
            constraint_installed = True
        async with AsyncSession(engine, expire_on_commit=False) as actor:
            async def acknowledged(method, args, force):
                assert force is True
                actor_pid = await actor.scalar(text("SELECT pg_backend_pid()"))
                async with engine.connect() as independent:
                    observer_pid = await independent.scalar(text("SELECT pg_backend_pid()"))
                    durable = await independent.scalar(
                        select(AdapterPendingChange.status).where(AdapterPendingChange.id == change_id)
                    )
                assert actor_pid != observer_pid
                connections.append((actor_pid, observer_pid))
                observed_claims.append(durable)
                assert durable == "applying"
                calls.append((method, args, force))
                return AdapterResult.ok(data={"owned_acknowledgement": True})

            class OwnedTransport:
                async def create_did(self, data, *, force=False):
                    return await acknowledged("create_did", [data], force)

                async def update_extension(self, number, data, *, force=False):
                    return await acknowledged("update_extension", [number, data], force)

                async def forget_client(self, site, mac, *, force=False):
                    return await acknowledged("forget_client", [site, mac], force)

            transport = OwnedTransport()
            service_type = {"inbound": FreePBXInboundRoutesService,
                            "extension": FreePBXExtensionsService,
                            "unifi": GatewayUniFiClientsService}[kind]
            service = service_type(actor)

            async def owned_client(controller):
                assert controller.id == controller_id and controller.site_id == site_id
                return transport

            monkeypatch.setattr(service, "_get_adapter" if kind == "unifi" else "_get_client", owned_client)
            pending = await actor.get(AdapterPendingChange, change_id)
            applier = service.build_applier(pending)
            result = await AdapterStagingService(actor).apply_change(
                change_id, force=True, confirmed=True, applier=applier,
            )
            assert result.status == "applied" and observed_claims == ["applying"] and len(calls) == 1
            assert "confirmed" not in payload
            with pytest.raises(HTTPException) as refused:
                await AdapterStagingService(actor).apply_change(
                    change_id, force=True, confirmed=True, applier=applier,
                )
            assert refused.value.status_code == 409 and len(calls) == 1
            await actor.rollback()
        async with AsyncSession(engine, expire_on_commit=False) as independent:
            persisted = await independent.get(AdapterPendingChange, change_id)
            assert persisted.status == "applied" and persisted.applied_at is not None
            assert persisted.failure_reason is None and persisted.payload == payload
            records = list((await independent.scalars(select(AuditLogRecord).where(
                AuditLogRecord.organization_id == org_id,
                AuditLogRecord.action == f"apply:{feature}:{operation}",
            ))).all())
            errors = [r for r in caplog.records if r.name == "app.services.audit" and r.levelno >= 40]
            if mode == "sql_rejection":
                assert records == []
                assert len(errors) == 1 and "audit log write failed" in errors[0].getMessage()
                assert errors[0].exc_info is not None
                failure = errors[0].exc_info[1]
                assert isinstance(failure, IntegrityError) and failure.orig.sqlstate == "23514"
                assert await independent.scalar(text("SELECT 1")) == 1
            else:
                assert not errors and len(records) == 1
                record = records[0]
                assert record.prev_hash == expected_previous and record.row_hmac
                assert record.resource_id == str(controller_id) and record.site_id == site_id
                assert record.extra_metadata["change_id"] == str(change_id)
                assert record.new_state["payload_keys"] == "[REDACTED]"
                assert record.tags == ["staging", "apply"]
                check = await AuditService(independent).validate_audit_chain()
                assert check["valid"] and check["unchained"] == 0
                assert check["checked"] == (2 if mode == "existing_tail" else 1)
                record.resource_name = "owned tamper detection control"
                await independent.flush()
                changed = await AuditService(independent).validate_audit_chain()
                assert changed["valid"] is False and changed["broken_at"] == str(record.id)
                await independent.rollback()
        if mode != "sql_rejection":
            async with AsyncSession(engine) as reader:
                assert (await AuditService(reader).validate_audit_chain())["valid"] is True
        record_property("durable_claim_before_owned_transport", True)
        record_property("independent_PG_connection_pairs", json.dumps(connections))
        record_property("one_transport_call_and_reapply_refused", True)
        record_property("committed_audit_or_real_SQL23514_savepoint", mode)
    finally:
        if constraint_installed:
            async with engine.begin() as cleanup:
                await cleanup.execute(text(f"ALTER TABLE audit.audit_logs DROP CONSTRAINT {constraint}"))
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.organization_id == org_id))
            await cleanup.execute(delete(AdapterPendingChange).where(AdapterPendingChange.id == change_id))
            await cleanup.execute(delete(PBX).where(PBX.id == controller_id))
            await cleanup.execute(delete(Controller).where(Controller.id == controller_id))
            await cleanup.execute(delete(Site).where(Site.id == site_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup.commit()
        await engine.dispose()
