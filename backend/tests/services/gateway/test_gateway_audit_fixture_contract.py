"""Audit call-contract controls for gateway doubles, not SQL durability proof."""
from unittest.mock import MagicMock

import pytest

from app.models.security_audit import AuditLogRecord
from app.services.adapter_staging import AdapterStagingService
from tests.services.gateway import test_freepbx_apply_pipeline as inbound
from tests.services.gateway import test_freepbx_extension_apply_pipeline as extension
from tests.services.gateway import test_unifi_apply_pipeline as unifi


def pipeline(kind):
    if kind == "inbound":
        change = inbound._change()
        session = inbound._make_session()
        applier = inbound._freepbx_applier(session, change, inbound._RecAdapter())
    elif kind == "extension":
        change = extension._change()
        session = extension._make_session()
        applier = extension._ext_applier(session, change, extension._RecAdapter())
    else:
        change = unifi._forget_change()
        session = unifi._make_session(change)
        applier = unifi._RecApplier()
    session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
    return session, change, applier


@pytest.fixture(autouse=True)
def allow_owned_transport_only(monkeypatch):
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))


@pytest.mark.parametrize("kind", ["inbound", "extension", "unifi"])
@pytest.mark.parametrize("previous", [None, "a" * 64], ids=["genesis", "existing-tail"])
async def test_success_reaches_actual_audit_row_add_and_flush(kind, previous, caplog):
    session, change, applier = pipeline(kind)
    # The parameter still distinguishes genesis/existing-tail. The latter now
    # has a real signed body, rather than an arbitrary legacy hash sentinel.
    previous = session.seed_audit_tail() if previous is not None else None
    records = []
    session.add.side_effect = records.append
    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, confirmed=True, applier=applier
    )
    assert result.status == "applied"
    assert len(records) == 1 and isinstance(records[0], AuditLogRecord)
    record = records[0]
    assert record.action == f"apply:{change.feature}:{change.operation}"
    assert record.organization_id == change.organization_id
    assert record.resource_id == str(change.controller_id)
    assert record.extra_metadata["change_id"] == str(change.id)
    assert record.prev_hash == previous
    assert isinstance(record.row_hmac, str) and len(record.row_hmac) == 64
    assert set(record.row_hmac) <= set("0123456789abcdef")
    session.begin_nested.assert_called_once_with()
    session.begin_nested.return_value.__aenter__.assert_awaited_once()
    session.begin_nested.return_value.__aexit__.assert_awaited_once_with(None, None, None)
    session.flush.assert_awaited_once_with()
    assert session.commit.await_count == 2
    assert not [r for r in caplog.records if r.name == "app.services.audit" and r.levelno >= 40]


@pytest.mark.parametrize("kind", ["inbound", "extension", "unifi"])
async def test_audit_flush_failure_is_visible_and_does_not_reapply_transport(kind, caplog):
    session, change, applier = pipeline(kind)
    session.flush.side_effect = RuntimeError("owned audit fixture flush failure")
    calls = 0

    async def once(item):
        nonlocal calls
        calls += 1
        return await applier(item)

    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, confirmed=True, applier=once
    )
    assert result.status == "applied" and calls == 1
    session.add.assert_called_once()
    session.flush.assert_awaited_once_with()
    errors = [r for r in caplog.records if r.name == "app.services.audit" and r.levelno >= 40]
    assert len(errors) == 1 and "audit log write failed" in errors[0].getMessage()
    # This intentionally failed write is not a persisted audit record.
    assert session.commit.await_count == 2
