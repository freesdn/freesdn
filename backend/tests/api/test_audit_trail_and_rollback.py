# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two more of the same class, found by sweeping the SERVICE layer rather than
the endpoint layer -- which is where the previous sweep could not see.

1. THE AUDIT TRAIL DROPPED THE ACTOR'S EMAIL
   ``AuditService.log()`` accepts ``actor_email`` and ``session_id``,
   documents both, and ``AuditLogRecord`` has a column for each. Neither was
   ever written: the ``AuditEntry`` dataclass had no field for them, so they
   were discarded between the signature and the row.

   Six call sites pass ``actor_email`` -- login/logout, user management,
   plugin install, agent and marketplace actions. Every one lost it.
   ``actor_id`` alone is a foreign key into a table the actor can later be
   deleted from, and a deleted admin is exactly when an audit trail has to
   still say who acted.

   ``request_body`` was dropped too, but that one has no column and no
   caller, so it stops being advertised instead.

2. A FIRMWARE ROLLBACK THAT ROLLED NOTHING BACK
   ``POST /firmware/devices/{id}/rollback`` ran a full auth + org + site-grant
   check and then returned ``{"success": true, "message": "Rollback
   initiated"}`` from a stub whose own comment said "in a real implementation
   this would trigger adapter-level rollback". It ignored ``backup_id``
   entirely and echoed ``target_version`` back.

   An operator rolling a device off bad firmware was told it worked while the
   device kept running the firmware they were trying to escape. No adapter
   exposes a rollback primitive, so the honest answer is 501 -- the same way
   this codebase already reports the FreePBX trunk writes it cannot perform.
"""

from __future__ import annotations

import inspect

import pytest


def _src(obj) -> str:
    return "\n".join(
        line for line in inspect.getsource(obj).splitlines() if not line.strip().startswith("#")
    )


def _body(obj) -> str:
    """Source minus the docstring.

    The rollback fix quotes the fabricated result it replaced inside its own
    docstring, so searching the raw source finds the OLD code in the NEW
    function and fails for a reason unrelated to behaviour.
    """
    src = _src(obj)
    for quote in ('"""', "'" * 3):
        first = src.find(quote)
        if first != -1:
            end = src.find(quote, first + 3)
            if end != -1:
                return src[:first] + src[end + 3 :]
    return src


# ── 1. the audit trail ───────────────────────────────────────────


def test_the_entry_can_carry_the_actor_email_and_session():
    """The dataclass had no field, so the value had nowhere to go."""
    from app.services.audit import AuditEntry

    fields = AuditEntry.__dataclass_fields__
    assert "actor_email" in fields, "AuditEntry still cannot carry actor_email"
    assert "session_id" in fields, "AuditEntry still cannot carry session_id"


def test_log_passes_them_into_the_entry():
    from app.services.audit import AuditService

    code = _src(AuditService.log)
    assert "actor_email=actor_email" in code, "log() still drops actor_email"
    assert "session_id=" in code, "log() still drops session_id"


def test_the_row_actually_gets_them():
    """
    The half that matters. Carrying the value on the dataclass and then not
    writing it to AuditLogRecord would leave the column NULL exactly as
    before -- a fix that changes nothing observable.
    """
    from app.services.audit import AuditService

    src = inspect.getsource(AuditService)
    assert "actor_email=entry.actor_email" in src, "the column is still never written"
    assert "session_id=entry.session_id" in src


def test_the_columns_exist_to_write_into():
    """Premise. If these ever disappear, the fix above is wrong, not stale."""
    from app.models.security_audit import AuditLogRecord

    assert hasattr(AuditLogRecord, "actor_email")
    assert hasattr(AuditLogRecord, "session_id")


def test_reads_return_what_writes_stored():
    """
    The query path builds AuditEntry too. Leaving it out there would raise on
    every audit read once the dataclass gained required fields -- and would
    hide the value even after it started being stored.
    """
    from app.services.audit import AuditService

    src = inspect.getsource(AuditService)
    assert "actor_email=r.actor_email" in src, "the read path drops actor_email"
    assert "session_id=r.session_id" in src


def test_callers_really_do_supply_an_actor_email():
    """
    Premise for calling this data loss rather than dead surface: if nothing
    passed it, the honest fix would have been removal, as with request_body.
    """
    import pathlib

    app_dir = pathlib.Path(inspect.getfile(_marker_module())).parent
    hits = [
        p
        for p in app_dir.rglob("*.py")
        if "actor_email=" in p.read_text(encoding="utf-8", errors="replace")
        and p.name != "audit.py"
    ]
    assert len(hits) >= 3, f"expected several callers passing actor_email, found {hits}"


def _marker_module():
    import app

    return app


def test_request_body_is_no_longer_advertised():
    """It had no column and no caller -- the same call made for site_id."""
    from app.services.audit import AuditService

    assert "request_body" not in inspect.signature(AuditService.log).parameters


# ── 2. the firmware rollback ─────────────────────────────────────


def test_the_service_no_longer_fabricates_a_rollback():
    from app.services.firmware import PersistentFirmwareService

    code = _body(PersistentFirmwareService.rollback_device)
    assert "NotImplementedError" in code, "the stub still returns a fabricated result"
    assert '"success": True' not in code, "still claims success"
    assert "Rollback initiated" not in code


async def test_calling_it_raises_rather_than_reporting_success():
    """Behaviour, not just source: the old stub returned, it never raised."""
    from uuid import uuid4

    from app.services.firmware import PersistentFirmwareService

    with pytest.raises(NotImplementedError) as exc:
        await PersistentFirmwareService.rollback_device(None, uuid4())
    assert "not implemented" in str(exc.value).lower()


def test_the_endpoint_answers_501():
    from app.api.v1.endpoints import firmware

    code = _src(firmware.rollback_device)
    assert "status_code=501" in code, "endpoint still returns a 200 for a no-op"
    assert "not implemented" in code.lower()


def test_the_permission_checks_still_run_first():
    """
    A 501 must not become a way to skip the org / site-grant boundary. The
    checks were there before the fix and have to stay ahead of the raise, so
    an unauthorized caller still gets 404 and learns nothing.
    """
    from app.api.v1.endpoints import firmware

    code = _src(firmware.rollback_device)
    grant_at = code.index("_validate_site_grant")
    raise_at = code.index("status_code=501")
    assert grant_at < raise_at, "the 501 now short-circuits the site-grant check"
    assert "Device firmware status not found" in code[:raise_at]


# ── 3. a sync flag that could not be honoured ────────────────────


def test_gateway_sync_reports_that_full_sync_did_not_happen():
    """
    ``POST /firewall/gateways/{id}/sync`` accepts ``full_sync`` and threads it
    into the service, which ignores it -- full rule-sync into the local models
    is a Tier B feature that does not exist yet. The basic sync IS real, so a
    501 would be wrong; the caller just has to be told which half ran.
    """
    from app.modules.firewall.gateway_service import GatewayService

    code = _src(GatewayService.trigger_sync)
    assert '"full_sync_performed": False' in code, "full_sync is still silently dropped"
    assert '"full_sync_requested": full' in code, "the request flag is not echoed back"


def test_the_endpoint_still_passes_the_flag_down():
    """The response is only honest if the value it reports is the caller's."""
    from app.modules.firewall import gateway_api

    assert "full=body.full_sync" in _src(gateway_api.trigger_sync)


# ── 4. two more collected-and-discarded values ───────────────────


def test_openvpn_import_no_longer_collects_a_description_it_cannot_store():
    """
    ``_OpenVPNImportRequest.description`` was a 500-char field the operator
    could fill in on every .ovpn import. ``SiteVPNConfiguration`` has no
    description column, so it was threaded down one layer and dropped. Same
    call as site_id: stop asking for what there is nowhere to put.
    """
    from app.api.v1.endpoints.vpn import _OpenVPNImportRequest
    from app.services.brain_vpn import BrainVPNService

    assert "description" not in _OpenVPNImportRequest.model_fields
    assert "description" not in inspect.signature(BrainVPNService.import_openvpn_config).parameters


def test_the_vpn_config_model_still_has_nowhere_to_store_one():
    """Premise. A description column appearing later means implement, not remove."""
    from app.models.vpn import SiteVPNConfiguration

    assert not hasattr(SiteVPNConfiguration, "description")


def test_ids_rules_no_longer_claims_a_filter_it_never_had():
    """
    ``get_live_ids_rules`` took a ``params`` dict under the comment "Only
    allow known safe params to prevent kwarg injection" and then called the
    adapter with no arguments at all. The behaviour was safe -- nothing was
    forwarded -- but the comment described a guard that did not exist, which
    would let a reviewer assume caller input is sanitised somewhere.
    """
    from app.modules.firewall.gateway_service import GatewayService

    assert "params" not in inspect.signature(GatewayService.get_live_ids_rules).parameters
    src = inspect.getsource(GatewayService.get_live_ids_rules)
    assert "Only allow known safe params" not in src, "the misleading comment is back"


def test_ids_rules_still_forwards_nothing_to_the_adapter():
    """The safe behaviour is the part that must not change."""
    from app.modules.firewall.gateway_service import GatewayService

    assert "adapter.get_ids_rules()" in _src(GatewayService.get_live_ids_rules)
