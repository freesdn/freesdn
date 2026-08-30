# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression: a stranded apply must not be reported as a definite failure.

``apply_change`` commits ``status="applying"`` BEFORE invoking the remote
applier. If the worker is killed, loses its database connection, or is
terminated between the device write and the terminal commit, the row is left in
``applying``. ``_recover_stale_applying`` used to flip every such row to
``failed`` -- but the model defines ``failed`` as "apply attempted and the
controller REJECTED it", which is exactly what is NOT known here. The write may
well have landed.

The consequence was operational, not cosmetic: the operator saw a failure and
could re-stage a non-idempotent create / delete / reboot that had already taken
effect on the device.

The in-process error paths already make a best-effort second commit of
``applied`` when the device write demonstrably happened, so what reaches this
sweep is the residue -- chiefly process death, where no ``except`` ever ran.
Those rows now become ``reconciliation_required``.

Pure-unit: the emitted UPDATE is captured and compiled; no DB is contacted.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.adapter_staging import (
    STATUS_RECONCILIATION_REQUIRED,
    AdapterStagingService,
)


def _service_capturing_update() -> tuple[AdapterStagingService, dict]:
    """Build a service whose ``db.execute`` records the statement it is given."""
    captured: dict = {}

    async def fake_execute(stmt):
        captured["stmt"] = stmt
        return SimpleNamespace(rowcount=1)

    db = MagicMock()
    db.execute = AsyncMock(side_effect=fake_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return AdapterStagingService(db), captured


def _bound_values(stmt) -> dict:
    """Extract the literal values an UPDATE statement sets."""
    compiled = stmt.compile()
    return dict(compiled.params)


@pytest.mark.asyncio
async def test_stale_applying_becomes_reconciliation_required_not_failed() -> None:
    """The core regression.

    Fails before the fix: the UPDATE set ``status='failed'``.
    """
    svc, captured = _service_capturing_update()

    recovered = await svc._recover_stale_applying(uuid4())

    assert recovered == 1
    values = _bound_values(captured["stmt"])
    statuses = [v for v in values.values() if isinstance(v, str) and v in {
        "failed", STATUS_RECONCILIATION_REQUIRED
    }]
    assert STATUS_RECONCILIATION_REQUIRED in statuses, (
        f"stale 'applying' rows must move to {STATUS_RECONCILIATION_REQUIRED!r}; "
        f"got {statuses!r}"
    )
    assert "failed" not in statuses, (
        "a stranded apply must NOT be recorded as 'failed' -- the model defines "
        "that as 'the controller rejected it', which is not known here"
    )


@pytest.mark.asyncio
async def test_recovery_reason_tells_the_operator_the_outcome_is_unknown() -> None:
    """The stored reason must not claim the change did not happen."""
    svc, captured = _service_capturing_update()
    await svc._recover_stale_applying(uuid4())

    reasons = [
        v for v in _bound_values(captured["stmt"]).values()
        if isinstance(v, str) and len(v) > 30
    ]
    assert reasons, "no failure_reason recorded"
    reason = reasons[0].lower()
    assert "unknown" in reason, f"reason should flag the unknown outcome: {reason!r}"
    assert "verify" in reason, f"reason should tell the operator to verify: {reason!r}"


@pytest.mark.asyncio
async def test_recovery_is_best_effort_and_swallows_db_errors() -> None:
    """This runs opportunistically on normal queue traffic; it must never
    surface a maintenance error into an unrelated request."""
    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("db gone"))
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    svc = AdapterStagingService(db)
    assert await svc._recover_stale_applying(uuid4()) == 0
    db.rollback.assert_awaited_once()


def test_reconciliation_required_is_not_the_pending_state() -> None:
    """The apply guard admits only ``pending``.

    A row awaiting reconciliation must therefore be refused by the ordinary
    apply path -- that is what stops the operator re-running a mutation that may
    already have taken effect.
    """
    assert STATUS_RECONCILIATION_REQUIRED != "pending"
    assert STATUS_RECONCILIATION_REQUIRED != "failed"


def test_forced_discard_admits_reconciliation_required() -> None:
    """The operator escape hatch.

    Once the device has been verified by hand, ``discard(force=True)`` must be
    able to clear the row -- otherwise it is stuck in the queue forever.
    """
    import inspect

    from app.services import adapter_staging

    source = inspect.getsource(adapter_staging.AdapterStagingService.discard)
    # The forced branch enumerates the statuses a force-discard may clear.
    assert "STATUS_RECONCILIATION_REQUIRED" in source, (
        "force-discard must admit a reconciliation_required row, or the operator "
        "has no way to resolve it"
    )


# ---------------------------------------------------------------------------
# The CLASS, not the edit
# ---------------------------------------------------------------------------
#
# The first fix here changed ``_recover_stale_applying`` and the test above
# covered exactly that method -- so it went green while TWO other sites kept
# writing the same wrong label:
#
#   * ``app/tasks/maintenance.py::reap_stuck_omada_pending_changes`` -- a Celery
#     BEAT task duplicating the same sweep on a schedule, writing
#     status="failed", failure_reason="janitor_timeout";
#   * ``AdapterStagingService.apply_change``'s generic exception handler, which
#     recorded ``failed`` for ANY exception -- including a read timeout, where
#     the request was already on the wire -- and told the operator
#     "controller rejected the change".
#
# These tests pin the whole class.


def test_transport_failure_after_send_is_an_unknown_outcome() -> None:
    """A response we never received is not a rejection."""
    import httpx

    from app.services.adapter_staging import outcome_is_unknown

    assert outcome_is_unknown(httpx.ReadTimeout("no response")) is True
    assert outcome_is_unknown(httpx.WriteTimeout("no response")) is True
    assert outcome_is_unknown(httpx.RemoteProtocolError("peer closed")) is True
    assert outcome_is_unknown(ConnectionResetError("reset")) is True
    assert outcome_is_unknown(TimeoutError()) is True


def test_connect_phase_failure_is_a_true_failure() -> None:
    """Nothing was sent, so ``failed`` is honest and must stay precise."""
    import httpx

    from app.services.adapter_staging import outcome_is_unknown

    assert outcome_is_unknown(httpx.ConnectError("refused")) is False
    assert outcome_is_unknown(httpx.ConnectTimeout("unreachable")) is False


def test_vendor_rejection_stays_failed() -> None:
    """The device answered and said no -- that IS a rejection."""
    from app.services.adapter_staging import outcome_is_unknown

    class OmadaApiError(Exception):
        pass

    assert outcome_is_unknown(OmadaApiError("-1005: operation forbidden")) is False
    assert outcome_is_unknown(ValueError("bad payload")) is False


def test_wrapped_transport_error_is_still_detected() -> None:
    """Adapters wrap transport errors in vendor exception types."""
    import httpx

    from app.services.adapter_staging import outcome_is_unknown

    class VendorError(Exception):
        pass

    try:
        try:
            raise httpx.ReadTimeout("no response")
        except httpx.ReadTimeout as inner:
            raise VendorError("push failed") from inner
    except VendorError as wrapped:
        assert outcome_is_unknown(wrapped) is True


def test_connect_failure_wins_over_a_wrapped_timeout() -> None:
    """If the chain shows we never connected, nothing was sent."""
    import httpx

    from app.services.adapter_staging import outcome_is_unknown

    try:
        try:
            raise httpx.ConnectError("refused")
        except httpx.ConnectError as inner:
            raise TimeoutError("gave up") from inner
    except TimeoutError as wrapped:
        assert outcome_is_unknown(wrapped) is False


def test_no_sweep_anywhere_labels_a_stale_applying_row_failed() -> None:
    """Ratchet over the CLASS: any code that sweeps ``applying`` rows must not
    write ``failed``.

    This is the test that would have caught the incomplete first fix. It scans
    the whole app tree rather than one method, so a fourth site cannot appear.
    """
    import ast
    from pathlib import Path

    app_root = Path(__file__).resolve().parents[2] / "app"
    offenders: list[str] = []

    for path in app_root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "values"):
                continue
            # Does this .values(...) set status="failed"?
            sets_failed = any(
                kw.arg == "status"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == "failed"
                for kw in node.keywords
            )
            if not sets_failed:
                continue
            # Is it part of a statement that filters on status == "applying"?
            src = ast.get_source_segment(path.read_text(encoding="utf-8"), node) or ""
            enclosing = path.read_text(encoding="utf-8")
            window_start = max(0, enclosing.find(src) - 600)
            window = enclosing[window_start : enclosing.find(src) + len(src)]
            if '"applying"' in window:
                offenders.append(f"{path.relative_to(app_root.parent)}:{node.lineno}")

    assert not offenders, (
        "These sweep rows out of 'applying' and label them 'failed', which the "
        "AdapterPendingChange lifecycle defines as 'the controller REJECTED it' -- "
        "an assertion the code cannot make about a stranded apply. Use "
        "STATUS_RECONCILIATION_REQUIRED:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# The state must FIT (R3 F-01)
# ---------------------------------------------------------------------------
#
# The lifecycle gained ``reconciliation_required`` (23 chars) while the column
# was String(16). On PostgreSQL every write raised "value too long for type
# character varying(16)", so the recovery paths could not persist and the row
# stayed ``applying`` forever. The sweep swallows DB errors by design, so it
# failed silently.
#
# Every test above used a MOCKED session that compiles the UPDATE without
# executing it, so none of them could see this. This one compares the declared
# width against the values the code actually writes -- no database needed.


def test_every_lifecycle_value_fits_the_status_column() -> None:
    """A state the column cannot hold is a state the system cannot enter."""
    from app.models.staging import AdapterPendingChange
    from app.services.adapter_staging import STATUS_RECONCILIATION_REQUIRED

    column = AdapterPendingChange.__table__.c.status
    width = column.type.length
    assert width is not None, "status column has no declared width"

    lifecycle = {
        "pending",
        "applying",
        "applied",
        "discarded",
        "failed",
        STATUS_RECONCILIATION_REQUIRED,
    }
    too_long = {v: len(v) for v in lifecycle if len(v) > width}
    assert not too_long, (
        f"status is String({width}) but these lifecycle values do not fit: "
        f"{too_long}. PostgreSQL rejects the write with 'value too long', and the "
        "opportunistic sweep swallows that error, so the row is stranded silently."
    )


def test_status_column_keeps_headroom_for_another_state() -> None:
    """Widened to 32 rather than exactly-enough, so the next state added to the
    lifecycle does not need its own migration."""
    from app.models.staging import AdapterPendingChange

    assert AdapterPendingChange.__table__.c.status.type.length >= 32


def test_a_migration_widens_deployed_databases() -> None:
    """Changing the model alone fixes fresh create_all, not existing appliances.

    Pins that the migration exists and targets this column -- the model change
    without it would leave every deployed database broken while tests passed.
    """
    from pathlib import Path

    versions = Path(__file__).resolve().parents[2] / "alembic" / "versions"
    widening = [
        p
        for p in versions.glob("*.py")
        if "adapter_pending_changes" in p.read_text(encoding="utf-8")
        and "status" in p.read_text(encoding="utf-8")
    ]
    assert widening, (
        "no migration alters adapter_pending_changes.status; deployed databases "
        "would keep the narrow column and silently strand reconciliation rows"
    )


# ---------------------------------------------------------------------------
# The taxonomy is inheritance-based (R3 F-02)
# ---------------------------------------------------------------------------
#
# The classifier compared exact ``type(e).__name__`` strings. aiohttp's
# ``SocketTimeoutError`` -- the READ-phase failure -- is a SUBCLASS of
# ``ServerTimeoutError``, so it fell through to "definite failure" and invited
# the operator to re-run a write the device may already have applied. Conversely
# httpx's ``PoolTimeout`` happens while waiting for a connection from the LOCAL
# pool, before anything is sent, and was wrongly treated as an unknown outcome.


def test_a_read_phase_subclass_is_recognised_through_its_base() -> None:
    """``SocketTimeoutError`` subclasses ``ServerTimeoutError``."""
    from app.services.adapter_staging import outcome_is_unknown

    class ServerTimeoutError(Exception):
        pass

    class SocketTimeoutError(ServerTimeoutError):
        """aiohttp's read-phase timeout."""

    assert outcome_is_unknown(SocketTimeoutError("no response")) is True


def test_a_connect_phase_subclass_is_recognised_through_its_base() -> None:
    """aiohttp's ``ConnectionTimeoutError`` never sent anything."""
    from app.services.adapter_staging import outcome_is_unknown

    class ConnectionTimeoutError(Exception):
        pass

    assert outcome_is_unknown(ConnectionTimeoutError("could not connect")) is False


def test_pool_timeout_is_a_true_failure_not_an_unknown_outcome() -> None:
    """Waiting for a LOCAL connection slot means the request never left."""
    import httpx

    from app.services.adapter_staging import outcome_is_unknown

    assert outcome_is_unknown(httpx.PoolTimeout("no free connection")) is False


def test_a_vendor_error_wrapping_a_read_subclass_is_unknown() -> None:
    """Adapters wrap transport errors; the chain AND the MRO must both be walked."""
    from app.services.adapter_staging import outcome_is_unknown

    class ServerTimeoutError(Exception):
        pass

    class SocketTimeoutError(ServerTimeoutError):
        pass

    class VendorError(Exception):
        pass

    try:
        try:
            raise SocketTimeoutError("no response")
        except SocketTimeoutError as inner:
            raise VendorError("push failed") from inner
    except VendorError as wrapped:
        assert outcome_is_unknown(wrapped) is True
