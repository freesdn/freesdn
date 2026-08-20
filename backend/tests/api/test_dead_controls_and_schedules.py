# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The tail: controls that were offered, accepted, and connected to nothing.

1. SLA REPORT SCHEDULES GENERATED NOTHING, TWICE OVER
   ``SLAReportGenerator.generate_scheduled`` existed complete and had NO
   CALLER -- its own docstring says "Called by a periodic task (e.g. Celery
   beat, APScheduler)" and no such task was ever added.

   And it would not have mattered if one had been: the method selects on
   ``next_run_at <= now`` and skips NULL, while ``create_schedule`` set
   ``next_run_at=data.get("next_run_at")`` and the API does not collect it. So
   every schedule was born NULL and could never come due. ``_compute_next_run``
   already existed -- it just only ran AFTER a report, which never happened.
   Both halves had to be fixed or the fix is theatre.

2. THE OPENWRT ALIAS DELETE IGNORED THE ID IT ASKED FOR
   ``delete_alias(uuid=...)`` declared the parameter, read it nowhere, and
   fell through to ``AdapterResult.fail("Either uuid or name required")`` --
   while holding the uuid the caller had just supplied. Delete-by-id was
   impossible and the error blamed the caller.

3. TWO FREEPBX SINGLE-READS COULD NEVER SUCCEED
   The gateway services call ``client.get_ring_group`` / ``client.get_queue``,
   and ``_get_client`` returns the ADAPTER (documented: FreePBX's write helpers
   live there behind ``_check_write_allowed``). Only the inner REST client had
   those methods, so both endpoints raised AttributeError on every call. The
   list endpoints beside them worked, which is what hid it.

4. THE 'blocked' FILTER ON THE CLIENTS LIST WAS NEVER APPLIED
   Declared as a query param, used in the RESPONSE, and absent from the query
   -- while every sibling filter (search / status / connection_type) was
   applied. The Clients page's Blocked filter returned the whole list either
   way.

   The NULL case is the subtle half: ``blocked`` only exists in
   client_metadata once the block endpoint has written it, so a client that
   was never blocked has no key at all. ``is_(False)`` misses all of them, and
   filtering for "not blocked" would have returned almost nothing.

5. IMPORT / EXPORT JOB FAILURES LEFT THE JOB AT PENDING
   The services set FAILED + error_message and ``flush()``; the task then
   ``rollback()``ed, discarding the verdict along with the partial work. A
   failed job sat in the list as "pending" forever with nothing to explain it.
   Same shape as the ZTP adoption bug fixed earlier in this wave.

6. THE DISTRIBUTION LOG EXPANDER WAS STRUCTURALLY EMPTY
   ``GET /distribution/{id}`` declared ``response_model=DistributionResponse``
   -- the LIST shape, which has no ``step_results`` -- while its docstring
   promised "step details". FastAPI stripped them, and
   ``DistributionDetailResponse`` was referenced by nothing at all. Which tier
   failed, on which device, with what error was unreachable.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. SLA report schedules ──────────────────────────────────────


def test_a_new_schedule_gets_a_first_fire_time() -> None:
    """
    The half that made a beat task pointless on its own: every schedule was
    born with next_run_at NULL, and the due-query skips NULL.
    """
    from app.services.sla_reports import SLAReportGenerator

    code = _code(SLAReportGenerator.create_schedule)
    assert "_compute_next_run" in code, "schedules are still created unable to come due"


def test_editing_the_cadence_moves_the_next_run() -> None:
    from app.services.sla_reports import SLAReportGenerator

    code = _code(SLAReportGenerator.update_schedule)
    assert "_compute_next_run" in code
    assert "retimed" in code


def test_the_due_query_still_skips_null() -> None:
    """
    Premise. This is WHY a NULL next_run_at is fatal rather than merely
    untidy, and it pins the two together.
    """
    from app.services.sla_reports import SLAReportGenerator

    code = _code(SLAReportGenerator.generate_scheduled)
    assert "next_run_at.isnot(None)" in code
    assert "next_run_at <= now" in code


@pytest.mark.parametrize(
    ("frequency", "min_days"),
    [("weekly", 6), ("monthly", 29), ("quarterly", 89)],
)
def test_the_next_run_is_in_the_future_for_each_cadence(frequency: str, min_days: int) -> None:
    from app.services.sla_reports import SLAReportGenerator

    now = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    schedule = SimpleNamespace(frequency=frequency)
    nxt = SLAReportGenerator._compute_next_run(schedule, now)
    assert nxt > now
    assert nxt - now >= timedelta(days=min_days)


def test_a_periodic_task_now_calls_the_generator() -> None:
    """The regression: the method was complete and nothing invoked it."""
    from app.tasks import sla

    code = _code(sla)
    assert "generate_scheduled()" in code
    assert "SLAReportGenerator" in code


def test_the_task_is_registered_on_beat_and_on_a_real_queue() -> None:
    """
    A task nobody schedules is the same bug in a new place. The queue must
    also be one a worker consumes, or it is scheduled into a void.
    """
    from app.core.celery_app import celery_app

    beat = celery_app.conf.beat_schedule
    entry = beat.get("sla-generate-scheduled-reports")
    assert entry is not None, "the SLA report task is not on the beat schedule"
    assert entry["task"] == "app.tasks.sla.generate_scheduled_reports"

    queue = entry.get("options", {}).get("queue")
    assert queue in celery_app.conf.task_queues or any(
        getattr(q, "name", None) == queue for q in (celery_app.conf.task_queues or [])
    ), f"queue {queue!r} is not a declared task queue"


def test_the_task_module_is_in_the_celery_include() -> None:
    """Without this no worker registers the task, however it is scheduled."""
    from app.core.celery_app import celery_app

    assert "app.tasks.sla" in (celery_app.conf.include or [])


def test_one_orgs_failure_does_not_abort_the_run() -> None:
    from app.tasks import sla

    code = _code(sla._generate_scheduled_reports)
    assert "except Exception" in code


# ── 2. the OpenWrt alias delete ──────────────────────────────────


def test_delete_alias_reads_the_uuid_it_accepts() -> None:
    from app.adapters.openwrt.adapter import OpenWRTAdapter

    code = _code(OpenWRTAdapter.delete_alias)
    assert "if uuid:" in code, "the uuid parameter is still accepted and ignored"
    assert "_find_uci_section" in code


def test_it_resolves_the_id_the_same_way_update_does() -> None:
    """
    Two ways to interpret an alias id is how delete starts removing the wrong
    section. Pin them to the same resolver.
    """
    from app.adapters.openwrt.adapter import OpenWRTAdapter

    assert "_find_uci_section" in _code(OpenWRTAdapter._uci_update)


def test_deleting_something_already_gone_is_a_success() -> None:
    """Delete is idempotent: already absent is the desired end state."""
    from app.adapters.openwrt.adapter import OpenWRTAdapter

    code = _code(OpenWRTAdapter.delete_alias)
    assert "already_absent" in code
    assert "if name or uuid:" in code


def test_supplying_neither_is_still_an_error() -> None:
    from app.adapters.openwrt.adapter import OpenWRTAdapter

    assert "Either uuid or name required" in _code(OpenWRTAdapter.delete_alias)


# ── 3. the FreePBX single reads ──────────────────────────────────


@pytest.mark.parametrize("method", ["get_ring_group", "get_queue"])
def test_the_adapter_exposes_the_single_read(method: str) -> None:
    """
    The services call these on the ADAPTER. Only the REST client had them, so
    every call raised AttributeError.
    """
    from app.adapters.freepbx.adapter import FreePBXAdapter

    assert callable(getattr(FreePBXAdapter, method, None)), f"FreePBXAdapter has no {method}"


@pytest.mark.parametrize("method", ["get_ring_group", "get_queue"])
def test_a_missing_record_is_a_clean_not_found(method: str) -> None:
    """404, not a 500 and not a bare success with empty data."""
    from app.adapters.freepbx.adapter import FreePBXAdapter

    code = _code(getattr(FreePBXAdapter, method))
    assert "NOT_FOUND" in code


def test_the_service_really_calls_it_on_the_adapter() -> None:
    """
    Premise. ``_get_client`` returning the adapter is deliberate and
    documented; that is exactly why the adapter needed these methods.
    """
    from app.services import adapter_freepbx_base

    doc = inspect.getsource(adapter_freepbx_base.FreePBXServiceBase._get_client)
    assert "FreePBXAdapter" in doc
    assert "NOT the" in doc


# ── 4. the 'blocked' client filter ───────────────────────────────


def test_the_blocked_filter_reaches_the_query() -> None:
    from app.api.v1.endpoints import network

    code = _code(network.list_clients)
    assert "if blocked is not None:" in code
    assert 'client_metadata["blocked"]' in code


def test_not_blocked_includes_clients_that_were_never_blocked() -> None:
    """
    The subtle half. The key only exists once the block endpoint writes it, so
    a never-blocked client is NULL, not False -- and ``is_(False)`` would have
    matched only the explicitly-unblocked.
    """
    from app.api.v1.endpoints import network

    code = _code(network.list_clients)
    assert "is_(None)" in code


def test_the_service_filter_has_the_same_null_handling() -> None:
    """The sibling had the identical NULL bug; both were fixed together."""
    from app.modules.network.service import NetworkClientService

    code = _code(NetworkClientService.list)
    assert "is_(None)" in code
    assert "metadata_filter.is_(blocked)" not in code


# ── 5. import / export job state ─────────────────────────────────


@pytest.mark.parametrize("task", ["run_export_job", "run_import_job"])
def test_a_failed_job_is_recorded_as_failed(task: str) -> None:
    from app.tasks import import_export

    code = _code(getattr(import_export, task))
    assert "_record_job_failure" in code
    assert code.index("await session.rollback()") < code.index("_record_job_failure"), (
        "the verdict must be written AFTER the rollback or it is rolled back too"
    )


def test_the_terminal_write_uses_states_that_exist() -> None:
    """
    JobStatus has no RUNNING -- it is PENDING / VALIDATING / IN_PROGRESS.
    Naming one that does not exist would raise into the except and make the
    whole fix a silent no-op, which is the bug class being fixed.
    """
    from app.models.import_export import JobStatus
    from app.tasks import import_export

    code = _code(import_export._record_job_failure)
    assert not hasattr(JobStatus, "RUNNING")
    for state in ("PENDING", "VALIDATING", "IN_PROGRESS"):
        assert hasattr(JobStatus, state)
        assert f"JobStatus.{state}" in code


def test_the_bookkeeping_cannot_mask_the_real_failure() -> None:
    from app.tasks import import_export

    assert "except Exception" in _code(import_export._record_job_failure)


def test_the_services_still_set_failed_before_flushing() -> None:
    """Premise: they flush, never commit, which is why the rollback erased it."""
    from app.services.import_export import DataImportExportService

    for name in ("run_export", "run_import"):
        code = _code(getattr(DataImportExportService, name))
        assert "JobStatus.FAILED" in code
        assert "await session.flush()" in code


# ── 6. the Distribution Log detail ───────────────────────────────


def test_the_detail_endpoint_returns_the_detail_shape() -> None:
    from app.modules.gateway.api import distribution_api

    code = _code(distribution_api.get_distribution)
    assert "DistributionDetailResponse" in code
    assert "response_model=DistributionResponse)" not in code


def test_the_detail_shape_actually_carries_the_steps() -> None:
    from app.modules.gateway.schemas import DistributionDetailResponse, DistributionResponse

    assert "step_results" in DistributionDetailResponse.model_fields
    # And the list shape deliberately does not: step_results is a JSONB blob
    # per row and has no place in a paginated log.
    assert "step_results" not in DistributionResponse.model_fields


def test_the_list_endpoint_keeps_the_slim_shape() -> None:
    from app.modules.gateway.api import distribution_api

    code = _code(distribution_api)
    assert "response_model=DistributionListResponse" in code
