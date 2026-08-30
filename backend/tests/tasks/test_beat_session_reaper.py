# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The session reaper must be wired all the way to a worker that runs it.

``app.tasks.maintenance.cleanup_orphan_sessions`` is the only code in the tree
that deletes from ``core.user_sessions`` / ``core.sso_sessions``. It shipped
registered and unsendable: no ``beat_schedule`` entry, no
``MANUALLY_TRIGGERABLE_TASKS`` entry, and no ``.delay``/``.apply_async``
anywhere -- its only other references were the re-exports in
``app/tasks/__init__.py``. So no session row was ever pruned (135 rows on the
dev DB going back to 2026-06-16, 0 deleted), the table grows for the life of
the install, and ``GET /auth/sessions`` lists a user's entire login history as
though every row were a live device.

``test_celery_queue_registry.py`` already refuses a task with no sender at all,
but its allow-list can be extended with a sentence, and "add a beat entry" is
only the first of the four conditions CLAUDE.md records for a task actually
running. The other three are what this file pins, because getting the entry
itself right and the routing wrong fails silently -- the message is published,
declared into existence by ``task_create_missing_queues``, and sits unconsumed:

* the entry must name a task some worker REGISTERS (module in ``include=``),
* on a queue ``task_queues`` DECLARES,
* that every tier's ``WORKER_QUEUES`` actually CONSUMES. ``.env.max.example``
  and ``.env.pro.example`` subscribe to ``default,priority`` only, so routing a
  maintenance sweep to "sync" would run it on lite and nowhere else.

A beat entry's ``options["queue"]`` overrides ``task_routes`` the same way an
explicit ``queue=`` on ``apply_async`` does, so the queue asserted here is the
one that is really used -- there is no route that can rescue it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.core.celery_app import celery_app

REAPER = "app.tasks.maintenance.cleanup_orphan_sessions"

ENV_EXAMPLES = sorted(Path(__file__).resolve().parents[3].glob(".env.*.example"))


@pytest.fixture(scope="module")
def entry() -> dict[str, Any]:
    """The single beat entry that drives the reaper."""
    entries = {
        name: cfg
        for name, cfg in (celery_app.conf.beat_schedule or {}).items()
        if cfg.get("task") == REAPER
    }
    assert entries, (
        f"No beat_schedule entry sends {REAPER}. It is the only deleter of "
        "core.user_sessions/core.sso_sessions, so without one those tables are "
        "append-only for the life of the install and every revoked or expired "
        "session stays in GET /auth/sessions forever. Add the entry in "
        "app/core/celery_app.py."
    )
    assert len(entries) == 1, f"Duplicate beat entries for {REAPER}: {sorted(entries)}"
    return dict(next(iter(entries.values())))


def _worker_queues_by_tier() -> dict[str, set[str]]:
    """WORKER_QUEUES per .env.<tier>.example.

    Empty when the suite runs against a container that mounts only backend/
    (scripts/ci-gate.sh does exactly that), so callers skip rather than fail --
    same contract as ``_worker_queues_from_env_examples`` next door.
    """
    tiers: dict[str, set[str]] = {}
    for path in ENV_EXAMPLES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("WORKER_QUEUES="):
                value = line.split("=", 1)[1].strip()
                tiers[path.name] = {q.strip() for q in value.split(",") if q.strip()}
    return tiers


def test_reaper_beat_entry_names_a_registered_task(entry: dict[str, Any]) -> None:
    """Beat publishes by NAME; an unregistered name is a message no worker can run."""
    celery_app.loader.import_default_modules()
    celery_app.finalize()
    assert REAPER in celery_app.tasks, (
        f"beat sends {REAPER!r} but no worker registers it -- its module is "
        "missing from include= in app/core/celery_app.py, so the message is "
        "published and then rejected as unregistered."
    )


def test_reaper_beat_queue_is_declared(entry: dict[str, Any]) -> None:
    """The entry's queue must exist in ``task_queues``."""
    declared = {q.name for q in (celery_app.conf.task_queues or [])}
    queue = entry.get("options", {}).get("queue")
    assert queue in declared, (
        f"The {REAPER} beat entry routes to queue={queue!r}, which task_queues "
        f"does not declare. task_create_missing_queues defaults True, so the "
        f"producer would create it and the sweeps would pile up unconsumed.\n"
        f"Declared: {sorted(declared)}"
    )


def test_reaper_beat_queue_is_consumed_by_every_tier(entry: dict[str, Any]) -> None:
    """A maintenance sweep has to run on lite, pro AND max.

    ``.env.pro.example`` and ``.env.max.example`` set
    ``WORKER_QUEUES=default,priority``; only lite subscribes to the full set.
    Routing this to "discovery"/"sync"/"metrics" would leave two of the three
    shipped tiers with an append-only user_sessions table and nothing to show
    for it in any log.
    """
    tiers = _worker_queues_by_tier()
    if not tiers:
        pytest.skip("No .env.*.example reachable (backend-only mount).")
    queue = entry.get("options", {}).get("queue")
    starved = sorted(tier for tier, queues in tiers.items() if queue not in queues)
    assert not starved, (
        f"The {REAPER} beat entry routes to queue={queue!r}, which "
        f"{starved} do not consume. A beat entry's options['queue'] overrides "
        f"task_routes, so no routing rule can rescue this.\n"
        f"Tier config: { {k: sorted(v) for k, v in tiers.items()} }"
    )


def test_reaper_schedule_actually_fires(entry: dict[str, Any]) -> None:
    """Ask the schedule itself, rather than trusting the crontab literal.

    A crontab can be syntactically fine and still never come due (``month_of_year``
    pinned to a month that lacks the ``day_of_month``, say). Two days after its
    last run any daily sweep must report due, and must promise a next run inside
    a day.
    """
    schedule = entry["schedule"]
    last_run = datetime.now(UTC) - timedelta(days=2)
    is_due, next_in_seconds = schedule.is_due(last_run)
    assert is_due, (
        f"{REAPER} is scheduled as {schedule!r}, which is not due two days "
        "after its last run -- beat would hold the message indefinitely."
    )
    assert 0 < next_in_seconds <= 24 * 60 * 60 + 60, (
        f"{REAPER} runs less often than daily ({next_in_seconds}s to the next "
        "run). user_sessions grows on every login; the sweep has to keep up."
    )
