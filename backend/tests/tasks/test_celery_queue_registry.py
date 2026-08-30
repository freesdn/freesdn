# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Meta-test: Celery task/queue wiring must be internally consistent.

Background
----------
`app.tasks.webhooks.retry_webhook_delivery` shipped in 26.06.1 declaring
``queue="webhooks"`` while (a) no such queue was declared in ``task_queues``,
(b) no worker in any tier consumed it, and (c) the module was absent from the
Celery ``include=`` list so no worker even registered the task. Every dispatch
site imports the module lazily inside a function, so the API process imported it
happily and the breakage was invisible: failed deliveries flipped to RETRYING,
enqueued into the void, and never reached the dead-letter table.

These tests turn each leg of that failure into a red build.

Legs 5 and 6 were added later, for two failures of the same family found in the
opposite direction -- tasks and routes that are perfectly declared and simply
never used:

* ``task_routes`` globs match a task's REGISTERED NAME, not its module path, so
  ``"app.tasks.analytics.*"`` matched none of the four ``analytics.*`` tasks and
  they routed to the quick "default" lane instead of the "metrics" I/O lane.
  Alongside it ``"app.tasks.*.high_priority_*"`` matched nothing at all, in any
  release, which left the declared+subscribed ``priority`` queue permanently
  empty.
* Nine registered tasks had no sender of any kind -- not beat, not the manual
  trigger endpoint, not a ``.delay``/``.apply_async``/``send_task`` call site.
  One of them, ``agents.notify_offline``, had been written specifically to move
  SMTP/Slack round-trips out of the ``agents.cleanup_stale`` beat slot; it was
  registered and never sent, so the inline dispatch it replaced kept running.
"""

from __future__ import annotations

import ast
import fnmatch
import re
from pathlib import Path

import pytest

from app.core.celery_app import celery_app

APP_DIR = Path(__file__).resolve().parents[2] / "app"
ENV_EXAMPLES = sorted((APP_DIR.parent.parent).glob(".env.*.example"))


def _declared_queues() -> set[str]:
    return {q.name for q in (celery_app.conf.task_queues or [])}


def _worker_queues_from_env_examples() -> dict[str, set[str]]:
    """
    Map each .env.<tier>.example to the queue set its workers consume.

    The .env examples live one level above backend/, so they are absent when the
    suite runs against a container that mounts only backend/ (scripts/ci-gate.sh
    does exactly this). Callers must skip rather than fail in that case.
    """
    tiers: dict[str, set[str]] = {}
    for path in ENV_EXAMPLES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("WORKER_QUEUES="):
                value = line.split("=", 1)[1].strip()
                tiers[path.name] = {q.strip() for q in value.split(",") if q.strip()}
    return tiers


def _tasks_declaring_a_queue() -> list[tuple[str, str, int]]:
    """Find every @celery_app.task(..., queue="X") in app/. Returns (file, queue, lineno)."""
    found: list[tuple[str, str, int]] = []
    for py in APP_DIR.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                for kw in deco.keywords:
                    if kw.arg == "queue" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str):
                            found.append(
                                (str(py.relative_to(APP_DIR)), kw.value.value, deco.lineno)
                            )
    return found


def _dispatch_sites_naming_a_queue() -> list[tuple[str, str, int]]:
    """
    Find every ``.apply_async(..., queue="X")`` / ``.delay`` sibling in app/.

    This is the leg the first version of this test missed. An explicit ``queue=``
    kwarg on apply_async overrides BOTH the task's decorator routing and
    ``task_routes``, so fixing the decorator alone changes nothing observable if a
    dispatch site still names the old queue. Returns (file, queue, lineno).
    """
    found: list[tuple[str, str, int]] = []
    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"apply_async", "delay", "send_task"}:
                continue
            for kw in node.keywords:
                if kw.arg == "queue" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        found.append((str(py.relative_to(APP_DIR)), kw.value.value, node.lineno))
    return found


def test_every_dispatch_site_queue_is_actually_declared() -> None:
    """
    An explicit queue= on apply_async wins over every other routing mechanism.

    Regression guard for the webhook lane: the decorator and include= were fixed
    first, the suite went green, and the bug stayed live because three
    apply_async sites still passed queue="webhooks" explicitly.
    """
    declared = _declared_queues()
    offenders = [
        f"{path}:{lineno} dispatches to queue={queue!r}"
        for path, queue, lineno in _dispatch_sites_naming_a_queue()
        if queue not in declared
    ]
    assert not offenders, (
        "Dispatch site(s) publish to an undeclared queue. An explicit queue= on "
        "apply_async overrides the task's routing AND task_routes, and Celery's "
        "task_create_missing_queues defaults True, so the producer will happily "
        "declare the queue and the messages will sit in it unconsumed.\n"
        f"Declared queues: {sorted(declared)}\n" + "\n".join(offenders)
    )


def test_every_task_declared_queue_is_actually_declared() -> None:
    """A task may not route to a queue that ``task_queues`` never declares."""
    declared = _declared_queues()
    offenders = [
        f"{path}:{lineno} routes to queue={queue!r}"
        for path, queue, lineno in _tasks_declaring_a_queue()
        if queue not in declared
    ]
    assert not offenders, (
        "Task(s) route to an undeclared queue. Declare it in "
        "app/core/celery_app.py task_queues, or drop the queue= kwarg so the "
        f"task routes to 'default'.\nDeclared queues: {sorted(declared)}\n" + "\n".join(offenders)
    )


def test_every_declared_queue_is_consumed_by_some_tier() -> None:
    """A declared queue nobody consumes is a silent message sink."""
    tiers = _worker_queues_from_env_examples()
    if not tiers:
        pytest.skip("No .env.*.example reachable (backend-only mount); cannot verify consumption.")
    consumed: set[str] = set().union(*tiers.values())
    orphans = sorted(_declared_queues() - consumed)
    assert not orphans, (
        f"Queue(s) declared but consumed by no tier: {orphans}. "
        f"Add them to WORKER_QUEUES in the relevant .env.*.example, or remove "
        f"the queue. Tier config: { {k: sorted(v) for k, v in tiers.items()} }"
    )


def test_default_queue_is_consumed_by_every_tier() -> None:
    """'default' is the fallback for any task without an explicit queue."""
    tiers = _worker_queues_from_env_examples()
    if not tiers:
        pytest.skip("No .env.*.example reachable (backend-only mount).")
    for tier, queues in tiers.items():
        assert "default" in queues, (
            f"{tier} does not consume the 'default' queue. Any task without an "
            f"explicit queue= would be stranded in that tier."
        )


@pytest.mark.parametrize("module", sorted(set(celery_app.conf.include or [])))
def test_included_modules_are_importable(module: str) -> None:
    """Every module in ``include=`` must import — an unimportable one is silently skipped."""
    __import__(module)


def test_task_modules_defining_tasks_are_in_the_include_list() -> None:
    """
    A module defining @celery_app.task must be in ``include=``.

    Otherwise workers never register the task, and any lazy (function-level)
    import from the API process hides the breakage — exactly the webhook bug.
    """
    include = set(celery_app.conf.include or [])
    # Column 0 only: an INDENTED @celery_app.task sits inside a factory/class and
    # is registered when that code runs, not at import time, so it does not need
    # an include= entry. Matching those produced false positives on
    # app/tasks/base.py and app/modules/ai/governance.py.
    module_level_task = re.compile(r"^@(?:celery_app\.task|shared_task)\b", re.MULTILINE)
    # The module that DEFINES celery_app is loaded by every worker by definition.
    always_loaded = {"app.core.celery_app"}
    missing: list[str] = []

    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        if not module_level_task.search(py.read_text(encoding="utf-8")):
            continue
        dotted = "app." + ".".join(py.relative_to(APP_DIR).with_suffix("").parts)
        if dotted not in include and dotted not in always_loaded:
            missing.append(dotted)

    assert not missing, (
        "Module(s) define Celery tasks but are absent from the include= list in "
        "app/core/celery_app.py, so no worker registers them:\n  " + "\n  ".join(sorted(missing))
    )


# ── Leg 5: routes that match something ──────────────────────────────────────


def _registered_task_names() -> set[str]:
    """Every task name a worker would hold, excluding Celery's own internals."""
    # include= modules are imported lazily; without this the registry holds only
    # whatever the test session happened to import, and the assertions below
    # would pass by looking at a near-empty registry.
    celery_app.loader.import_default_modules()
    celery_app.finalize()
    return {n for n in celery_app.tasks if not n.startswith("celery.")}


def test_every_task_route_glob_matches_a_registered_task() -> None:
    """A ``task_routes`` key that matches nothing is a routing rule that lies.

    Mutation this catches: change ``"analytics.*"`` back to
    ``"app.tasks.analytics.*"`` (the module path rather than the registered
    name) and this fails naming that pattern. It also fails on a rule left
    behind for a task that was renamed or deleted.
    """
    names = _registered_task_names()
    dead = [
        pattern
        for pattern in (celery_app.conf.task_routes or {})
        if not any(fnmatch.fnmatch(n, pattern) for n in names)
    ]
    assert not dead, (
        "task_routes pattern(s) match no registered task, so the rule has no "
        "effect and the tasks it was meant to steer fall through to "
        f"task_default_queue={celery_app.conf.task_default_queue!r}. Patterns "
        "are matched against the REGISTERED NAME (the decorator's name=), not "
        f"the module path.\nDead patterns: {dead}"
    )


# ── Leg 6: tasks that something actually sends ──────────────────────────────

#: Registered tasks with no sender, each one deliberate rather than forgotten.
#: This is an ALLOW-LIST, not a blessing: every entry is a real gap, recorded so
#: the ratchet can still catch the NEXT one. Adding a name here must come with a
#: reason, and giving the task a sender (or deleting it) is always the better fix.
_UNDISPATCHED_BY_DESIGN: dict[str, str] = {
    # Celery's own scaffolding sanity task; invoked by hand from a shell.
    "app.core.celery_app.debug_task": "operator smoke-test, invoked manually",
    # On-demand helpers whose only caller was removed; they take per-entity
    # arguments so no beat entry can drive them either.
    "app.tasks.discovery.discovery_health_check": "on-demand; no caller left",
    "app.tasks.maintenance.refresh_materialized_views": "on-demand; no caller left",
    "app.tasks.maintenance.vacuum_database": "on-demand DBA action",
    "app.tasks.metrics.collect_controller_metrics": "per-controller; no caller left",
    "app.tasks.metrics.collect_site_metrics": "per-site; no caller left",
    "app.tasks.sync.sync_device_config": "per-device; no caller left",
    "backup.run_backup": "per-job; the API path runs backups inline",
    "gateway.sync_gateway": "per-gateway; callers use gateway.sync_all_gateways",
    # VoIP: registered, listed in VoipModule.get_tasks() (which nothing calls),
    # and never sent. voip.health_check was the only one of the eight that
    # PERSISTS what it collects, so it is the only one that earned a beat entry
    # (voip-phone-health-check); the rest need per-entity arguments or discard
    # their result, and wiring those means editing app/modules/voip/.
    "voip.bulk_reboot": "per-phone-list; needs a voip API route",
    "voip.check_firmware_compliance": (
        "returns a report it never stores; the API serves the same data on demand"
    ),
    "voip.generate_provisioning_files": "per-PBX; needs a voip API route",
    "voip.poll_extension_states": (
        "fetches extension states and discards them, so a schedule would add "
        "load without adding a refresh"
    ),
    "voip.sync_cdr": "per-PBX; needs a voip API route",
    "voip.sync_extensions": "per-PBX; needs a voip API route",
    "voip.sync_phones": "per-PBX; needs a voip API route",
}


def _task_name_by_function() -> dict[str, set[str]]:
    """Map each task function's ``def`` name to the task name(s) it registers as."""
    mapping: dict[str, set[str]] = {}
    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                label = getattr(deco.func, "attr", getattr(deco.func, "id", ""))
                if label not in ("task", "shared_task"):
                    continue
                explicit = next(
                    (
                        kw.value.value
                        for kw in deco.keywords
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant)
                    ),
                    None,
                )
                if explicit is None:
                    dotted = "app." + ".".join(py.relative_to(APP_DIR).with_suffix("").parts)
                    explicit = f"{dotted}.{node.name}"
                mapping.setdefault(node.name, set()).add(str(explicit))
    return mapping


def _task_names_with_a_dispatch_site() -> set[str]:
    """Task names reachable from a ``.delay`` / ``.apply_async`` / ``send_task`` in app/.

    Deliberately permissive: an attribute or bare name matching a task
    function's ``def`` name counts, and ``from x import y as z`` aliases are
    resolved. Over-matching only ever makes this test MISS a dead task, never
    invent one -- the safe direction for a ratchet whose other failure mode
    would be a false accusation against working code.
    """
    by_function = _task_name_by_function()
    found: set[str] = set()
    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        aliases = {
            a.asname: a.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for a in node.names
            if a.asname
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr in ("delay", "apply_async"):
                base = node.func.value
                caller = getattr(base, "attr", getattr(base, "id", None))
                if caller:
                    for candidate in (caller, aliases.get(caller, caller)):
                        found |= by_function.get(candidate, set())
            elif node.func.attr == "send_task" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    found.add(first.value)
    return found


def _reachable_task_names() -> set[str]:
    from app.api.v1.endpoints.tasks import MANUALLY_TRIGGERABLE_TASKS

    beat = {entry["task"] for entry in (celery_app.conf.beat_schedule or {}).values()}
    return beat | set(MANUALLY_TRIGGERABLE_TASKS) | _task_names_with_a_dispatch_site()


def test_every_registered_task_has_a_dispatch_path() -> None:
    """Registering a task is three of four legs; something must also SEND it.

    ``agents.notify_offline`` passed every other check in this file -- right
    queue, module in ``include=``, importable -- and executed zero times in
    every release it shipped in, because ``agents.cleanup_stale`` still did the
    dispatch inline. So did eight VoIP tasks whose docstrings name a beat
    cadence nobody ever wrote down.

    Mutation this catches: delete the ``notify_offline_agent.apply_async(...)``
    call in app/tasks/agents.py, or the ``voip-phone-health-check`` beat entry
    in app/core/celery_app.py, and this fails naming exactly that task.
    """
    orphans = sorted(
        _registered_task_names() - _reachable_task_names() - set(_UNDISPATCHED_BY_DESIGN)
    )
    assert not orphans, (
        "Registered task(s) that nothing sends: no beat_schedule entry, no "
        "MANUALLY_TRIGGERABLE_TASKS entry, and no .delay/.apply_async/send_task "
        "call site under app/. A task like this is dead code that reads as a "
        "shipped feature -- and if it was extracted from an inline code path, "
        "that inline path is still what runs.\n"
        "Give it a sender, or add it to _UNDISPATCHED_BY_DESIGN with a reason.\n  "
        + "\n  ".join(orphans)
    )


def test_undispatched_allow_list_has_no_stale_entries() -> None:
    """An allow-list entry for a task that is now wired (or gone) must be removed.

    Without this the allow-list only ever grows, and a name left behind after a
    task is finally wired silently exempts whatever gets that name next.
    """
    unregistered = sorted(set(_UNDISPATCHED_BY_DESIGN) - _registered_task_names())
    now_wired = sorted(set(_UNDISPATCHED_BY_DESIGN) & _reachable_task_names())
    assert not unregistered and not now_wired, (
        "_UNDISPATCHED_BY_DESIGN is stale. Remove these entries.\n"
        f"  no longer registered: {unregistered}\n"
        f"  now dispatched: {now_wired}"
    )
