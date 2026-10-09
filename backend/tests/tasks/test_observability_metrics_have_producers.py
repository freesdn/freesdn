# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A shipped alert or panel may only read a metric some FreeSDN code writes.

A ``prometheus_client`` metric declared at module scope in
``app/core/metrics.py`` is registered, exported on ``/metrics`` and scraped
whether or not anything ever calls ``.inc()`` on it. Prometheus then evaluates
``freesdn_celery_queue_depth > 1000`` against an empty family forever: no data,
no alert, no error, and no way for an operator to tell "the queue is healthy"
apart from "this rule is dead". Three shipped rules were in exactly that state
(``freesdn_celery_queue_depth``, ``freesdn_celery_tasks_total``,
``freesdn_rate_limit_hits_total``) along with two dashboard panels
(``freesdn_celery_queue_depth``, ``freesdn_websocket_connections``), so an
operator who wired observability/ into Alertmanager and Grafana believed they
had Celery backlog paging, Celery failure paging, rate-limit paging, a queue
graph and a WebSocket count, and had none of the five.

The class had already been found once and fixed by wiring the producer: see the
``plugin_operations_total`` comment in ``app/core/metrics.py`` ("declared,
scraped, always zero").

This is the gate that keeps it from coming back. It reads the SHIPPED
artefacts, not the docs, and it goes through ``yaml.safe_load`` / ``json.loads``
rather than scanning raw text -- the dead rules are commented out in
``alerts.yml`` with their expressions kept verbatim for whoever re-arms them,
and a text scan would "find" those and fail on a rule Prometheus never loads.

Only ``expr`` is checked. A metric named in a ``description`` is documentation,
not something that fires.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest
import yaml

# tests/tasks/ -> backend/ -> freesdn/
FREESDN_DIR = Path(__file__).resolve().parents[3]
BACKEND = FREESDN_DIR / "backend"
APP = BACKEND / "app"
METRICS_MODULE = APP / "core" / "metrics.py"
OBSERVABILITY = FREESDN_DIR / "observability"
ALERTS = OBSERVABILITY / "prometheus" / "alerts.yml"
GRAFANA = OBSERVABILITY / "grafana"
COMPOSE = FREESDN_DIR / "docker-compose.yml"

_FREESDN_METRIC = re.compile(r"\bfreesdn_[a-z0-9_]+\b")

# prometheus_client derives these series names from one declared metric.
_EXPOSITION_SUFFIXES = ("_bucket", "_sum", "_count", "_created", "_total", "_info")

# Reaching any of these off a metric object is a write, or the first half of one
# (``.labels(...).inc()``). Reads are deliberately absent: a metric that is only
# ever read from is still empty as far as a scrape is concerned.
_WRITE_ATTRS = frozenset(
    {
        "inc",
        "dec",
        "set",
        "observe",
        "info",
        "labels",
        "set_to_current_time",
        "set_function",
        "time",
        "track_inprogress",
        "remove",
        "clear",
    }
)


def _backup_produced() -> set[str]:
    """Execute the status exporter; comments or declarations are not producers."""
    import runpy
    import tempfile

    exporter = FREESDN_DIR / "docker" / "backup_metrics.py"
    _require(exporter)
    namespace = runpy.run_path(str(exporter))
    with tempfile.TemporaryDirectory() as directory:
        return set(namespace["collect"](Path(directory), Path(directory), {}, 1_800_000_000))


def _require(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"not mounted in this environment ({path})")


def declared_metrics(metrics_module: Path) -> dict[str, str]:
    """``{python name: prometheus name}`` for every module-level metric."""
    tree = ast.parse(metrics_module.read_text(encoding="utf-8"))
    declared: dict[str, str] = {}
    for node in tree.body:
        target: ast.expr | None = None
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        first = node.value.args[0] if node.value.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            declared[target.id] = first.value
    return declared


def _writes_in(tree: ast.AST, names: set[str]) -> set[str]:
    """Python metric names this AST calls a write method on.

    Matches ``metric.inc()`` and ``module.metric.labels(...)`` alike. AST rather
    than a text search on purpose: metrics.py documents the missing Celery probe
    in a comment ("updated by a periodic probe, see app.tasks.metrics"), and a
    grep would read that comment as a producer.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr not in _WRITE_ATTRS:
            continue
        owner = node.value
        if isinstance(owner, ast.Name) and owner.id in names:
            found.add(owner.id)
        elif isinstance(owner, ast.Attribute) and owner.attr in names:
            found.add(owner.attr)
    return found


def written_metrics(app_root: Path, declared: dict[str, str]) -> set[str]:
    """Prometheus names of the declared metrics that some code actually writes."""
    names = set(declared)
    written: set[str] = set()
    for path in sorted(app_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        # Cheap prefilter: a file that never mentions a still-unproven metric
        # name cannot be its producer, so it never gets parsed.
        if not any(name in text for name in names - written):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - would fail the PEP 765 CI step
            continue
        if path == METRICS_MODULE:
            # Skip the declarations themselves. Only writes inside a function
            # body count (setup_metrics() sets the build-info Info metric).
            written |= {
                name
                for node in tree.body
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                for name in _writes_in(node, names)
            }
            continue
        written |= _writes_in(tree, names)
    return {declared[name] for name in written}


def _metrics_in(expr: str) -> set[str]:
    return set(_FREESDN_METRIC.findall(expr))


def alert_expressions() -> list[tuple[str, str]]:
    """``(alert name, expr)`` for every rule Prometheus would actually load."""
    document = yaml.safe_load(ALERTS.read_text(encoding="utf-8"))
    return [
        (rule["alert"], rule["expr"]) for group in document["groups"] for rule in group["rules"]
    ]


def dashboard_expressions() -> list[tuple[str, str]]:
    """``(panel title, expr)`` for every target in every shipped dashboard."""
    out: list[tuple[str, str]] = []
    for path in sorted(GRAFANA.glob("*.json")):
        board = json.loads(path.read_text(encoding="utf-8"))
        for panel in board.get("panels", []):
            for target in panel.get("targets", []):
                if target.get("expr"):
                    out.append((f"{path.name}: {panel.get('title')}", target["expr"]))
    return out


def _produced() -> set[str]:
    _require(METRICS_MODULE)
    declared = declared_metrics(METRICS_MODULE)
    assert len(declared) > 10, f"only {len(declared)} metrics parsed out of {METRICS_MODULE}"
    return written_metrics(APP, declared)


def _base_name(name: str, produced: set[str]) -> str:
    for suffix in _EXPOSITION_SUFFIXES:
        if name.endswith(suffix) and name[: -len(suffix)] in produced:
            return name[: -len(suffix)]
    return name


def _assert_all_produced(pairs: list[tuple[str, str]], what: str) -> None:
    produced = _produced() | _backup_produced()
    dead = sorted(
        (owner, name)
        for owner, expr in pairs
        for name in _metrics_in(expr)
        if _base_name(name, produced) not in produced
    )
    assert not dead, (
        f"{what} reads metric(s) that no code under app/ ever writes. A declared-"
        "but-never-incremented prometheus_client metric is still registered and "
        "still scraped, so the expression evaluates against an empty family "
        f"forever and can never fire: {dead}"
    )


def test_writer_detection_distinguishes_written_from_merely_declared(tmp_path: Path) -> None:
    """Non-vacuity: prove the detector is not simply answering "written" to all.

    A broken ``_writes_in`` would make every assertion below pass against any
    artefact at all, which is the same failure mode as the alerts this file
    exists to catch.
    """
    core = tmp_path / "app" / "core"
    core.mkdir(parents=True)
    (core / "metrics.py").write_text(
        'live: Counter = Counter("freesdn_live_total", "d", ["a"])\n'
        'dead: Gauge = Gauge("freesdn_dead", "d")\n'
        "# dead.set(1) in a comment must not count as a producer\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "user.py").write_text(
        "from app.core.metrics import live\n"
        "\n"
        "\n"
        "def f() -> None:\n"
        '    """dead.set(2) in a docstring must not count either."""\n'
        '    live.labels(a="x").inc()\n',
        encoding="utf-8",
    )
    declared = declared_metrics(core / "metrics.py")
    assert declared == {"live": "freesdn_live_total", "dead": "freesdn_dead"}
    assert written_metrics(tmp_path / "app", declared) == {"freesdn_live_total"}


def test_every_alert_expression_reads_a_metric_something_writes() -> None:
    _require(ALERTS)
    rules = alert_expressions()
    assert len(rules) > 5, f"only {len(rules)} alert rules parsed out of {ALERTS}"
    assert {name for _alert, expr in rules for name in _metrics_in(expr)}, (
        "no freesdn_* metric found in any alert expr; the extractor broke"
    )
    _assert_all_produced(rules, "alerts.yml")


def test_every_dashboard_expression_reads_a_metric_something_writes() -> None:
    _require(GRAFANA)
    panels = dashboard_expressions()
    assert panels, f"no panel targets parsed out of {GRAFANA}"
    assert {name for _panel, expr in panels for name in _metrics_in(expr)}, (
        "no freesdn_* metric found in any panel expr; the extractor broke"
    )
    _assert_all_produced(panels, "the Grafana dashboards")


def test_non_backend_metrics_are_emitted_by_the_scraped_backup_exporter() -> None:
    _require(ALERTS)
    _require(GRAFANA)
    produced = _produced()
    used = {
        name
        for _owner, expr in [*alert_expressions(), *dashboard_expressions()]
        for name in _metrics_in(expr)
    }
    external = {name for name in used if _base_name(name, produced) not in produced}
    assert external == _backup_produced()
    _require(COMPOSE)
    compose = yaml.safe_load(COMPOSE.read_text())
    assert "backup-metrics" in compose["services"]
    scrape = yaml.safe_load((FREESDN_DIR / "docker/prometheus/prometheus.yml").read_text())
    job = next(job for job in scrape["scrape_configs"] if job["job_name"] == "freesdn-backups")
    assert job["static_configs"] == [{"targets": ["backup-metrics:9788"]}]
