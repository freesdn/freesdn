# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The shipped Grafana dashboard and the shipped Prometheus config must agree.

``docker/prometheus/prometheus.yml`` declares ``job_name: freesdn-api`` for the
FreeSDN target, with no ``relabel_configs`` to rewrite it. The dashboard's three
HTTP panels hard-coded ``job="freesdn"``, and its ``templating.list`` held only
a datasource variable -- there was no ``job`` variable that could supply a
different value, so the selector was fixed and matched nothing. An operator who
enabled the ``metrics`` compose profile and imported "FreeSDN Overview" got
"No data" on HTTP request rate, HTTP error rate and HTTP latency, and the
dashboard's own description told them to check their scrape config, so they
debugged a Prometheus that was in fact correct.

``alerts.yml`` in the same directory already used the right value
(``up{job="freesdn-api"}``), so the two shipped artefacts disagreed with each
other -- which is the part a pure text assertion can gate, in-repo, forever.

Placed under tests/tasks/ next to the existing alerts.yml assertions in
test_backup_validate_restore.py, which resolve ``observability/`` the same way
(and which is why ci-gate.sh mounts that tree at /observability).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

# tests/tasks/ -> backend/ -> freesdn/
FREESDN_DIR = Path(__file__).resolve().parents[3]
OBSERVABILITY = FREESDN_DIR / "observability"
DASHBOARD = OBSERVABILITY / "grafana" / "freesdn-overview.json"
ALERTS = OBSERVABILITY / "prometheus" / "alerts.yml"
SCRAPE_CONFIG = FREESDN_DIR / "docker" / "prometheus" / "prometheus.yml"

_JOB_SELECTOR = re.compile(r'job\s*=~?\s*"([^"]+)"')


def _dashboard() -> dict[str, Any]:
    if not DASHBOARD.is_file():
        pytest.skip(f"observability tree not mounted ({DASHBOARD})")
    return json.loads(DASHBOARD.read_text(encoding="utf-8"))


def _panel_exprs(dashboard: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (str(panel.get("title")), target["expr"])
        for panel in dashboard.get("panels", [])
        for target in panel.get("targets", [])
        if target.get("expr")
    ]


def _declared_scrape_jobs() -> set[str] | None:
    """Job names from the shipped scrape config, or None when it is unreachable.

    ci-gate.sh mounts only backend/ + observability/, so docker/ is absent
    there. The dashboard-vs-alerts check below does not depend on this and
    stays a hard gate in every environment.
    """
    if not SCRAPE_CONFIG.is_file():
        return None
    config = yaml.safe_load(SCRAPE_CONFIG.read_text(encoding="utf-8"))
    return {job["job_name"] for job in config.get("scrape_configs", [])}


def test_dashboard_job_selector_is_a_variable_not_a_literal() -> None:
    """A hard-coded job name is wrong for anyone who re-hosts the scrape.

    Mutation this catches: put ``job="freesdn"`` (or any other literal) back
    into a panel expression -- the whole class, not just the one wrong value.
    """
    dashboard = _dashboard()
    literals = [
        (title, match)
        for title, expr in _panel_exprs(dashboard)
        for match in _JOB_SELECTOR.findall(expr)
        if not match.startswith("$")
    ]
    assert not literals, (
        "Panel(s) select a literal job name. Prometheus labels every sample "
        "with the job_name that scraped it, which an operator is free to "
        "change, so the dashboard must read it from a template variable:\n"
        + "\n".join(f"  {title!r}: job={value!r}" for title, value in literals)
    )


def test_dashboard_declares_the_job_variable_it_selects_on() -> None:
    """``$job`` with no matching templating entry renders as literally "$job".

    Mutation this catches: delete the ``job`` variable from templating.list
    while leaving ``job="$job"`` in the panels -- every HTTP panel silently
    goes back to "No data", the exact original symptom.
    """
    dashboard = _dashboard()
    declared = {var["name"] for var in dashboard.get("templating", {}).get("list", [])}
    used = {
        match.lstrip("$").strip("{}")
        for _title, expr in _panel_exprs(dashboard)
        for match in _JOB_SELECTOR.findall(expr)
        if match.startswith("$")
    }
    assert used <= declared, (
        f"Panel expressions select on {sorted(used - declared)}, which "
        f"templating.list does not declare (it has {sorted(declared)})."
    )


def test_dashboard_default_job_matches_the_shipped_alert_rules() -> None:
    """Both artefacts ship together; they must name the same job out of the box.

    This is the always-on half: alerts.yml and the dashboard both live under
    observability/, so it holds even where docker/ is not mounted.
    """
    dashboard = _dashboard()
    job_var = next(
        (v for v in dashboard.get("templating", {}).get("list", []) if v["name"] == "job"),
        None,
    )
    assert job_var is not None, "dashboard has no 'job' template variable"
    default = job_var["current"]["value"]

    if not ALERTS.is_file():
        pytest.skip(f"alerts.yml not reachable ({ALERTS})")
    alert_jobs = set(_JOB_SELECTOR.findall(ALERTS.read_text(encoding="utf-8")))
    assert alert_jobs, "no job selector left in alerts.yml to compare against"
    assert default in alert_jobs, (
        f"the dashboard defaults to job={default!r} while alerts.yml selects "
        f"{sorted(alert_jobs)}. The two shipped artefacts must agree, or one of "
        f"them silently matches nothing on a stock install."
    )


def test_every_job_name_used_under_observability_is_actually_scraped() -> None:
    """Close the loop against the scrape config when it is reachable."""
    declared = _declared_scrape_jobs()
    if declared is None:
        pytest.skip(f"scrape config not reachable ({SCRAPE_CONFIG}); backend-only mount")

    used: set[str] = set()
    for path in OBSERVABILITY.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix in {".yml", ".yaml"}:
            used |= set(_JOB_SELECTOR.findall(path.read_text(encoding="utf-8")))
        elif path.suffix == ".json":
            # Parse rather than regex the raw bytes: a Grafana expr stores the
            # selector as job=\"...\", so a text scan silently finds nothing
            # and the check passes on a dashboard it never actually read.
            board = json.loads(path.read_text(encoding="utf-8"))
            for _title, expr in _panel_exprs(board):
                used |= set(_JOB_SELECTOR.findall(expr))
            # Template DEFAULTS are literals too, and must resolve.
            for var in board.get("templating", {}).get("list", []):
                if var["name"] == "job":
                    used.add(str(var["current"]["value"]))
    used = {job for job in used if not job.startswith("$")}

    assert used <= declared, (
        f"observability/ selects job(s) {sorted(used - declared)} that "
        f"docker/prometheus/prometheus.yml never declares "
        f"(it ships {sorted(declared)}); those queries return no data."
    )
