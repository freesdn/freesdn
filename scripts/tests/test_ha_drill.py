"""Tests for the HA failover drill harness.

The drill talks to Docker and a live HTTP endpoint in production; here we
drive it with fake ``inject``/``probe``/``clock``/``sleep`` hooks so the
timeline is deterministic. This pins the report shape + the RTO math +
the pass/fail verdict semantics that operators will read off the
generated report.md.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

import pytest

# Make ``scripts/`` importable without installing the harness as a package.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))

import ha_drill  # noqa: E402


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------

class _Clock:
    """Deterministic monotonic clock the test can advance manually."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, sec: float) -> None:
        self.now += sec


def _cfg(tmp_path: Path, **overrides) -> ha_drill.DrillConfig:
    base = dict(
        scenario="primary_kill",
        lb_url="http://127.0.0.1:18080",
        report_dir=tmp_path,
        rto_budget_sec=10.0,
        max_wait_sec=30.0,
        probe_interval_sec=0.5,
    )
    base.update(overrides)
    return ha_drill.DrillConfig(**base)


def _scripted_probes(statuses: list[str]) -> Iterator[ha_drill.ProbeSample]:
    """Yield ProbeSamples with the given statuses in order."""
    for st in statuses:
        yield ha_drill.ProbeSample(
            t_offset_sec=0.0,
            status=st,
            http_code=200 if st == "ok" else 503,
            latency_ms=12.3,
        )


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------

class TestSafetyGuard:
    def test_loopback_allowed(self) -> None:
        ha_drill.assert_safe_target("http://127.0.0.1:8080")
        ha_drill.assert_safe_target("http://localhost:8080")

    def test_rfc1918_allowed(self) -> None:
        ha_drill.assert_safe_target("http://192.168.1.150")
        ha_drill.assert_safe_target("http://10.0.0.1:8000")

    def test_public_address_rejected(self) -> None:
        with pytest.raises(SystemExit) as e:
            ha_drill.assert_safe_target("http://8.8.8.8")
        assert "refusing" in str(e.value)

    def test_unresolvable_host_rejected(self) -> None:
        with pytest.raises(SystemExit):
            ha_drill.assert_safe_target(
                "http://nonexistent-host-that-must-not-resolve.invalid",
            )


# ---------------------------------------------------------------------------
# Scenario target resolution
# ---------------------------------------------------------------------------

class TestScenarioTarget:
    def test_primary_kill_targets_postgres(self, tmp_path) -> None:
        cfg = _cfg(tmp_path, scenario="primary_kill")
        assert ha_drill.scenario_target(cfg) == "freesdn-postgres"

    def test_redis_kill_targets_redis(self, tmp_path) -> None:
        cfg = _cfg(tmp_path, scenario="redis_kill")
        assert ha_drill.scenario_target(cfg) == "freesdn-redis"

    def test_api_kill_targets_api(self, tmp_path) -> None:
        cfg = _cfg(tmp_path, scenario="api_kill")
        assert ha_drill.scenario_target(cfg) == "freesdn-api"

    def test_unknown_scenario_exits(self, tmp_path) -> None:
        cfg = _cfg(tmp_path)
        cfg.scenario = "rmrf"
        with pytest.raises(SystemExit):
            ha_drill.scenario_target(cfg)


# ---------------------------------------------------------------------------
# Drill runner — RTO math + verdict
# ---------------------------------------------------------------------------

class TestRunDrill:
    def test_clean_recovery_within_budget_passes(self, tmp_path) -> None:
        """Baseline ok → kill → 2 failed probes → recovered → PASS.

        Timeline (advance per probe): baseline ok @ 0s,
        kill at 0.5s, fail at 1.0s, fail at 1.5s, recover at 2.0s.
        RTO = 2.0 - 0.5 = 1.5s ≤ 10s budget → PASS.
        """
        clock = _Clock()
        probes = _scripted_probes(["ok", "down", "down", "ok"])
        injected: list[str] = []

        def fake_inject(name: str) -> None:
            injected.append(name)
            clock.advance(0.5)  # kill takes some time

        def fake_probe(_url: str) -> ha_drill.ProbeSample:
            clock.advance(0.5)  # each probe takes some time
            return next(probes)

        def fake_sleep(_s: float) -> None:
            # Don't really sleep; clock advances inside fake_probe.
            return None

        cfg = _cfg(tmp_path)
        result = ha_drill.run_drill(
            cfg, inject=fake_inject, probe=fake_probe,
            clock=clock, sleep=fake_sleep,
        )

        assert injected == ["freesdn-postgres"]
        assert result.passed is True
        assert result.rto_sec is not None
        assert result.rto_sec <= cfg.rto_budget_sec
        # 4 samples taken: baseline + 3 post-kill
        assert result.total_request_count == 4
        assert result.failed_request_count == 2

    def test_rto_exceeds_budget_fails(self, tmp_path) -> None:
        """Recovery happens, but past the budget → FAIL verdict."""
        clock = _Clock()
        # 1 baseline + many down + final ok
        n_down = 30
        statuses = ["ok"] + ["down"] * n_down + ["ok"]
        probes = _scripted_probes(statuses)

        def fake_inject(_name: str) -> None:
            clock.advance(0.1)

        def fake_probe(_url: str) -> ha_drill.ProbeSample:
            clock.advance(0.5)
            return next(probes)

        cfg = _cfg(tmp_path, rto_budget_sec=5.0)
        result = ha_drill.run_drill(
            cfg, inject=fake_inject, probe=fake_probe,
            clock=clock, sleep=lambda _s: None,
        )
        assert result.rto_sec is not None
        assert result.rto_sec > cfg.rto_budget_sec
        assert result.passed is False

    def test_never_recovers_marks_failure(self, tmp_path) -> None:
        """Eternal down → loop exits at max_wait_sec, no recovery, FAIL."""
        clock = _Clock()
        probes = _scripted_probes(["ok"] + ["down"] * 1000)

        def fake_inject(_name: str) -> None:
            clock.advance(0.1)

        def fake_probe(_url: str) -> ha_drill.ProbeSample:
            clock.advance(0.5)
            return next(probes)

        cfg = _cfg(tmp_path, max_wait_sec=5.0)
        result = ha_drill.run_drill(
            cfg, inject=fake_inject, probe=fake_probe,
            clock=clock, sleep=lambda _s: None,
        )
        assert result.first_recovery_t_sec is None
        assert result.rto_sec is None
        assert result.passed is False
        assert any("max_wait_sec" in n for n in result.notes)

    def test_baseline_unhealthy_aborts(self, tmp_path) -> None:
        """If the stack isn't healthy BEFORE we inject, refuse to kill."""
        injected: list[str] = []

        def fake_inject(name: str) -> None:
            injected.append(name)  # must NOT be called

        probes = _scripted_probes(["down"])  # baseline is down
        def fake_probe(_url: str) -> ha_drill.ProbeSample:
            return next(probes)

        cfg = _cfg(tmp_path)
        result = ha_drill.run_drill(
            cfg, inject=fake_inject, probe=fake_probe,
            clock=_Clock(), sleep=lambda _s: None,
        )
        assert injected == []
        assert result.passed is False
        assert any("baseline NOT healthy" in n for n in result.notes)

    def test_docker_unavailable_records_note(self, tmp_path) -> None:
        """When docker isn't on the box, capture that in the note —
        operator can fix the precondition and re-run."""
        probes = _scripted_probes(["ok"])
        def fake_probe(_url: str) -> ha_drill.ProbeSample:
            return next(probes)

        def fake_inject(_name: str) -> None:
            raise ha_drill.DockerNotAvailable("docker CLI not found")

        cfg = _cfg(tmp_path)
        result = ha_drill.run_drill(
            cfg, inject=fake_inject, probe=fake_probe,
            clock=_Clock(), sleep=lambda _s: None,
        )
        assert result.passed is False
        assert any("docker" in n.lower() for n in result.notes)


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

class TestReportWriters:
    def test_writes_all_three_files(self, tmp_path) -> None:
        result = ha_drill.DrillResult(
            scenario="primary_kill",
            started_at="2026-05-24T00:00:00+00:00",
            finished_at="2026-05-24T00:00:30+00:00",
            duration_sec=30.0,
            target_container="freesdn-postgres",
            kill_at_t_sec=1.0,
            first_failure_t_sec=1.5,
            first_recovery_t_sec=4.2,
            rto_sec=3.2,
            rto_budget_sec=10.0,
            passed=True,
            failed_request_count=5,
            total_request_count=20,
            samples=[
                ha_drill.ProbeSample(0.0, "ok", 200, 12.0),
                ha_drill.ProbeSample(1.5, "down", None, None),
                ha_drill.ProbeSample(4.2, "ok", 200, 15.0),
            ],
            notes=["baseline healthy"],
        )
        out = tmp_path / "drill1"
        ha_drill.write_reports(result, out)

        assert (out / "report.json").exists()
        assert (out / "report.md").exists()
        assert (out / "health-timeline.csv").exists()

        data = json.loads((out / "report.json").read_text())
        assert data["scenario"] == "primary_kill"
        assert data["passed"] is True
        assert data["rto_sec"] == 3.2

        md = (out / "report.md").read_text()
        assert "PASS" in md
        assert "freesdn-postgres" in md
        assert "3.20s" in md  # formatted rto

    def test_fail_verdict_renders_in_md(self, tmp_path) -> None:
        result = ha_drill.DrillResult(
            scenario="primary_kill",
            started_at="2026-05-24T00:00:00+00:00",
            finished_at="2026-05-24T00:01:00+00:00",
            duration_sec=60.0,
            target_container="freesdn-postgres",
            kill_at_t_sec=1.0,
            first_failure_t_sec=1.5,
            first_recovery_t_sec=None,
            rto_sec=None,
            rto_budget_sec=10.0,
            passed=False,
            failed_request_count=120,
            total_request_count=121,
            samples=[],
            notes=["max_wait_sec=60 exceeded without recovery"],
        )
        out = tmp_path / "drill_fail"
        ha_drill.write_reports(result, out)
        md = (out / "report.md").read_text()
        assert "FAIL" in md
        assert "n/a (no recovery)" in md
        assert "max_wait_sec" in md
