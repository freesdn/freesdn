#!/usr/bin/env python3
# =============================================================================
# FreeSDN HA Failover Drill
# =============================================================================
"""Run a controlled failover drill against the HA stack and emit evidence.

Scenarios:
    primary_kill   — docker-kill the postgres primary; observe API recovery
                     (depends on app retry + standby promotion). Default.
    redis_kill     — kill the redis master; observe sentinel-led failover.
    api_kill       — kill one API pod; observe LB drain.

Usage:
    python scripts/ha_drill.py --scenario primary_kill \
        --lb-url http://127.0.0.1:18080 \
        --report-dir drills/

Outputs:
    drills/<scenario>-<UTC-iso>/report.json
    drills/<scenario>-<UTC-iso>/report.md
    drills/<scenario>-<UTC-iso>/health-timeline.csv

Exit codes:
    0  drill completed AND RTO under the configured budget
    1  drill completed but RTO exceeded budget
    2  drill could not run (precondition failed)
    3  unexpected error

This script is intentionally side-effect-only on the test stack — it
does NOT touch production. It refuses to run if the LB URL points at
a non-loopback / non-private address (paranoid guard against running
in prod by accident).
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOG = logging.getLogger("ha_drill")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class DrillConfig:
    scenario: str
    lb_url: str
    report_dir: Path
    # Time budgets (seconds). A drill that exceeds these is FAILED.
    rto_budget_sec: float = 60.0
    # How long to keep probing after kill before declaring "never recovered".
    max_wait_sec: float = 180.0
    # Health-probe cadence.
    probe_interval_sec: float = 0.5
    # docker-compose project name (used for container resolution if needed).
    compose_project: str = ""
    # Override container names per scenario (helps tests inject fakes).
    primary_container: str = "freesdn-postgres"
    redis_container: str = "freesdn-redis"
    api_container: str = "freesdn-api"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ProbeSample:
    """One health probe data point."""
    t_offset_sec: float
    status: str  # "ok" / "degraded" / "down" / "error"
    http_code: int | None
    latency_ms: float | None


@dataclass
class DrillResult:
    scenario: str
    started_at: str
    finished_at: str
    duration_sec: float
    target_container: str
    kill_at_t_sec: float
    first_failure_t_sec: float | None
    first_recovery_t_sec: float | None
    rto_sec: float | None
    rto_budget_sec: float
    passed: bool
    failed_request_count: int
    total_request_count: int
    samples: list[ProbeSample] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Safety guards — never run against prod
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_safe_target(lb_url: str) -> None:
    """Refuse to run against anything that doesn't look like a lab box.

    Drills KILL containers. Doing that against prod by typo would be a
    full outage. We explicitly require the LB to be on loopback or an
    RFC1918 address; anything else aborts with exit-code 2.
    """
    parsed = urllib.parse.urlparse(lb_url)
    host = parsed.hostname or ""
    if host in _ALLOWED_HOSTS:
        return
    # Try to resolve to an IP and check RFC1918 / link-local.
    try:
        info = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SystemExit(
            f"ha_drill: refusing to run — could not resolve {host!r}: {exc}",
        ) from exc

    for fam, _typ, _proto, _canon, addr in info:
        ip_str = addr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise SystemExit(
                f"ha_drill: refusing to run against non-private host "
                f"{host} ({ip_str}). Drills kill containers — use a lab box.",
            )


# ---------------------------------------------------------------------------
# Health probes
# ---------------------------------------------------------------------------

def probe_health(lb_url: str, *, timeout: float = 3.0) -> ProbeSample:
    """One health probe — hits /api/v1/health/ready (deep check)."""
    url = lb_url.rstrip("/") + "/api/v1/health/ready"
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            code = resp.getcode()
            elapsed_ms = (time.monotonic() - started) * 1000
            return ProbeSample(
                t_offset_sec=0.0,  # caller overwrites
                status="ok" if code == 200 else "degraded",
                http_code=code,
                latency_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        return ProbeSample(
            t_offset_sec=0.0,
            status="degraded" if exc.code < 500 else "down",
            http_code=exc.code,
            latency_ms=elapsed_ms,
        )
    except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError):
        elapsed_ms = (time.monotonic() - started) * 1000
        return ProbeSample(
            t_offset_sec=0.0, status="down",
            http_code=None, latency_ms=elapsed_ms,
        )
    except Exception as exc:  # noqa: BLE001 — defensive
        LOG.exception("probe_health unexpected error: %s", exc)
        return ProbeSample(
            t_offset_sec=0.0, status="error",
            http_code=None, latency_ms=None,
        )


# ---------------------------------------------------------------------------
# Failure injection
# ---------------------------------------------------------------------------

class DockerNotAvailable(RuntimeError):
    """Raised when ``docker`` is missing or not in PATH."""


def kill_container(name: str) -> None:
    """SIGKILL a container by name via docker CLI.

    Why SIGKILL not stop: stop sends SIGTERM and waits up to 10s for
    graceful shutdown. The point of the drill is to simulate a CRASH,
    not a graceful restart — applications behave very differently
    under the two and the crash path is the one ops sees in incidents.
    """
    if shutil.which("docker") is None:
        raise DockerNotAvailable("docker CLI not found in PATH")
    LOG.info("Killing container: %s", name)
    result = subprocess.run(
        ["docker", "kill", name],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker kill {name} failed: {result.stderr.strip()}",
        )


def scenario_target(cfg: DrillConfig) -> str:
    """Map scenario name → container to kill."""
    if cfg.scenario == "primary_kill":
        return cfg.primary_container
    if cfg.scenario == "redis_kill":
        return cfg.redis_container
    if cfg.scenario == "api_kill":
        return cfg.api_container
    raise SystemExit(f"ha_drill: unknown scenario {cfg.scenario!r}")


# ---------------------------------------------------------------------------
# Drill runner
# ---------------------------------------------------------------------------

def run_drill(
    cfg: DrillConfig,
    *,
    inject: callable = kill_container,
    probe: callable = probe_health,
    clock: callable = time.monotonic,
    sleep: callable = time.sleep,
) -> DrillResult:
    """Execute the drill and return a DrillResult.

    The hooks (``inject``, ``probe``, ``clock``, ``sleep``) are injected
    so tests can drive deterministic timelines without touching real
    docker or sockets.
    """
    target = scenario_target(cfg)
    started_dt = datetime.now(UTC)
    started_mono = clock()
    samples: list[ProbeSample] = []
    notes: list[str] = []

    def _probe_at(t_offset: float) -> ProbeSample:
        s = probe(cfg.lb_url)
        s.t_offset_sec = round(t_offset, 3)
        samples.append(s)
        return s

    # ─── Phase 1: baseline — must be healthy before we kill anything ─────
    LOG.info("Phase 1: baseline health check")
    baseline = _probe_at(clock() - started_mono)
    if baseline.status != "ok":
        notes.append(
            f"baseline NOT healthy ({baseline.status} / code={baseline.http_code}) "
            f"— refusing to inject failure"
        )
        return _finalize(
            cfg, target, started_dt, started_mono, clock(), samples, notes,
            kill_at=None, first_fail=None, first_recovery=None, passed=False,
        )

    # ─── Phase 2: inject failure ──────────────────────────────────────────
    kill_t = clock() - started_mono
    LOG.info("Phase 2: injecting failure on %s at t=%.2fs", target, kill_t)
    try:
        inject(target)
    except DockerNotAvailable as exc:
        notes.append(f"could not inject: {exc}")
        return _finalize(
            cfg, target, started_dt, started_mono, clock(), samples, notes,
            kill_at=kill_t, first_fail=None, first_recovery=None, passed=False,
        )
    except Exception as exc:  # noqa: BLE001 — record + bail
        notes.append(f"inject raised: {exc!r}")
        return _finalize(
            cfg, target, started_dt, started_mono, clock(), samples, notes,
            kill_at=kill_t, first_fail=None, first_recovery=None, passed=False,
        )

    # ─── Phase 3: observe failure → recovery ──────────────────────────────
    first_fail_t: float | None = None
    first_recovery_t: float | None = None

    while True:
        t_off = clock() - started_mono
        if t_off > cfg.max_wait_sec:
            notes.append(f"max_wait_sec={cfg.max_wait_sec} exceeded without recovery")
            break

        s = _probe_at(t_off)
        if first_fail_t is None and s.status != "ok":
            first_fail_t = t_off
            LOG.info("First failed probe at t=%.2fs (code=%s)", t_off, s.http_code)

        if first_fail_t is not None and s.status == "ok":
            first_recovery_t = t_off
            LOG.info("Recovered at t=%.2fs", t_off)
            break

        sleep(cfg.probe_interval_sec)

    return _finalize(
        cfg, target, started_dt, started_mono, clock(), samples, notes,
        kill_at=kill_t, first_fail=first_fail_t, first_recovery=first_recovery_t,
        passed=None,  # decided below
    )


def _finalize(
    cfg: DrillConfig,
    target: str,
    started_dt: datetime,
    started_mono: float,
    end_mono: float,
    samples: list[ProbeSample],
    notes: list[str],
    *,
    kill_at: float | None,
    first_fail: float | None,
    first_recovery: float | None,
    passed: bool | None,
) -> DrillResult:
    duration = end_mono - started_mono
    rto = (first_recovery - kill_at) if (first_recovery is not None and kill_at is not None) else None

    if passed is None:
        passed = bool(
            kill_at is not None
            and rto is not None
            and rto <= cfg.rto_budget_sec
        )

    failed_count = sum(1 for s in samples if s.status != "ok")
    return DrillResult(
        scenario=cfg.scenario,
        started_at=started_dt.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
        duration_sec=round(duration, 3),
        target_container=target,
        kill_at_t_sec=round(kill_at, 3) if kill_at is not None else -1.0,
        first_failure_t_sec=round(first_fail, 3) if first_fail is not None else None,
        first_recovery_t_sec=round(first_recovery, 3) if first_recovery is not None else None,
        rto_sec=round(rto, 3) if rto is not None else None,
        rto_budget_sec=cfg.rto_budget_sec,
        passed=passed,
        failed_request_count=failed_count,
        total_request_count=len(samples),
        samples=samples,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def write_reports(result: DrillResult, out_dir: Path) -> None:
    """Emit report.json + report.md + health-timeline.csv."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON — machine-readable, includes every sample
    (out_dir / "report.json").write_text(
        json.dumps(asdict(result), indent=2, default=str),
    )

    # CSV — timeline for spreadsheet/Grafana
    with (out_dir / "health-timeline.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_offset_sec", "status", "http_code", "latency_ms"])
        for s in result.samples:
            w.writerow([s.t_offset_sec, s.status, s.http_code, s.latency_ms])

    # Markdown — operator-facing summary
    (out_dir / "report.md").write_text(_markdown_report(result))


def _markdown_report(r: DrillResult) -> str:
    verdict = "PASS" if r.passed else "FAIL"
    rto_str = f"{r.rto_sec:.2f}s" if r.rto_sec is not None else "n/a (no recovery)"
    notes_section = (
        "\n".join(f"- {n}" for n in r.notes) if r.notes else "_(none)_"
    )
    return (
        f"# HA Failover Drill — {r.scenario}\n\n"
        f"**Verdict:** {verdict}\n\n"
        f"| | |\n"
        f"|---|---|\n"
        f"| Started | {r.started_at} |\n"
        f"| Finished | {r.finished_at} |\n"
        f"| Duration | {r.duration_sec:.2f}s |\n"
        f"| Target | `{r.target_container}` |\n"
        f"| Killed at | t+{r.kill_at_t_sec:.2f}s |\n"
        f"| First failure | t+{r.first_failure_t_sec}s |\n"
        f"| First recovery | t+{r.first_recovery_t_sec}s |\n"
        f"| **RTO measured** | **{rto_str}** |\n"
        f"| RTO budget | {r.rto_budget_sec:.0f}s |\n"
        f"| Failed probes | {r.failed_request_count} / {r.total_request_count} |\n"
        f"\n## Notes\n\n{notes_section}\n"
        f"\nSee `health-timeline.csv` for the full per-probe timeline.\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="FreeSDN HA failover drill")
    p.add_argument("--scenario", choices=("primary_kill", "redis_kill", "api_kill"),
                   default="primary_kill")
    p.add_argument("--lb-url", default="http://127.0.0.1:18080",
                   help="HA-LB URL (must be loopback / private)")
    p.add_argument("--report-dir", default="drills",
                   help="Where to write report.json / report.md / health-timeline.csv")
    p.add_argument("--rto-budget", type=float, default=60.0,
                   help="RTO budget in seconds (drill fails if exceeded)")
    p.add_argument("--max-wait", type=float, default=180.0,
                   help="Max seconds to wait for recovery before giving up")
    p.add_argument("--probe-interval", type=float, default=0.5,
                   help="Health probe cadence in seconds")
    p.add_argument("--primary-container", default="freesdn-postgres")
    p.add_argument("--redis-container", default="freesdn-redis")
    p.add_argument("--api-container", default="freesdn-api")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    assert_safe_target(args.lb_url)

    cfg = DrillConfig(
        scenario=args.scenario,
        lb_url=args.lb_url,
        report_dir=Path(args.report_dir),
        rto_budget_sec=args.rto_budget,
        max_wait_sec=args.max_wait,
        probe_interval_sec=args.probe_interval,
        primary_container=args.primary_container,
        redis_container=args.redis_container,
        api_container=args.api_container,
    )

    result = run_drill(cfg)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = cfg.report_dir / f"{cfg.scenario}-{timestamp}"
    write_reports(result, out_dir)

    LOG.info("Report written to %s", out_dir)
    LOG.info("Verdict: %s — RTO=%s budget=%.1fs",
             "PASS" if result.passed else "FAIL",
             f"{result.rto_sec:.2f}s" if result.rto_sec is not None else "n/a",
             result.rto_budget_sec)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
