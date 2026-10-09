#!/usr/bin/env python3
"""
FreeSDN Self-Healing Watchdog (v2)
==================================
Cross-container health supervision + auto-recovery for the FreeSDN Docker stack.

Docker's ``restart: unless-stopped`` already supervises individual containers.
This watchdog adds what Docker can't: cross-service reasoning, crash-loop
detection with exponential backoff, dependency-aware healing, OOM/disk
diagnosis, and escalation/alerting when remediation fails.

Tier/profile aware — it DISCOVERS the running containers from `docker compose ps`
rather than hard-coding names, so it works for any tier (lite/pro/max), the dev
overlay, and the HA overlay, including profile services (edge, worker-io,
pgbouncer, go2rtc, the HA replica/sentinels/LB).

Usage:
  python scripts/selfheal.py --tier pro --status      # one-shot status
  python scripts/selfheal.py --tier pro --check        # wait-for-healthy, exit 0/1
  python scripts/selfheal.py --tier pro --monitor      # continuous self-healing (daemon)
  python scripts/selfheal.py --tier max --ha --monitor # supervise the HA topology
  python scripts/selfheal.py --dev --monitor           # dev overlay
  python scripts/selfheal.py --env-file .env.pro --restart

  Stack target (pick one; default: .env if present, else --tier required):
    --tier lite|pro|max   use .env.<tier> + docker-compose.yml
    --dev                 add docker-compose.dev.yml + .env.dev
    --ha                  add docker-compose.ha.yml
    --env-file PATH       explicit env file
    --project NAME        override the compose project name

Escalation: set SELFHEAL_WEBHOOK to a URL to receive a JSON POST when a service
crash-loops or exhausts restarts.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Force UTF-8 output on Windows (box-drawing chars otherwise crash cp1252).
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

# ─── Tunables ─────────────────────────────────────────────────────────────────
MONITOR_INTERVAL = 30          # seconds between monitor cycles
HEALTH_CHECK_INTERVAL = 5      # seconds between --check polls
MAX_HEALTH_RETRIES = 60        # --check / wait-for-healthy attempts
BACKOFF_BASE = 5               # seconds; per-service heal backoff base
BACKOFF_CAP = 300              # seconds; max backoff
CRASH_LOOP_THRESHOLD = 5       # restarts within the window → quarantine
CRASH_LOOP_WINDOW = 600        # seconds

# Infra services are healed BEFORE the app tier that depends on them. Matched by
# substring against the compose SERVICE name (tier/profile agnostic).
INFRA_HINTS = ("postgres", "logdb", "redis", "pgbouncer", "sentinel")
# Services without a Docker healthcheck that are still "ok" when merely running.
# (Discovery reads the real healthcheck state; this is only the fallback.)

# ─── Colors / logging ───────────────────────────────────────────────────────
class C:
    if platform.system() == "Windows":
        os.system("")
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"


def _log(icon: str, msg: str, color: str = "") -> None:
    ts = time.strftime("%H:%M:%S")
    print(f" {C.DIM}{ts}{C.RESET}  {icon}  {color}{msg}{C.RESET}")


def log_ok(m: str) -> None: _log("✅", m, C.GREEN)
def log_warn(m: str) -> None: _log("⚠️ ", m, C.YELLOW)
def log_err(m: str) -> None: _log("❌", m, C.RED)
def log_info(m: str) -> None: _log("ℹ️ ", m, C.CYAN)
def log_action(m: str) -> None: _log("🔧", m, C.MAGENTA)


def banner(title: str) -> None:
    w = 64
    print(f"\n {C.BOLD}{C.BLUE}{'═' * w}{C.RESET}")
    print(f" {C.BOLD}{C.BLUE}║{C.RESET} {C.BOLD}{title.center(w - 4)}{C.RESET} {C.BOLD}{C.BLUE}║{C.RESET}")
    print(f" {C.BOLD}{C.BLUE}{'═' * w}{C.RESET}\n")


# ─── Shell ────────────────────────────────────────────────────────────────────
def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"not found: {cmd[0]}")


def docker_available() -> bool:
    return run(["docker", "info"], timeout=15).returncode == 0


# ─── Compose target resolution ────────────────────────────────────────────────
@dataclass
class Target:
    """How to invoke `docker compose` for the chosen tier/overlay."""
    compose_args: list[str]              # e.g. ["--env-file", ".env.pro", "-f", "docker-compose.yml"]
    label: str

    def compose(self, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        return run(["docker", "compose", *self.compose_args, *args], timeout=timeout)


def resolve_target(ns: argparse.Namespace) -> Target:
    files = ["-f", "docker-compose.yml"]
    env_file: Optional[str] = None
    label_bits: list[str] = []

    if ns.env_file:
        env_file = ns.env_file
        label_bits.append(Path(env_file).name)
    elif ns.dev:
        env_file = ".env.dev"
        label_bits.append("dev")
    elif ns.tier:
        env_file = f".env.{ns.tier}"
        label_bits.append(ns.tier)
    elif (PROJECT_DIR / ".env").exists():
        env_file = ".env"
        label_bits.append("env")

    if ns.dev:
        files += ["-f", "docker-compose.dev.yml"]
    if ns.ha:
        files += ["-f", "docker-compose.ha.yml"]
        label_bits.append("ha")

    compose_args: list[str] = []
    if env_file:
        if not (PROJECT_DIR / env_file).exists():
            log_err(f"env file not found: {env_file}  (use --tier / --env-file)")
            sys.exit(3)
        compose_args += ["--env-file", env_file]
    else:
        log_err("No tier selected and no .env present. Pass --tier lite|pro|max, --dev, or --env-file.")
        sys.exit(3)
    compose_args += files
    if ns.project:
        compose_args = ["-p", ns.project, *compose_args]

    return Target(compose_args=compose_args, label=" ".join(label_bits) or "default")


# ─── Discovery ────────────────────────────────────────────────────────────────
@dataclass
class Svc:
    service: str          # compose service name
    name: str             # container name
    state: str            # running | exited | restarting | created | ...
    health: str           # healthy | unhealthy | starting | none
    exit_code: int = 0
    restart_count: int = 0
    oom_killed: bool = False

    @property
    def is_infra(self) -> bool:
        return any(h in self.service for h in INFRA_HINTS)

    @property
    def ok(self) -> bool:
        if self.state != "running":
            return False
        # If a healthcheck is defined, require it to pass; else running is enough.
        if self.health in ("", "none"):
            return True
        return self.health == "healthy"


def _parse_ps(stdout: str) -> list[dict]:
    stdout = stdout.strip()
    if not stdout:
        return []
    # Compose may emit a JSON array or newline-delimited objects depending on version.
    try:
        data = json.loads(stdout)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return rows


def discover(target: Target) -> list[Svc]:
    """Enumerate the stack's containers from `docker compose ps` (all states)."""
    res = target.compose(["ps", "--all", "--format", "json"], timeout=30)
    svcs: list[Svc] = []
    for row in _parse_ps(res.stdout):
        name = row.get("Name") or row.get("name") or ""
        if not name:
            continue
        svc = Svc(
            service=row.get("Service") or row.get("service") or name,
            name=name,
            state=(row.get("State") or row.get("state") or "unknown").lower(),
            health=(row.get("Health") or row.get("health") or "none").lower() or "none",
            exit_code=int(row.get("ExitCode") or row.get("exitCode") or 0),
        )
        # Enrich with RestartCount + OOM from docker inspect (ps doesn't carry these).
        ins = run(["docker", "inspect", "--format", "{{.RestartCount}}|{{.State.OOMKilled}}", name])
        if ins.returncode == 0:
            parts = ins.stdout.strip().split("|")
            try:
                svc.restart_count = int(parts[0])
            except (ValueError, IndexError):
                pass
            svc.oom_killed = len(parts) > 1 and parts[1].strip().lower() == "true"
        svcs.append(svc)
    return svcs


# ─── Escalation ───────────────────────────────────────────────────────────────
def escalate(event: str, service: str, detail: str) -> None:
    """Structured escalation: always logs; POSTs to SELFHEAL_WEBHOOK if set."""
    log_err(f"ESCALATION [{event}] {service}: {detail}")
    webhook = os.environ.get("SELFHEAL_WEBHOOK", "").strip()
    if not webhook:
        return
    payload = json.dumps({
        "source": "freesdn-selfheal",
        "event": event,
        "service": service,
        "detail": detail,
        "host": platform.node(),
        "ts": int(time.time()),
    }).encode()
    try:
        req = urllib.request.Request(webhook, data=payload, method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        log_info("Escalation webhook delivered")
    except Exception as exc:  # noqa: BLE001 - best-effort
        log_warn(f"Escalation webhook failed: {exc}")


# ─── Healing state ────────────────────────────────────────────────────────────
@dataclass
class HealState:
    """Per-service heal bookkeeping for backoff + crash-loop detection."""
    attempts: int = 0
    next_allowed: float = 0.0                         # epoch; don't heal before this
    restarts: deque = field(default_factory=lambda: deque(maxlen=CRASH_LOOP_THRESHOLD * 2))
    quarantined: bool = False

    def backoff(self) -> float:
        return min(BACKOFF_CAP, BACKOFF_BASE * (2 ** self.attempts))

    def record_restart(self, now: float) -> bool:
        """Record a restart; return True if this trips the crash-loop guard."""
        self.restarts.append(now)
        recent = [t for t in self.restarts if now - t <= CRASH_LOOP_WINDOW]
        return len(recent) >= CRASH_LOOP_THRESHOLD


def diagnose(target: Target, svc: Svc) -> None:
    """Log recent container logs + OOM hint for an unhealthy service."""
    res = run(["docker", "logs", "--tail", "12", svc.name])
    tail = (res.stdout or "") + (res.stderr or "")
    if tail.strip():
        log_info(f"recent logs — {svc.service}:")
        for line in tail.strip().splitlines()[-6:]:
            print(f"          {C.DIM}{line[:160]}{C.RESET}")
    if svc.oom_killed:
        log_err(f"  {svc.service} was OOMKilled — raise its *_MEM_LIMIT in the tier env file")


def heal(target: Target, svc: Svc, state: dict[str, HealState]) -> None:
    """Heal one unhealthy service with backoff + crash-loop quarantine."""
    st = state.setdefault(svc.service, HealState())
    now = time.time()

    if st.quarantined:
        return
    if now < st.next_allowed:
        wait = int(st.next_allowed - now)
        log_warn(f"{svc.service}: in backoff ({wait}s left) — skipping")
        return

    diagnose(target, svc)
    log_action(f"healing {svc.service} (attempt {st.attempts + 1}, restart_count={svc.restart_count})…")
    res = target.compose(["restart", svc.service], timeout=90)

    tripped = st.record_restart(now)
    if res.returncode == 0:
        log_ok(f"restarted {svc.service}")
    else:
        log_err(f"restart of {svc.service} failed: {(res.stderr or '').strip()[:160]}")

    st.attempts += 1
    st.next_allowed = now + st.backoff()

    if tripped:
        st.quarantined = True
        escalate("crash-loop", svc.service,
                 f"{CRASH_LOOP_THRESHOLD}+ restarts within {CRASH_LOOP_WINDOW}s — "
                 f"quarantined (no further auto-restart). exit={svc.exit_code} oom={svc.oom_killed}")


# ─── Disk / preflight ─────────────────────────────────────────────────────────
def check_disk(min_gb: float = 5.0, floor_gb: float = 2.0) -> bool:
    u = shutil.disk_usage(PROJECT_DIR)
    free = u.free / (1024 ** 3)
    if free < floor_gb:
        log_err(f"Critically low disk: {free:.1f} GB free (< {floor_gb} GB) — Docker will fail")
        return False
    if free < min_gb:
        log_warn(f"Low disk: {free:.1f} GB free (recommend ≥ {min_gb} GB)")
    else:
        log_ok(f"Disk: {free:.1f} GB free")
    return True


# ─── Reporting ────────────────────────────────────────────────────────────────
def report(target: Target, svcs: list[Svc]) -> None:
    banner(f"FreeSDN Stack — {target.label}")
    if not svcs:
        log_warn("No containers found for this target. Is the stack up? "
                 f"(docker compose {' '.join(target.compose_args)} up -d)")
        return
    print(f"  {'Service':<18} {'State':<11} {'Health':<10} {'Restarts':<9} {'OOM'}")
    print(f"  {'─'*18} {'─'*11} {'─'*10} {'─'*9} {'─'*3}")
    for s in sorted(svcs, key=lambda x: (not x.is_infra, x.service)):
        sc = C.GREEN if s.ok else (C.YELLOW if s.state == "running" else C.RED)
        icon = "●" if s.ok else ("◐" if s.state == "running" else "○")
        oom = f"{C.RED}yes{C.RESET}" if s.oom_killed else "-"
        print(f"  {s.service:<18} {sc}{s.state:<11}{C.RESET} {sc}{icon} {s.health:<8}{C.RESET} "
              f"{s.restart_count:<9} {oom}")
    healthy = sum(1 for s in svcs if s.ok)
    print()
    (log_ok if healthy == len(svcs) else log_warn)(f"{healthy}/{len(svcs)} services healthy")


# ─── Workflows ────────────────────────────────────────────────────────────────
def wait_for_healthy(target: Target) -> bool:
    banner(f"Waiting for healthy — {target.label}")
    for attempt in range(1, MAX_HEALTH_RETRIES + 1):
        svcs = discover(target)
        if svcs and all(s.ok for s in svcs):
            log_ok(f"All {len(svcs)} services healthy")
            return True
        ready = sum(1 for s in svcs if s.ok)
        total = len(svcs) or 1
        bar = int(28 * ready / total)
        sys.stdout.write(f"\r  [{'█'*bar}{'░'*(28-bar)}] {ready}/{len(svcs)} ready "
                         f"(attempt {attempt}/{MAX_HEALTH_RETRIES})   ")
        sys.stdout.flush()
        time.sleep(HEALTH_CHECK_INTERVAL)
    print()
    log_err("Timed out waiting for healthy")
    for s in discover(target):
        if not s.ok:
            log_err(f"  {s.service}: state={s.state} health={s.health} restarts={s.restart_count}")
    return False


def heal_cycle(target: Target, state: dict[str, HealState]) -> list[Svc]:
    """One supervision pass: infra first, then app tier; heal what's unhealthy."""
    svcs = discover(target)
    unhealthy = [s for s in svcs if not s.ok]
    if not unhealthy:
        # Recovery: decay attempt counters for services that are healthy again.
        for s in svcs:
            st = state.get(s.service)
            if st and not st.quarantined and st.attempts:
                st.attempts = max(0, st.attempts - 1)
        return svcs
    # Dependency-aware: heal infra before dependents, give deps a beat to settle.
    infra = [s for s in unhealthy if s.is_infra]
    app = [s for s in unhealthy if not s.is_infra]
    log_warn(f"unhealthy: {', '.join(s.service for s in unhealthy)}")
    for s in infra:
        heal(target, s, state)
    if infra and app:
        log_info("healed infra — pausing 10s before dependents")
        time.sleep(10)
    for s in app:
        heal(target, s, state)
    return svcs


def monitor(target: Target) -> int:
    banner(f"Self-Healing Watchdog — {target.label}")
    log_info(f"interval={MONITOR_INTERVAL}s  crash-loop={CRASH_LOOP_THRESHOLD}/{CRASH_LOOP_WINDOW}s  "
             f"backoff={BACKOFF_BASE}→{BACKOFF_CAP}s  (Ctrl+C to stop)")
    webhook = "set" if os.environ.get("SELFHEAL_WEBHOOK") else "unset (log-only escalation)"
    log_info(f"escalation webhook: {webhook}")
    print()
    state: dict[str, HealState] = {}
    last_disk = 0.0
    try:
        while True:
            # Periodic disk check (every ~5 min).
            if time.time() - last_disk > 300:
                check_disk()
                last_disk = time.time()
            svcs = heal_cycle(target, state)
            quarantined = [k for k, v in state.items() if v.quarantined]
            ts = time.strftime("%H:%M:%S")
            if svcs and all(s.ok for s in svcs) and not quarantined:
                sys.stdout.write(f"\r  {C.DIM}{ts}{C.RESET}  ✅  "
                                 f"{C.GREEN}all {len(svcs)} services healthy{C.RESET}      ")
                sys.stdout.flush()
            elif quarantined:
                print()
                log_err(f"quarantined (manual intervention needed): {', '.join(quarantined)}")
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        print()
        log_info("watchdog stopped")
        return 0


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description="FreeSDN Self-Healing Watchdog (v2)")
    # target selection
    p.add_argument("--tier", choices=["lite", "pro", "max"], help="use .env.<tier>")
    p.add_argument("--dev", action="store_true", help="dev overlay (.env.dev + docker-compose.dev.yml)")
    p.add_argument("--ha", action="store_true", help="add the HA overlay")
    p.add_argument("--env-file", help="explicit env file")
    p.add_argument("--project", help="override compose project name")
    # actions
    g = p.add_mutually_exclusive_group()
    g.add_argument("--status", action="store_true", help="one-shot status (default)")
    g.add_argument("--check", action="store_true", help="wait for healthy, exit 0/1")
    g.add_argument("--monitor", action="store_true", help="continuous self-healing watchdog")
    g.add_argument("--restart", action="store_true", help="restart the whole stack")
    g.add_argument("--stop", action="store_true", help="stop the stack")
    g.add_argument("--up", action="store_true", help="bring the stack up (-d)")
    ns = p.parse_args()

    if not docker_available():
        log_err("Docker daemon is not running")
        return 2

    target = resolve_target(ns)

    if ns.check:
        return 0 if wait_for_healthy(target) else 1
    if ns.monitor:
        return monitor(target)
    if ns.stop:
        banner(f"Stopping — {target.label}")
        r = target.compose(["down"], timeout=120)
        (log_ok if r.returncode == 0 else log_err)("stack stopped" if r.returncode == 0 else "stop had errors")
        return r.returncode
    if ns.up or ns.restart:
        if ns.restart:
            banner(f"Restarting — {target.label}")
            target.compose(["down"], timeout=120)
        if not check_disk():
            return 1
        banner(f"Bringing up — {target.label}")
        r = target.compose(["up", "-d", "--build"], timeout=900)
        if r.returncode != 0:
            log_err("up failed")
            for line in (r.stderr or "").strip().splitlines()[-6:]:
                log_err(f"  {line}")
            return 1
        ok = wait_for_healthy(target)
        report(target, discover(target))
        return 0 if ok else 2

    # default: --status
    report(target, discover(target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
