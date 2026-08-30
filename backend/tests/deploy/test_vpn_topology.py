# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Whatever runs VPN work must live inside the VPN sidecar's network namespace.

``docker-compose.vpn.yml`` used to move ONLY ``api`` into ``network_mode:
service:vpn``. Almost no VPN work runs in the api process:

* ``vpn.sync_vpn_connections`` / ``check_vpn_health`` / ``auto_reconnect`` /
  ``check_tunnel_health`` are beat-scheduled onto the ``sync`` queue, consumed by
  ``worker`` in lite and ``worker-io`` in pro/max;
* ``vpn.purge_old_*`` / ``vpn.scan_vpn_certificates`` land on ``default``;
* ``overlay.poll_health`` shells the tailscale/netbird CLIs and is pinned to
  ``metrics`` by beat while routing to ``default`` on a manual dispatch.

Outside the namespace ``NETBIRD_DAEMON_ADDR=tcp://127.0.0.1:41731`` points at the
worker's own loopback, ``/var/run/tailscale/tailscaled.sock`` is not mounted, and
``FREESDN_OPENVPN_SIDECAR`` / ``FREESDN_WIREGUARD_SIDECAR`` are unset - which
``OpenVPNService``/``WireGuardService`` read straight off ``os.environ``
(``vpn_integration.py:1585`` and ``:1113``). ``get_all_connections()`` logs and
continues per provider, so the task reported ``{"synced": 0, "errors": 0}``:
false success against a topology that could never have worked.

Two derivations keep this test's REACH ahead of the next refactor:

1. The set of VPN-dependent tasks is computed from the import graph of ``app/``
   - every ``app/tasks/*`` module that transitively imports
   ``app.services.vpn_integration`` - and their queues from Celery's own router
   plus their beat entries. Nothing here hardcodes "sync". That is what catches
   ``overlay.poll_health``, which reaches the tailscale CLI through
   ``app.services.overlay_discovery`` and sits on a different queue entirely.
2. What "wired into the sidecar" means is derived by DIFFING the rendered ``api``
   with and without the overlay, so a control volume or env flag added to ``api``
   later is automatically required of the workers too.

Rendering goes through ``docker compose config`` rather than a YAML parse: the
merge semantics that made this bug possible (an override file cannot delete the
base's ``networks:`` key, and ``networks`` + ``network_mode`` on one service is
rejected outright) only exist in Docker's own resolver.
"""

from __future__ import annotations

import ast
import collections
import importlib
import json
import os
import pathlib
import shutil
import subprocess

import pytest

from app.core.celery_app import celery_app

#: ``app/services/vpn_integration.py`` owns every path and process that only
#: exists inside the sidecar: the tailscaled socket, the netbird daemon address,
#: and the OpenVPN/WireGuard config + runtime directories.
VPN_RUNTIME_MODULE = "app.services.vpn_integration"

APP_DIR = pathlib.Path(__file__).resolve().parents[2] / "app"


def _compose_dir() -> pathlib.Path | None:
    """Find the directory holding the shipped compose files."""
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "docker-compose.yml").is_file():
            if (parent / "docker-compose.vpn.yml").is_file():
                return parent
    return None


COMPOSE_DIR = _compose_dir()


def _docker_compose_works() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env-dependent
        return False
    return completed.returncode == 0


#: Skip at MODULE level, never from inside a parametrize argument: that runs at
#: COLLECTION time and turns a skip into a collection ERROR (which is how
#: tests/deploy first went red). The CI backend leg mounts only backend/, so the
#: compose files are absent there; real CI checks out the monorepo on a runner
#: that has docker compose, so this executes for real.
pytestmark = [
    pytest.mark.skipif(
        COMPOSE_DIR is None,
        reason="compose files are not in this checkout (backend-only mount)",
    ),
    pytest.mark.skipif(
        not _docker_compose_works(),
        reason="`docker compose` is unavailable; this test renders with Docker's own resolver",
    ),
]


# ── 1. which tasks need the sidecar, and which queues carry them ─────────────


def _app_import_graph() -> dict[str, set[str]]:
    """Module -> the ``app.*`` modules it imports (top level AND function local)."""
    graph: dict[str, set[str]] = collections.defaultdict(set)
    for py in APP_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        rel = py.relative_to(APP_DIR.parent).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        name = ".".join(parts)
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own bug
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module and node.module.startswith("app."):
                    graph[name].add(node.module)
            elif isinstance(node, ast.Import):
                graph[name].update(a.name for a in node.names if a.name.startswith("app."))
    return graph


def _task_modules_needing_the_sidecar() -> list[str]:
    """``app.tasks.*`` modules that transitively import the VPN runtime module."""
    graph = _app_import_graph()
    importers: dict[str, set[str]] = collections.defaultdict(set)
    for src, dsts in graph.items():
        for dst in dsts:
            importers[dst].add(src)

    seen = {VPN_RUNTIME_MODULE}
    stack = [VPN_RUNTIME_MODULE]
    while stack:
        for parent in importers.get(stack.pop(), ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return sorted(m for m in seen if m.startswith("app.tasks."))


def _vpn_queues() -> dict[str, set[str]]:
    """Queue -> the VPN-dependent task names that can land on it.

    A task can reach a queue two ways, so take the union of both: Celery's
    router (``task_routes`` + ``task_default_queue``) and any explicit
    ``options={"queue": ...}`` on a beat entry, which overrides the router.
    """
    modules = _task_modules_needing_the_sidecar()
    for module in modules:
        importlib.import_module(module)

    names = {
        name
        for name, task in celery_app.tasks.items()
        if getattr(task, "__module__", "") in modules
    }

    queues: dict[str, set[str]] = collections.defaultdict(set)
    router = celery_app.amqp.router
    for name in names:
        queue = router.route({}, name).get("queue")
        queues[getattr(queue, "name", str(queue))].add(name)
    for entry in (celery_app.conf.beat_schedule or {}).values():
        task = entry.get("task")
        if task in names:
            pinned = (entry.get("options") or {}).get("queue")
            if pinned:
                queues[pinned].add(task)
    return dict(queues)


# ── 2. render the shipped compose, per tier ──────────────────────────────────


def _tiers() -> dict[str, pathlib.Path]:
    """Shipped deployment tiers: an ``.env.<tier>.example`` that sizes a worker.

    Globbed, not listed, so a new tier is covered the day its env file lands.
    ``.env.example`` / ``.env.dev.example`` declare no WORKER_QUEUES and are not
    tiers.
    """
    # Return empty rather than asserting: this runs at MODULE level via
    # ``TIERS = _tiers()``, and an assert there is a COLLECTION error, not a
    # skip -- which is the very trap the comment above warns about, in a
    # different costume. The pytestmark skipif still handles the real case; this
    # just lets the module import where the compose files are absent.
    if COMPOSE_DIR is None:
        return {}
    out = {}
    for path in sorted(COMPOSE_DIR.glob(".env.*.example")):
        lines = path.read_text(encoding="utf-8").splitlines()
        if any(line.startswith("WORKER_QUEUES=") for line in lines):
            out[path.name.removeprefix(".env.").removesuffix(".example")] = path
    return out


def _profiles(env_file: pathlib.Path) -> str:
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("COMPOSE_PROFILES="):
            return line.split("=", 1)[1].strip()
    return ""


def _render(env_file: pathlib.Path, *, with_vpn: bool) -> dict:
    assert COMPOSE_DIR is not None
    files = ["-f", "docker-compose.yml"]
    profiles = _profiles(env_file)
    if with_vpn:
        files += ["-f", "docker-compose.vpn.yml"]
        profiles = ",".join(p for p in (profiles, "vpn") if p)
    argv = ["docker", "compose", "--env-file", env_file.name]
    argv += files + ["config", "--format", "json"]
    # Inherit the real environment (docker needs it, especially on Windows) but
    # pin everything that would let the developer's shell change the render.
    child_env = dict(os.environ)
    child_env["COMPOSE_PROFILES"] = profiles
    child_env["COMPOSE_PROJECT_NAME"] = "freesdn-topology-test"
    child_env.pop("COMPOSE_FILE", None)
    proc = subprocess.run(
        argv,
        cwd=COMPOSE_DIR,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=child_env,
    )
    assert proc.returncode == 0, (
        f"`docker compose config` rejected {env_file.name} "
        f"(with_vpn={with_vpn}, profiles={profiles!r}):\n{proc.stderr}"
    )
    return json.loads(proc.stdout)


def _consumed_queues(service: dict) -> set[str]:
    """Queues a rendered celery-worker service subscribes to, from its ``-Q``."""
    command = service.get("command") or []
    if isinstance(command, str):
        command = command.split()
    command = [str(c) for c in command]
    if "worker" not in command:
        return set()
    out: set[str] = set()
    for index, token in enumerate(command):
        value = None
        if token in ("-Q", "--queues") and index + 1 < len(command):
            value = command[index + 1]
        elif token.startswith(("-Q=", "--queues=")):
            value = token.split("=", 1)[1]
        if value:
            out.update(q.strip() for q in value.split(",") if q.strip())
    return out


def _mount_targets(service: dict) -> set[str]:
    return {v["target"] for v in (service.get("volumes") or []) if v.get("target")}


TIERS = _tiers()


# ── 3. guard the guards ──────────────────────────────────────────────────────


def test_the_scan_finds_vpn_dependent_tasks() -> None:
    """A scan that found nothing would make every assertion below vacuous."""
    modules = _task_modules_needing_the_sidecar()
    assert modules, f"no app.tasks module reaches {VPN_RUNTIME_MODULE}; the graph walk is broken"
    assert _vpn_queues(), "VPN-dependent tasks resolved to no queue at all"
    # overlay.poll_health reaches the tailscale CLI only through
    # app.services.overlay_discovery. A walk that stops at DIRECT importers of
    # vpn_integration misses that hop - and with it a whole queue.
    assert "app.tasks.overlay_monitor" in modules, (
        f"transitive import walk missed app.tasks.overlay_monitor: {modules}"
    )


def test_the_scan_finds_tiers() -> None:
    assert len(TIERS) >= 2, f"expected several shipped tiers, found {sorted(TIERS)}"


@pytest.mark.parametrize("tier", sorted(TIERS))
def test_the_overlay_actually_changes_the_render(tier: str) -> None:
    """The with/without diff defines 'wired in'; it must not be empty."""
    plain = _render(TIERS[tier], with_vpn=False)["services"]
    overlaid = _render(TIERS[tier], with_vpn=True)["services"]
    assert plain["api"].get("network_mode") is None
    assert overlaid["api"].get("network_mode") == "service:vpn"
    assert "vpn" in overlaid, f"{tier}: the vpn profile did not start the sidecar"
    added_mounts = _mount_targets(overlaid["api"]) - _mount_targets(plain["api"])
    assert added_mounts, f"{tier}: the overlay adds no VPN control volumes to api"


# ── 4. the invariant ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("tier", sorted(TIERS))
def test_every_vpn_queue_consumer_shares_the_sidecar_namespace(tier: str) -> None:
    """Any worker that can run a VPN task must be wired in exactly like ``api``."""
    env_file = TIERS[tier]
    plain = _render(env_file, with_vpn=False)["services"]
    overlaid = _render(env_file, with_vpn=True)["services"]

    api = overlaid["api"]
    required_mounts = _mount_targets(api) - _mount_targets(plain["api"])
    plain_env = plain["api"].get("environment") or {}
    required_env = {
        key: value
        for key, value in (api.get("environment") or {}).items()
        if plain_env.get(key) != value
    }

    vpn_queues = _vpn_queues()
    checked = 0
    for name, service in sorted(overlaid.items()):
        overlap = _consumed_queues(service) & set(vpn_queues)
        if not overlap:
            continue
        checked += 1
        tasks = sorted({t for queue in overlap for t in vpn_queues[queue]})
        because = f"{tier}: `{name}` consumes {sorted(overlap)}, which carries {tasks}"

        assert service.get("network_mode") == "service:vpn", (
            f"{because} - but it is outside the sidecar netns "
            f"(network_mode={service.get('network_mode')!r}). "
            "NETBIRD_DAEMON_ADDR points at its own loopback and every tunnel route "
            "installed by the sidecar is invisible to it."
        )
        missing = required_mounts - _mount_targets(service)
        assert not missing, (
            f"{because} - but it does not mount the VPN control paths {sorted(missing)} "
            "that `api` gets from the same overlay (tailscaled.sock / openvpn / wireguard state)."
        )
        service_env = service.get("environment") or {}
        wrong = {k: v for k, v in required_env.items() if service_env.get(k) != v}
        assert not wrong, (
            f"{because} - but the sidecar env `api` gets is missing or different here: "
            f"{sorted(wrong)}. vpn_integration reads these off os.environ directly, so the "
            "non-sidecar code path runs in this process."
        )

    assert checked, (
        f"{tier}: no rendered service consumes any VPN queue {sorted(vpn_queues)}. "
        "Either the -Q parse broke or the tier ships no worker - both make this test blind."
    )
