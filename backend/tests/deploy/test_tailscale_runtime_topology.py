# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tailscale runs in its own small capless container, on every tier.

Until 26.12 capless tailscaled ran inside the api container: first as a child
of whichever gunicorn worker served the Connect click (killed with it on every
worker recycle), then under a supervisor there. Now the ``tailscale`` service of
the base compose owns it, Docker supervises it, and the api and the workers only
share its LocalAPI socket (control) and reach its SOCKS5 server (data).

The YAML checks run anywhere the compose files are; the render checks go
through ``docker compose config``, because the merge semantics (an overlay
replacing a volume by target, the vpn overlay's env merge) only exist in
Docker's own resolver.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

yaml = pytest.importorskip("yaml")


def _repo_dir() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "docker-compose.yml").is_file() and (parent / "backend").is_dir():
            return parent
    return None


ROOT = _repo_dir()
pytestmark = pytest.mark.skipif(
    ROOT is None, reason="compose files are not in this checkout (backend-only mount)"
)

APP_SERVICES = ("api", "worker", "worker-io")
SOCKET_DIR = "/var/run/tailscale"
STATE_DIR = "/var/lib/tailscale"


def _load(name: str) -> dict:
    assert ROOT is not None
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8")) or {}


def _mounts(service: dict) -> dict[str, str]:
    """target -> 'source[:mode]' for the short volume syntax used here."""
    out = {}
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            parts = entry.split(":")
            out[parts[1]] = ":".join([parts[0], *parts[2:]])
    return out


@pytest.fixture(scope="module")
def compose() -> dict:
    return _load("docker-compose.yml")


@pytest.fixture(scope="module")
def runtime(compose) -> dict:
    service = compose["services"].get("tailscale")
    assert service, "docker-compose.yml has no `tailscale` runtime service"
    return service


# ── the container itself ─────────────────────────────────────────────────────


def test_it_is_in_the_base_compose_on_every_tier(runtime):
    assert "profiles" not in runtime, "behind a profile it would not run on every tier"
    assert runtime["build"]["target"] == "tailscale-runtime"
    assert runtime["build"]["context"] == "./backend"
    assert runtime["restart"] == "unless-stopped"
    assert runtime.get("init") is True


def test_it_is_capless_non_root_and_read_only(runtime):
    assert runtime["user"] == "1001:1001", "uid 1001 is what gives the api write access"
    assert runtime["read_only"] is True
    assert runtime["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in runtime["security_opt"]
    for forbidden in ("cap_add", "devices", "privileged", "network_mode", "ports"):
        assert forbidden not in runtime, f"the runtime container must not set {forbidden}"
    assert str(runtime["sysctls"]["net.ipv4.tcp_retries2"]) == "8"


def test_it_has_resource_limits_and_a_real_healthcheck(runtime):
    limits = runtime["deploy"]["resources"]["limits"]
    assert re.fullmatch(r"\$\{TAILSCALE_MEM_LIMIT:-\d+M\}", limits["memory"])
    assert "TAILSCALE_CPU_LIMIT" in str(limits["cpus"])
    assert int(limits["pids"]) == int(runtime["pids_limit"])
    assert runtime["healthcheck"]["test"] == ["CMD", "/usr/local/bin/freesdn-tailscale-health"]


def test_it_holds_the_node_state_and_no_app_secret(runtime):
    mounts = _mounts(runtime)
    assert mounts[STATE_DIR] == "tailscale_state"
    assert mounts[SOCKET_DIR] == "tailscale_run"
    env = runtime.get("environment") or {}
    assert set(env) == {"TAILSCALE_NO_LOGS_NO_SUPPORT"}, (
        f"the runtime container gets the app's environment: {sorted(env)}. It must not "
        "see DATABASE_URL, SECRET_KEY or the Valkey password."
    )


# ── how the app containers use it ────────────────────────────────────────────


def test_api_and_workers_share_the_socket_but_not_the_node_key(compose):
    services = compose["services"]
    for name in APP_SERVICES:
        mounts = _mounts(services[name])
        assert mounts.get(SOCKET_DIR, "").startswith("tailscale_run"), (
            f"`{name}` cannot reach tailscaled's LocalAPI socket"
        )
        assert STATE_DIR not in mounts, f"`{name}` mounts the node's private keys"
    assert _mounts(services["api"])[SOCKET_DIR] == "tailscale_run", "Connect writes a request"
    for name in ("worker", "worker-io"):
        assert _mounts(services[name])[SOCKET_DIR] == "tailscale_run:ro"


def test_nothing_waits_for_it(compose):
    """The api and workers must start, and report Tailscale not running, without it."""
    for name, service in compose["services"].items():
        assert "tailscale" not in (service.get("depends_on") or {}), (
            f"`{name}` depends on the tailscale runtime container"
        )
        assert service.get("network_mode") != "service:tailscale"


def test_the_app_environment_points_at_the_runtime(compose, runtime):
    env = compose["x-backend-env"]
    assert env["TAILSCALE_RUNTIME"] == "container"
    assert env["FREESDN_OVERLAY_SOCKS5"] == "${FREESDN_OVERLAY_SOCKS5:-socks5://tailscale:1055}"
    assert env["VPN_MODE"] == "${VPN_MODE:-off}", "the workers must see the api's VPN mode"
    for name in APP_SERVICES:
        merged = compose["services"][name]["environment"]
        assert merged["TAILSCALE_RUNTIME"] == "container", name
        assert merged["VPN_MODE"] == "${VPN_MODE:-off}", name


def test_the_log_upload_setting_defaults_to_todays_behaviour(compose, runtime):
    expected = "${TAILSCALE_NO_LOGS_NO_SUPPORT:-true}"
    assert compose["x-backend-env"]["TAILSCALE_NO_LOGS_NO_SUPPORT"] == expected
    assert runtime["environment"]["TAILSCALE_NO_LOGS_NO_SUPPORT"] == expected


ENV_EXAMPLES = (".env.example", ".env.lite.example", ".env.pro.example", ".env.max.example")


@pytest.mark.parametrize("env_file", ENV_EXAMPLES)
def test_every_env_example_documents_the_log_upload_setting(env_file):
    assert ROOT is not None
    lines = (ROOT / env_file).read_text(encoding="utf-8").splitlines()
    assert "# TAILSCALE_NO_LOGS_NO_SUPPORT=false" in lines, env_file
    assert not [line for line in lines if line.startswith("TAILSCALE_NO_LOGS_NO_SUPPORT=")], (
        f"{env_file} overrides the compose default (no log upload)"
    )


def test_the_vpn_overlay_stands_the_runtime_down(compose):
    overlay = _load("docker-compose.vpn.yml")
    env = overlay["services"]["tailscale"]["environment"]
    assert env["VPN_MODE"] == "sidecar"


# ── the image ────────────────────────────────────────────────────────────────


def _stage(dockerfile: str, name: str) -> str:
    pattern = rf"^FROM [^\n]+ AS {re.escape(name)}\n(.*?)(?=^FROM |\Z)"
    match = re.search(pattern, dockerfile, re.M | re.S)
    assert match, f"backend/Dockerfile has no {name} stage"
    return match.group(0)


def test_the_image_is_pinned_and_carries_only_tailscale():
    assert ROOT is not None
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    stage = _stage(dockerfile, "tailscale-runtime")
    base = stage.splitlines()[0]
    assert re.fullmatch(r"FROM alpine:[\d.]+@sha256:[0-9a-f]{64} AS tailscale-runtime", base), base
    copies = re.findall(r"^COPY (.+)$", stage, re.M)
    sources = [c for c in copies if not c.startswith("--from=")]
    assert all(c.startswith(("tailscale-build/", "tailscale-runtime/")) for c in sources), copies
    assert [c for c in copies if c.startswith("--from=")] == [
        "--from=tailscale-builder /out/tailscale /out/tailscaled /usr/local/bin/"
    ]
    assert "USER 1001:1001" in stage
    # The same Tailscale the backend image ships, at the version go.mod pins.
    gomod = (ROOT / "backend" / "tailscale-build" / "go.mod").read_text(encoding="utf-8")
    version = re.search(r"tailscale\.com v(\d+\.\d+\.\d+)", gomod)
    assert version, "tailscale.com is no longer pinned in tailscale-build/go.mod"
    builder = _stage(dockerfile, "tailscale-builder")
    assert f"shortStamp={version.group(1)}" in builder


# ── rendered by Docker, per tier ─────────────────────────────────────────────


def _docker_compose() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, timeout=60, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def _tiers() -> list[str]:
    if ROOT is None:
        return []
    return sorted(
        p.name.removeprefix(".env.").removesuffix(".example")
        for p in ROOT.glob(".env.*.example")
        if any(line.startswith("WORKER_QUEUES=") for line in p.read_text().splitlines())
    )


def _render(tier: str, *, vpn: bool) -> dict:
    assert ROOT is not None
    env_file = ROOT / f".env.{tier}.example"
    profiles = next(
        (
            line.split("=", 1)[1].strip()
            for line in env_file.read_text().splitlines()
            if line.startswith("COMPOSE_PROFILES=")
        ),
        "",
    )
    files = ["-f", "docker-compose.yml"]
    if vpn:
        files += ["-f", "docker-compose.vpn.yml"]
        profiles = ",".join(p for p in (profiles, "vpn") if p)
    child_env = dict(os.environ)
    child_env.update(COMPOSE_PROFILES=profiles, COMPOSE_PROJECT_NAME="freesdn-tailscale-test")
    child_env.pop("COMPOSE_FILE", None)
    proc = subprocess.run(
        ["docker", "compose", "--env-file", env_file.name, *files, "config", "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=child_env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["services"]


def _rendered_mount(service: dict, target: str) -> dict | None:
    return next((v for v in service.get("volumes") or [] if v.get("target") == target), None)


needs_docker = pytest.mark.skipif(not _docker_compose(), reason="`docker compose` unavailable")


@needs_docker
def test_the_scan_finds_tiers():
    assert len(_tiers()) >= 3, _tiers()


@needs_docker
@pytest.mark.parametrize("tier", _tiers())
def test_every_tier_renders_the_runtime_container(tier):
    services = _render(tier, vpn=False)
    runtime = services.get("tailscale")
    assert runtime, f"{tier}: no tailscale runtime container"
    assert runtime["environment"]["TAILSCALE_NO_LOGS_NO_SUPPORT"] == "true"
    assert runtime.get("cap_drop") == ["ALL"] and not runtime.get("cap_add")
    for name in APP_SERVICES:
        if name not in services:
            continue  # worker-io is pro/max only
        env = services[name]["environment"]
        assert env["FREESDN_OVERLAY_SOCKS5"] == "socks5://tailscale:1055", (tier, name)
        assert env["TAILSCALE_RUNTIME"] == "container", (tier, name)
        assert _rendered_mount(services[name], SOCKET_DIR), (tier, name)
        assert not _rendered_mount(services[name], STATE_DIR), (tier, name)


@needs_docker
@pytest.mark.parametrize("tier", _tiers())
def test_in_sidecar_mode_the_runtime_stands_by_and_workers_keep_a_writable_socket(tier):
    services = _render(tier, vpn=True)
    assert services["tailscale"]["environment"]["VPN_MODE"] == "sidecar"
    for name in APP_SERVICES:
        if name not in services:
            continue
        mount = _rendered_mount(services[name], SOCKET_DIR)
        assert mount and mount["source"] == "tailscale_run", (tier, name)
        # The overlay's entry replaces the base's read-only one, as before.
        assert not mount.get("read_only"), (tier, name)
