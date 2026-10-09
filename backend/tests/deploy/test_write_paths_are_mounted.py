# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A directory the code writes to must be mounted on the service that writes it.

Every backend service in the shipped compose runs the SAME image with
``read_only: true``. So a write to a path that service does not mount fails with
EROFS at runtime, and this codebase swallows that kind of failure.

That is not hypothetical. ``app/tasks/cameras.py:324`` does
``os.makedirs(settings.EVIDENCE_DIR)`` and its own docstring says "Runs in a
Celery worker" -- but only ``api`` mounted ``evidence_data``, so legal-hold
evidence export could never write its file on the shipped compose. It was
invisible because ``docker-compose.dev.yml`` sets ``read_only: false``, where the
write lands on the container's own layer and appears to work (and is silently
lost when the container is recreated).

This asserts the invariant directly: for each settings-declared write path, every
backend-image service that is not explicitly exempt must mount it.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

import pytest

yaml = pytest.importorskip("yaml")


def _repo_file(*relative: str) -> pathlib.Path | None:
    """Find a file by walking up from this test toward the monorepo root."""
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent.joinpath(*relative)
        if candidate.is_file():
            return candidate
    return None


def _compose_path() -> pathlib.Path | None:
    return _repo_file("docker-compose.yml")


#: The CI backend leg mounts ONLY backend/, so docker-compose.yml (one level up)
#: is absent there. Skip at MODULE level: calling pytest.skip() from inside a
#: parametrize argument runs at COLLECTION time and raises a collection error
#: rather than skipping -- which is how this file first turned the gate red.
#: Real CI checks out the whole monorepo, so this runs there.
pytestmark = pytest.mark.skipif(
    _compose_path() is None,
    reason="docker-compose.yml is not in this checkout (backend-only mount)",
)


def _compose() -> dict:
    path = _compose_path()
    if path is None:
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _backend_services(compose: dict) -> dict[str, dict]:
    """Services built from the backend image -- they can run any backend code."""
    out = {}
    for name, svc in (compose.get("services") or {}).items():
        build = svc.get("build") or {}
        ctx = build.get("context", "") if isinstance(build, dict) else str(build)
        if "backend" in str(ctx) or "backend" in str(svc.get("image", "")):
            out[name] = svc
    return out


def _mounts(svc: dict) -> set[str]:
    return {v.split(":")[1] for v in (svc.get("volumes") or []) if isinstance(v, str) and ":" in v}


#: Write paths declared in Settings, and which backend services legitimately do
#: NOT need them. Each exemption needs a reason, because a wrong exemption
#: re-creates the exact defect this test exists to catch.
WRITE_PATH_EXEMPTIONS: dict[str, set[str]] = {
    # Fabric runs in the API process only -- it is started from main.py's
    # lifespan and no Celery task invokes the executor.
    "/data/fabric_artifacts": {"worker", "worker-io", "scheduler", "collector", "flower", "vpn"},
    # flower is a read-only Celery dashboard; scheduler only enqueues, it never
    # executes a task body; collector and vpn run their own narrow entrypoints.
    "/data/evidence": {"scheduler", "flower", "collector", "vpn"},
    "/data/proxmox-uploads": {"scheduler", "flower", "collector", "vpn"},
    # The release path is now also a Settings field. Match the existing
    # HARDCODED_WRITE_PATHS policy: beat only enqueues, Flower runs no task
    # bodies, and collector/vpn have dedicated non-HTTP entrypoints. The API
    # and both workers must still mount this directory in BOTH checks.
    "/data/agent-releases": {"scheduler", "flower", "collector", "vpn"},
    # PLUGIN_DIR remains a module constant, so only HARDCODED_WRITE_PATHS can
    # check it. test_no_exemption_is_dead rejects exemptions for invisible paths.
}


_ENV_DEFAULT = re.compile(r"^\$\{[A-Z0-9_]+:-(?P<value>[^}]*)\}$")


def _effective(raw: str) -> str:
    """Resolve a compose ``${VAR:-default}`` to the default it ships with."""
    m = _ENV_DEFAULT.match(raw.strip())
    return m.group("value") if m else raw.strip()


def _declared_write_paths() -> dict[str, str]:
    """Settings fields naming an absolute write path, as the SHIPPED compose
    resolves them.

    Reading the Python default alone is wrong and this test got it wrong first:
    PROXMOX_UPLOAD_DIR defaults to /var/lib/freesdn/uploads in config.py, but
    docker-compose.yml:75 supplies ${PROXMOX_UPLOAD_DIR:-/data/proxmox-uploads},
    so the shipped value is the volume path and there was nothing wrong with it.
    The invariant is about what the deployment actually resolves to.
    """
    from app.core.config import Settings

    compose = _compose()
    if not compose:
        return {}
    env: dict[str, str] = {}
    for svc in _backend_services(compose).values():
        raw_env = svc.get("environment") or {}
        if isinstance(raw_env, dict):
            env.update({k: str(v) for k, v in raw_env.items()})

    out = {}
    for name, field in Settings.model_fields.items():
        default = field.default
        if not (isinstance(default, str) and name.endswith(("_DIR", "_PATH"))):
            continue
        value = _effective(env[name]) if name in env else default
        if value.startswith("/"):
            out[name] = value
    return out


def test_the_scan_finds_write_paths_to_check() -> None:
    """Guard the guard: a scan that finds nothing would pass forever."""
    paths = _declared_write_paths()
    assert len(paths) >= 2, f"expected several path settings, found {paths}"


def test_no_exemption_is_dead() -> None:
    """An exemption for a path this scan cannot see is worse than none.

    It exempts nothing -- but it reads like the path is covered, so nobody adds
    the check that actually is missing. That is exactly what happened to
    /data/plugins and /data/agent-releases: both sat in WRITE_PATH_EXEMPTIONS
    for months while no per-service mount check existed for either.
    """
    visible = set(_declared_write_paths().values())
    dead = sorted(set(WRITE_PATH_EXEMPTIONS) - visible)
    assert not dead, (
        f"WRITE_PATH_EXEMPTIONS names paths _declared_write_paths() never "
        f"yields: {dead}. Nothing is being exempted, and the entry disguises an "
        "unchecked path. Either the path comes from a Settings field (fix the "
        "scan) or it does not (move it to HARDCODED_WRITE_PATHS)."
    )


@pytest.mark.parametrize("setting,path", sorted(_declared_write_paths().items()))
def test_every_backend_service_that_needs_a_write_path_mounts_it(setting: str, path: str) -> None:
    """Fails before the fix on /data/evidence for worker and worker-io."""
    compose = _compose()
    services = _backend_services(compose)
    assert services, "no backend services found -- this test is checking nothing"

    exempt = WRITE_PATH_EXEMPTIONS.get(path, set())
    missing = []
    for name, svc in services.items():
        if name in exempt:
            continue
        if path not in _mounts(svc):
            missing.append((name, svc.get("read_only")))

    assert not missing, (
        f"{setting} = {path} is written by backend code, but these services run "
        f"the backend image without mounting it: {missing}. Every backend service "
        "ships read_only: true, so a write there fails with EROFS at runtime. "
        f"If a service genuinely never writes {path}, add it to "
        "WRITE_PATH_EXEMPTIONS with a reason."
    )


# ── A named volume and the image directory under it must agree ────────────
#
# Two failure modes, opposite directions, both silent, both real here:
#
#   mounted but NOT pre-created by the image
#       Docker creates the mountpoint itself, root:root 0755. The container runs
#       USER appuser (uid 1001), so it cannot write there. /data/plugins was in
#       this state, which made EVERY plugin install path 500 on any production
#       deployment -- upload, install-from-URL and the marketplace -- with a
#       generic "Install failed" and the real PermissionError only in the log.
#       The Dockerfile's own comment states the mechanism: "Without this, the
#       volume root is root-owned and the non-root appuser (uid 1001) cannot
#       mkdir/write".
#
#   pre-created but NOT mounted
#       The path lives in the image layer, and every backend service ships
#       read_only: true, so writing to it fails with EROFS -- and it could not
#       survive a restart even if it worked. /data/freesdn_firmware was in this
#       state, so firmware upload 500'd.
#
# Dev masks both: the development stage runs as root with read_only: false.


def _dockerfile() -> str:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "backend" / "Dockerfile"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
        candidate = parent / "Dockerfile"
        if candidate.is_file() and "appuser" in candidate.read_text(encoding="utf-8"):
            return candidate.read_text(encoding="utf-8")
    return ""


def _data_paths(text: str, mounted: bool) -> set[str]:
    pattern = r":(/data/[A-Za-z0-9_-]+)" if mounted else r"/data/[A-Za-z0-9_-]+"
    return set(re.findall(pattern, text))


def test_the_dockerfile_is_readable() -> None:
    """Guard the guard: an empty read would make both checks below vacuous."""
    df = _dockerfile()
    if not df:
        pytest.skip("backend/Dockerfile not in this checkout")
    assert "mkdir -p" in df and "chown" in df


def test_every_mounted_data_path_is_pre_created_by_the_image() -> None:
    """Fails before the fix on /data/plugins."""
    df = _dockerfile()
    if not df:
        pytest.skip("backend/Dockerfile not in this checkout")
    compose_path = _compose_path()
    assert compose_path is not None
    dc = compose_path.read_text(encoding="utf-8")

    missing = sorted(_data_paths(dc, True) - _data_paths(df, False))
    assert not missing, (
        f"these paths are mounted as named volumes but the image never creates "
        f"them: {missing}. Docker will create each mountpoint root-owned, and the "
        "container runs as a non-root user, so every write there fails with "
        "PermissionError. Add them to the RUN mkdir -p ... && chown block."
    )


def test_every_pre_created_data_path_is_mounted() -> None:
    """Fails before the fix on /data/freesdn_firmware."""
    df = _dockerfile()
    if not df:
        pytest.skip("backend/Dockerfile not in this checkout")
    compose_path = _compose_path()
    assert compose_path is not None
    dc = compose_path.read_text(encoding="utf-8")

    unmounted = sorted(_data_paths(df, False) - _data_paths(dc, True))
    assert not unmounted, (
        f"the image creates these paths but nothing mounts them: {unmounted}. "
        "Every backend service ships read_only: true, so a write there fails with "
        "EROFS -- and it could not survive a restart even if it succeeded."
    )


# ── Write paths the CODE hardcodes ────────────────────────────────────────
#
# _declared_write_paths() above can only see Settings fields, so it is blind to
# a directory named by a module-level literal -- and every one of those shipped
# with nothing mounting it. Same EROFS mechanism, four more features:
#
#   /data/backups            the shipped "Local Storage" backup destination.
#                            Every out-of-the-box backup ended FAILED with
#                            "[Errno 30] Read-only file system: '/data/backups'".
#   /data/sla_reports        CSV/PDF rendering. The failure is SWALLOWED, so the
#                            download endpoint silently served raw JSON instead.
#   /data/provisioning/voip  handset config XML. The OSError is not the
#                            ProvisioningError the callers catch, so the
#                            unauthenticated cfg{MAC}.xml route 500'd forever.
#   /tmp/freesdn_data        import/export. /tmp is a PRIVATE tmpfs per
#                            container, so the api wrote a file the worker could
#                            not see and vice versa -- broken even in dev, where
#                            read_only:false hides every other path in this file.
#
# Each entry pins the literal to the module that owns it. Without that, moving
# or renaming a constant would leave the mount table below silently stale and
# this file would keep passing over a re-broken deployment.


@dataclass(frozen=True)
class HardcodedWritePath:
    path: str
    source: str
    literal: str
    #: backend service -> why that service can never execute this write.
    exempt: dict[str, str]
    #: Set when the SOURCE does not name ``path`` at all because the deployment
    #: redirects it through an env var (the module's own default is elsewhere).
    #: The literal then pins the env var name, and the compose is checked to
    #: still map that variable to ``path`` -- so the pin covers both halves of
    #: the wiring rather than half of it.
    env_var: str | None = None


#: The Celery queue split is env-driven (WORKER_QUEUES / WORKER_IO_QUEUES are
#: operator settings, and .env.lite.example puts EVERY queue on `worker`), so no
#: task can be assumed to run on one particular worker: api, worker and worker-io
#: all have to mount what any task writes.
_NON_TASK_SERVICES = {
    "scheduler": "celery beat only ENQUEUES; it never executes a task body",
    "flower": "read-only Celery dashboard; runs no application code",
    "collector": "runs `python -m app.modules.collector.run`, a UDP receiver "
    "entrypoint that registers no Celery task and serves no HTTP route",
    "vpn": "execs vpn-sidecar-entrypoint.sh (tailscaled/netbird/openvpn); it "
    "never imports the FastAPI app or the Celery worker",
}

HARDCODED_WRITE_PATHS: tuple[HardcodedWritePath, ...] = (
    HardcodedWritePath(
        path="/data/backups",
        source="app/services/backup.py",
        literal='config.get("path", "/data/backups")',
        exempt=_NON_TASK_SERVICES,
    ),
    HardcodedWritePath(
        path="/data/sla_reports",
        source="app/services/sla_reports.py",
        literal='os.environ.get("SLA_REPORTS_DIR", "/data/sla_reports")',
        exempt=_NON_TASK_SERVICES,
    ),
    HardcodedWritePath(
        path="/data/provisioning/voip",
        source="app/modules/voip/provisioning.py",
        literal='_PROVISION_DIR = Path("/data/provisioning/voip")',
        exempt=_NON_TASK_SERVICES,
    ),
    HardcodedWritePath(
        path="/tmp/freesdn_data",
        source="app/services/import_export.py",
        literal='DATA_DIR = Path("/tmp/freesdn_data")',
        exempt=_NON_TASK_SERVICES,
    ),
    # The three below were covered only by the Dockerfile<->compose SET equality
    # further down, which asks "is this mounted by SOMEBODY and created by the
    # image" and is satisfied by `api` alone. Dropping the worker's plugin_data
    # mount would therefore have left every test in this file green while plugin
    # loading in a Celery task broke -- the same shape as the bug the file was
    # written for. Found 2026-08-29 by probing the paths inside a running lite
    # stack rather than by reading the compose: `worker` and `scheduler` disagree
    # about what they can write, and only the running containers say so.
    HardcodedWritePath(
        path="/data/plugins",
        source="app/plugins/loader.py",
        literal='PLUGIN_DIR = Path(os.getenv("PLUGIN_DIR", "/data/plugins"))',
        exempt=_NON_TASK_SERVICES,
    ),
    HardcodedWritePath(
        path="/data/freesdn_firmware",
        source="app/services/firmware.py",
        literal='FIRMWARE_DIR = Path("/data/freesdn_firmware")',
        exempt=_NON_TASK_SERVICES,
    ),
    # Pinned on the ENV VAR, not on a path literal: this module's own default is
    # /var/lib/freesdn/agent-releases and docker-compose.yml:74 redirects it with
    # FREESDN_AGENT_RELEASE_DIR=${...:-/data/agent-releases}. The mount and the
    # override are what make the two agree, so the pin has to be the thing that
    # would break if either moved.
    HardcodedWritePath(
        path="/data/agent-releases",
        source="app/api/v1/endpoints/agent_release_upload.py",
        literal='"FREESDN_AGENT_RELEASE_DIR",',
        exempt=_NON_TASK_SERVICES,
        env_var="FREESDN_AGENT_RELEASE_DIR",
    ),
)


def _backend_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("entry", HARDCODED_WRITE_PATHS, ids=lambda e: e.path)
def test_the_hardcoded_write_path_is_still_written_by_that_module(
    entry: HardcodedWritePath,
) -> None:
    """Pin the literal, so the mount table cannot go stale unnoticed.

    Catches: someone repoints LocalStorageBackend's default (or any of the other
    three constants) at a new directory. The mount would then guard a path
    nothing writes while the new one ships unmounted -- the shipped bug again,
    behind a green suite.
    """
    src = _backend_root() / entry.source
    if not src.is_file():
        pytest.skip(f"{entry.source} not in this checkout")
    text = src.read_text(encoding="utf-8")
    assert entry.literal in text, (
        f"{entry.source} no longer contains {entry.literal!r}. The write path "
        f"{entry.path} was moved or renamed -- update HARDCODED_WRITE_PATHS and "
        "the docker-compose.yml mounts together, or the new path ships unmounted."
    )


@pytest.mark.parametrize("entry", HARDCODED_WRITE_PATHS, ids=lambda e: e.path)
def test_every_service_that_can_run_a_hardcoded_write_mounts_it(
    entry: HardcodedWritePath,
) -> None:
    """Fails before the fix on all four paths, for api, worker and worker-io."""
    services = _backend_services(_compose())
    assert services, "no backend services found -- this test is checking nothing"

    stale = sorted(set(entry.exempt) - set(services))
    assert not stale, (
        f"{entry.path} exempts services that no longer exist: {stale}. A stale "
        "exemption name exempts nothing, but it means the service list moved and "
        "the real exemptions need re-checking."
    )

    missing = [
        name
        for name, svc in services.items()
        if name not in entry.exempt and entry.path not in _mounts(svc)
    ]
    assert not missing, (
        f"{entry.path} is hardcoded in {entry.source} but these services run the "
        f"backend image without mounting it: {missing}. Every backend service "
        "ships read_only: true, so the write fails with EROFS; and for "
        "/tmp/freesdn_data the per-container tmpfs additionally means api and "
        "worker cannot see each other's files even where the write succeeds."
    )


def _dockerfile_tokens() -> list[str]:
    """The Dockerfile's INSTRUCTIONS, continuations joined, split on whitespace.

    Comment lines are dropped first, or a path merely NAMED in the prose above
    the RUN block would satisfy the "the image creates it" check -- and the
    comments here name every one of these paths.
    """
    body = "\n".join(
        line for line in _dockerfile().splitlines() if not line.lstrip().startswith("#")
    )
    return body.replace("\\\n", " ").split()


def _chowned_dirs(tokens: list[str]) -> set[str]:
    """Absolute paths handed to a ``chown -R appuser:appgroup`` in the image."""
    out: set[str] = set()
    for i, tok in enumerate(tokens):
        if tok != "chown":
            continue
        j = i + 1
        # skip the flags and the user:group operand (bounded, so a chown with no
        # path operand cannot run on into the NEXT command's arguments)
        while j < len(tokens) and j <= i + 3 and not tokens[j].startswith("/"):
            j += 1
        while j < len(tokens) and tokens[j].startswith("/"):
            out.add(tokens[j].rstrip("/"))
            j += 1
    return out


@pytest.mark.parametrize("entry", HARDCODED_WRITE_PATHS, ids=lambda e: e.path)
def test_the_image_pre_creates_and_owns_each_hardcoded_write_path(
    entry: HardcodedWritePath,
) -> None:
    """The /data-only regexes below cannot see /tmp/freesdn_data. This can.

    Mounting a named volume is only half the fix: Docker seeds a fresh volume
    from the image directory at the mountpoint, so if the image does not create
    AND chown that directory the volume root lands root:root and every write by
    appuser (uid 1001) fails with PermissionError instead of EROFS. Verified by
    hand: an image WITHOUT these mkdir/chown lines gives
    "PermissionError [Errno 13] Permission denied: '/data/backups/2026'".

    Catches: dropping any of the four paths from the RUN mkdir -p / chown block
    while leaving the compose mount in place.
    """
    if not _dockerfile():
        pytest.skip("backend/Dockerfile not in this checkout")
    tokens = _dockerfile_tokens()
    assert entry.path in tokens, (
        f"backend/Dockerfile never creates {entry.path}, but docker-compose.yml "
        "mounts a named volume there. Docker seeds that volume from the image "
        "directory, so the volume root will be root-owned and every write by "
        "appuser fails with PermissionError. Add it to the RUN mkdir -p block."
    )
    chowned = _chowned_dirs(tokens)
    assert len(chowned) >= 3, f"chown scan found almost nothing ({chowned}) -- it is broken"
    covered = any(entry.path == owned or entry.path.startswith(owned + "/") for owned in chowned)
    assert covered, (
        f"{entry.path} is created in the image but never chowned to "
        f"appuser:appgroup (chowned: {sorted(chowned)}). A root-owned mountpoint "
        "makes the seeded named volume root-owned too, and the container runs as "
        "uid 1001."
    )


def test_the_hardcoded_write_path_table_is_populated() -> None:
    """Guard the guard: an empty table would make both checks above vacuous."""
    assert len(HARDCODED_WRITE_PATHS) >= 4
    for entry in HARDCODED_WRITE_PATHS:
        assert entry.path.startswith("/")
        assert entry.exempt, f"{entry.path} exempts nothing -- did it lose its reasons?"
        if entry.env_var is None:
            assert entry.path in entry.literal, (
                f"{entry.path} pins a literal that does not contain it, so the pin "
                "could survive the path moving. Either quote the real literal, or "
                "set env_var if the deployment redirects the path."
            )
            continue
        # The source names only the variable; the compose supplies the value.
        assert entry.env_var in entry.literal, (
            f"{entry.path} declares env_var={entry.env_var} but its literal does "
            "not mention it -- the pin would not notice the variable being renamed."
        )
        # Resolve the compose ENVIRONMENT MAPPING, not the file's text. A
        # substring check is not good enough and was wrong here first: renaming
        # the key to FREESDN_AGENT_RELEASE_DIR_TYPO leaves
        # "${FREESDN_AGENT_RELEASE_DIR:-/data/agent-releases}" on the right-hand
        # side, so `"FREESDN_AGENT_RELEASE_DIR:" in text` still matched and the
        # mutation passed. Matching the name instead of the thing that enforces
        # the behaviour is the standing failure mode for detectors in this repo.
        env: dict[str, str] = {}
        for svc in _backend_services(_compose()).values():
            raw_env = svc.get("environment") or {}
            if isinstance(raw_env, dict):
                env.update({k: str(v) for k, v in raw_env.items()})
        assert entry.env_var in env, (
            f"no backend service sets {entry.env_var} in docker-compose.yml, so "
            f"{entry.source} falls back to its own default instead of "
            f"{entry.path} -- and nothing mounts that default."
        )
        resolved = _effective(env[entry.env_var])
        assert resolved == entry.path, (
            f"docker-compose.yml maps {entry.env_var} to {resolved!r}, not "
            f"{entry.path!r}. The mount and the code now point at different "
            "directories."
        )


# ── The HA overlay has to cover every backend service ─────────────────────
#
# docker-compose.ha.yml re-declares each backend service purely to merge
# *sentinel-env into it. A service left off that list keeps the base anchor's
# REDIS_URL, and app/core/redis_client.py's sentinel_addrs() -- finding
# REDIS_SENTINELS empty -- falls back to a DIRECT connection to the `redis`
# service name. After Sentinel promotes redis-replica, `redis` is a read-only
# replica: every write from that service fails with READONLY and never recovers,
# while the rest of the stack follows the new master. `collector` was in exactly
# that state, and it reports itself healthy the whole time.

#: service -> why it needs no Sentinel wiring.
SENTINEL_EXEMPT = {
    "vpn": "execs vpn-sidecar-entrypoint.sh and never opens a Redis client",
}


def _ha_compose() -> dict:
    path = _repo_file("docker-compose.ha.yml")
    if path is None:
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def test_every_backend_service_is_wired_to_sentinel_by_the_ha_overlay() -> None:
    """Fails before the fix on `collector`."""
    ha = _ha_compose()
    if not ha:
        pytest.skip("docker-compose.ha.yml is not in this checkout")
    base_services = _backend_services(_compose())
    assert base_services, "no backend services found -- this test is checking nothing"

    ha_services = ha.get("services") or {}
    unwired = []
    for name in base_services:
        if name in SENTINEL_EXEMPT:
            continue
        env = (ha_services.get(name) or {}).get("environment") or {}
        if not isinstance(env, dict) or not env.get("REDIS_SENTINELS"):
            unwired.append(name)

    assert not unwired, (
        f"docker-compose.ha.yml never merges *sentinel-env into {unwired}. Those "
        "services keep a direct connection to `redis`, which becomes a READ-ONLY "
        "replica the moment Sentinel promotes redis-replica -- every write from "
        "them then fails with READONLY forever while the rest of the stack "
        "follows the new master. Add `<name>: {environment: *sentinel-env}`, or "
        "add it to SENTINEL_EXEMPT with a reason."
    )


# ── The edge probe must survive Caddy's automatic HTTPS ───────────────────
#
# Caddy installs a global HTTP->HTTPS redirect on :80 as soon as
# CADDY_SITE_ADDRESS is a hostname or `localhost` -- the shipped pro/max value,
# and what install.sh picks on a fresh install with no --domain. A probe that
# FOLLOWS that 308 lands on https://127.0.0.1/, where the handshake fails
# because Caddy holds no certificate for the IP. The old
# `wget -qO- http://127.0.0.1/health` did exactly that and reported the edge
# `unhealthy` forever while it served traffic perfectly, which made
# scripts/selfheal.py restart a healthy container until it quarantined it.
#
# busybox wget cannot be told not to follow, so the probe must not be wget.

_FOLLOWS_REDIRECTS = ("wget", "-L", "--location")


def test_the_edge_healthcheck_does_not_follow_caddys_auto_https_redirect() -> None:
    """Catches a revert to `wget -qO- http://127.0.0.1/health`, or adding -L."""
    edge = (_compose().get("services") or {}).get("edge")
    assert edge, "no `edge` service -- this test is checking nothing"
    probe = (edge.get("healthcheck") or {}).get("test")
    assert isinstance(probe, list) and probe, f"unexpected edge healthcheck: {probe!r}"

    offenders = sorted({tok for tok in probe if tok in _FOLLOWS_REDIRECTS})
    assert not offenders, (
        f"the edge healthcheck uses {offenders}, which follows Caddy's "
        "HTTP->HTTPS redirect to https://127.0.0.1/ and fails the handshake "
        "there. With CADDY_SITE_ADDRESS set to a hostname (pro/max) or "
        "`localhost` the container then reports unhealthy forever. Probe :80 "
        "WITHOUT following redirects (curl -fsS, no -L): the 308 is the correct "
        f"answer from a TLS-terminating Caddy. Current probe: {probe}"
    )
    assert any("/health" in tok for tok in probe), (
        f"the edge healthcheck no longer probes /health: {probe}"
    )
