# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The optional Tailscale access addon honours TAILSCALE_NO_LOGS_NO_SUPPORT.

``docker-compose.tailscale.yml`` runs its own tailscaled (Tailscale's
containerboot, to serve the UI on the tailnet). The log-upload setting added in
26.12 reached the runtime container and the vpn sidecar but not this one: the
addon passed nothing, so with ``TAILSCALE_NO_LOGS_NO_SUPPORT=true`` set for the
stack its tailscaled still uploaded logs to Tailscale Inc.

The image's entrypoint now maps the setting onto ``--no-logs-no-support`` in
containerboot's ``TS_TAILSCALED_EXTRA_ARGS`` (1.104.5 ``cmd/containerboot``
splits that on whitespace onto tailscaled's argv). Not as tailscaled's own
``TS_NO_LOGS_NO_SUPPORT`` variable: envknob parses that with strconv.ParseBool
and calls log.Fatalf on "yes" or "on", which FreeSDN accepts.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

BACKEND = pathlib.Path(__file__).resolve().parents[2]
WRAPPER = BACKEND / "tailscale-access" / "entrypoint.sh"


def _repo_file(name: str) -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / name).is_file() and (parent / "backend").is_dir():
            return parent / name
    return None


ADDON = _repo_file("docker-compose.tailscale.yml")
BASE = _repo_file("docker-compose.yml")

#: The base stack's expression, which tests/deploy/test_tailscale_runtime_topology.py pins.
EXPECTED = "${TAILSCALE_NO_LOGS_NO_SUPPORT:-true}"


@pytest.mark.skipif(ADDON is None or BASE is None, reason="compose files not in this checkout")
def test_the_addon_gets_the_same_setting_as_the_stack():
    yaml = pytest.importorskip("yaml")
    assert ADDON is not None and BASE is not None
    addon = yaml.safe_load(ADDON.read_text(encoding="utf-8"))["services"]["tailscale-access"]
    base = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    assert addon["environment"]["TAILSCALE_NO_LOGS_NO_SUPPORT"] == EXPECTED
    assert base["x-backend-env"]["TAILSCALE_NO_LOGS_NO_SUPPORT"] == EXPECTED
    assert "TS_NO_LOGS_NO_SUPPORT" not in addon["environment"], (
        "tailscaled exits on a non-Go boolean there; the entrypoint maps it instead"
    )


def test_the_addon_image_starts_through_the_wrapper():
    df = (BACKEND / "Dockerfile").read_text(encoding="utf-8")
    stage = re.search(r"^FROM [^\n]+ AS tailscale-access\n(.*?)(?=^FROM |\Z)", df, re.M | re.S)
    assert stage, "backend/Dockerfile has no tailscale-access stage"
    body = stage.group(1)
    assert "COPY tailscale-access/entrypoint.sh /usr/local/bin/freesdn-tailscale-access" in body
    assert 'ENTRYPOINT ["/usr/local/bin/freesdn-tailscale-access"]' in body
    # containerboot stays where Tailscale's own image keeps it.
    assert "ln -s /usr/local/bin/containerboot /tailscale/run.sh" in body


FAKE_CONTAINERBOOT = """#!/bin/sh
{
  echo "extra=${TS_TAILSCALED_EXTRA_ARGS-<unset>}"
  echo "knob=${TS_NO_LOGS_NO_SUPPORT-<unset>}"
  echo "args=$*"
} > "$OUT"
"""


@pytest.fixture
def run_wrapper(tmp_path):
    if sys.platform != "linux" or shutil.which("sh") is None:
        pytest.skip("POSIX shell script")
    boot = tmp_path / "containerboot"
    boot.write_text(FAKE_CONTAINERBOOT)
    boot.chmod(0o755)
    out = tmp_path / "out"

    def run(*args: str, **env: str) -> tuple[dict[str, str], str]:
        full = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "CONTAINERBOOT_BIN": str(boot),
            "OUT": str(out),
            **env,
        }
        proc = subprocess.run(
            ["sh", str(WRAPPER), *args], env=full, capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0, proc.stderr
        seen = dict(line.split("=", 1) for line in out.read_text().splitlines())
        return seen, proc.stderr

    return run


@pytest.mark.parametrize("value", [None, "", "false", "0", "no", "off", "FALSE"])
def test_uploads_stay_on_unless_turned_off(run_wrapper, value):
    env = {} if value is None else {"TAILSCALE_NO_LOGS_NO_SUPPORT": value}
    seen, log = run_wrapper(**env)
    assert seen["extra"] == "<unset>"
    assert seen["knob"] == "<unset>"
    assert "log upload to Tailscale on" in log


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
def test_true_adds_the_tailscaled_flag(run_wrapper, value):
    seen, log = run_wrapper(TAILSCALE_NO_LOGS_NO_SUPPORT=value)
    assert seen["extra"] == "--no-logs-no-support"
    assert seen["knob"] == "<unset>", "never handed on as tailscaled's strict env knob"
    assert "log upload to Tailscale off" in log


def test_extra_daemon_args_are_kept_and_arguments_passed_on(run_wrapper):
    seen, _ = run_wrapper(
        "--example", TAILSCALE_NO_LOGS_NO_SUPPORT="true", TS_TAILSCALED_EXTRA_ARGS="--debug=:9001"
    )
    assert seen["extra"] == "--debug=:9001 --no-logs-no-support"
    assert seen["args"] == "--example"
