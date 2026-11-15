# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN's own Prometheus must be able to scrape FreeSDN.

In production the api serves ``/metrics`` only to ``Authorization: Bearer
<METRICS_AUTH_TOKEN>`` (fail-closed, app/core/metrics.py). No tier example set
the token and the bundled Prometheus sent none, so on every pro/max install the
``freesdn-api`` target was DOWN with a 404 and every alert rule built on API
metrics was dead. Found on the 2026-11 soak VM.

The wiring pinned here was verified against the built Prometheus image on the
test VM: with the entrypoint below the token file is 0600, owned by the
Prometheus user, and Prometheus starts and scrapes with an empty or a real
token. A compose ``secrets: environment:`` source was rejected because compose
refuses to create ANY container when the variable is unset, which is exactly
the state of every install upgraded from an env file without the token.
"""

from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")


def _repo_root() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "docker-compose.yml").is_file() and (parent / "docker").is_dir():
            return parent
    return None


ROOT = _repo_root()
pytestmark = pytest.mark.skipif(ROOT is None, reason="compose files not in this checkout")

TOKEN_FILE = "/tmp/metrics_auth_token"


def _prometheus_service() -> dict:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["prometheus"]


def _api_job() -> dict:
    config = yaml.safe_load(
        (ROOT / "docker" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    )
    jobs = {job["job_name"]: job for job in config["scrape_configs"]}
    return jobs["freesdn-api"]


def test_the_api_job_sends_the_token_from_a_file():
    auth = _api_job().get("authorization")
    assert auth, "freesdn-api is scraped without credentials: DOWN (404) in production"
    assert auth.get("type") == "Bearer"
    assert auth.get("credentials_file") == TOKEN_FILE
    # The token itself never lives in the config file (it is in git).
    assert "credentials" not in auth


def test_prometheus_writes_that_file_from_the_installer_generated_variable():
    service = _prometheus_service()
    assert service["environment"]["METRICS_AUTH_TOKEN"].startswith("${METRICS_AUTH_TOKEN")
    entrypoint = service["entrypoint"]
    assert entrypoint[:2] == ["/bin/sh", "-c"]
    script = entrypoint[2]
    # Private file, then the variable is dropped before Prometheus starts.
    assert script.startswith("umask 077 ")
    assert f'printf %s "$$METRICS_AUTH_TOKEN" > {TOKEN_FILE}' in script
    assert "unset METRICS_AUTH_TOKEN" in script
    assert script.rstrip().endswith('exec /bin/prometheus "$$@"')
    # $0 for sh -c; the service's command: becomes Prometheus's own arguments.
    assert entrypoint[3] == "prometheus"
    assert service["command"][0].startswith("--config.file=")
    # Ephemeral container /tmp, not the persisted TSDB volume.
    assert not TOKEN_FILE.startswith("/prometheus")


def test_the_token_is_not_baked_into_the_prometheus_image():
    dockerfile = (ROOT / "docker" / "Dockerfile.prometheus").read_text(encoding="utf-8")
    assert "METRICS_AUTH_TOKEN" not in dockerfile
    assert "metrics_auth_token" not in dockerfile


@pytest.mark.parametrize("tier", ["lite", "pro", "max"])
def test_every_tier_example_has_the_installer_generate_it(tier):
    text = (ROOT / f".env.{tier}.example").read_text(encoding="utf-8")
    assert re.search(r"^METRICS_AUTH_TOKEN=__CHANGE_ME__\s*$", text, re.MULTILINE), (
        f".env.{tier}.example must carry an uncommented METRICS_AUTH_TOKEN=__CHANGE_ME__ "
        "so install.sh generates it"
    )
