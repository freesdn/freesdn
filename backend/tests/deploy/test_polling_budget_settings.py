# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The polling budgets are settings, reach every backend service, and drive beat.

shipped GATEWAY_SYNC_MIN_INTERVAL_SECONDS as a setting that a Compose
install could not change: the compose file passes backend settings through an
explicit list and it was not on it. Every budget here must be on that list with
the app's own default, and the beat schedule must read it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app.core.celery_app import celery_app
from app.core.config import Settings, settings

BUDGETS = (
    "GATEWAY_SYNC_MIN_INTERVAL_SECONDS",
    "GATEWAY_CONFIG_XML_REFRESH_SECONDS",
    "FIREWALL_HEALTH_INTERVAL_SECONDS",
    "CONTROLLER_SYNC_MIN_INTERVAL_SECONDS",
    "DEVICE_STATUS_INTERVAL_SECONDS",
    "CONTROLLER_HEALTH_INTERVAL_SECONDS",
    "CONTROLLER_LOGIN_PROBE_INTERVAL_SECONDS",
    "OMADA_MONITOR_INTERVAL_SECONDS",
    "CAMERA_HEALTH_INTERVAL_SECONDS",
    "CAMERA_ALERT_POLL_INTERVAL_SECONDS",
    "VOIP_HEALTH_INTERVAL_SECONDS",
    "HYPERVISOR_HEALTH_INTERVAL_SECONDS",
    "STORAGE_HEALTH_INTERVAL_SECONDS",
    "CONFIG_BACKUP_INTERVAL_HOURS",
    "RECONCILE_INTERVAL_SECONDS",
    "DEVICE_UI_READ_WAIT_SECONDS",
    "DEVICE_UI_READ_MAX_WAIT_SECONDS",
    "DEVICE_UI_READ_CONCURRENCY",
    "DEVICE_UI_READ_CACHE_SECONDS",
    "DEVICE_WRITE_SLOT_WAIT_SECONDS",
    "CELERY_QUEUE_STALE_SECONDS",
)

#: beat entry -> the setting its interval comes from
BEAT = {
    "firewall-poll-health": "FIREWALL_HEALTH_INTERVAL_SECONDS",
    "sync-device-statuses": "DEVICE_STATUS_INTERVAL_SECONDS",
    "check-controller-health": "CONTROLLER_HEALTH_INTERVAL_SECONDS",
    "omada-poll-health": "OMADA_MONITOR_INTERVAL_SECONDS",
    "camera-poll-health": "CAMERA_HEALTH_INTERVAL_SECONDS",
    "camera-ingest-alerts": "CAMERA_ALERT_POLL_INTERVAL_SECONDS",
    "voip-phone-health-check": "VOIP_HEALTH_INTERVAL_SECONDS",
    "hypervisor-poll-health": "HYPERVISOR_HEALTH_INTERVAL_SECONDS",
    "storage-poll-health": "STORAGE_HEALTH_INTERVAL_SECONDS",
    "enterprise-reconcile-all": "RECONCILE_INTERVAL_SECONDS",
}


def _compose() -> dict:
    root = Path(__file__).resolve().parents[3]
    path = root / "docker-compose.yml"
    if not path.exists():
        pytest.skip("docker-compose.yml not reachable (backend-only mount)")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", BUDGETS)
def test_every_budget_reaches_every_backend_service_with_the_app_default(name) -> None:
    compose = _compose()
    backend = [
        svc
        for svc in compose["services"].values()
        if str(svc.get("image", "")).startswith("${BACKEND_IMAGE")
    ]
    assert len(backend) >= 4
    default = Settings.model_fields[name].default
    for svc in backend:
        value = svc["environment"].get(name)
        assert value is not None, f"{name} is not passed to a backend service"
        match = re.fullmatch(r"\$\{" + name + r":-([^}]*)\}", str(value))
        assert match, f"{name} should read ${{{name}:-<default>}}, got {value!r}"
        assert float(match.group(1)) == float(default), (
            f"{name}: compose default {match.group(1)} differs from the app's {default}"
        )


@pytest.mark.parametrize(("entry", "name"), sorted(BEAT.items()))
def test_beat_intervals_come_from_the_settings(entry, name) -> None:
    schedule = celery_app.conf.beat_schedule[entry]["schedule"]
    assert float(schedule) == float(getattr(settings, name))


def test_the_defaults_are_the_owners_budgets() -> None:
    """Owner decision 2026-11-13: firewalls full 15-30 min + light health 2-5
    min; controllers 5-15 min; NVRs and phones 5 min; Proxmox/TrueNAS 2-5 min;
    config backups daily."""
    d = {name: Settings.model_fields[name].default for name in BUDGETS}
    assert 900 <= d["GATEWAY_SYNC_MIN_INTERVAL_SECONDS"] <= 1800
    assert 120 <= d["FIREWALL_HEALTH_INTERVAL_SECONDS"] <= 300
    assert 300 <= d["CONTROLLER_SYNC_MIN_INTERVAL_SECONDS"] <= 900
    assert 300 <= d["DEVICE_STATUS_INTERVAL_SECONDS"] <= 900
    assert d["CAMERA_HEALTH_INTERVAL_SECONDS"] == 300
    assert d["VOIP_HEALTH_INTERVAL_SECONDS"] == 300
    assert 120 <= d["HYPERVISOR_HEALTH_INTERVAL_SECONDS"] <= 300
    assert 120 <= d["STORAGE_HEALTH_INTERVAL_SECONDS"] <= 300
    assert d["CONFIG_BACKUP_INTERVAL_HOURS"] == 24


def test_a_poll_message_expires_before_the_next_one_is_due() -> None:
    for entry in ("firewall-poll-health", "check-controller-health", "voip-phone-health-check"):
        conf = celery_app.conf.beat_schedule[entry]
        assert conf["options"]["expires"] < float(conf["schedule"])
