# SPDX-License-Identifier: AGPL-3.0-only
"""Actual plugin configuration and payload behavior; vendor transport is synthetic."""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import yaml

from app.plugins.sandbox import plugin_import_guard, restrict_plugin_builtins
from app.plugins.sdk_alias import install_freesdn_sdk_alias

LEGACY_MAP = "critical=1,high=2,medium=2,low=3,info=3"
EXPECTED_MAP = {"critical": "1", "error": "2", "warning": "2", "info": "3"}


def registry() -> Path:
    for parent in Path(__file__).resolve().parents:
        found = parent / "registry" / "plugins"
        if found.is_dir():
            return found
    raise AssertionError("Frozen companion registry is required, never skip")


def manifest(name: str) -> dict:
    return yaml.safe_load((registry() / name / "plugin.yaml").read_bytes())


def load_plugin(name: str):
    install_freesdn_sdk_alias()
    spec = importlib.util.spec_from_file_location(
        "ticketing_default_probe_" + name.replace("-", "_"), registry() / name / "plugin.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    restrict_plugin_builtins(module, name)
    with plugin_import_guard(name):
        spec.loader.exec_module(module)
    return getattr(module, manifest(name)["class_name"])()


def configure(plugin, *, legacy=False, dry_run=False):
    values = {
        name: spec["default"]
        for name, spec in manifest("servicenow-incidents")["settings_schema"]["properties"].items()
        if "default" in spec
    }
    values.update(
        instance_url="https://ticketing.invalid",
        username="synthetic-integration",
        password="synthetic-not-a-credential",
        minimum_severity="info",
        dry_run=dry_run,
    )
    if legacy:
        values["urgency_map"] = LEGACY_MAP

    async def get(name, default=None):
        return values.get(name, default)

    async def put(name, value):
        values[name] = value

    response = SimpleNamespace(
        status_code=201, json=lambda: {"result": {"sys_id": "synthetic-incident", "number": "INC-SYNTHETIC"}}
    )
    http = SimpleNamespace(get=AsyncMock(return_value=response), post=AsyncMock(return_value=response))
    plugin.ctx = SimpleNamespace(
        settings=SimpleNamespace(get=AsyncMock(side_effect=get), set=AsyncMock(side_effect=put)),
        http=http,
        logger=logging.getLogger("ticketing-default-probe"),
    )
    return values, http


@pytest.mark.parametrize("name", ["jira-tickets", "servicenow-incidents", "pagerduty-incidents"])
def test_manifest_severity_default_is_an_allowed_choice(name):
    spec = manifest(name)["settings_schema"]["properties"]["minimum_severity"]
    assert spec["type"] == "string"
    assert isinstance(spec["default"], str)
    assert spec["default"] in spec["enum"]


@pytest.mark.parametrize("legacy", [False, True], ids=["declared", "persisted-legacy"])
def test_urgency_map_accepts_declared_and_persisted_configuration(legacy):
    plugin = load_plugin("servicenow-incidents")
    raw = LEGACY_MAP if legacy else manifest("servicenow-incidents")["settings_schema"]["properties"]["urgency_map"]["default"]
    assert plugin._parse_urgency_map(raw, strict=True) == EXPECTED_MAP


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("high=1", {"error": "1"}), ("medium=1", {"warning": "1"}),
     ("low=2", {"info": "2"}), (" ERROR = 2 ", {"error": "2"})],
    ids=["high", "medium", "low", "canonical-whitespace"],
)
def test_saved_urgency_aliases_keep_operator_values(raw, expected):
    assert load_plugin("servicenow-incidents")._parse_urgency_map(raw, strict=True) == expected


@pytest.mark.parametrize("raw", ["urgent=1", "error=4", "error"], ids=["unknown", "invalid-urgency", "missing-pair"])
def test_invalid_maps_are_still_refused(raw):
    assert isinstance(load_plugin("servicenow-incidents")._parse_urgency_map(raw, strict=True), str)


def test_lenient_runtime_keeps_valid_pairs_without_accepting_invalid_urgency():
    assert load_plugin("servicenow-incidents")._parse_urgency_map("error=2,urgent=1,warning=4,broken") == {"error": "2"}


@pytest.mark.parametrize("legacy", [False, True], ids=["declared", "persisted-legacy"])
@pytest.mark.parametrize(("severity", "urgency"), list(EXPECTED_MAP.items()), ids=list(EXPECTED_MAP))
async def test_actual_incident_payload_preserves_urgency(severity, urgency, legacy, record_property):
    plugin = load_plugin("servicenow-incidents")
    values, http = configure(plugin, legacy=legacy)
    await plugin._create("synthetic-alert", {"severity": severity, "title": "Synthetic alert"})
    http.post.assert_awaited_once()
    payload = http.post.await_args.kwargs["json"]
    record_property("observed_incident_payload", json.dumps(payload, sort_keys=True))
    assert payload["urgency"] == urgency
    assert payload["impact"] == "2"
    assert payload["correlation_id"] == "freesdn:synthetic-alert"
    assert values["__snow_incident__synthetic-alert"] == "synthetic-incident"


@pytest.mark.parametrize("legacy", [False, True], ids=["declared", "persisted-legacy"])
async def test_config_validator_accepts_usable_mapping_after_transport_boundary(legacy, record_property):
    plugin = load_plugin("servicenow-incidents")
    _, http = configure(plugin, legacy=legacy)
    observed = await plugin.async_validate_config()
    http.get.assert_awaited_once()
    record_property("observed_config_warning", json.dumps(observed))
    assert observed is None


@pytest.mark.parametrize("name", ["jira-tickets", "servicenow-incidents"])
@pytest.mark.parametrize(
    ("severity", "floor", "allowed"),
    [("error", "high", True), ("warning", "high", False), ("warning", "medium", True),
     ("info", "medium", False), ("info", "low", True), ("error", "error", True)],
    ids=["error-high", "warning-high", "warning-medium", "info-medium", "info-low", "canonical"],
)
def test_existing_severity_floor_aliases_remain_supported(name, severity, floor, allowed):
    assert load_plugin(name)._meets_floor(severity, floor) is allowed


async def test_dry_run_still_sends_no_incident():
    plugin = load_plugin("servicenow-incidents")
    _, http = configure(plugin, dry_run=True)
    await plugin._create("synthetic-alert", {"severity": "error", "title": "Synthetic alert"})
    http.post.assert_not_awaited()
