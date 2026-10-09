# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL/SDK settings semantics; vendor transport remains synthetic."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.plugins import PluginSetting
from app.plugins.schema import PluginManifest
from app.plugins.sdk import PluginSettingsSDK
from tests.plugins.test_ticketing_settings_defaults import (
    EXPECTED_MAP,
    LEGACY_MAP,
    configure,
    load_plugin,
    manifest,
)

STATES = ["missing", "blank", "custom", "legacy"]
CUSTOM_MAP = {"critical": "2", "error": "1", "warning": "3", "info": "2"}
CUSTOM_TEXT = "critical=2,error=1,warning=3,info=2"


async def seed(db_session, state):
    plugin = load_plugin("servicenow-incidents")
    plugin._plugin_manifest_data = PluginManifest.model_validate(manifest("servicenow-incidents"))
    values, http = configure(plugin)
    if state == "missing":
        del values["urgency_map"]
    else:
        values["urgency_map"] = {"blank": "", "custom": CUSTOM_TEXT, "legacy": LEGACY_MAP}[state]
    org, other_org = uuid4(), uuid4()
    rows = [PluginSetting(plugin_id="servicenow-incidents", organization_id=org, key=k, value=v) for k, v in values.items()]
    sentinel = PluginSetting(plugin_id="servicenow-incidents", organization_id=other_org, key="urgency_map", value="critical=3,error=1,warning=1,info=1")
    db_session.add_all([*rows, sentinel])
    await db_session.flush()
    plugin.ctx.settings = PluginSettingsSDK("servicenow-incidents", org, db_session)
    return plugin, http, org, sentinel.id


async def raw_setting(db_session, org):
    row = (await db_session.execute(select(PluginSetting).where(
        PluginSetting.plugin_id == "servicenow-incidents",
        PluginSetting.organization_id == org,
        PluginSetting.key == "urgency_map",
    ))).scalar_one_or_none()
    return {"present": row is not None, "value": row.value if row else None}


def intended_map(state):
    return {} if state == "blank" else CUSTOM_MAP if state == "custom" else EXPECTED_MAP


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("severity", list(EXPECTED_MAP))
async def test_persisted_sdk_settings_produce_intended_payload(db_session, state, severity, record_property):
    plugin, http, org, sentinel_id = await seed(db_session, state)
    before = await raw_setting(db_session, org)
    await plugin._create("synthetic-persisted-alert", {"severity": severity, "title": "Synthetic persisted settings"})
    http.post.assert_awaited_once()
    payload = http.post.await_args.kwargs["json"]
    after = await raw_setting(db_session, org)
    tracked = await plugin.ctx.settings.get("__snow_incident__synthetic-persisted-alert")
    sentinel = await db_session.get(PluginSetting, sentinel_id, populate_existing=True)
    observation = {"state": state, "severity": severity, "payload_urgency": payload["urgency"],
                   "before_setting": before, "after_setting": after, "tracked_incident": tracked,
                   "other_org_setting": sentinel.value}
    record_property("observed_persisted_payload", json.dumps(observation, sort_keys=True))
    assert payload["urgency"] == intended_map(state).get(severity, "3")
    assert before == after
    assert tracked == "synthetic-incident"
    assert sentinel.value == "critical=3,error=1,warning=1,info=1"


@pytest.mark.parametrize("state", STATES)
async def test_configuration_advisory_respects_missing_vs_explicit_blank(db_session, state, record_property):
    plugin, http, org, _ = await seed(db_session, state)
    before = await raw_setting(db_session, org)
    warning = await plugin.async_validate_config()
    after = await raw_setting(db_session, org)
    http.get.assert_awaited_once()
    record_property("observed_persisted_advisory", json.dumps({"state": state, "warning": warning, "before": before, "after": after}, sort_keys=True))
    if state == "blank":
        assert warning == "Connected, but urgency_map is unusable: no usable severity=urgency pairs"
    else:
        assert warning is None
    assert before == after


@pytest.mark.parametrize("state", STATES)
async def test_status_describes_the_same_effective_map_without_writing_defaults(db_session, state, record_property):
    plugin, http, org, _ = await seed(db_session, state)
    before = await raw_setting(db_session, org)
    status = await plugin._status()
    after = await raw_setting(db_session, org)
    record_property("observed_persisted_status", json.dumps({"state": state, "urgency_map": status["urgency_map"], "before": before, "after": after}, sort_keys=True))
    assert status["urgency_map"] == intended_map(state)
    assert before == after
    http.get.assert_not_awaited()
    http.post.assert_not_awaited()
