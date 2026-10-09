# SPDX-License-Identifier: AGPL-3.0-only
"""Exact old/new ZIPs through the real loader and PostgreSQL savepoint fixture.

No marketplace/authentication or vendor transport is substituted for this loader
scope. SQL commits here retain the original outer fixture transaction; a new
loader proves disk reload, not process/host restart or independent durability.
"""
from __future__ import annotations

import hashlib
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from zipfile import ZipFile

import pytest
from sqlalchemy import select
from starlette.datastructures import UploadFile

from app.models.plugins import InstalledPlugin, PluginSetting
from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader, PluginLoadError
from app.plugins.sdk import PluginSettingsSDK
from tests.plugins.test_ticketing_settings_defaults import EXPECTED_MAP, LEGACY_MAP

SLUGS = ["jira-tickets", "servicenow-incidents"]
CUSTOM = "critical=2,error=1,warning=3,info=2"


def archive(slug, version):
    for root in Path(__file__).resolve().parents:
        path = root / "registry" / "public" / "dl" / f"{slug}-{version}.zip"
        if path.is_file():
            return path.read_bytes()
    raise AssertionError("Frozen archive required, never skip")


def disk_files(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file()}


def expected_files(raw):
    with ZipFile(BytesIO(raw)) as z:
        assert set(z.namelist()) == {"plugin.py", "plugin.yaml"}
        return {name: hashlib.sha256(z.read(name)).hexdigest() for name in z.namelist()}


async def settings_rows(db, slug):
    rows = (await db.execute(select(PluginSetting).where(PluginSetting.plugin_id == slug))).scalars().all()
    return sorted((str(r.organization_id), r.key, json.dumps(r.value, sort_keys=True)) for r in rows)


async def seed_settings(db, slug, profile):
    org, other = uuid4(), uuid4()
    values = {"__tracked_ticket__": "synthetic-retained", "dry_run": True}
    if profile != "missing":
        values["minimum_severity"] = {"legacy": "high", "custom": "warning", "blank": ""}[profile]
        if slug == "servicenow-incidents":
            values["urgency_map"] = {"legacy": LEGACY_MAP, "custom": CUSTOM, "blank": ""}[profile]
    db.add_all([PluginSetting(plugin_id=slug, organization_id=org, key=k, value=v) for k, v in values.items()])
    db.add(PluginSetting(plugin_id=slug, organization_id=other, key="minimum_severity", value="critical"))
    await db.commit()
    return org


def make_loader(monkeypatch, tmp_path):
    dest = tmp_path / "installed"
    monkeypatch.setattr(loader_module, "PLUGIN_DIR", dest)
    # Never permit dependency installation as a side effect of this rehearsal.
    monkeypatch.setattr(loader_module.settings, "PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS", False)
    return PluginLoader(), dest


async def observe_status(plugin, db, slug, org):
    plugin.ctx = SimpleNamespace(settings=PluginSettingsSDK(slug, org, db))
    return await plugin._status()


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("source_kind", ["bytes", "multipart"])
async def test_exact_candidate_installs_and_reloads(db_session, monkeypatch, tmp_path, slug, source_kind, record_property):
    loader, dest = make_loader(monkeypatch, tmp_path)
    raw = archive(slug, "1.0.4")
    source = UploadFile(BytesIO(raw), filename=f"{slug}.zip") if source_kind == "multipart" else raw
    try:
        row = await loader.install_plugin(source, db_session, None)
    finally:
        if source_kind == "multipart":
            await source.close()
    reload = PluginLoader()
    loaded = await reload.load_all_plugins(db_session)
    actual = {"version": row.version, "status": row.status, "active": row.is_active,
              "manifest_version": row.manifest_cache["version"], "files": disk_files(dest / slug),
              "reload_count": len(loaded), "reload_missing": reload.missing_on_disk,
              "loaded_version": reload._loaded[slug]._plugin_manifest_data.version}
    record_property("actual_install", json.dumps(actual, sort_keys=True))
    assert actual == {"version": "1.0.4", "status": "installed", "active": True,
                      "manifest_version": "1.0.4", "files": expected_files(raw),
                      "reload_count": 1, "reload_missing": [], "loaded_version": "1.0.4"}
    assert await settings_rows(db_session, slug) == []


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("profile", ["missing", "legacy", "custom", "blank"])
async def test_published_archive_upgrades_with_settings_intact(db_session, monkeypatch, tmp_path, slug, profile, record_property):
    loader, dest = make_loader(monkeypatch, tmp_path)
    old, new = archive(slug, "1.0.3"), archive(slug, "1.0.4")
    row = await loader.install_plugin(old, db_session, None)
    assert row.version == "1.0.3" and disk_files(dest / slug) == expected_files(old)
    original_id = row.id
    org = await seed_settings(db_session, slug, profile)
    before = await settings_rows(db_session, slug)
    upgraded = await loader.upgrade_plugin(slug, new, db_session, None)
    reload = PluginLoader()
    loaded = await reload.load_all_plugins(db_session)
    status = await observe_status(reload._loaded[slug], db_session, slug, org)
    after = await settings_rows(db_session, slug)
    actual = {"version": upgraded.version, "status": upgraded.status, "same_row": upgraded.id == original_id,
              "files": disk_files(dest / slug), "settings_unchanged": before == after,
              "settings_count": len(after), "reload_count": len(loaded),
              "minimum_severity": status["minimum_severity"], "urgency_map": status.get("urgency_map")}
    record_property("actual_upgrade", json.dumps(actual, sort_keys=True))
    assert upgraded.version == "1.0.4" and upgraded.status == "installed" and upgraded.id == original_id
    assert before == after and disk_files(dest / slug) == expected_files(new) and len(loaded) == 1
    assert status["minimum_severity"] == {"missing": "error", "legacy": "high", "custom": "warning", "blank": ""}[profile]
    if slug == "servicenow-incidents":
        assert status["urgency_map"] == ({"critical": "2", "error": "1", "warning": "3", "info": "2"} if profile == "custom" else {} if profile == "blank" else EXPECTED_MAP)


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("bad_input", ["corrupt", "wrong-plugin"])
async def test_invalid_upgrade_refuses_without_installing_or_stranding(db_session, monkeypatch, tmp_path, slug, bad_input, record_property):
    loader, dest = make_loader(monkeypatch, tmp_path)
    await loader.install_plugin(archive(slug, "1.0.3"), db_session, None)
    await seed_settings(db_session, slug, "legacy")
    before_files = disk_files(dest)
    before_settings = await settings_rows(db_session, slug)
    other = next(s for s in SLUGS if s != slug)
    raw = b"synthetic-invalid-zip" if bad_input == "corrupt" else archive(other, "1.0.4")
    error = None
    returned = None
    try:
        row = await loader.upgrade_plugin(slug, raw, db_session, None)
        returned = row.plugin_id
    except PluginLoadError as exc:
        error = str(exc)
    rows = (await db_session.execute(select(InstalledPlugin).execution_options(populate_existing=True))).scalars().all()
    state = sorted((r.plugin_id, r.version, r.status, r.is_active) for r in rows)
    actual = {"input": bad_input, "rejected": error is not None, "error": error,
              "returned_plugin": returned, "rows": state,
              "files_unchanged": disk_files(dest) == before_files,
              "settings_unchanged": await settings_rows(db_session, slug) == before_settings}
    record_property("actual_invalid_upgrade", json.dumps(actual, sort_keys=True))
    assert error is not None, actual
    assert state == [(slug, "1.0.3", "installed", True)]
    assert actual["files_unchanged"] and actual["settings_unchanged"]
