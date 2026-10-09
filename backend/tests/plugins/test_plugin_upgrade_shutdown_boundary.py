# SPDX-License-Identifier: AGPL-3.0-only
"""Observe real runtime shutdown relative to validation, locking and replacement."""
import json

import pytest

from app.plugins import loader as loader_module
from app.plugins.loader import PluginLoader
from tests.plugins.test_plugin_upgrade_runtime_recovery import (
    test_authenticated_upload_preserves_running_plugin as run_upload,
)
from tests.plugins.test_ticketing_archive_lifecycle import (
    SLUGS,
    archive,
    disk_files,
    expected_files,
)


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("outcome", ["corrupt", "wrong-plugin", "valid"])
async def test_actual_shutdown_follows_validation_before_replacement(
    monkeypatch, tmp_path, record_property, slug, outcome,
):
    original_stop = PluginLoader.stop_plugin_everywhere
    observations = []

    async def observe_stop(loader, plugin_id, db=None):
        runtimes = [runtime for (pid, _org), runtime in loader.get_active().items() if pid == plugin_id]
        if runtimes:
            lock = loader._lifecycle_locks.get(plugin_id)
            observations.append({
                "lock_held": lock is not None and lock.locked(),
                "active_orgs": len(runtimes),
                "runtime_versions": sorted(r._plugin_manifest_data.version for r in runtimes),
                "old_files_still_exact": disk_files(loader_module.PLUGIN_DIR / plugin_id) == expected_files(archive(plugin_id, "1.0.3")),
            })
        # Observe, then execute the real shutdown, including hooks and unsubscribe.
        return await original_stop(loader, plugin_id, db)

    monkeypatch.setattr(PluginLoader, "stop_plugin_everywhere", observe_stop)
    try:
        await run_upload(monkeypatch, tmp_path, record_property, slug, "jwt", outcome)
    finally:
        record_property("actual_shutdown_boundary", json.dumps(observations, sort_keys=True))
    cleanup = {"lock_held": False, "active_orgs": 2,
               "runtime_versions": ["1.0.4" if outcome == "valid" else "1.0.3"] * 2,
               "old_files_still_exact": outcome != "valid"}
    expected = ([{"lock_held": True, "active_orgs": 2, "runtime_versions": ["1.0.3"] * 2,
                  "old_files_still_exact": True}] if outcome == "valid" else []) + [cleanup]
    assert observations == expected
