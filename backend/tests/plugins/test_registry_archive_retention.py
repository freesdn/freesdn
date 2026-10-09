# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A new catalog must not delete or silently replace older immutable downloads."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
import zipfile
from pathlib import Path

import pytest


def _load_builder():
    for parent in Path(__file__).resolve().parents:
        path = parent / "registry" / "build.py"
        if path.is_file():
            spec = importlib.util.spec_from_file_location("_registry_retention_builder", path)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    return None


builder = _load_builder()
pytestmark = pytest.mark.skipif(builder is None, reason="registry/ not present in this checkout")


def _archive(path: Path, text: str) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("plugin.py", text)
    return path.read_bytes()


@pytest.fixture
def registry(tmp_path, monkeypatch):
    source = tmp_path / "plugins" / "retention-fixture"
    source.mkdir(parents=True)
    (source / "plugin.yaml").write_text(
        "id: retention-fixture\nversion: 1.0.1\nname: Retention Fixture\n"
    )
    (source / "plugin.py").write_text("# Fixture version 1.0.1\n")
    public = tmp_path / "public"
    downloads = public / "dl"
    downloads.mkdir(parents=True)
    old = _archive(downloads / "retention-fixture-1.0.0.zip", "# Old fixture\n")
    (public / "plugins.json").write_text(
        json.dumps(
            {
                "catalog_version": 1,
                "serial": 10,
                "plugins": [
                    {
                        "plugin_id": "retention-fixture",
                        "version": "1.0.0",
                        "checksum_sha256": hashlib.sha256(old).hexdigest(),
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(builder, "PLUGIN_SRC", tmp_path / "plugins")
    monkeypatch.setattr(builder, "PUBLIC", public)
    monkeypatch.setattr(builder, "DOWNLOADS", downloads)
    monkeypatch.setitem(sys.modules, "site_render", types.SimpleNamespace(render=lambda *_args: 0))
    monkeypatch.setattr(sys, "argv", ["build.py", "--unsigned", "--seed-out", ""])
    return source, public, downloads


def test_new_version_preserves_current_and_retired_archive_bytes(registry):
    _, public, downloads = registry
    _archive(downloads / "retention-fixture-0.9.0.zip", "# Older fixture\n")
    _archive(downloads / "withdrawn-fixture-1.0.0.zip", "# Removed from catalog\n")
    original = {p.name: p.read_bytes() for p in downloads.iterdir()}

    assert builder.main() == 0

    assert (downloads / "retention-fixture-1.0.1.zip").is_file()
    for name, content in original.items():
        assert (downloads / name).read_bytes() == content
    catalog = json.loads((public / "plugins.json").read_text())
    assert catalog["serial"] == 11
    assert [p["plugin_id"] for p in catalog["plugins"]] == ["retention-fixture"]


def test_old_immutable_url_cannot_be_reused_outside_current_catalog(registry):
    _, public, downloads = registry
    occupied = downloads / "retention-fixture-1.0.1.zip"
    old = _archive(occupied, "# Previously published different version bytes\n")
    catalog = (public / "plugins.json").read_bytes()

    assert builder.main() == 1

    assert occupied.read_bytes() == old
    assert (public / "plugins.json").read_bytes() == catalog


def test_identical_existing_archive_is_not_an_immutable_conflict(registry, tmp_path):
    source, _, downloads = registry
    builder.package_plugin(source, "https://registry.example.test", downloads)
    original = (downloads / "retention-fixture-1.0.1.zip").read_bytes()

    assert builder.main() == 0

    assert (downloads / "retention-fixture-1.0.1.zip").read_bytes() == original


def test_unexpected_download_file_refuses_before_catalog_or_archive_changes(registry):
    _, public, downloads = registry
    unexpected = downloads / ".env"
    unexpected.write_text("not a package\n")
    catalog = (public / "plugins.json").read_bytes()
    original = (downloads / "retention-fixture-1.0.0.zip").read_bytes()

    assert builder.main() == 1

    assert unexpected.read_text() == "not a package\n"
    assert (public / "plugins.json").read_bytes() == catalog
    assert (downloads / "retention-fixture-1.0.0.zip").read_bytes() == original


def test_symlinked_archive_refuses_without_reading_or_removing_target(registry, tmp_path):
    _, public, downloads = registry
    target = tmp_path / "outside.txt"
    target.write_text("outside fixture\n")
    (downloads / "linked-fixture-1.0.0.zip").symlink_to(target)
    catalog = (public / "plugins.json").read_bytes()

    assert builder.main() == 1

    assert target.read_text() == "outside fixture\n"
    assert (downloads / "linked-fixture-1.0.0.zip").is_symlink()
    assert (public / "plugins.json").read_bytes() == catalog


def test_explicit_unpublished_version_reuse_opt_out_remains_explicit(registry, monkeypatch):
    _, _, downloads = registry
    occupied = downloads / "retention-fixture-1.0.1.zip"
    old = _archive(occupied, "# Unpublished fixture bytes\n")
    monkeypatch.setattr(
        sys, "argv", ["build.py", "--unsigned", "--seed-out", "", "--allow-version-reuse"]
    )

    assert builder.main() == 0

    assert occupied.read_bytes() != old
