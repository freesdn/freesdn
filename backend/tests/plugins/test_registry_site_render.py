# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The registry site must publish a 404 page.

Without a top-level 404.html, Cloudflare Pages treats the registry as a
single-page app and answers every unknown path with index.html and a 200.
Under /dl/* that HTML was labelled application/zip and cached immutable for a
year, so a missing archive looked like a successful download of a corrupt ZIP.

These tests skip in a backend-only checkout, where registry/ is absent.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest


def _load_site_render():
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "site_render.py"
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("_registry_site_render", candidate)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules["_registry_site_render"] = module
            spec.loader.exec_module(module)
            return module
    return None


site_render = _load_site_render()
pytestmark = pytest.mark.skipif(site_render is None, reason="registry/ not present")


def _render(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    (tmp_path / "plugins.json").write_text(
        json.dumps({"plugins": [{"plugin_id": "demo", "name": "Demo", "version": "1.0.0"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(site_render, "PUBLIC", tmp_path)
    site_render.render("https://registry.example")
    return tmp_path


def test_render_publishes_a_404_page(tmp_path, monkeypatch):
    public = _render(tmp_path, monkeypatch)
    page = (public / "404.html").read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert '<meta name="robots" content="noindex">' in page
    assert "Nothing is published at this address" in page
    assert 'href="/plugins.json"' in page


def test_only_the_404_page_is_kept_out_of_search(tmp_path, monkeypatch):
    public = _render(tmp_path, monkeypatch)
    indexed = [public / "index.html", public / "publishing.html", public / "p" / "demo.html"]
    for page in indexed:
        assert "noindex" not in page.read_text(encoding="utf-8"), page.name
    sitemap = (public / "sitemap.xml").read_text(encoding="utf-8")
    assert "404" not in sitemap
