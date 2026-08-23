# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A plugin that stages a change nothing can apply is worse than one that refuses.

FreeSDN resolves a staged change to an applier by its ``feature`` prefix, in
``_service_for_feature``. A feature with no matching branch produces a row that
sits in Pending Changes forever and fails at apply time with a message about
sub-domain services -- long after whoever configured it has moved on.

So config-drift-guard refuses to stage under a feature family it cannot match,
and carries its own copy of the appliable list because a plugin must not import
backend internals. A copy drifts, and a drifted copy is the worst outcome
available here: the plugin would tell an operator it had checked, and stage the
change anyway.

This test is what makes the copy safe to keep.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest


def _dispatcher_prefixes() -> set[str]:
    """Feature prefixes ``_service_for_feature`` actually branches on."""
    source = (
        pathlib.Path(__file__).resolve().parents[2]
        / "app"
        / "api"
        / "v1"
        / "endpoints"
        / "adapter_omada_vpn.py"
    ).read_text(encoding="utf-8")

    start = source.index("def _service_for_feature")
    match = re.search(r"\n(?:@|def |class )", source[start + 10 :])
    body = source[start : start + 10 + match.start()] if match else source[start:]

    # Every literal handed to a startswith() in the dispatcher, single or tuple.
    prefixes: set[str] = set()
    for call in re.finditer(r"startswith\((.*?)\)", body, re.S):
        prefixes.update(re.findall(r'"([a-z_]+\.[a-z_.]*)"', call.group(1)))
    return {p for p in prefixes if p.endswith(".")}


def _plugin_prefixes() -> tuple[set[str], pathlib.Path] | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / "config-drift-guard" / "plugin.py"
        if candidate.is_file():
            tree = ast.parse(candidate.read_text(encoding="utf-8"))
            for node in tree.body:
                if not isinstance(node, ast.Assign):
                    continue
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if "APPLIABLE_PREFIXES" not in names:
                    continue
                values = {
                    e.value
                    for e in getattr(node.value, "elts", [])
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                }
                return values, candidate
    return None


def test_the_dispatcher_scan_finds_something():
    """Premise. If this breaks, every other assertion here is vacuous."""
    found = _dispatcher_prefixes()
    assert len(found) > 10, f"only found {len(found)} prefixes; the scan is broken"
    assert "opnsense." in found
    assert "unifi." in found


def test_the_plugin_claims_no_prefix_the_platform_cannot_apply():
    """
    The dangerous direction. A prefix the plugin accepts but the dispatcher does
    not recognise means the plugin stages an un-appliable change while reporting
    that it validated the family.
    """
    loaded = _plugin_prefixes()
    if loaded is None:  # pragma: no cover - backend-only checkout
        pytest.skip("config-drift-guard is not present in this checkout")
    claimed, path = loaded

    real = _dispatcher_prefixes()
    # A claimed prefix is fine if the dispatcher branches on it OR on something
    # beneath it (the plugin lists "unifi." where the dispatcher also has
    # "unifi.switch." and friends).
    invented = sorted(p for p in claimed if not any(r.startswith(p) for r in real))
    assert not invented, (
        f"{path.name} claims feature families FreeSDN cannot apply: {invented}. "
        "Staging under one creates a pending change nobody can approve."
    )


def test_the_plugin_refuses_before_staging_rather_than_after():
    """
    The check has to happen in the plugin, not be left to the apply attempt.
    Failing at apply time surfaces to a different person on a different day.
    """
    loaded = _plugin_prefixes()
    if loaded is None:  # pragma: no cover
        pytest.skip("config-drift-guard is not present in this checkout")
    _, path = loaded

    source = path.read_text(encoding="utf-8")
    assert "APPLIABLE_PREFIXES" in source
    assert "startswith(APPLIABLE_PREFIXES)" in source, (
        "the plugin no longer validates the configured prefix before staging"
    )
    # And it must never be able to apply, whatever it stages.
    for forbidden in ("apply_change", ".apply(", "force=True", "confirmed=True"):
        assert forbidden not in source, f"the plugin references {forbidden!r}; it must only stage"
