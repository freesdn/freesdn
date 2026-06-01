# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Soft-delete leak CI guard
=========================

Structural regression guard for the SOFT-DELETE LEAK class.

Many ORM models inherit ``SoftDeleteMixin`` (a nullable ``deleted_at``).
A SELECT / GET / UPDATE / DELETE against such a model that omits a
``deleted_at`` filter leaks (or mutates) soft-deleted rows. We hand-fixed
~50 such queries; this guard prevents *new* ones from landing.

How it works
------------
A small AST scan walks ``app/{api,services,tasks,modules,core}`` and finds
query entry points -- ``select(Model)`` / ``update(Model)`` / ``delete(Model)``
and ``*.get(Model, ...)`` -- whose enclosing function contains NO satisfying
token (an inline ``deleted_at`` filter, the ``Model.alive()`` helper, an
``include_deleted`` opt-out, a known tenancy helper that injects the filter,
or the explicit ``# freesdn:include-deleted`` marker).

The set of such sites that exist TODAY is frozen in
``soft_delete_guard_baseline.txt`` (grandfathered debt -- these are tracked
and will be retired by the global ``do_orm_execute`` filter / per-query
fixes). The test FAILS only when a *new* site appears that is not in the
baseline. To regenerate the baseline after legitimately changing the set::

    python tests/test_soft_delete_guard.py

The key is ``relpath::function::model`` (line-number independent) so
refactors that move code do not churn the baseline.
"""
from __future__ import annotations

import ast
from pathlib import Path

# 46 soft-deletable models (confirmed exhaustively: every class inheriting
# SoftDeleteMixin in app/models + app/modules/*/models.py).
SOFT_DELETE_MODELS = {
    "RemoteAgent", "AgentSchedule", "AlertRule", "Organization", "Site",
    "Controller", "User", "Credential", "CustomRole", "Device",
    "DiscoveredHost", "TopologyEdge", "ConfigTemplate", "PoESchedule",
    "RadiusServerProfile", "Dot1xPortConfig", "SSOProvider",
    "VPNTunnelTemplate", "ProvisioningProfile", "AccessController", "Door",
    "Reader", "Cardholder", "AccessCredential", "AccessSchedule",
    "BackupSchedule", "Camera", "NVR", "CameraGroup", "CameraView",
    "RecordingScheduleTemplate", "FirewallDevice", "GatewayConnection",
    "FirewallRule", "NATRule", "VPNTunnel", "CanonicalVLAN", "VLANTemplate",
    "Network", "WifiNetwork", "PortProfile", "Phone", "PBX", "Extension",
    "RingGroup", "VoicemailMessage",
}

# Presence of any of these in the enclosing function's source marks the
# soft-delete concern as handled.
SATISFYING_TOKENS = (
    "deleted_at",                # inline .deleted_at.is_(None) / post-fetch check
    ".alive(",                   # the blessed SoftDeleteMixin.alive() helper
    "include_deleted",           # global-filter opt-out execution_option
    "freesdn:include-deleted",   # explicit allowlist marker comment
    "tenant_filter(",            # central tenancy predicate (injects deleted_at)
    "_org_site_filter(",         # org/site subquery helper (injects deleted_at)
    "site_scope_filter(",        # per-user site-grant predicate
    "apply_tenant_scope(",
    "scope_to_org(",
)

SCAN_DIRS = ("api", "services", "tasks", "modules", "core")

_APP = Path(__file__).resolve().parent.parent / "app"
_BASELINE = Path(__file__).resolve().parent / "soft_delete_guard_baseline.txt"


def _model_of_first_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    a = call.args[0]
    if isinstance(a, ast.Name) and a.id in SOFT_DELETE_MODELS:
        return a.id
    if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name):
        if a.value.id in SOFT_DELETE_MODELS:
            return a.value.id
    return None


def _entry_point_model(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name) and f.id in ("select", "update", "delete"):
        return _model_of_first_arg(call)
    if isinstance(f, ast.Attribute) and f.attr == "get":
        return _model_of_first_arg(call)
    return None


def _funcs(tree: ast.AST) -> list[tuple[int, int, ast.AST]]:
    out: list[tuple[int, int, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.lineno, getattr(node, "end_lineno", node.lineno), node))
    return out


def _scan_file(path: Path) -> set[str]:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    funcs = _funcs(tree)
    rel = path.relative_to(_APP).as_posix()
    hits: set[str] = set()
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        model = _entry_point_model(call)
        if not model:
            continue
        line = call.lineno
        enclosing = None
        for lo, hi, node in funcs:
            if lo <= line <= hi and (enclosing is None or lo > enclosing[0]):
                enclosing = (lo, hi, node)
        if enclosing is not None:
            context = ast.get_source_segment(src, enclosing[2]) or ""
            func_name = enclosing[2].name
        else:
            lines = src.splitlines()
            context = "\n".join(lines[max(0, line - 7):line + 6])
            func_name = "<module>"
        if not any(tok in context for tok in SATISFYING_TOKENS):
            hits.add(f"{rel}::{func_name}::{model}")
    return hits


def scan() -> set[str]:
    keys: set[str] = set()
    for d in SCAN_DIRS:
        base = _APP / d
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            keys |= _scan_file(path)
    return keys


def _load_baseline() -> set[str]:
    if not _BASELINE.exists():
        return set()
    return {
        ln.strip()
        for ln in _BASELINE.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    }


def test_no_new_soft_delete_leaks() -> None:
    """Fail if a query against a soft-deletable model lacks a deleted_at
    filter and is not in the grandfathered baseline."""
    current = scan()
    baseline = _load_baseline()
    new = sorted(current - baseline)
    assert not new, (
        "New soft-delete leak(s) detected -- a query against a soft-deletable "
        "model is missing a `deleted_at` filter.\n\nAdd one of: "
        "`.where(Model.alive())`, `Model.deleted_at.is_(None)`, a tenancy "
        "helper, or -- if you GENUINELY need deleted rows -- "
        "`.execution_options(include_deleted=True)` or a `# freesdn:include-deleted` "
        "marker comment in the function.\n\nNew sites:\n  "
        + "\n  ".join(new)
    )


def test_baseline_has_no_stale_entries() -> None:
    """Informational: baseline entries that no longer exist should be pruned
    (regenerate with `python tests/test_soft_delete_guard.py`). Non-fatal so a
    fix never breaks CI; surfaces shrinkable debt."""
    stale = sorted(_load_baseline() - scan())
    if stale:
        print(
            "\n[soft-delete guard] "
            f"{len(stale)} baseline entr{'y' if len(stale) == 1 else 'ies'} "
            "now fixed -- prune the baseline:\n  " + "\n  ".join(stale)
        )


if __name__ == "__main__":
    keys = sorted(scan())
    header = (
        "# Soft-delete leak guard baseline -- grandfathered debt.\n"
        "# Each line: <relpath under app/>::<function>::<model>.\n"
        "# A query against a soft-deletable model with no deleted_at filter.\n"
        "# These are tracked for retirement (global do_orm_execute filter /\n"
        "# per-query fixes). Regenerate: python tests/test_soft_delete_guard.py\n"
        f"# Count: {len(keys)}\n"
    )
    _BASELINE.write_text(header + "\n".join(keys) + "\n", encoding="utf-8")
    print(f"Wrote {len(keys)} baseline entries to {_BASELINE}")
