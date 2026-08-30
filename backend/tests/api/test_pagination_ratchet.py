# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: no NEW list endpoint may ship an unbounded page/offset/skip param.

The defect, and the two guards that already exist for it, are described in
``tests/api/test_pagination_bounds.py``. What that file does not do -- and
cannot -- is stop the class from growing: bounding the parameter is a per-route
edit and there is no shared chokepoint to fix it at. ``pagination_params``
(app/core/query.py) already carries ``le=MAX_PAGE`` but has zero call sites,
and the routes hand-roll their own ``Query(...)`` declarations across 69 files.

So THIS TEST STOPS THE BLEEDING. The inventory below is the measured debt at
the time it was written; anything above it fails CI.

Rules for editing ``KNOWN_UNBOUNDED``:
  * LOWERING a count, or removing a file, is always correct -- it means a route
    was bounded. The assertion is ``<=``, so a fix never has to touch this map
    (though trimming it keeps the ratchet tight).
  * RAISING a count, or adding a file, means a new unbounded parameter shipped.
    The default answer is ``le=MAX_PAGE`` (app.core.query), not an entry here.

Not every entry is equally dangerous, and the migration doc says which is
which: a large fraction of the MikroTik/pfSense gateway pass-throughs slice an
already-materialised list in Python (``_paginate(rows, limit, offset)``), where
an absurd offset returns an empty page and nothing reaches a driver. The ones
that matter feed ``.offset()`` on a SQLAlchemy select. You cannot tell them
apart from the signature, which is exactly why the ratchet covers both.

See docs/agents/PAGINATION-BOUNDS.md.
"""

from __future__ import annotations

import ast
from pathlib import Path

_APP = Path(__file__).resolve().parents[2] / "app"

#: Parameter names whose value becomes (or becomes part of) a SQL OFFSET.
_PAGINATION_PARAMS = {"page", "offset", "skip"}

#: Keywords that put a ceiling on a ``Query(...)`` declaration.
_UPPER_BOUND_KEYWORDS = {"le", "lt"}

#: Measured debt. Path (posix, relative to the backend root) -> count.
KNOWN_UNBOUNDED: dict[str, int] = {
    "app/api/v1/endpoints/access_points.py": 1,
    "app/api/v1/endpoints/adapter_mikrotik_capsman.py": 6,
    "app/api/v1/endpoints/adapter_mikrotik_dhcp.py": 3,
    "app/api/v1/endpoints/adapter_mikrotik_dns.py": 2,
    "app/api/v1/endpoints/adapter_mikrotik_firewall.py": 4,
    "app/api/v1/endpoints/adapter_mikrotik_hotspot.py": 7,
    "app/api/v1/endpoints/adapter_mikrotik_interfaces.py": 6,
    "app/api/v1/endpoints/adapter_mikrotik_ip.py": 3,
    "app/api/v1/endpoints/adapter_mikrotik_ppp.py": 5,
    "app/api/v1/endpoints/adapter_mikrotik_queues.py": 3,
    "app/api/v1/endpoints/adapter_mikrotik_routing.py": 9,
    "app/api/v1/endpoints/adapter_mikrotik_security.py": 4,
    "app/api/v1/endpoints/adapter_mikrotik_system.py": 7,
    "app/api/v1/endpoints/adapter_mikrotik_vpn.py": 8,
    "app/api/v1/endpoints/adapter_omada_open_api.py": 1,
    "app/api/v1/endpoints/adapter_opnsense_firewall.py": 2,
    "app/api/v1/endpoints/adapter_pfsense_dhcp.py": 3,
    "app/api/v1/endpoints/adapter_pfsense_diagnostics.py": 2,
    "app/api/v1/endpoints/adapter_pfsense_dns.py": 1,
    "app/api/v1/endpoints/adapter_pfsense_firewall.py": 2,
    "app/api/v1/endpoints/adapter_pfsense_interfaces.py": 3,
    "app/api/v1/endpoints/adapter_pfsense_nat.py": 3,
    "app/api/v1/endpoints/adapter_pfsense_routing.py": 2,
    "app/api/v1/endpoints/adapter_pfsense_services.py": 1,
    "app/api/v1/endpoints/adapter_pfsense_vpn.py": 5,
    "app/api/v1/endpoints/agents.py": 2,
    "app/api/v1/endpoints/audit.py": 5,
    "app/api/v1/endpoints/automation.py": 3,
    "app/api/v1/endpoints/backups.py": 1,
    "app/api/v1/endpoints/config_versions.py": 1,
    "app/api/v1/endpoints/controllers.py": 1,
    "app/api/v1/endpoints/correlation.py": 1,
    "app/api/v1/endpoints/devices.py": 1,
    "app/api/v1/endpoints/discovery.py": 2,
    "app/api/v1/endpoints/dpi.py": 1,
    "app/api/v1/endpoints/enterprise.py": 2,
    "app/api/v1/endpoints/events.py": 1,
    "app/api/v1/endpoints/firmware.py": 3,
    "app/api/v1/endpoints/integrations.py": 1,
    "app/api/v1/endpoints/logs.py": 1,
    "app/api/v1/endpoints/network.py": 4,
    "app/api/v1/endpoints/notifications.py": 1,
    "app/api/v1/endpoints/organizations.py": 1,
    "app/api/v1/endpoints/radius.py": 3,
    "app/api/v1/endpoints/roaming.py": 1,
    "app/api/v1/endpoints/security.py": 5,
    "app/api/v1/endpoints/sites.py": 1,
    "app/api/v1/endpoints/sla.py": 2,
    "app/api/v1/endpoints/sla_reports.py": 2,
    "app/api/v1/endpoints/users.py": 1,
    "app/api/v1/endpoints/vpn.py": 2,
    "app/api/v1/endpoints/vpn_orchestration.py": 2,
    "app/api/v1/endpoints/webhooks.py": 3,
    "app/api/v1/endpoints/ztp.py": 4,
    "app/modules/access_control/api.py": 5,
    "app/modules/ai/api.py": 1,
    "app/modules/api.py": 1,
    "app/modules/cameras/api.py": 4,
    "app/modules/collector/api.py": 2,
    "app/modules/firewall/api.py": 5,
    "app/modules/firewall/gateway_api.py": 1,
    "app/modules/gateway/api/canonical_api.py": 1,
    "app/modules/gateway/api/dashboard_api.py": 6,
    "app/modules/gateway/api/distribution_api.py": 1,
    "app/modules/gateway/api/drift_api.py": 1,
    "app/modules/gateway/api/import_api.py": 1,
    "app/modules/gateway/api/template_api.py": 1,
    "app/modules/network/api.py": 4,
    "app/modules/voip/api.py": 11,
}

#: Total at the time of measurement. Progress is reported against this.
MEASURED_BASELINE = 196


def _is_query_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "Query"
    return isinstance(func, ast.Attribute) and func.attr == "Query"


def _query_declaration(arg: ast.arg, default: ast.expr | None) -> ast.Call | None:
    """The ``Query(...)`` call for a parameter, in either supported form.

    FastAPI accepts ``page: int = Query(1, ge=1)`` and
    ``page: Annotated[int, Query(ge=1)] = 1``. Both appear in this codebase, and
    a scanner that only understands the first misses every MikroTik and pfSense
    gateway route -- which is most of the inventory.
    """
    if default is not None and _is_query_call(default):
        assert isinstance(default, ast.Call)
        return default
    if arg.annotation is not None:
        for sub in ast.walk(arg.annotation):
            if _is_query_call(sub):
                assert isinstance(sub, ast.Call)
                return sub
    return None


def _is_unbounded(arg: ast.arg, default: ast.expr | None) -> bool:
    if arg.arg not in _PAGINATION_PARAMS:
        return False
    call = _query_declaration(arg, default)
    if call is None:
        return False
    return not ({kw.arg for kw in call.keywords} & _UPPER_BOUND_KEYWORDS)


def _unbounded_in(path: Path) -> list[str]:
    """``file:line function(param)`` for each unbounded pagination parameter."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:  # pragma: no cover - a syntax error fails louder elsewhere
        return []

    found: list[str] = []
    rel = path.relative_to(_APP.parent).as_posix()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        args = node.args
        positional = args.posonlyargs + args.args
        padding: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
        pairs: list[tuple[ast.arg, ast.expr | None]] = list(
            zip(positional, padding + list(args.defaults), strict=True)
        )
        pairs += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))
        found.extend(
            f"{rel}:{node.lineno} {node.name}({arg.arg})"
            for arg, default in pairs
            if _is_unbounded(arg, default)
        )
    return found


def _scan() -> dict[str, list[str]]:
    by_file: dict[str, list[str]] = {}
    for path in sorted(_APP.rglob("*.py")):
        hits = _unbounded_in(path)
        if hits:
            by_file[path.relative_to(_APP.parent).as_posix()] = hits
    return by_file


def test_scan_actually_covers_the_app() -> None:
    """Guard the guard: a broken scan root must not read as a clean result.

    Mutation this catches: mistyping ``_APP`` or narrowing the glob, which makes
    every assertion below pass vacuously.
    """
    assert _APP.is_dir(), f"scan root not found: {_APP}"
    files = list(_APP.rglob("*.py"))
    assert len(files) > 500, f"the scan looks truncated -- only {len(files)} files under {_APP}"
    assert (_APP / "api" / "v1" / "endpoints" / "switches.py").exists()


def test_detector_distinguishes_bounded_from_unbounded() -> None:
    """The detector must actually read ``le=``, not just count parameters.

    Mutation this catches: dropping the ``_UPPER_BOUND_KEYWORDS`` check, which
    would flag every route and make the pinned counts meaningless; or dropping
    the ``Annotated[...]`` branch, which would silently zero out the largest
    part of the inventory and read as "already fixed".
    """

    def hits(source: str) -> int:
        fn = ast.parse(source).body[0]
        assert isinstance(fn, ast.AsyncFunctionDef)
        pairs = zip(fn.args.args, fn.args.defaults, strict=True)
        return sum(1 for arg, default in pairs if _is_unbounded(arg, default))

    assert hits("async def r(page: int = Query(1, ge=1, le=MAX_PAGE)): ...") == 0
    assert hits("async def r(page: int = Query(1, ge=1)): ...") == 1
    assert hits("async def r(offset: Annotated[int, Query(ge=0)] = 0): ...") == 1
    # ``limit`` is bounded everywhere and does not produce an OFFSET.
    assert hits("async def r(limit: int = Query(50, ge=1)): ...") == 0


def test_no_new_unbounded_pagination_parameters() -> None:
    """The ratchet itself.

    Mutation this catches: removing ``le=MAX_PAGE`` from any route that has it
    -- the file's count exceeds its pin, or the file appears where it was
    absent entirely.
    """
    found = _scan()

    regressions: list[str] = []
    for rel, hits in sorted(found.items()):
        allowed = KNOWN_UNBOUNDED.get(rel, 0)
        if len(hits) > allowed:
            regressions.append(
                f"{rel}: {len(hits)} unbounded, pinned at {allowed}\n    "
                + "\n    ".join(sorted(hits))
            )

    assert not regressions, (
        "New unbounded page/offset/skip query parameter(s). Bound them with "
        "le=MAX_PAGE (app.core.query): an unbounded value is bound into SQL as "
        "OFFSET $n::BIGINT and asyncpg raises while ENCODING it, which only the "
        "shared DBAPIError->400 floor keeps out of a 500.\n" + "\n".join(regressions)
    )


def test_pinned_inventory_has_not_silently_grown() -> None:
    """The pin is a debt register, so it must only shrink.

    Mutation this catches: "fixing" a ratchet failure by raising a pinned count
    instead of bounding the parameter. The per-file assertion above would go
    green again; this is the number the migration doc reports progress against.
    """
    assert sum(KNOWN_UNBOUNDED.values()) <= MEASURED_BASELINE, (
        "KNOWN_UNBOUNDED grew past the measured baseline; bound the parameter "
        "instead of pinning it (docs/agents/PAGINATION-BOUNDS.md)"
    )


def test_the_two_routes_bounded_in_this_pass_stay_bounded() -> None:
    """Named explicitly so a revert is legible, not just a count change.

    Mutation this catches: dropping ``le=MAX_PAGE`` from ``list_switches`` or
    ``list_alerts``, both reachable with any authenticated ``network:read`` /
    ``alert:read`` credential.
    """
    found = _scan()
    for rel in (
        "app/api/v1/endpoints/switches.py",
        "app/api/v1/endpoints/alert_rules.py",
    ):
        assert rel not in found, f"{rel} regressed: {found.get(rel)}"
