#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Fail the build when the frontend calls a backend route that does not exist.

Why this exists
---------------
The frontend talks to the backend through ~1,370 hand-written ``api.<verb>()``
calls. Nothing checked that the other end of any of them was real. A sweep on
2026-08-18 found **52 calls whose path or method had no backend route at all**
-- wrong verb (``PATCH /network/clients/{id}`` where the backend serves ``PUT``),
renamed resources (``/organizations/current/*``, never implemented), and whole
feature areas that were removed on the backend while the client kept its
methods (``/poe/analytics/*``, ``/notifications/templates/*``).

Every one of those turned out to be uncalled, so no user ever hit a 404 -- but
that is luck, not design. Each was a loaded gun: wire a button to
``devicePortsApi.setPoeState`` and it 404s in production. That had already
happened once and been fixed in place; see the comment at
``frontend/src/pages/poe/PoEPage.tsx`` explaining why the PoE page routes
through ``poeApi.updatePort`` instead.

``openapi.d.ts`` does not catch this: it is generated, committed, and drifts
silently, and it only types the calls that go through it.

The check
---------
Mount the app exactly as ``main.py`` does -- **including module routers, which
are registered inside the lifespan** (``main.py``: ``loader.register_routes``),
so a plain ``app.openapi()`` at import time is missing ~800 routes and this
whole check would pass vacuously. Then match every frontend call against that
table, allowing a path parameter to match any segment.

Deliberately permissive about frontend shape, because a false positive here
blocks a release: a template hole (``${id}``) may match a backend literal,
since it is often a variable holding exactly that constant.

Usage
-----
    python freesdn/scripts/check_api_contract.py            # from the repo root
    python freesdn/scripts/check_api_contract.py --list     # print the route table

Requires the backend importable (``poetry install`` in ``freesdn/backend``).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parent  # freesdn/
BACKEND = APP_ROOT / "backend"
FRONTEND_SRC = APP_ROOT / "frontend" / "src"

# Calls whose backend route legitimately does not exist in the table. Add here
# ONLY with a reason and a revisit trigger; the point of this file is that the
# list stays empty.
ALLOWED: dict[tuple[str, str], str] = {}


def collect_backend_routes() -> set[tuple[str, str]]:
    """(METHOD, normalised path) for every route the running app serves."""
    sys.path.insert(0, str(BACKEND))
    os.environ.setdefault("SECRET_KEY", "api-contract-check-not-for-production")
    os.environ.setdefault("ENCRYPTION_SALT", "api-contract-check-not-for-production")
    os.environ.setdefault("ENVIRONMENT", "development")

    from app.main import app
    from app.modules.loader import ModuleLoader

    async def _mount() -> None:
        loader = ModuleLoader()
        loader.discover_modules()
        await loader.load_all_modules()
        loader.register_routes(app, prefix="/api/v1")

    asyncio.run(_mount())
    app.openapi_schema = None  # regenerate now that module routers are mounted

    routes: set[tuple[str, str]] = set()
    for path, operations in app.openapi()["paths"].items():
        p = path.replace("/api/v1", "", 1)
        for method in operations:
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                routes.add((method.upper(), normalise(p)))
    return routes


def normalise(path: str) -> str:
    """/a/{controller_id}/b/ -> /a/{}/b"""
    path = re.sub(r"\{[^}]*\}", "{}", path)
    path = path.split("?")[0]
    return path.rstrip("/") or "/"


# api.get<T>(`/x/${y}`)  |  api.post('/x', body)  |  api.get('/x/' + fmt)
_CALL = re.compile(
    r"""\bapi\.(get|post|put|patch|delete)\s*(?:<[^(]*?>)?\s*\(\s*([`'"])(/[^`'"]*)\2(\s*\+)?""",
    re.S,
)


def collect_frontend_calls() -> list[tuple[str, str, str, int]]:
    """(METHOD, normalised path, source file, line) for every api.<verb>() call."""
    calls: list[tuple[str, str, str, int]] = []
    files = [
        f
        for f in list(FRONTEND_SRC.rglob("*.ts")) + list(FRONTEND_SRC.rglob("*.tsx"))
        if "__tests__" not in str(f) and not f.name.endswith(".d.ts")
    ]
    for f in sorted(files):
        text = f.read_text(encoding="utf-8")
        for match in _CALL.finditer(text):
            verb = match.group(1).upper()
            raw = match.group(3)
            concatenated = match.group(4) is not None
            path = re.sub(r"\$\{[^}]*\}", "{}", raw)
            if concatenated and path.endswith("/"):
                # '/logs/export/' + fmt  ->  /logs/export/{}
                path += "{}"
            line = text[: match.start()].count("\n") + 1
            calls.append((verb, normalise(path), str(f.relative_to(APP_ROOT)), line))
    return calls


def _segment_matches(fe: str, be: str) -> bool:
    """
    A backend path param matches any segment.

    A frontend segment that *contains* a template hole matches any literal, not
    just an identical one: the client composes whole route prefixes from a
    variable (``/gateway-mikrotik-${section}/...``, ``/gateway-freepbx-${x}/``),
    so the hole stands for a set of real backend prefixes. Requiring an exact
    match there reports a false break on a route that works.
    """
    return be == "{}" or fe == be or "{}" in fe


def matches(fe_path: str, verb: str, routes: set[tuple[str, str]]) -> bool:
    fe_segments = fe_path.split("/")
    for be_verb, be_path in routes:
        if be_verb != verb:
            continue
        be_segments = be_path.split("/")
        if len(be_segments) != len(fe_segments):
            continue
        if all(_segment_matches(a, b) for a, b in zip(fe_segments, be_segments)):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print the backend route table")
    args = parser.parse_args()

    routes = collect_backend_routes()
    if args.list:
        for verb, path in sorted(routes, key=lambda r: (r[1], r[0])):
            print(f"{verb:6} {path}")
        return 0

    # A near-empty table means the mount failed; without this the check passes
    # vacuously and silently stops protecting anything.
    if len(routes) < 500:
        print(
            f"ERROR: only {len(routes)} backend routes collected — module routers "
            "almost certainly failed to mount. Refusing to report a false pass.",
            file=sys.stderr,
        )
        return 2

    calls = collect_frontend_calls()
    if not calls:
        print(
            "ERROR: no frontend api.<verb>() calls found — the regex broke?",
            file=sys.stderr,
        )
        return 2

    broken = []
    for verb, path, src, line in calls:
        if (verb, path) in ALLOWED:
            continue
        if not matches(path, verb, routes):
            broken.append((verb, path, src, line))

    print(f"backend routes: {len(routes)}    frontend api calls: {len(calls)}")

    if not broken:
        print("OK: every frontend api call resolves to a backend route.")
        return 0

    print(f"\n{len(broken)} frontend call(s) have no backend route:\n", file=sys.stderr)
    for verb, path, src, line in sorted(set(broken), key=lambda r: (r[2], r[3])):
        same_path = sorted({v for v, p in routes if p == path})
        hint = f"  (path exists for {same_path})" if same_path else ""
        print(f"  {src}:{line}\n      {verb} {path}{hint}", file=sys.stderr)
    print(
        "\nEither the backend route was renamed/removed, the verb is wrong, or the "
        "frontend function is dead and should be deleted.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
