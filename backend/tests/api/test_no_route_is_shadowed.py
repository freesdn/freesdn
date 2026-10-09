# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A literal route must not be registered after a parameterised one that eats it.

Starlette matches routes in REGISTRATION order and returns the first template
that fits. So a literal path declared after a same-shape ``/{param}`` route on
the same router is unreachable -- the parameterised handler answers instead,
with the parameter bound to the literal.

``GET /api/v1/modules/events`` was in exactly that state. ``/{module_id}`` was
declared at ``app/modules/api.py:137`` and ``/events`` at ``:491``, so every
request reached ``get_module`` with ``module_id="events"`` and came back::

    404 {"error": {"code": 404, "message": "Module 'events' not found"}}

which is byte-for-byte what a genuinely unknown module id returns -- so nothing
about the response suggested a routing fault. The endpoint was in the published
OpenAPI schema and had three separate rounds of org-scoping hardening applied to
it (all cited in its own comments) while being
unreachable the whole time. Found 2026-08-29 by sweeping every parameterless GET
against a running clean install and looking at what was not a 200.

The check runs against the ASSEMBLED app, not one router, so it also covers
shadowing introduced by the order in which routers are included.
"""

from __future__ import annotations

import pathlib

import pytest


def _flatten(routes: object, prefix: str = "") -> list[tuple[str, frozenset[str], str]]:
    """(path, methods) in REGISTRATION order, descending into included routers.

    FastAPI 0.137 stopped copying a sub-router's routes into the parent at
    ``include_router`` time. ``app.routes`` now holds ``_IncludedRouter``
    placeholders that resolve lazily on first match, so reading it gives ten
    entries for an app that serves sixteen hundred paths -- and any check built
    on it silently passes. (This repo has met that ripple before; the note on
    it says to use ``app.openapi()["paths"]``, which is right for an inventory
    but loses the ORDER this file is about.)

    So the placeholders are walked. Two internal attributes are used, and
    ``test_the_route_table_is_populated`` fails loudly if a FastAPI upgrade
    changes them, rather than letting this file go quietly blind.
    """
    out: list[tuple[str, frozenset[str], str]] = []
    for route in routes:  # type: ignore[attr-defined]
        if type(route).__name__ == "_IncludedRouter":
            inner = getattr(route, "original_router", None)
            context = getattr(route, "include_context", None)
            if inner is None:
                continue
            sub_prefix = getattr(context, "prefix", "") or ""
            out.extend(_flatten(inner.routes, prefix + sub_prefix))
            continue
        path = getattr(route, "path", None)
        if path is None:
            continue
        # `path is not None`, NOT `if path`: a router declares its collection
        # endpoint as @router.get(""), and the empty string is FALSY. That
        # dropped 7 live routes -- including /api/v1/webhooks/templates, one of
        # the two this file was written to guard. The full path only exists
        # after the include prefix is applied, which is why the raw value is
        # empty here and meaningful after composition.
        methods = getattr(route, "methods", None)
        if not methods:
            # WebSocket routes have no .methods at all, so the old guard hid
            # both of them and websocket shadowing was 100% invisible. Give them
            # a pseudo-method so they take part in the same first-match rule.
            methods = {"WEBSOCKET"} if "WebSocket" in type(route).__name__ else None
        if methods:
            endpoint = getattr(route, "endpoint", None)
            name = f"{getattr(endpoint, '__module__', '?')}.{getattr(endpoint, '__name__', '?')}"
            out.append((prefix + path, frozenset(methods), name))
    return out


_ROUTE_CACHE: list[tuple[str, frozenset[str], str]] | None = None
_SCHEMA_CACHE: list[tuple[str, str]] | None = None


def _routes() -> list[tuple[str, frozenset[str], str]]:
    """The assembled app's full route table, in registration order.

    Enters the LIFESPAN, because ``loader.register_routes()`` runs there: without
    it the table is ~1,300 routes and every ``app/modules/*`` router -- about 660
    routes -- is never examined at all. That blind spot is why the 13 dead
    /api/v1/network routes had to be found by hand.

    Cached, and deliberately so: entering the lifespan appends the module routers
    again each time, so repeated calls would grow the table. The predicate below
    compares ENDPOINTS and is therefore immune to duplicate registrations, but
    there is no reason to pay for them.
    """
    global _ROUTE_CACHE
    if _ROUTE_CACHE is None:
        # Built in a SUBPROCESS, deliberately. The table is only complete after
        # the lifespan has run (that is where loader.register_routes happens, and
        # without it ~660 module routes are invisible) -- but the lifespan also
        # starts the event bus, the Fabric negotiator, the plugin runtime and the
        # collector, all process-wide singletons. Doing that in-process left
        # three unrelated tests (plugin runtime x2, collector ingest) with
        # pre-populated global state and failed them. Registering the routers
        # directly is not enough either: load_all_modules() calls each module's
        # on_load, which subscribes to the bus.
        #
        # A subprocess is the only version of this that cannot reach the suite
        # it is running inside. It costs a few seconds once per session.
        import json
        import subprocess
        import sys

        script = (
            "import json,sys,warnings;warnings.filterwarnings('ignore');"
            "sys.path.insert(0,'.');sys.path.insert(0,'tests');"
            "from fastapi.testclient import TestClient;"
            "from tests.api.test_no_route_is_shadowed import _flatten;"
            "from app.main import app;"
            "c=TestClient(app);c.__enter__();"
            "r=[[p,sorted(m),e] for p,m,e in _flatten(app.router.routes)];"
            "s=[[pp,mm.upper()] for pp,ops in app.openapi()['paths'].items() for mm in ops];"
            "print('@@@'+json.dumps({'routes':r,'schema':s}))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[2]),
        )
        marker = [ln for ln in proc.stdout.splitlines() if ln.startswith("@@@")]
        assert marker, (
            "the route-table subprocess produced nothing, so this file would "
            "be checking a partial table and passing silently. stderr tail: " + proc.stderr[-800:]
        )
        payload = json.loads(marker[0][3:])
        global _SCHEMA_CACHE
        _SCHEMA_CACHE = [(pp, mm) for pp, mm in payload["schema"]]
        _ROUTE_CACHE = [
            (path, frozenset(methods), endpoint) for path, methods, endpoint in payload["routes"]
        ]
    return _ROUTE_CACHE


def _schema_operations() -> list[tuple[str, str]]:
    """(path, METHOD) from app.openapi(), captured in the same subprocess."""
    _routes()
    assert _SCHEMA_CACHE is not None
    return _SCHEMA_CACHE


#: Stand-in for a {param} when turning a template into a concrete probe URL.
#: Deliberately unlikely to equal a real path segment.
_PROBE_TOKEN = "__freesdn_probe__"


def _segments(path: str) -> list[str]:
    return [s for s in path.strip("/").split("/") if s]


def _strip_convertor(segment: str) -> str:
    """``{volume:path}`` -> ``{volume}``. The schema publishes the stripped form."""
    if segment.startswith("{") and ":" in segment:
        return "{" + segment[1:].split(":", 1)[0] + "}"
    return segment


def _template_matches(template: list[str], concrete: list[str]) -> bool:
    """Would Starlette's regex for ``template`` match the literal ``concrete``?

    A ``{name:path}`` convertor matches GREEDILY across segment boundaries, so a
    route ending in one covers every deeper path under its prefix -- segment-count
    equality is wrong for it. Starlette only permits ``:path`` as the final
    segment, so handling it there is sufficient.
    """
    if template and template[-1].startswith("{") and template[-1].endswith(":path}"):
        head = template[:-1]
        if len(concrete) < len(head) + 1:  # the greedy tail needs something to eat
            return False
        return all(t.startswith("{") or t == c for c, t in zip(concrete, head, strict=False))
    if len(template) != len(concrete):
        return False
    return all(t.startswith("{") or t == c for c, t in zip(concrete, template, strict=True))


def _first_match(
    routes: list[tuple[str, frozenset[str], str]], probe: list[str], method: str
) -> tuple[str, str] | None:
    """(template, endpoint) that ANSWERS ``method path`` -- Starlette's own rule.

    Starlette walks its route list in registration order and returns the FIRST
    full match. So the question is never "does some earlier parameterised route
    also match?" but "which route wins?".

    Asking the weaker question produced false ACCUSATIONS, which is worse than
    the under-reporting it was written to prevent. When another test enters the
    app's lifespan, module routers are appended a second time; the duplicate copy
    of a literal then sees an unrelated parameterised route registered between
    the two copies and gets reported unreachable -- while the FIRST copy is
    serving requests perfectly well. Running the CSP test before this one made
    the detector fail on /api/v1/firewall/gateways/summary and six others, all
    reachable. Comparing against the winner is immune to that: the first copy
    wins, equals the candidate, and nothing is reported.
    """
    for candidate_path, candidate_methods, candidate_endpoint in routes:
        if method not in candidate_methods:
            continue
        if _template_matches(_segments(candidate_path), probe):
            return candidate_path, candidate_endpoint
    return None


# No knowingly unreachable HTTP routes remain. Core network endpoints retain
# ownership of the retired module method/path registrations.
KNOWN_SHADOWED: frozenset[str] = frozenset()


def test_each_normalized_method_path_has_one_owner() -> None:
    import re
    from collections import Counter

    counts = Counter(
        (method, re.sub(r"\{[^}]+\}", "{parameter}", path))
        for path, methods, _endpoint in _routes()
        for method in methods
    )
    assert {key: count for key, count in counts.items() if count > 1} == {}


def test_the_walk_sees_every_route_the_schema_publishes() -> None:
    """Anti-blindness guard: the inventory must cover the app's own schema.

    A count floor is not enough and never was. ``len(routes) > 500`` was
    satisfied by the core routes alone while ~660 module routes were missing,
    and it stayed satisfied when the walk silently dropped every
    ``@router.get("")`` route -- the finding. Neither showed up as a
    failure, because a route the walk cannot see simply cannot be reported
    shadowed.

    ``app.openapi()["paths"]`` is public API and an INDEPENDENT view of the same
    app, so anything it publishes and the walk misses is a hole in the walk.
    Subset, not equality: routes marked ``include_in_schema=False`` (the
    KNOWN_SHADOWED thirteen among them) are correctly in the walk and absent
    from the schema.
    """
    routes = _routes()

    # Compare with the convertor stripped: the walk keeps the raw declaration
    # ({volume:path}) while the schema publishes the bare name ({volume}).
    def _key(path: str) -> str:
        return "/" + "/".join(_strip_convertor(s) for s in _segments(path))

    walked = {(_key(path), method) for path, methods, _ in routes for method in methods}
    missing = sorted(
        f"{m.upper()} {p}"
        for p, m in _schema_operations()
        if m.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        and (_key(p), m.upper()) not in walked
    )
    assert not missing, (
        "the app publishes these operations but the route walk cannot see them, "
        "so they can never be reported as shadowed -- the walk is blind here:"
        + chr(10)
        + "  "
        + (chr(10) + "  ").join(missing[:40])
    )


def test_the_route_table_is_populated() -> None:
    """Guard the guard: an empty table would make the check below vacuous."""
    routes = _routes()
    assert len(routes) > 1500, f"expected the full route table, found {len(routes)}"
    for required in ("/api/v1/modules/events", "/api/v1/webhooks/templates"):
        assert any(p == required for p, _, _ in routes), (
            f"{required} is missing from the walk. It is declared "
            '@router.get("") on a prefixed router, so a falsy-path filter drops '
            "it -- which is exactly how this detector went blind before."
        )
    assert any(p == "/api/v1/modules/events" for p, _, _ in routes), (
        "/api/v1/modules/events is gone -- if it was removed on purpose, drop this "
        "assertion; if it was renamed, this test is no longer watching the route "
        "the file was written for."
    )


def test_no_literal_route_is_shadowed_by_an_earlier_parameterised_one() -> None:
    routes = _routes()
    shadowed: list[str] = []
    for path, methods, endpoint in routes:
        segments = _segments(path)
        if not segments:
            continue
        # Probe PARAMETERISED routes too, not just literals. Substituting a
        # concrete token for each {param} turns any template into a URL the
        # first-match rule can be asked about -- which is the only way to see
        # a parameterised route eaten by an earlier one of the same shape. That
        # is not hypothetical here: GET /api/v1/network/vlans/{vlan_uuid} loses
        # to /vlans/{vlan_id}, and a literal-only sweep is blind to it.
        #
        # LIMIT, stated rather than discovered later: this compares SHAPES, so
        # two same-shape templates always collide. That is correct while every
        # path convertor in this app is the default string one; an {id:int}
        # beside a {name} would need the convertor consulted, and this would
        # report a false positive. There are none today.
        probe = [_PROBE_TOKEN if s.startswith("{") else s for s in segments]
        for method in sorted(methods):
            winner = _first_match(routes, probe, method)
            # Compare the ENDPOINT, not the path template. Two registrations can
            # legitimately serve one URL: this codebase deliberately declares a
            # no-slash alias next to the canonical trailing-slash path (see
            # /api/v1/cameras/nvrs and /nvrs/, both -> cameras.api.list_nvrs),
            # and a router included twice yields exact duplicates. Neither is a
            # dead route. What IS dead is a route whose URL a DIFFERENT handler
            # answers -- which is exactly this comparison.
            if winner is not None and winner[1] != endpoint:
                shadowed.append(
                    f"[{method}] {path} -> nothing reaches {endpoint}; "
                    f"{winner[0]!r} ({winner[1]}) is registered earlier "
                    "and answers that URL instead"
                )

    found = {s.split(" -> ", 1)[0] for s in shadowed}
    unexpected = sorted(s for s in shadowed if s.split(" -> ", 1)[0] not in KNOWN_SHADOWED)
    _sep = chr(10) + "  "
    assert not unexpected, (
        "these routes can never be reached -- Starlette answers with the FIRST "
        "route that matches, so an earlier registration takes their URL. The "
        "failure usually looks like an ordinary 404 or 422, which is why they "
        "survive:" + _sep + _sep.join(unexpected)
    )
    healed = sorted(KNOWN_SHADOWED - found)
    assert not healed, (
        "these are listed in KNOWN_SHADOWED but are now reachable. Remove them "
        "from that set -- an exemption that no longer applies is how a table "
        "like this stops meaning anything:" + _sep + _sep.join(healed)
    )


@pytest.mark.parametrize("literal", ["/api/v1/modules/events", "/api/v1/modules/states"])
def test_the_modules_literals_come_before_the_catch_all(literal: str) -> None:
    """The specific ordering this file was written for, pinned by position.

    The check above would also catch a regression here, but only as one entry in
    a list. This names the file to edit.
    """
    order = [p for p, _, _ in _routes()]
    assert literal in order, f"{literal} is no longer registered"
    catch_all = "/api/v1/modules/{module_id}"
    assert catch_all in order, "the /{module_id} route is gone -- re-check this test"
    assert order.index(literal) < order.index(catch_all), (
        f"{literal} is registered after {catch_all}, so it is unreachable. Move its "
        "@router.get block above the /{module_id} block in app/modules/api.py."
    )
