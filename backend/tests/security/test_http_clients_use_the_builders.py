"""Outbound HTTP clients are built by ``app/core/http_client.py``.

``build_async_client`` / ``build_aiohttp_session`` are drop-in replacements
for ``httpx.AsyncClient`` / ``aiohttp.ClientSession`` that cap the connect
phase (an unreachable device fails in ~8s instead of hanging a page) and, in
userspace VPN mode, route through the overlay SOCKS5 proxy so tailnet devices
are reachable at all. An inline client skips both. Every client that talks to
a device, a controller or a host the operator configured (backup target,
webhook, plugin registry, AI endpoint) uses a builder; this test fails when a
new inline client appears outside the reasoned allow-list below.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"

#: ``relpath::function`` -> why this client must stay inline.
ALLOWED: dict[str, str] = {
    "core/http_client.py::build_async_client": "the builder itself",
    "core/http_client.py::build_aiohttp_session": "the builder itself",
    "modules/cameras/api.py::_ensure_go2rtc_stream": (
        "go2rtc is FreeSDN's own sidecar on the compose network (GO2RTC_URL), not a "
        "device; the overlay proxy cannot reach it. Bounded by a 10s timeout."
    ),
    "modules/cameras/api.py::_proxy": (
        "live_stream_mp4's relay from the same go2rtc sidecar; 15s connect, 30s "
        "mid-stream read timeout."
    ),
}

_CLIENTS = {("httpx", "AsyncClient"), ("aiohttp", "ClientSession")}


def _imported_names(tree: ast.AST) -> set[str]:
    """Bare names bound by ``from httpx import AsyncClient`` and the like."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {m for m, _ in _CLIENTS}:
            for alias in node.names:
                if (node.module, alias.name) in _CLIENTS:
                    names.add(alias.asname or alias.name)
    return names


def _inline_clients(source: str, rel: str) -> list[str]:
    tree = ast.parse(source)
    bare = _imported_names(tree)
    found: list[str] = []

    def visit(node: ast.AST, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            scope = function
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = child.name
            if isinstance(child, ast.Call):
                func = child.func
                inline = (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _CLIENTS
                ) or (isinstance(func, ast.Name) and func.id in bare)
                if inline:
                    found.append(f"{rel}::{scope}")
            visit(child, scope)

    visit(tree, "<module>")
    return found


def _scan() -> list[str]:
    hits: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        rel = path.relative_to(APP).as_posix()
        hits.extend(_inline_clients(path.read_text(encoding="utf-8"), rel))
    return hits


def test_no_inline_http_client_outside_the_allow_list() -> None:
    unexpected = sorted({hit for hit in _scan() if hit not in ALLOWED})
    assert not unexpected, (
        "Inline httpx.AsyncClient / aiohttp.ClientSession found. Use "
        "app.core.http_client.build_async_client / build_aiohttp_session (they "
        "cap the connect phase and reach overlay devices), or add the call site "
        "to ALLOWED with the reason it must stay inline:\n  " + "\n  ".join(unexpected)
    )


def test_every_allow_list_entry_is_still_needed() -> None:
    stale = sorted(set(ALLOWED) - set(_scan()))
    assert not stale, f"Allow-list entries with no inline client left: {stale}"


def test_the_scan_sees_every_spelling() -> None:
    source = (
        "import httpx, aiohttp\n"
        "from httpx import AsyncClient as AC\n"
        "async def a():\n    httpx.AsyncClient()\n"
        "async def b():\n    aiohttp.ClientSession()\n"
        "async def c():\n    AC()\n"
        "async def d():\n    build_async_client()\n"
    )
    assert _inline_clients(source, "x.py") == ["x.py::a", "x.py::b", "x.py::c"]
