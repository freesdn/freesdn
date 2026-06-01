# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Verify structured logging is wired up end-to-end.

Covers:
 - setup_logging(json_format=True) installs JSONLogFormatter on the root logger
 - request_id ContextVar propagates into JSON log records
 - text/colored format path still works without raising
 - uvicorn loggers are rerouted through our handler
"""

import json
import logging

from app.core.logging import (
    ColoredFormatter,
    JSONLogFormatter,
    request_id_var,
    setup_logging,
)


def test_setup_logging_installs_json_formatter() -> None:
    """setup_logging(json_format=True) must install JSONLogFormatter on root."""
    setup_logging(level="INFO", json_format=True)
    root = logging.getLogger()
    has_json = any(isinstance(h.formatter, JSONLogFormatter) for h in root.handlers)
    assert has_json, (
        "Root logger must have JSONLogFormatter after setup_logging(json_format=True)"
    )


def test_setup_logging_reroutes_uvicorn_loggers() -> None:
    """uvicorn.* loggers should share our handler so their lines are JSON too."""
    setup_logging(level="INFO", json_format=True)
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv = logging.getLogger(name)
        assert uv.handlers, f"{name} should have a handler installed"
        assert any(isinstance(h.formatter, JSONLogFormatter) for h in uv.handlers), (
            f"{name} handler must use JSONLogFormatter"
        )
        assert uv.propagate is False, f"{name} should not propagate (avoid dup logs)"


def test_request_id_propagates_to_logs() -> None:
    """A log emitted while request_id_var is set must include the request_id."""
    formatter = JSONLogFormatter()
    token = request_id_var.set("test-req-123")
    try:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello",
            args=(),
            exc_info=None,
        )
        out = formatter.format(record)
        payload = json.loads(out)
        assert payload.get("request_id") == "test-req-123"
        assert payload.get("message") == "hello"
        assert payload.get("level") == "INFO"
    finally:
        request_id_var.reset(token)


def test_request_id_absent_when_unset() -> None:
    """Without a request_id set, the field must be omitted from the JSON payload."""
    # Ensure clean state
    try:
        request_id_var.set(None)
    except Exception:
        pass
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="no-req-id",
        args=(),
        exc_info=None,
    )
    payload = json.loads(formatter.format(record))
    assert "request_id" not in payload


def test_text_format_still_works() -> None:
    """LOG_FORMAT=text should install ColoredFormatter and not raise."""
    setup_logging(level="INFO", json_format=False)
    root = logging.getLogger()
    has_colored = any(isinstance(h.formatter, ColoredFormatter) for h in root.handlers)
    assert has_colored, "Root logger must have ColoredFormatter when json_format=False"
    logging.getLogger("test").info("text mode test")


def test_request_id_middleware_sets_context_var() -> None:
    """RequestIDMiddleware must set the ContextVar so logs inside handlers see it."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from app.core.middleware import RequestIDMiddleware

    captured: dict[str, str | None] = {}

    async def handler(request: object) -> JSONResponse:
        captured["request_id"] = request_id_var.get()
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/ping", handler)])
    app.add_middleware(RequestIDMiddleware)
    client = TestClient(app)

    # Client-supplied upstream header is accepted, but prefixed with
    # ``ext-`` so log-poisoning attempts are visible and cannot
    # impersonate server-generated correlation IDs.
    resp = client.get("/ping", headers={"X-Request-ID": "upstream-abc"})
    assert resp.status_code == 200
    assert resp.headers.get("x-request-id") == "ext-upstream-abc"
    assert captured["request_id"] == "ext-upstream-abc"

    # Invalid client-supplied ID (contains characters outside [A-Za-z0-9-_])
    # is dropped and replaced with a server-generated UUID.
    captured.clear()
    resp = client.get("/ping", headers={"X-Request-ID": "bad id with spaces!"})
    assert resp.status_code == 200
    rid = resp.headers.get("x-request-id") or ""
    assert rid and not rid.startswith("ext-"), "invalid IDs must be replaced, not prefixed"
    assert captured["request_id"] == rid

    # Auto-generated when absent
    captured.clear()
    resp = client.get("/ping")
    assert resp.status_code == 200
    assert resp.headers.get("x-request-id"), "middleware must generate an ID"
    assert captured["request_id"] is not None
    assert captured["request_id"] == resp.headers["x-request-id"]
    assert not resp.headers["x-request-id"].startswith("ext-")
