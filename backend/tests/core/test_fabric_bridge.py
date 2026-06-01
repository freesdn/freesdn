# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the external-orchestration bridge: the outbound fabric.webhook
operation (SSRF-guarded) and the inbound /fabric/ingest emit helper."""

from __future__ import annotations

import uuid

import pytest

from app.core.fabric.execution import OperationContext

ORG = uuid.uuid4()


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text


class TestWebhookOperation:
    @pytest.mark.asyncio
    async def test_requires_url(self) -> None:
        from app.core.fabric.builtin_ops import _webhook_handler

        res = await _webhook_handler(OperationContext(ORG, {}))
        assert not res.success and res.error_code == "NO_TARGET"

    @pytest.mark.asyncio
    async def test_ssrf_blocked_is_refused(self, monkeypatch) -> None:
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        async def _boom(*a, **k):
            raise ValueError("blocked private/loopback/metadata IP")

        monkeypatch.setattr(su, "safe_http_request", _boom)
        res = await _webhook_handler(
            OperationContext(ORG, {"url": "http://169.254.169.254/latest/meta-data"})
        )
        assert not res.success and res.error_code == "SSRF_BLOCKED"

    @pytest.mark.asyncio
    async def test_happy_post_returns_status(self, monkeypatch) -> None:
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        calls: dict = {}

        async def _fake(method, url, **kw):
            calls.update(method=method, url=url, json=kw.get("json"), headers=kw.get("headers"))
            return _Resp(200, '{"ok": 1}')

        monkeypatch.setattr(su, "safe_http_request", _fake)
        ctx = OperationContext(
            ORG,
            {
                "url": "https://n8n.example/webhook/abc",
                "payload": {"a": 1},
                "headers": {"X-Auth": "t"},
            },
        )
        res = await _webhook_handler(ctx)
        assert res.success and res.output["status_code"] == 200 and res.output["ok"] is True
        assert calls["method"] == "POST" and calls["url"].startswith("https://n8n")
        assert calls["json"] == {"a": 1} and calls["headers"] == {"X-Auth": "t"}

    @pytest.mark.asyncio
    async def test_defaults_payload_to_trigger(self, monkeypatch) -> None:
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        calls: dict = {}

        async def _fake(method, url, **kw):
            calls["json"] = kw.get("json")
            return _Resp(204)

        monkeypatch.setattr(su, "safe_http_request", _fake)
        ctx = OperationContext(
            ORG,
            {"url": "https://n8n.example/webhook/abc"},
            trigger={"event": "cameras.event.motion"},
        )
        await _webhook_handler(ctx)
        assert calls["json"] == {"event": "cameras.event.motion"}

    @pytest.mark.asyncio
    async def test_signs_body_when_secret_configured(self, monkeypatch) -> None:
        import hashlib
        import hmac
        import json as _json

        import app.core.config as cfg
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        monkeypatch.setattr(cfg.settings, "FABRIC_WEBHOOK_SIGNING_SECRET", "s3cr3t")
        calls: dict = {}

        async def _fake(method, url, **kw):
            calls.update(content=kw.get("content"), json=kw.get("json"), headers=kw.get("headers"))
            return _Resp(200)

        monkeypatch.setattr(su, "safe_http_request", _fake)
        await _webhook_handler(
            OperationContext(ORG, {"url": "https://n8n.example/h", "payload": {"a": 1}})
        )
        raw = _json.dumps({"a": 1}, default=str).encode()
        assert calls["json"] is None and calls["content"] == raw  # signed path: content, not json=
        # Replay-resistant: signature binds the X-Fabric-Timestamp it sent.
        ts = calls["headers"]["X-Fabric-Timestamp"]
        assert int(ts) > 0
        signed = ts.encode() + b"." + raw
        expected = "sha256=" + hmac.new(b"s3cr3t", signed, hashlib.sha256).hexdigest()
        assert calls["headers"]["X-Fabric-Signature"] == expected

    @pytest.mark.asyncio
    async def test_non_2xx_is_failure(self, monkeypatch) -> None:
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        async def _fake(*a, **k):
            return _Resp(500, "boom")

        monkeypatch.setattr(su, "safe_http_request", _fake)
        res = await _webhook_handler(
            OperationContext(ORG, {"url": "https://n8n.example/webhook/abc"})
        )
        assert not res.success and res.error_code == "BAD_STATUS"


class TestIngestEmit:
    @pytest.mark.asyncio
    async def test_sanitizes_name_and_publishes_canonical_event(self, monkeypatch) -> None:
        import app.core.events as events
        from app.api.v1.endpoints.fabric import _emit_ingest

        published: dict = {}

        class _Bus:
            async def publish(self, ev):
                published["ev"] = ev

        monkeypatch.setattr(events, "get_event_bus", lambda: _Bus())
        org = uuid.uuid4()
        name = await _emit_ingest(org, "n8n Done!! <spoof>", {"x": 1})
        assert name == "n8ndonespoof"  # sanitized to [a-z0-9_-]
        e = published["ev"]
        # ALWAYS the canonical type — never operator-controlled (anti-spoof)
        assert e.event_type == "ingest.external"
        assert str(e.organization_id) == str(org) and e.source == "ingest"
        assert e.payload == {"name": "n8ndonespoof", "data": {"x": 1}}

    @pytest.mark.asyncio
    async def test_empty_name_defaults_external(self, monkeypatch) -> None:
        import app.core.events as events
        from app.api.v1.endpoints.fabric import _emit_ingest

        class _Bus:
            async def publish(self, ev):
                pass

        monkeypatch.setattr(events, "get_event_bus", lambda: _Bus())
        assert await _emit_ingest(uuid.uuid4(), "", {}) == "external"
        assert await _emit_ingest(uuid.uuid4(), "!!!", {}) == "external"


def test_ingest_per_org_rate_limit() -> None:
    # Exercises the in-process fallback window directly (the async _ingest_rate_ok
    # prefers a cluster-wide Redis counter; see test_fabric_audit_fixes).
    from app.api.v1.endpoints import fabric as fab

    org = uuid.uuid4()
    fab._ingest_hits.pop(str(org), None)
    try:
        for _ in range(fab._INGEST_RATE_MAX):
            assert fab._ingest_rate_ok_local(org) is True
        assert fab._ingest_rate_ok_local(org) is False  # over the per-org window
        assert fab._ingest_rate_ok_local(uuid.uuid4()) is True  # a different org is unaffected
    finally:
        fab._ingest_hits.pop(str(org), None)


class TestWebhookAllowlist:
    """The deploy-owner allow_hosts lets fabric.webhook reach a self-hosted
    n8n/HA on the LAN/tailnet (private IP) while still blocking everything else
    and NEVER bypassing cloud-metadata."""

    def test_private_blocked_without_allowlist(self, monkeypatch) -> None:
        import app.core.security_utils as su

        monkeypatch.setattr(
            su.socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("192.168.1.150", 0))]
        )
        with pytest.raises(ValueError, match="blocked IP"):
            su._resolve_and_validate("n8n.lan")

    def test_private_allowed_when_host_allowlisted(self, monkeypatch) -> None:
        import app.core.security_utils as su

        monkeypatch.setattr(
            su.socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("192.168.1.150", 0))]
        )
        assert (
            su._resolve_and_validate("n8n.lan", allow_hosts=frozenset({"n8n.lan"}))
            == "192.168.1.150"
        )

    def test_allowlisting_one_host_does_not_allow_others(self, monkeypatch) -> None:
        import app.core.security_utils as su

        monkeypatch.setattr(
            su.socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.0.0.5", 0))]
        )
        with pytest.raises(ValueError, match="blocked IP"):
            su._resolve_and_validate("other.lan", allow_hosts=frozenset({"n8n.lan"}))

    @pytest.mark.asyncio
    async def test_cloud_metadata_never_bypassed(self) -> None:
        import app.core.security_utils as su

        with pytest.raises(ValueError, match="metadata"):
            await su.safe_http_request(
                "GET",
                "http://169.254.169.254/latest/meta-data",
                allow_hosts=frozenset({"169.254.169.254"}),
            )

    @pytest.mark.asyncio
    async def test_handler_passes_config_allowlist(self, monkeypatch) -> None:
        import app.core.config as cfg
        import app.core.security_utils as su
        from app.core.fabric.builtin_ops import _webhook_handler

        monkeypatch.setattr(
            cfg.settings, "FABRIC_WEBHOOK_ALLOWED_HOSTS", "n8n.example.net, 192.168.1.150"
        )
        captured: dict = {}

        async def _fake(method, url, **kw):
            captured["allow_hosts"] = kw.get("allow_hosts")
            return _Resp(200)

        monkeypatch.setattr(su, "safe_http_request", _fake)
        await _webhook_handler(
            OperationContext(ORG, {"url": "https://n8n.example.net/webhook/x"})
        )
        assert captured["allow_hosts"] == frozenset({"n8n.example.net", "192.168.1.150"})


def test_bridge_primitives_declared() -> None:
    from app.core.fabric.builtin_ops import builtin_events, builtin_operations

    ops = {o.id: o for o in builtin_operations()}
    assert "fabric.webhook" in ops
    wh = ops["fabric.webhook"]
    # permission=None ⇒ excluded from the AI bridge (human-only) + gated by authorship
    assert wh.permission is None and wh.handler is not None and wh.write is False
    evs = {e.event_type for e in builtin_events()}
    assert "ingest.external" in evs
