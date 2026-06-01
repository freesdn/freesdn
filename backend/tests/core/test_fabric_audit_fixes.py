# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for the end-to-end security+stability audit remediation:
SSRF never-bypassable metadata/CGNAT, the scoped-key org-admin floor, step-param
redaction, and the negotiator's cluster-wide idempotency/cooldown guards."""

from __future__ import annotations

import ipaddress
import uuid

import pytest


class TestSSRFNeverBypassable:
    """allow_hosts may open RFC1918/CGNAT for a trusted LAN/tailnet host, but the
    cloud-metadata / loopback / link-local set is NEVER bypassable (invariant 6)."""

    def test_public_ip_allowed(self) -> None:
        import app.core.security_utils as su

        assert su._ip_block_reason(ipaddress.ip_address("1.1.1.1")) is None

    def test_private_blocked_untrusted_allowed_trusted(self) -> None:
        import app.core.security_utils as su

        ip = ipaddress.ip_address("192.168.1.150")
        assert su._ip_block_reason(ip, trusted=False) == "is_private"
        assert su._ip_block_reason(ip, trusted=True) is None

    def test_cgnat_blocked_untrusted_allowed_trusted(self) -> None:
        import app.core.security_utils as su

        ip = ipaddress.ip_address("100.64.1.2")  # Tailscale / RFC6598
        assert su._ip_block_reason(ip, trusted=False) == "cgnat(100.64.0.0/10)"
        assert su._ip_block_reason(ip, trusted=True) is None

    def test_metadata_link_local_blocked_even_trusted(self) -> None:
        import app.core.security_utils as su

        ip = ipaddress.ip_address("169.254.169.254")  # AWS/Azure/GCP IMDS
        assert su._ip_block_reason(ip, trusted=True) is not None

    def test_alibaba_metadata_inside_cgnat_blocked_even_trusted(self) -> None:
        import app.core.security_utils as su

        # 100.100.100.200 is inside CGNAT (would be trusted-allowed) but is an
        # explicit metadata IP — must stay blocked even for a trusted host.
        ip = ipaddress.ip_address("100.100.100.200")
        assert su._ip_block_reason(ip, trusted=True) == "cloud-metadata"

    def test_loopback_blocked_even_trusted(self) -> None:
        import app.core.security_utils as su

        assert su._ip_block_reason(ipaddress.ip_address("127.0.0.1"), trusted=True) is not None

    def test_ipv4_mapped_metadata_blocked(self) -> None:
        # ::ffff:100.100.100.200 (Alibaba IMDS) must not slip past via the mapped
        # form — unwrap to embedded IPv4 first (re-verification residual).
        import app.core.security_utils as su

        ip = ipaddress.ip_address("::ffff:100.100.100.200")
        assert su._ip_block_reason(ip, trusted=True) == "cloud-metadata"

    def test_ipv4_mapped_cgnat_blocked_untrusted(self) -> None:
        import app.core.security_utils as su

        ip = ipaddress.ip_address("::ffff:100.64.1.2")
        assert su._ip_block_reason(ip, trusted=False) == "cgnat(100.64.0.0/10)"
        assert su._ip_block_reason(ip, trusted=True) is None  # trusted tailnet ok

    def test_trusted_hostname_resolving_to_metadata_is_rejected(self, monkeypatch) -> None:
        import app.core.security_utils as su

        # The dangerous case the audit found: a trusted HOSTNAME that resolves to
        # the metadata IP previously skipped all IP checks. It must now raise.
        monkeypatch.setattr(
            su.socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("169.254.169.254", 0))]
        )
        with pytest.raises(ValueError):
            su._resolve_and_validate("evil.lan", allow_hosts=frozenset({"evil.lan"}))

    def test_trusted_hostname_resolving_to_lan_is_allowed(self, monkeypatch) -> None:
        import app.core.security_utils as su

        monkeypatch.setattr(
            su.socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("192.168.1.150", 0))]
        )
        assert (
            su._resolve_and_validate("n8n.lan", allow_hosts=frozenset({"n8n.lan"}))
            == "192.168.1.150"
        )


class TestCodeReviewFixes:
    """Regression tests for the end-to-end code-review remediation."""

    def test_ai_tool_name_sanitizes_dotted_op_id(self) -> None:
        # Dotted op-ids must map to provider-legal tool names (^[A-Za-z0-9_-]{1,64}$)
        # or the Anthropic/OpenAI tool-call API 400s every chat request.
        import re

        from app.core.fabric.ai_bridge import _ai_tool_name

        assert _ai_tool_name("cameras.snapshot") == "cameras_snapshot"
        assert _ai_tool_name("storage.store_blob") == "storage_store_blob"
        for op_id in ("cameras.snapshot", "network.client.list", "x.y.z"):
            assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", _ai_tool_name(op_id))

    def test_media_compatible_artifact_op_needs_a_producing_source(self) -> None:
        # A blob-REQUIRING op is NOT compatible with a source that produces nothing
        # (the matchmaker must not recommend store_blob for ingest.external).
        from app.core.fabric.operations import MEDIA_BLOB, media_compatible

        assert media_compatible((), (MEDIA_BLOB,)) is False
        assert media_compatible((), ("image/jpeg",)) is False
        assert media_compatible(("image/jpeg",), (MEDIA_BLOB,)) is True  # source produces a blob
        assert media_compatible((), ()) is True  # data-only op fits anything


class TestWebhookReplaySignature:
    """Webhook/Fabric deliveries bind a timestamp into the HMAC so a captured
    request can't be replayed outside the receiver's freshness window."""

    def test_signature_binds_timestamp(self) -> None:
        import app.core.security_utils as su

        body = '{"a":1}'
        s1 = su.sign_webhook_payload("secret", body, 1000)
        s2 = su.sign_webhook_payload("secret", body, 2000)
        assert s1.startswith("sha256=") and s1 != s2  # timestamp changes the signature

    def test_signature_matches_canonical_hmac(self) -> None:
        import hashlib
        import hmac

        import app.core.security_utils as su

        sig = su.sign_webhook_payload("k", "body", 1234)
        expected = "sha256=" + hmac.new(b"k", b"1234.body", hashlib.sha256).hexdigest()
        assert sig == expected

    def test_str_and_bytes_body_equivalent(self) -> None:
        import app.core.security_utils as su

        assert su.sign_webhook_payload("k", b"body", 9) == su.sign_webhook_payload("k", "body", 9)


class TestIngestRateLimitRedis:
    """Per-org /fabric/ingest throttle is cluster-wide via a Redis fixed-window
    counter, with an in-process fallback when Redis is down."""

    async def test_redis_window_enforced_cluster_wide(self, monkeypatch) -> None:
        from app.api.v1.endpoints import fabric as fab

        counters: dict[str, int] = {}

        class FakeRedis:
            async def incr(self, k):  # noqa: ANN001
                counters[k] = counters.get(k, 0) + 1
                return counters[k]

            async def expire(self, _k, _s):  # noqa: ANN001
                return True

        monkeypatch.setattr(fab, "_ingest_redis", FakeRedis())  # already-probed client
        org = uuid.uuid4()
        for _ in range(fab._INGEST_RATE_MAX):
            assert await fab._ingest_rate_ok(org) is True
        assert await fab._ingest_rate_ok(org) is False  # over budget in the same window

    async def test_falls_back_to_inprocess_without_redis(self, monkeypatch) -> None:
        from app.api.v1.endpoints import fabric as fab

        monkeypatch.setattr(fab, "_ingest_redis", False)  # probed → unavailable
        org = uuid.uuid4()
        fab._ingest_hits.pop(str(org), None)
        try:
            assert await fab._ingest_rate_ok(org) is True
        finally:
            fab._ingest_hits.pop(str(org), None)


class _U:
    def __init__(self, is_org_admin: bool, scoped: bool) -> None:
        self.is_org_admin = is_org_admin
        self._scoped = scoped


class TestScopedAdminFloor:
    """A scoped API key must not inherit full org-admin authority."""

    def test_full_admin_passes(self) -> None:
        from app.api.v1.endpoints.fabric import _is_unscoped_org_admin

        assert _is_unscoped_org_admin(_U(True, False)) is True

    def test_scoped_admin_refused(self) -> None:
        from app.api.v1.endpoints.fabric import _is_unscoped_org_admin

        assert _is_unscoped_org_admin(_U(True, True)) is False

    def test_non_admin_refused(self) -> None:
        from app.api.v1.endpoints.fabric import _is_unscoped_org_admin

        assert _is_unscoped_org_admin(_U(False, False)) is False


class _Conn:
    id = uuid.uuid4()
    organization_id = uuid.uuid4()
    name = "n"
    description = None
    enabled = True
    source_event = "e"
    conditions = None
    steps = [
        {
            "operation_id": "fabric.webhook",
            "params": {"url": "https://x", "headers": {"Authorization": "Bearer s3cr3t"}},
            "continue_on_error": True,
        }
    ]
    cooldown_seconds = 0
    last_run_at = None
    run_count = 0
    created_by = None
    created_at = None
    updated_at = None


class TestStepParamRedaction:
    """Step params can carry secrets (webhook auth headers, Slack URLs); list/get
    are readable by any org member, so non-authors must not see raw params."""

    def test_redacted_steps_strips_secret_params(self) -> None:
        from app.api.v1.endpoints.fabric import _redacted_steps

        out = _redacted_steps(_Conn.steps)
        assert out[0]["operation_id"] == "fabric.webhook"  # wire still visible
        assert "s3cr3t" not in str(out)
        assert out[0]["params"] == {"__redacted__": "hidden — author-only"}

    def test_conn_dict_full_vs_redacted(self) -> None:
        from app.api.v1.endpoints.fabric import _conn_dict

        full = _conn_dict(_Conn(), full_params=True)
        redacted = _conn_dict(_Conn(), full_params=False)
        assert "s3cr3t" in str(full["steps"])  # author can edit
        assert "s3cr3t" not in str(redacted["steps"])  # viewer cannot see it


def _engine_conn(**kw):
    from app.core.fabric.negotiator import Connection

    base = {
        "id": "c1",
        "organization_id": uuid.uuid4(),
        "name": "n",
        "source_event": "*",
        "steps": [],
    }
    base.update(kw)
    return Connection(**base)


class TestNegotiatorClusterGuards:
    """Cluster-wide at-most-once + cooldown via Redis, with single-instance fallback."""

    async def test_claim_event_fail_open_without_redis(self) -> None:
        from app.core.fabric.negotiator import Negotiator

        n = Negotiator()
        n._redis = None  # probed, unavailable
        ev = type("E", (), {"id": "e1"})()
        assert await n._claim_event(_engine_conn(), ev) is True

    async def test_claim_event_without_event_id_proceeds(self) -> None:
        from app.core.fabric.negotiator import Negotiator

        n = Negotiator()
        n._redis = None
        assert await n._claim_event(_engine_conn(), type("E", (), {})()) is True

    async def test_claim_event_dedupes_across_workers(self) -> None:
        from app.core.fabric.negotiator import Negotiator

        store: set[str] = set()

        class FakeRedis:
            async def set(self, k, _v, nx=False, ex=None):  # noqa: ANN001
                if nx and k in store:
                    return None
                store.add(k)
                return True

        n = Negotiator()
        n._redis = FakeRedis()
        conn = _engine_conn()
        ev = type("E", (), {"id": "e1"})()
        assert await n._claim_event(conn, ev) is True  # first worker claims
        assert await n._claim_event(conn, ev) is False  # second worker, same event → skip

    async def test_cooldown_inprocess_fallback(self) -> None:
        from app.core.fabric.negotiator import Negotiator

        n = Negotiator()
        n._redis = None
        conn = _engine_conn(cooldown_seconds=60)
        assert await n._cooldown_ok(conn) is True  # first fire opens the window
        assert await n._cooldown_ok(conn) is False  # still cooling down

    def test_remove_connection_prunes_last_fire(self) -> None:
        from app.core.fabric.negotiator import Negotiator

        n = Negotiator()
        n._last_fire["c1"] = 1.0
        n.remove_connection("c1")
        assert "c1" not in n._last_fire

    async def test_detached_dispatch_runs_handle_event_off_the_bus_budget(
        self, monkeypatch
    ) -> None:
        # The bus subscriber must run chains in a detached task (not inline under
        # the bus's 10s wait_for), so a long chain can't be cancelled mid-run.
        from app.core.fabric import runtime
        from app.core.fabric.negotiator import negotiator

        seen: dict[str, str | None] = {}

        async def _fake_handle(ev):  # noqa: ANN001
            seen["called"] = getattr(ev, "event_type", None)
            return []

        monkeypatch.setattr(negotiator, "handle_event", _fake_handle)
        # The dispatcher pre-filters via would_handle (skips events no Connection
        # matches); force it true so this test exercises the detach path itself.
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)
        ev = type(
            "E", (), {"event_type": "x.y", "organization_id": None, "payload": {}, "id": "e"}
        )()
        await runtime._dispatch_connections(ev)  # returns immediately
        for t in list(runtime._chain_tasks):  # drain the detached task
            await t
        assert seen.get("called") == "x.y"

    async def test_dispatch_skips_events_no_connection_matches(self, monkeypatch) -> None:
        # would_handle=False → no task spawned, no DB session opened (pool guard).
        from app.core.fabric import runtime
        from app.core.fabric.negotiator import negotiator

        called = {"n": 0}

        async def _fake_handle(_ev):  # noqa: ANN001
            called["n"] += 1

        monkeypatch.setattr(negotiator, "handle_event", _fake_handle)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: False)
        before = len(runtime._chain_tasks)
        await runtime._dispatch_connections(type("E", (), {"event_type": "x.y"})())
        assert called["n"] == 0 and len(runtime._chain_tasks) == before

    async def test_control_event_never_fires_a_connection(self) -> None:
        # Even a connection wired to the "*" firehose must not fire on the
        # internal fabric.connection.changed CRUD-propagation control event.
        from app.core.fabric.negotiator import Negotiator

        org = uuid.uuid4()
        n = Negotiator()
        n._redis = None
        n.add_connection(_engine_conn(organization_id=org, source_event="*"))
        ev = type(
            "E",
            (),
            {
                "event_type": "fabric.connection.changed",
                "organization_id": org,
                "payload": {},
                "id": "x",
            },
        )()
        assert await n.handle_event(ev) == []
