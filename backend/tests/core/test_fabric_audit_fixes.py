# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for the end-to-end security+stability audit remediation:
SSRF never-bypassable metadata/CGNAT, the scoped-key org-admin floor, step-param
redaction, and the negotiator's cluster-wide idempotency/cooldown guards."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import uuid

import pytest


def _flood_event(i: int):
    """A minimal bus-event stand-in the Fabric dispatcher accepts."""
    return type(
        "E", (), {"event_type": "x.y", "organization_id": None, "payload": {}, "id": str(i)}
    )()


class _Pool:
    """Handle onto the module-global chain pool, with counter deltas.

    ``_chain_stats`` is cumulative for the life of the process (that is the
    point -- an operator reads running totals), so tests must diff rather than
    read absolutes or they couple to execution order.
    """

    def __init__(self, runtime) -> None:  # noqa: ANN001
        self.rt = runtime
        self._base = dict(runtime._chain_stats)

    def delta(self) -> dict[str, int]:
        now = self.rt.dispatch_stats()
        return {k: now[k] - self._base[k] for k in ("admitted", "dropped", "handled")}


@pytest.fixture
async def chain_pool():
    """Give each test a torn-down pool, and tear it down again afterwards so no
    worker outlives its event loop."""
    from app.core.fabric import runtime

    await runtime.stop_fabric_runtime()
    runtime._last_drop_log = 0.0  # the drop WARNING is rate-limited; unmute it
    pool = _Pool(runtime)
    try:
        yield pool
    finally:
        await runtime.stop_fabric_runtime()
        runtime._last_drop_log = 0.0


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
        self, chain_pool, monkeypatch
    ) -> None:
        # The bus subscriber must run chains off the bus's 10s wait_for (a long
        # chain cancelled mid-run leaves partial side-effects and no run record),
        # so _dispatch_connections hands off and returns without awaiting it.
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        seen: dict[str, str | None] = {}
        started = asyncio.Event()
        release = asyncio.Event()

        async def _fake_handle(ev):  # noqa: ANN001
            started.set()
            await release.wait()
            seen["called"] = getattr(ev, "event_type", None)
            return []

        monkeypatch.setattr(negotiator, "handle_event", _fake_handle)
        # The dispatcher pre-filters via would_handle (skips events no Connection
        # matches); force it true so this test exercises the hand-off itself.
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)

        await rt._dispatch_connections(_flood_event(0))
        # DETACHED: the dispatcher returned while the chain is still blocked.
        await asyncio.wait_for(started.wait(), 2)
        assert "called" not in seen
        release.set()
        await asyncio.wait_for(rt._chain_queue.join(), 2)
        assert seen.get("called") == "x.y"
        assert chain_pool.delta()["handled"] == 1

    async def test_dispatch_skips_events_no_connection_matches(
        self, chain_pool, monkeypatch
    ) -> None:
        # would_handle=False → nothing admitted, no worker pool spun up, no DB
        # session opened (the pool guard for a '*' firehose of unwired events).
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        called = {"n": 0}

        async def _fake_handle(_ev):  # noqa: ANN001
            called["n"] += 1

        monkeypatch.setattr(negotiator, "handle_event", _fake_handle)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: False)
        for i in range(50):
            await rt._dispatch_connections(_flood_event(i))
        assert called["n"] == 0
        assert rt._chain_queue is None  # not even a queue was created
        assert chain_pool.delta() == {"admitted": 0, "dropped": 0, "handled": 0}

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


class TestChainDispatchIsAdmissionBounded:
    """F-05: Fabric capped chain EXECUTION but not ADMISSION.

    The dispatcher used to ``asyncio.create_task`` per matching event and only
    then have the task park on a semaphore, so a Connection wired to a high-rate
    event (or to '*') retained one live task + coroutine frame + event graph per
    event. Executed against the real dispatcher with a blocked handler, 1000
    events in produced 1000 retained tasks and 16 running ones.

    It is now a fixed pool of long-lived workers draining a bounded queue, with
    an explicit drop-newest overload policy that is counted and logged.
    """

    async def test_a_flood_does_not_retain_a_task_per_event(self, chain_pool, monkeypatch) -> None:
        """Mutation caught: going back to create_task-per-event. The live-task
        delta then tracks the event count (~1000) instead of the pool size, and
        admitted/dropped stop accounting for the flood."""
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        release = asyncio.Event()
        live = {"now": 0, "peak": 0}

        async def _blocked(_ev):  # noqa: ANN001
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
            await release.wait()
            live["now"] -= 1
            return []

        monkeypatch.setattr(negotiator, "handle_event", _blocked)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)

        n_events = 1000
        tasks_before = len(asyncio.all_tasks())
        try:
            for i in range(n_events):
                await rt._dispatch_connections(_flood_event(i))
            await asyncio.sleep(0.05)  # let every worker pick up and block

            # THE finding, measured the way the reviewer measured it and without
            # reference to the implementation: live asyncio tasks must not scale
            # with the event count.
            task_growth = len(asyncio.all_tasks()) - tasks_before
            assert task_growth <= rt._MAX_CONCURRENT_CHAINS + 2, (
                f"{n_events} events grew the task set by {task_growth}"
            )

            stats = rt.dispatch_stats()
            assert stats["workers"] == rt._MAX_CONCURRENT_CHAINS
            assert stats["queued"] <= rt._CHAIN_QUEUE_MAXSIZE
            assert live["peak"] <= rt._MAX_CONCURRENT_CHAINS  # execution still capped

            d = chain_pool.delta()
            # Nothing vanishes uncounted: every event that passed would_handle is
            # either admitted or recorded as shed.
            assert d["admitted"] + d["dropped"] == n_events
            assert d["admitted"] <= rt._CHAIN_QUEUE_MAXSIZE + rt._MAX_CONCURRENT_CHAINS
            assert d["dropped"] > 0  # overload happened, and it is on the record
        finally:
            release.set()

    async def test_overload_is_logged_not_silent(self, chain_pool, monkeypatch, caplog) -> None:
        """The reviewer asked for overload to be VISIBLE. Mutation caught:
        deleting the WARNING in _note_chain_drop (or letting the rate-limiter
        swallow the first drop of a burst)."""
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        monkeypatch.setattr(rt, "_CHAIN_QUEUE_MAXSIZE", 4)  # read when the pool is built
        release = asyncio.Event()

        async def _blocked(_ev):  # noqa: ANN001
            await release.wait()
            return []

        monkeypatch.setattr(negotiator, "handle_event", _blocked)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)

        try:
            with caplog.at_level(logging.WARNING, logger="app.core.fabric.runtime"):
                for i in range(60):
                    await rt._dispatch_connections(_flood_event(i))
            assert chain_pool.delta()["dropped"] > 0
            drops = [r for r in caplog.records if "DROPPING" in r.getMessage()]
            assert drops, "load shedding must be reported, not silent"
            assert "backlog full" in drops[0].getMessage()
        finally:
            release.set()

    async def test_a_crashing_chain_does_not_kill_its_worker(self, chain_pool, monkeypatch) -> None:
        """New invariant of the pool design: with per-event tasks a crash cost
        one task; with long-lived workers an unhandled exception would retire a
        worker permanently and 16 bad events would leave Fabric inert.

        Mutation caught: dropping the ``except Exception`` from _chain_worker.
        The worker then dies mid-item, its queue entry is never marked done, and
        both the join() below and the liveness assertion fail."""
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        seen: list[str] = []

        async def _handle(ev):  # noqa: ANN001
            seen.append(ev.id)
            if ev.id == "0":
                raise RuntimeError("step blew up")
            return []

        monkeypatch.setattr(negotiator, "handle_event", _handle)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)

        await rt._dispatch_connections(_flood_event(0))  # crashes
        await asyncio.wait_for(rt._chain_queue.join(), 2)
        workers = set(rt._chain_workers)
        assert all(not w.done() for w in workers), "a crashed chain retired its worker"

        await rt._dispatch_connections(_flood_event(1))  # still served
        await asyncio.wait_for(rt._chain_queue.join(), 2)
        assert seen == ["0", "1"]
        assert set(rt._chain_workers) == workers  # same pool, not a rebuilt one
        assert chain_pool.delta()["handled"] == 2  # a crash counts as handled

    async def test_shutdown_tears_the_pool_down_and_is_idempotent(
        self, chain_pool, monkeypatch
    ) -> None:
        """Mutation caught: leaving the workers running in stop_fabric_runtime --
        they would outlive the loop and be destroyed pending."""
        from app.core.fabric.negotiator import negotiator

        rt = chain_pool.rt
        release = asyncio.Event()

        async def _blocked(_ev):  # noqa: ANN001
            await release.wait()
            return []

        monkeypatch.setattr(negotiator, "handle_event", _blocked)
        monkeypatch.setattr(negotiator, "would_handle", lambda _ev: True)

        for i in range(5):
            await rt._dispatch_connections(_flood_event(i))
        await asyncio.sleep(0.05)
        workers = list(rt._chain_workers)
        assert workers and rt._chain_queue is not None

        await rt.stop_fabric_runtime()
        assert rt._chain_workers == set()
        assert rt._chain_queue is None
        assert all(w.done() for w in workers)
        await rt.stop_fabric_runtime()  # idempotent
        release.set()

    async def test_pool_rebuilds_when_the_event_loop_changes(self, chain_pool) -> None:
        """The pool holds loop-bound asyncio objects. If a stale pool from a dead
        loop were reused, put_nowait would queue onto a queue nobody drains and
        every event would silently stall.

        Mutation caught: dropping the ``_chain_loop is not loop`` arm of
        _ensure_chain_workers."""
        rt = chain_pool.rt
        rt._ensure_chain_workers()
        stale_workers = set(rt._chain_workers)
        stale_queue = rt._chain_queue
        # Pretend the pool was built on a different loop, without cleaning up.
        rt._chain_loop = None
        rt._ensure_chain_workers()
        assert rt._chain_queue is not stale_queue
        assert set(rt._chain_workers).isdisjoint(stale_workers)
        assert len(rt._chain_workers) == rt._MAX_CONCURRENT_CHAINS
