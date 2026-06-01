# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the FreeSDN Fabric execution engine.

Covers the security-critical runtime: safe templating, the org-scoped artifact
broker, the tier-aware executor (native-read / native-write→staging /
plugin→sandboxed), and the negotiator (org fail-closed, pattern + conditions,
step chain with data + artifact threading, the cross-tier permission gate).
"""

from __future__ import annotations

import uuid

import pytest

from app.core.fabric.artifact_broker import ArtifactBroker, ArtifactError
from app.core.fabric.execution import OperationContext, OperationResult
from app.core.fabric.executor import OperationExecutor
from app.core.fabric.negotiator import Connection, ConnectionStep, Negotiator, _event_matches
from app.core.fabric.operations import Operation, OperationTier
from app.core.fabric.templating import resolve_template

ORG = uuid.uuid4()


# ---------------------------------------------------------------------------
# Templating (safe, no-eval)
# ---------------------------------------------------------------------------


class TestTemplating:
    def test_whole_ref_preserves_type(self) -> None:
        ctx = {"trigger": {"count": 5, "obj": {"a": 1}}}
        assert resolve_template("{{trigger.count}}", ctx) == 5  # int, not "5"
        assert resolve_template("{{trigger.obj}}", ctx) == {"a": 1}

    def test_embedded_render_and_missing(self) -> None:
        ctx = {"trigger": {"n": 3}}
        assert resolve_template("got {{trigger.n}} frames", ctx) == "got 3 frames"
        assert resolve_template("{{trigger.nope}}", ctx) is None
        assert resolve_template("x={{trigger.nope}}", ctx) == "x="

    def test_list_indexing_and_nested_structures(self) -> None:
        ctx = {"steps": [{"output": {"bytes": 99}}]}
        assert resolve_template("{{steps.0.output.bytes}}", ctx) == 99
        out = resolve_template({"a": ["{{steps.0.output.bytes}}", "lit"]}, ctx)
        assert out == {"a": [99, "lit"]}

    def test_no_code_execution(self) -> None:
        # A would-be injection is just an unmatched literal — never evaluated.
        ctx = {"trigger": {}}
        assert resolve_template("{{__import__('os')}}", ctx) == "{{__import__('os')}}"


# ---------------------------------------------------------------------------
# Artifact broker
# ---------------------------------------------------------------------------


class TestArtifactBroker:
    @pytest.mark.asyncio
    async def test_put_get_roundtrip_and_integrity(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        ref = await broker.put(b"hello-bytes", "image/jpeg", ORG)
        assert ref.media_type == "image/jpeg" and ref.size == 11
        data, ref2 = await broker.get(ref.handle, ORG)
        assert data == b"hello-bytes" and ref2.sha256 == ref.sha256

    @pytest.mark.asyncio
    async def test_size_cap(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path, max_bytes=4)
        with pytest.raises(ArtifactError):
            await broker.put(b"toolong", "text/plain", ORG)

    @pytest.mark.asyncio
    async def test_cross_org_denied(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        ref = await broker.put(b"secret", "text/plain", ORG)
        with pytest.raises(ArtifactError):
            await broker.get(ref.handle, uuid.uuid4())  # different org

    @pytest.mark.asyncio
    async def test_bad_handle_rejected(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        with pytest.raises(ArtifactError):
            await broker.get("../../etc/passwd", ORG)

    @pytest.mark.asyncio
    async def test_expiry(self, tmp_path) -> None:
        import json
        import time

        broker = ArtifactBroker(base_dir=tmp_path)
        ref = await broker.put(b"x", "text/plain", ORG)
        # Live now.
        data, _ = await broker.get(ref.handle, ORG)
        assert data == b"x"
        # Force-expire by rewriting the sidecar's expires_at to the past.
        _, meta_path = broker._paths(ORG, ref.handle)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["expires_at"] = time.time() - 100
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        with pytest.raises(ArtifactError):
            await broker.get(ref.handle, ORG)
        # cleanup_expired sweeps it (already gone after the failed get, so 0 here)
        assert await broker.cleanup_expired() >= 0


# ---------------------------------------------------------------------------
# Executor — tier routing
# ---------------------------------------------------------------------------


def _native_read_op(handler, produces=()):
    return Operation(
        id="x.read",
        title="read",
        produces=produces,
        handler=handler,
        tier=OperationTier.NATIVE,
        provider_id="x",
    )


class TestExecutorNativeRead:
    @pytest.mark.asyncio
    async def test_handler_result_passthrough(self) -> None:
        async def h(ctx):
            return OperationResult.ok(output={"v": 1})

        ex = OperationExecutor()
        res = await ex.execute(_native_read_op(h), OperationContext(ORG, {}))
        assert res.success and res.output == {"v": 1}

    @pytest.mark.asyncio
    async def test_no_handler_is_not_supported(self) -> None:
        op = Operation(id="x.read", title="read", tier=OperationTier.NATIVE, provider_id="x")
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}))
        assert not res.success and res.error_code == "NOT_SUPPORTED"

    @pytest.mark.asyncio
    async def test_media_mismatch_rejected(self, tmp_path) -> None:
        from app.core.fabric.execution import ArtifactRef

        async def h(ctx):
            return OperationResult.ok(artifact=ArtifactRef("h", "text/plain", 1, "s"))

        op = _native_read_op(h, produces=("image/jpeg",))
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}))
        assert not res.success and res.error_code == "MEDIA_MISMATCH"


class TestExecutorNativeWrite:
    @pytest.mark.asyncio
    async def test_write_is_staged_not_applied(self, monkeypatch) -> None:
        captured = {}

        class _FakeChange:
            id = uuid.UUID("11111111-1111-1111-1111-111111111111")

        class _FakeStaging:
            def __init__(self, db):
                self.db = db

            async def stage_change(self, **kw):
                captured.update(kw)
                return _FakeChange()

        monkeypatch.setattr("app.services.adapter_staging.AdapterStagingService", _FakeStaging)

        async def _in_org(db, cid, org):
            return True

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _in_org)

        op = Operation(
            id="storage.dataset.create",
            title="create",
            write=True,
            feature="storage.dataset",
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        cid = uuid.uuid4()
        ctx = OperationContext(ORG, {"controller_id": str(cid), "name": "backups"}, db=object())
        res = await OperationExecutor().execute(op, ctx)
        assert res.success and res.staged_change_id == str(_FakeChange.id)
        assert captured["feature"] == "storage.dataset"
        assert captured["controller_id"] == cid
        assert captured["payload"] == {"name": "backups"}  # routing keys stripped

    @pytest.mark.asyncio
    async def test_write_requires_controller_id(self) -> None:
        op = Operation(
            id="storage.dataset.create",
            title="c",
            write=True,
            feature="storage.dataset",
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}, db=object()))
        assert not res.success and res.error_code == "NO_TARGET"

    @pytest.mark.asyncio
    async def test_write_requiring_artifact_without_one_fails_clearly(self, monkeypatch) -> None:
        # A write op that consumes an artifact (accepts non-empty) but gets none
        # (e.g. store_blob via /invoke, or fired from an artifact-less source) must
        # fail with ARTIFACT_REQUIRED — not stage a change that 400s at sign-off.
        async def _in_org(db, cid, org):
            return True

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _in_org)
        op = Operation(
            id="storage.store_blob",
            title="store",
            write=True,
            feature="storage.blob",
            accepts=("blob",),
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        ctx = OperationContext(ORG, {"controller_id": str(uuid.uuid4())}, db=object())
        res = await OperationExecutor().execute(op, ctx)  # no input_artifact
        assert not res.success and res.error_code == "ARTIFACT_REQUIRED"

    @pytest.mark.asyncio
    async def test_write_cross_org_rejected(self, monkeypatch) -> None:
        async def _not_in_org(db, cid, org):
            return False

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _not_in_org)
        op = Operation(
            id="storage.dataset.create",
            title="c",
            write=True,
            feature="storage.dataset",
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        ctx = OperationContext(ORG, {"controller_id": str(uuid.uuid4()), "name": "x"}, db=object())
        res = await OperationExecutor().execute(op, ctx)
        assert not res.success and res.error_code == "CROSS_TENANT_TARGET"

    @pytest.mark.asyncio
    async def test_write_update_requires_target_id(self, monkeypatch) -> None:
        async def _in_org(db, cid, org):
            return True

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _in_org)
        op = Operation(
            id="storage.dataset.update",
            title="u",
            write=True,
            feature="storage.dataset",
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        ctx = OperationContext(
            ORG, {"controller_id": str(uuid.uuid4()), "_staging_operation": "update"}, db=object()
        )
        res = await OperationExecutor().execute(op, ctx)
        assert not res.success and res.error_code == "NO_TARGET_ID"

    @pytest.mark.asyncio
    async def test_write_with_input_artifact_persists_durably(self, monkeypatch) -> None:
        # storage.store_blob-style write: the input artifact (a snapshot) must be
        # copied to the DURABLE store and only a small reference stamped into the
        # staged payload — never the bytes, and never left to the broker's TTL.
        import app.core.fabric.durable_store as ds_mod
        from app.core.fabric.execution import ArtifactRef

        captured = {}

        class _FakeChange:
            id = uuid.UUID("33333333-3333-3333-3333-333333333333")

        class _FakeStaging:
            def __init__(self, db):
                pass

            async def stage_change(self, **kw):
                captured.update(kw)
                return _FakeChange()

        class _FakeBroker:
            async def get(self, handle, org):
                return b"jpegbytes", ArtifactRef(
                    handle=handle, media_type="image/jpeg", size=9, sha256="sha9"
                )

        async def _in_org(db, cid, org):
            return True

        async def _put(data, org, media_type):
            return {
                "durable_token": "d" * 32,
                "sha256": "sha9",
                "size": len(data),
                "media_type": media_type,
            }

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _in_org)
        monkeypatch.setattr("app.services.adapter_staging.AdapterStagingService", _FakeStaging)
        monkeypatch.setattr(ds_mod.durable_store, "put", _put)

        op = Operation(
            id="storage.store_blob",
            title="store",
            write=True,
            feature="storage.store_blob",
            permission="storage.write",
            accepts=("image/jpeg",),
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        ctx = OperationContext(
            ORG,
            {
                "controller_id": str(uuid.uuid4()),
                "dataset_path": "/mnt/s4_hdd/freesdn",
                "filename": "cam.jpg",
            },
            db=object(),
            artifacts=_FakeBroker(),
            input_artifact=ArtifactRef(
                handle="h" * 32, media_type="image/jpeg", size=9, sha256="sha9"
            ),
        )
        res = await OperationExecutor().execute(op, ctx)
        assert res.success and res.staged_change_id == str(_FakeChange.id)
        # bytes are NOT in the payload — only a durable reference is
        art = captured["payload"]["_artifact"]
        assert art["durable_token"] == "d" * 32 and art["sha256"] == "sha9" and art["size"] == 9
        assert captured["payload"]["dataset_path"] == "/mnt/s4_hdd/freesdn"
        assert captured["payload"]["filename"] == "cam.jpg"

    @pytest.mark.asyncio
    async def test_write_update_passes_validated_target_id(self, monkeypatch) -> None:
        captured = {}

        class _FakeChange:
            id = uuid.UUID("22222222-2222-2222-2222-222222222222")

        class _FakeStaging:
            def __init__(self, db):
                pass

            async def stage_change(self, **kw):
                captured.update(kw)
                return _FakeChange()

        async def _in_org(db, cid, org):
            return True

        monkeypatch.setattr("app.core.fabric.executor._controller_in_org", _in_org)
        monkeypatch.setattr("app.services.adapter_staging.AdapterStagingService", _FakeStaging)
        op = Operation(
            id="storage.dataset.update",
            title="u",
            write=True,
            feature="storage.dataset",
            permission="storage.write",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        ctx = OperationContext(
            ORG,
            {
                "controller_id": str(uuid.uuid4()),
                "_staging_operation": "update",
                "target_id": "ds-7",
                "x": 1,
            },
            db=object(),
        )
        res = await OperationExecutor().execute(op, ctx)
        assert res.success
        assert captured["operation"] == "update" and captured["target_id"] == "ds-7"
        assert captured["payload"] == {"x": 1}  # target_id stripped from payload


class TestExecutorPlugin:
    @pytest.mark.asyncio
    async def test_plugin_dict_output(self) -> None:
        async def h(params):
            return {"ok": True, "echo": params.get("v")}

        op = Operation(
            id="plugin.acme.sync",
            title="sync",
            handler=h,
            tier=OperationTier.PLUGIN,
            provider_id="acme",
        )
        res = await OperationExecutor().execute(op, OperationContext(ORG, {"v": 7}))
        assert res.success and res.output == {"ok": True, "echo": 7}

    @pytest.mark.asyncio
    async def test_plugin_error_is_sanitized(self) -> None:
        async def h(params):
            raise RuntimeError("secret internal detail")

        op = Operation(
            id="plugin.acme.boom",
            title="boom",
            handler=h,
            tier=OperationTier.PLUGIN,
            provider_id="acme",
        )
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}))
        assert not res.success and res.error_code == "PLUGIN_ERROR"
        assert "secret internal detail" not in (res.error or "")

    @pytest.mark.asyncio
    async def test_plugin_write_forbidden(self) -> None:
        # constructing a plugin write op is allowed at the type level (feature set),
        # but the executor refuses to run it.
        async def h(params):
            return {}

        op = Operation(
            id="plugin.acme.write",
            title="w",
            write=True,
            feature="plugin.acme.write",
            permission="plugin.acme.write",
            handler=h,
            tier=OperationTier.PLUGIN,
            provider_id="acme",
        )
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}))
        assert not res.success and res.error_code == "PLUGIN_WRITE_FORBIDDEN"

    @pytest.mark.asyncio
    async def test_plugin_timeout(self, monkeypatch) -> None:
        import asyncio

        import app.core.fabric.executor as ex_mod

        monkeypatch.setattr(ex_mod, "PLUGIN_OP_TIMEOUT_SECONDS", 0.05)

        async def h(params):
            await asyncio.sleep(0.3)
            return {}

        op = Operation(
            id="plugin.acme.slow",
            title="slow",
            handler=h,
            tier=OperationTier.PLUGIN,
            provider_id="acme",
        )
        res = await OperationExecutor().execute(op, OperationContext(ORG, {}))
        assert not res.success and res.error_code == "PLUGIN_TIMEOUT"


# ---------------------------------------------------------------------------
# Negotiator — matching, org scoping, chain, artifact threading, permission gate
# ---------------------------------------------------------------------------


class _Event:
    def __init__(self, event_type, payload, organization_id):
        self.event_type = event_type
        self.payload = payload
        self.organization_id = organization_id


class _FakeRegistry:
    def __init__(self, ops):
        self._ops = {o.id: o for o in ops}

    def get_operation(self, op_id):
        return self._ops.get(op_id)


def test_event_matches() -> None:
    assert _event_matches("a.b.c", "*")
    assert _event_matches("a.b", "a.b")
    assert _event_matches("a.b", "a.*")
    assert not _event_matches("a.b.c", "a.*")  # one-segment wildcard
    assert _event_matches("a.b.c", "a.#")
    assert not _event_matches("x.y", "a.#")


class TestNegotiator:
    @pytest.mark.asyncio
    async def test_org_scope_fail_closed(self) -> None:
        async def sink(ctx):
            return OperationResult.ok()

        op = _native_read_op(sink)
        neg = Negotiator(
            registry=_FakeRegistry([op]), permission_checker=None, session_factory=lambda: None
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="t",
                source_event="a.evt",
                steps=[ConnectionStep("x.read")],
            )
        )
        # event from a DIFFERENT org must not fire
        runs = await neg.handle_event(_Event("a.evt", {}, uuid.uuid4()))
        assert runs == []

    @pytest.mark.asyncio
    async def test_chain_with_artifact_threading(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        executor = OperationExecutor(artifact_broker=broker)

        async def producer(ctx):
            ref = await ctx.artifacts.put(b"frame", "image/jpeg", ctx.organization_id)
            return OperationResult.ok(output={"bytes": 5}, artifact=ref)

        seen = {}

        async def consumer(ctx):
            # the prior step's artifact is threaded into input_artifact
            seen["input_artifact"] = ctx.input_artifact
            seen["templated_bytes"] = ctx.params.get("n")
            return OperationResult.ok(output={"stored": True})

        prod = Operation(
            id="cam.snap",
            title="snap",
            produces=("image/jpeg",),
            handler=producer,
            tier=OperationTier.NATIVE,
            provider_id="cam",
        )
        cons = Operation(
            id="store.put",
            title="put",
            accepts=("image/jpeg",),
            handler=consumer,
            tier=OperationTier.NATIVE,
            provider_id="store",
        )
        neg = Negotiator(
            registry=_FakeRegistry([prod, cons]),
            executor=executor,
            permission_checker=None,
            session_factory=lambda: None,
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="cam->store",
                source_event="cameras.event.motion",
                steps=[
                    ConnectionStep("cam.snap"),
                    ConnectionStep("store.put", params={"n": "{{steps.0.output.bytes}}"}),
                ],
            )
        )
        runs = await neg.handle_event(_Event("cameras.event.motion", {"camera_id": "abc"}, ORG))
        assert len(runs) == 1 and runs[0]["success"] is True
        assert (
            seen["input_artifact"] is not None and seen["input_artifact"].media_type == "image/jpeg"
        )
        assert seen["templated_bytes"] == 5  # data passed step0 → step1

    @pytest.mark.asyncio
    async def test_permission_gate_denies_without_checker(self) -> None:
        async def h(ctx):
            return OperationResult.ok()

        op = Operation(
            id="x.read",
            title="r",
            permission="storage.write",
            handler=h,
            tier=OperationTier.NATIVE,
            provider_id="x",
        )
        neg = Negotiator(
            registry=_FakeRegistry([op]), permission_checker=None, session_factory=lambda: None
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="t",
                source_event="a.evt",
                steps=[ConnectionStep("x.read")],
            )
        )
        runs = await neg.handle_event(_Event("a.evt", {}, ORG))
        assert runs[0]["steps"][0]["error_code"] == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    async def test_permission_gate_allows_with_checker(self) -> None:
        async def h(ctx):
            return OperationResult.ok(output={"done": True})

        async def allow(actor_id, permission, org_id):
            return True

        op = Operation(
            id="x.read",
            title="r",
            permission="storage.write",
            handler=h,
            tier=OperationTier.NATIVE,
            provider_id="x",
        )
        neg = Negotiator(
            registry=_FakeRegistry([op]), permission_checker=allow, session_factory=lambda: None
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="t",
                source_event="a.evt",
                steps=[ConnectionStep("x.read")],
            )
        )
        runs = await neg.handle_event(_Event("a.evt", {}, ORG))
        assert runs[0]["success"] and runs[0]["steps"][0]["success"]


# ---------------------------------------------------------------------------
# Hardening checks (fail-closed gates, bounds)
# ---------------------------------------------------------------------------


class TestHardening:
    def test_write_op_requires_permission(self) -> None:
        with pytest.raises(ValueError):
            Operation(
                id="s.dataset.create",
                title="c",
                write=True,
                feature="s.dataset",
                tier=OperationTier.NATIVE,
                provider_id="s",
            )  # no permission

    @pytest.mark.asyncio
    async def test_plugin_none_permission_denied(self) -> None:
        async def h(params):
            return {}

        # plugin op with no declared permission must be DENIED (fail-closed for the untrusted tier)
        op = Operation(
            id="plugin.acme.x", title="x", handler=h, tier=OperationTier.PLUGIN, provider_id="acme"
        )
        neg = Negotiator(
            registry=_FakeRegistry([op]), permission_checker=None, session_factory=lambda: None
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="t",
                source_event="a.evt",
                steps=[ConnectionStep("plugin.acme.x")],
            )
        )
        runs = await neg.handle_event(_Event("a.evt", {}, ORG))
        assert runs[0]["steps"][0]["error_code"] == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    async def test_checker_exception_denies_not_crashes(self) -> None:
        async def h(ctx):
            return OperationResult.ok()

        async def boom(actor, perm, org):
            raise RuntimeError("rbac backend down")

        op = Operation(
            id="x.read",
            title="r",
            permission="storage.write",
            handler=h,
            tier=OperationTier.NATIVE,
            provider_id="x",
        )
        neg = Negotiator(
            registry=_FakeRegistry([op]), permission_checker=boom, session_factory=lambda: None
        )
        neg.add_connection(
            Connection(
                id="c1",
                organization_id=ORG,
                name="t",
                source_event="a.evt",
                steps=[ConnectionStep("x.read")],
            )
        )
        runs = await neg.handle_event(_Event("a.evt", {}, ORG))
        # a raising checker DENIES the step (fail-closed), and the run does not crash
        assert runs[0]["steps"][0]["error_code"] == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    async def test_artifact_max_bytes_zero_forbids(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        with pytest.raises(ArtifactError):
            await broker.put(b"x", "text/plain", ORG, max_bytes=0)


# ---------------------------------------------------------------------------
# Live vertical — the real registry + executor + builtin sink + run recorder.
# This is the hermetic proxy of the boot wiring (runtime.wire_and_start): an
# event fires a Connection end-to-end, the run is timed, and the audit recorder
# is invoked exactly as main.py drives it on the live bus.
# ---------------------------------------------------------------------------


class TestLiveVertical:
    @pytest.mark.asyncio
    async def test_event_fires_builtin_sink_and_records_run(self) -> None:
        recorded: list = []

        async def recorder(conn, run, event_type, payload) -> None:
            recorded.append((conn.id, run, event_type, payload))

        # Default registry (includes the builtin fabric.log sink) + default
        # executor. session_factory=lambda: None ⇒ no DB needed (log sink is
        # db-free), proving the full path with zero external dependencies.
        neg = Negotiator(run_recorder=recorder, session_factory=lambda: None)
        neg.add_connection(
            Connection(
                id="live-1",
                organization_id=ORG,
                name="ping->log",
                source_event="test.fabric.*",
                steps=[ConnectionStep("fabric.log", params={"message": "saw {{trigger.what}}"})],
                actor_id=uuid.uuid4(),
            )
        )
        runs = await neg.handle_event(_Event("test.fabric.ping", {"what": "motion"}, ORG))
        assert len(runs) == 1
        r = runs[0]
        assert r["success"] is True
        assert r["steps"][0]["operation_id"] == "fabric.log"
        assert r["steps"][0]["success"] is True
        assert isinstance(r.get("duration_ms"), int)  # timing recorded
        # The audit recorder fired exactly once, with the concrete event type.
        assert len(recorded) == 1
        assert recorded[0][0] == "live-1"
        assert recorded[0][2] == "test.fabric.ping"

    @pytest.mark.asyncio
    async def test_reload_connections_replaces_store(self) -> None:
        neg = Negotiator(session_factory=lambda: None)
        neg.reload_connections(
            [
                Connection(
                    id="r1",
                    organization_id=ORG,
                    name="a",
                    source_event="x.y",
                    steps=[ConnectionStep("fabric.log")],
                )
            ]
        )
        assert {c.id for c in neg.list_connections()} == {"r1"}
        neg.reload_connections([])
        assert neg.list_connections() == []

    @pytest.mark.asyncio
    async def test_cooldown_skips_rapid_refire(self) -> None:
        # a connection with a cooldown fires once, then is skipped within window
        neg = Negotiator(session_factory=lambda: None)
        neg._redis = None  # exercise the deterministic in-process cooldown path
        neg.add_connection(
            Connection(
                id="cd1",
                organization_id=ORG,
                name="cd",
                source_event="x.y",
                steps=[ConnectionStep("fabric.log")],
                cooldown_seconds=60,
            )
        )
        r1 = await neg.handle_event(_Event("x.y", {}, ORG))
        r2 = await neg.handle_event(_Event("x.y", {}, ORG))
        assert len(r1) == 1 and len(r2) == 0  # second within cooldown → skipped

    @pytest.mark.asyncio
    async def test_no_cooldown_fires_every_time(self) -> None:
        neg = Negotiator(session_factory=lambda: None)
        neg.add_connection(
            Connection(
                id="cd2",
                organization_id=ORG,
                name="cd",
                source_event="x.y",
                steps=[ConnectionStep("fabric.log")],  # cooldown_seconds defaults 0
            )
        )
        assert len(await neg.handle_event(_Event("x.y", {}, ORG))) == 1
        assert len(await neg.handle_event(_Event("x.y", {}, ORG))) == 1

    @pytest.mark.asyncio
    async def test_run_once_applies_same_gates(self) -> None:
        # run_once bypasses event matching but still runs the chain + gates.
        neg = Negotiator(session_factory=lambda: None)
        conn = Connection(
            id="t1",
            organization_id=ORG,
            name="t",
            source_event="x.y",
            steps=[ConnectionStep("fabric.log", params={"message": "hi"})],
            actor_id=uuid.uuid4(),
        )
        run = await neg.run_once(conn, {"any": "payload"})
        assert run["success"] is True
        assert run["steps"][0]["operation_id"] == "fabric.log"

    @pytest.mark.asyncio
    async def test_artifact_invalid_org_rejected(self, tmp_path) -> None:
        broker = ArtifactBroker(base_dir=tmp_path)
        with pytest.raises(ArtifactError):
            await broker.put(b"x", "text/plain", "not-a-uuid")  # type: ignore[arg-type]

    def test_whole_ref_string_is_length_capped(self) -> None:
        from app.core.fabric.templating import _MAX_RENDERED_STR

        big = "A" * (_MAX_RENDERED_STR + 500)
        out = resolve_template("{{trigger.s}}", {"trigger": {"s": big}})
        assert isinstance(out, str) and len(out) == _MAX_RENDERED_STR
