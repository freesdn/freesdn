# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the P4 builder matchmaking: ``media_compatible`` + the registry's
``compatible_targets`` + the ``GET /fabric/connections/suggest`` annotation/sort
logic, plus the transient-artifact sweep lifecycle."""

from __future__ import annotations

import uuid

import pytest

from app.core.fabric.operations import (
    MEDIA_BLOB,
    EventSpec,
    Operation,
    OperationTier,
    media_compatible,
)

ORG = uuid.uuid4()


class TestMediaCompatible:
    def test_empty_accepts_is_always_compatible(self) -> None:
        # A data-only op (no input artifact) fits any source.
        assert media_compatible((), ()) is True
        assert media_compatible(("image/jpeg",), ()) is True

    def test_exact_media_match(self) -> None:
        assert media_compatible(("image/jpeg",), ("image/jpeg",)) is True
        assert media_compatible(("image/jpeg",), ("text/plain",)) is False

    def test_blob_is_wildcard_on_either_side(self) -> None:
        # An op that accepts blob takes any binary the source produces…
        assert media_compatible(("image/jpeg",), (MEDIA_BLOB,)) is True
        # …and a source that produces blob satisfies any binary accept.
        assert media_compatible((MEDIA_BLOB,), ("image/jpeg",)) is True

    def test_no_overlap_is_incompatible(self) -> None:
        assert media_compatible(("text/plain",), ("image/jpeg", "video/mp4")) is False

    def test_partial_overlap_is_compatible(self) -> None:
        assert media_compatible(("video/mp4",), ("image/jpeg", "video/mp4")) is True


def _op(op_id: str, *, accepts: tuple[str, ...] = (), **kw: object) -> Operation:
    return Operation(id=op_id, title=op_id, accepts=accepts, **kw)  # type: ignore[arg-type]


class TestCompatibleTargets:
    def test_filters_by_event_produced_media(self, monkeypatch) -> None:
        from app.core.fabric.registry import FabricRegistry

        reg = FabricRegistry()
        snapshot = _op("cameras.snapshot")  # data-only → always compatible
        store_blob = _op(
            "storage.store_blob",
            accepts=(MEDIA_BLOB,),
            write=True,
            permission="storage:write",
            feature="store_blob",
        )
        thumb = _op("media.thumbnail", accepts=("image/jpeg",))  # needs a jpeg
        transcode = _op("media.transcode", accepts=("video/mp4",))  # needs mp4

        ev = EventSpec(event_type="cameras.event.motion", title="Motion", produces=("image/jpeg",))
        monkeypatch.setattr(reg, "get_event", lambda _et: ev)
        monkeypatch.setattr(
            reg, "list_operations", lambda: [snapshot, store_blob, thumb, transcode]
        )

        ids = {o.id for o in reg.compatible_targets("cameras.event.motion")}
        # data-only + blob-wildcard + jpeg-match in; mp4-only out.
        assert ids == {"cameras.snapshot", "storage.store_blob", "media.thumbnail"}

    def test_pure_data_event_keeps_only_artifactless_ops(self, monkeypatch) -> None:
        from app.core.fabric.registry import FabricRegistry

        reg = FabricRegistry()
        notify = _op("fabric.notify")  # data-only
        store_blob = _op(
            "storage.store_blob",
            accepts=(MEDIA_BLOB,),
            write=True,
            permission="storage:write",
            feature="store_blob",
        )
        thumb = _op("media.thumbnail", accepts=("image/jpeg",))

        # ingest.external produces no artifact (pure data event).
        ev = EventSpec(event_type="ingest.external", title="Ingest")
        monkeypatch.setattr(reg, "get_event", lambda _et: ev)
        monkeypatch.setattr(reg, "list_operations", lambda: [notify, store_blob, thumb])

        ids = {o.id for o in reg.compatible_targets("ingest.external")}
        # Only the data-only op fits. A blob-REQUIRING op (store_blob) is NOT
        # compatible with a source that produces no artifact — recommending it
        # would stage a write that 400s at sign-off with no blob.
        assert ids == {"fabric.notify"}

    def test_unknown_event_treated_as_no_artifact(self, monkeypatch) -> None:
        from app.core.fabric.registry import FabricRegistry

        reg = FabricRegistry()
        notify = _op("fabric.notify")
        thumb = _op("media.thumbnail", accepts=("image/jpeg",))
        monkeypatch.setattr(reg, "get_event", lambda _et: None)  # unknown event
        monkeypatch.setattr(reg, "list_operations", lambda: [notify, thumb])

        ids = {o.id for o in reg.compatible_targets("does.not.exist")}
        assert ids == {"fabric.notify"}  # artifact-requiring op is excluded


class _User:
    """Minimal CurrentUser stand-in for the endpoint function."""

    def __init__(self, org: uuid.UUID | None, perms: set[str]) -> None:
        self.organization_id = org
        self._perms = perms

    def has_permission(self, perm: str) -> bool:
        return perm in self._perms


class _Reg:
    def __init__(self, ops: list[Operation], ev: EventSpec | None) -> None:
        self._ops = ops
        self._ev = ev

    def get_event(self, _et: str) -> EventSpec | None:
        return self._ev

    def compatible_targets(self, _et: str, *, event: EventSpec | None = None) -> list[Operation]:
        return self._ops


class TestSuggestEndpoint:
    async def test_annotates_and_sorts(self, monkeypatch) -> None:
        import app.core.fabric.registry as reg_mod
        from app.api.v1.endpoints.fabric import suggest_targets

        store_blob = _op(
            "storage.store_blob",
            accepts=(MEDIA_BLOB,),
            write=True,
            permission="storage:write",
            feature="store_blob",
        )
        notify = _op("fabric.notify")  # permissionless native sink → always allowed
        x_read = _op("x.read", permission="x:read")  # caller lacks → not allowed
        plugin_op = Operation(id="plugin.acme.do", title="plugin", tier=OperationTier.PLUGIN)

        ev = EventSpec(event_type="cameras.event.motion", title="Motion", produces=("image/jpeg",))
        monkeypatch.setattr(
            reg_mod, "fabric_registry", _Reg([store_blob, notify, x_read, plugin_op], ev)
        )

        user = _User(ORG, {"storage:write"})
        res = await suggest_targets("cameras.event.motion", user)  # type: ignore[arg-type]

        by_id = {t["id"]: t for t in res["targets"]}
        assert by_id["storage.store_blob"]["match"] == "artifact"
        assert by_id["storage.store_blob"]["allowed"] is True
        assert by_id["fabric.notify"]["match"] == "data"
        assert by_id["fabric.notify"]["allowed"] is True  # permissionless native sink
        assert by_id["x.read"]["allowed"] is False  # caller lacks x:read
        assert by_id["plugin.acme.do"]["allowed"] is False  # plugin w/ no permission never wirable

        # Order: authorable + artifact first, then authorable data, then the rest.
        ids = [t["id"] for t in res["targets"]]
        assert ids[0] == "storage.store_blob"
        assert ids[1] == "fabric.notify"
        assert res["counts"] == {"total": 4, "allowed": 2}
        assert res["event"]["event_type"] == "cameras.event.motion"

    async def test_match_label_is_data_when_source_produces_no_artifact(
        self, monkeypatch
    ) -> None:
        # Endpoint match-labeling in isolation (registry compatibility filtering
        # is tested in TestCompatibleTargets): even if a blob-accepting op reaches
        # the labeler, a source that produces no artifact yields match="data" — no
        # blob to hand off, so the builder's paperclip hint isn't a false promise.
        import app.core.fabric.registry as reg_mod
        from app.api.v1.endpoints.fabric import suggest_targets

        store_blob = _op(
            "storage.store_blob",
            accepts=(MEDIA_BLOB,),
            write=True,
            permission="storage:write",
            feature="store_blob",
        )
        ev = EventSpec(event_type="ingest.external", title="Ingest")  # produces == ()
        monkeypatch.setattr(reg_mod, "fabric_registry", _Reg([store_blob], ev))

        res = await suggest_targets("ingest.external", _User(ORG, {"storage:write"}))  # type: ignore[arg-type]
        t = res["targets"][0]
        assert t["id"] == "storage.store_blob"
        assert t["match"] == "data"  # NOT "artifact" — the source produces no blob
        assert t["allowed"] is True

    async def test_requires_org(self, monkeypatch) -> None:
        from fastapi import HTTPException

        import app.core.fabric.registry as reg_mod
        from app.api.v1.endpoints.fabric import suggest_targets

        monkeypatch.setattr(reg_mod, "fabric_registry", _Reg([], None))
        with pytest.raises(HTTPException) as exc:
            await suggest_targets("any.event", _User(None, set()))  # type: ignore[arg-type]
        assert exc.value.status_code == 400


class TestSweepLifecycle:
    async def test_start_then_stop_cancels_task(self) -> None:
        from app.core.fabric import runtime

        await runtime.stop_fabric_runtime()  # clean slate
        runtime._start_artifact_sweep()
        assert runtime._sweep_task is not None and not runtime._sweep_task.done()
        # Idempotent: a second start does not spawn a duplicate.
        first = runtime._sweep_task
        runtime._start_artifact_sweep()
        assert runtime._sweep_task is first
        await runtime.stop_fabric_runtime()
        assert runtime._sweep_task is None

    async def test_stop_is_safe_with_no_task(self) -> None:
        from app.core.fabric import runtime

        runtime._sweep_task = None
        await runtime.stop_fabric_runtime()  # must not raise
        assert runtime._sweep_task is None
