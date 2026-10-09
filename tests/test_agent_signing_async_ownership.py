"""Worker/admission contracts with a controlled public-identity boundary.

The first 18 setup errors and original inputs remain preserved. This adaptation
preprovisions only synthetic owned keys, uses the current anchored worker hooks,
and does not test SQL identity selection, HTTP authorization or deployed keys.
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import importlib.util
import inspect
import json
import logging
import os
import sys
import threading
import types
from pathlib import Path

import anyio
import pytest
from fastapi import HTTPException
from test_agent_signing_identity import MANIFEST, PUBLIC_NAME, _verify


@pytest.fixture
def facade(tmp_path, monkeypatch):
    root = Path(os.environ["FREESDN_SIGNING_ASYNC_SOURCE_ROOT"])
    manifest = json.loads(Path(os.environ["FREESDN_SIGNING_ASYNC_SOURCE_MANIFEST"]).read_text())
    assert root.is_absolute()
    names = {
        "app.core.owned_async": "app/core/owned_async.py",
        "app.services.release_signing": "app/services/release_signing.py",
        "app.services.release_signing_async": "app/services/release_signing_async.py",
    }
    for path in names.values():
        assert hashlib.sha256((root / path).read_bytes()).hexdigest() == manifest[path]
    # Only namespace resolution is isolated. Each tested implementation and the
    # original ownership helper is loaded from its bound real source bytes.
    for name in ("app", "app.core", "app.services"):
        package = types.ModuleType(name)
        package.__path__ = [str(root / name.replace(".", "/"))]
        monkeypatch.setitem(sys.modules, name, package)
    # This component fixture controls the trust-record read only; application
    # qualification separately exercises the real PostgreSQL identity reader.
    identity = None

    async def controlled_identity():
        await anyio.lowlevel.checkpoint()
        assert identity is not None
        return identity

    boundary = types.ModuleType("app.services.agent_signing_identity")
    # This component deliberately controls the trust-record read. Export its
    # matching fixture type for the current return-annotation import too;
    # this is not a real SQL identity-validation boundary.
    boundary.TrustedSigningIdentity = types.SimpleNamespace
    boundary.read_trusted_signing_identity = controlled_identity
    monkeypatch.setitem(sys.modules, "app.services.agent_signing_identity", boundary)
    modules = {}
    for name, path in names.items():
        spec = importlib.util.spec_from_file_location(name, root / path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        setattr(sys.modules[name.rsplit(".", 1)[0]], name.rsplit(".", 1)[1], module)
        spec.loader.exec_module(module)
        modules[name] = module
    keys = tmp_path / "owned-key-directory"
    keys.mkdir(mode=0o700)
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(keys))
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(keys))
    signer = modules["app.services.release_signing"]
    public = signer.prepare_signing_identity(mode="initialize")
    identity = types.SimpleNamespace(
        public_key_pem=public, public_key_sha256=hashlib.sha256(public).hexdigest(),
    )
    yield modules["app.services.release_signing_async"], keys


def _storage_snapshot(keys):
    return {p.name: (p.stat().st_ino, p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in keys.iterdir()}


async def _entered(event):
    with anyio.fail_after(5):
        while not event.is_set():
            await asyncio.sleep(0.005)


async def _drain(task):
    return (await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 8))[0]


@pytest.mark.parametrize("failure", (False, True))
@pytest.mark.parametrize("cancellation", ("none", "task", "scope"))
async def test_worker_is_owned_through_completion_and_repeated_cancellation(
    facade, monkeypatch, caplog, record_property, failure, cancellation,
):
    service, keys = facade
    original = service.release_signing._load_or_generate
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    context = contextvars.ContextVar("signing_owned_context", default="absent")
    context.set("synthetic request context")
    observation = {}
    scopes = []

    def blocked(**kwargs):
        observation["worker_context_preserved"] = context.get() == "synthetic request context"
        observation["off_event_loop"] = threading.get_ident() != main_thread
        entered.set()
        try:
            if not release.wait(6):
                observation["escape_fired"] = True
                raise RuntimeError("owned wait escape")
            if failure:
                raise OSError("synthetic detail must not enter cancellation diagnostics")
            return original(**kwargs)
        finally:
            finished.set()

    main_thread = threading.get_ident()
    monkeypatch.setattr(service.release_signing, "_load_or_generate", blocked)

    async def owner():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            return await service.sign_manifest_async(dict(MANIFEST))

    task = asyncio.create_task(owner())
    with caplog.at_level(logging.WARNING, logger="app.core.owned_async"):
        try:
            await _entered(entered)
            if cancellation == "task":
                for _ in range(3):
                    task.cancel()
                    await asyncio.sleep(0.005)
            elif cancellation == "scope":
                scopes[0].cancel()
            await asyncio.sleep(0.01)
            observation["caller_waited_for_worker"] = not task.done() and not finished.is_set()
        finally:
            release.set()
            result = await _drain(task)
    observation["worker_finished"] = finished.is_set()
    observation["cancellation_log_redacted"] = "synthetic detail" not in caplog.text
    for name, value in observation.items():
        record_property(name, value)
    assert observation["off_event_loop"] and observation["worker_context_preserved"]
    assert observation["caller_waited_for_worker"] and observation["worker_finished"]
    assert not observation.get("escape_fired", False)
    assert observation["cancellation_log_redacted"]
    if cancellation == "task":
        assert isinstance(result, asyncio.CancelledError)
    elif cancellation == "scope":
        assert result is None
    elif failure:
        assert isinstance(result, OSError)
    else:
        _verify((keys / PUBLIC_NAME).read_bytes(), result)


@pytest.mark.parametrize("mode", ("task", "scope"))
async def test_already_cancelled_caller_never_allocates_signing_work(facade, monkeypatch, mode):
    service, keys = facade
    calls = []

    def forbidden(**kwargs):
        calls.append(True)
        raise AssertionError("worker must not start")

    monkeypatch.setattr(service.release_signing, "public_key_for_anchor", forbidden)
    before = _storage_snapshot(keys)

    async def owner():
        with anyio.CancelScope() as scope:
            if mode == "task":
                asyncio.current_task().cancel()
            else:
                scope.cancel()
            await service.public_key_pem_async()

    result = await _drain(asyncio.create_task(owner()))
    assert not calls and _storage_snapshot(keys) == before
    if mode == "task":
        assert isinstance(result, asyncio.CancelledError)


async def test_manifest_values_are_copied_before_worker_wait(facade, monkeypatch):
    service, keys = facade
    original = service.release_signing._load_or_generate
    entered, release = threading.Event(), threading.Event()

    def blocked(**kwargs):
        entered.set()
        if not release.wait(6):
            raise RuntimeError("owned wait escape")
        return original(**kwargs)

    monkeypatch.setattr(service.release_signing, "_load_or_generate", blocked)
    manifest = dict(MANIFEST)
    task = asyncio.create_task(service.sign_manifest_async(manifest))
    try:
        await _entered(entered)
        manifest["version"] = "a changed caller value"
        manifest["digest"] = "b" * 64
    finally:
        release.set()
        result = await _drain(task)
    _verify((keys / PUBLIC_NAME).read_bytes(), result)


@pytest.mark.parametrize("kind", ("missing", "nested", "oversized", "boolean_version", "wrong_version"))
async def test_invalid_worker_input_refuses_before_storage(facade, kind):
    service, keys = facade
    before = _storage_snapshot(keys)
    manifest = dict(MANIFEST)
    if kind == "missing":
        del manifest["digest"]
    elif kind == "nested":
        manifest["version"] = {"unexpected": "object"}
    elif kind == "oversized":
        manifest["version"] = "v" * 1025
    elif kind == "boolean_version":
        manifest["v"] = True
    else:
        manifest["v"] = 2
    with pytest.raises(ValueError):
        await service.sign_manifest_async(manifest)
    assert _storage_snapshot(keys) == before


async def test_public_capacity_does_not_take_administrative_worker_slots(facade, monkeypatch, record_property):
    service, keys = facade
    original = service.release_signing.public_key_for_anchor
    release, both = threading.Event(), threading.Event()
    context = contextvars.ContextVar("signing_capacity_role", default="admin")
    count = 0
    count_lock = threading.Lock()

    def blocked(**kwargs):
        nonlocal count
        if context.get() == "public":
            with count_lock:
                count += 1
                if count == 2:
                    both.set()
            if not release.wait(6):
                raise RuntimeError("owned wait escape")
        return original(**kwargs)

    monkeypatch.setattr(service.release_signing, "public_key_for_anchor", blocked)

    async def public_owner():
        token = context.set("public")
        try:
            return await service.public_key_pem_async(public_request=True)
        finally:
            context.reset(token)

    tasks = [asyncio.create_task(public_owner()) for _ in range(2)]
    admin = None
    try:
        await _entered(both)
        with pytest.raises(service.SigningBusyError):
            await public_owner()
        # This establishes pool admission isolation before filesystem lock
        # contention, not freedom from an actual key-store lock or disk stall.
        admin = asyncio.create_task(service.sign_manifest_async(dict(MANIFEST)))
        signature = await asyncio.wait_for(asyncio.shield(admin), 3)
        record_property("admin_completed_while_public_workers_waited", not any(t.done() for t in tasks))
        assert not any(t.done() for t in tasks)
        _verify((keys / PUBLIC_NAME).read_bytes(), signature)
    finally:
        release.set()
        outcomes = [await _drain(task) for task in tasks]
        if admin is not None:
            await _drain(admin)
    assert count == 2 and all(isinstance(v, bytes) for v in outcomes)


@pytest.mark.parametrize("cancel", (False, True))
async def test_administrative_operation_retains_continuation_and_cleanup(facade, cancel):
    service, _ = facade
    entered, release = asyncio.Event(), asyncio.Event()
    stages = []

    @service.agent_release_operation
    async def operation(value: str = "original") -> str:
        try:
            stages.append("entered")
            entered.set()
            await release.wait()
            stages.append("continuation")
            return value
        finally:
            stages.append("cleanup")

    assert inspect.signature(operation) == inspect.signature(operation.__wrapped__)
    task = asyncio.create_task(operation())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        if cancel:
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
        result = await _drain(task)
    assert stages == ["entered", "continuation", "cleanup"]
    if cancel:
        assert isinstance(result, asyncio.CancelledError)
    else:
        assert result == "original"


async def test_administrative_admission_refuses_before_handler_work(facade):
    service, _ = facade
    started = []
    both, release = asyncio.Event(), asyncio.Event()

    @service.agent_release_operation
    async def operation(label: int):
        started.append(label)
        if len(started) == 2:
            both.set()
        await release.wait()
        return label

    tasks = [asyncio.create_task(operation(n)) for n in range(2)]
    try:
        await asyncio.wait_for(both.wait(), 3)
        with pytest.raises(HTTPException) as caught:
            await operation(2)
        assert caught.value.status_code == 503
        assert caught.value.headers == {"Retry-After": "1"}
        assert started == [0, 1]
    finally:
        release.set()
        outcomes = [await _drain(task) for task in tasks]
    assert outcomes == [0, 1]
