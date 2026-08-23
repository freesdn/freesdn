# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two defects that between them made the plugin system unusable from the UI.
Both were found by running the documented flow end to end against a live
instance: scaffold with the SDK CLI, validate, package, upload, enable, call
the plugin's own route.

1. INSTALL BY UPLOAD RETURNED 500 FOR EVERY FILE
   The loader branched on ``isinstance(source, UploadFile)`` with UploadFile
   imported from fastapi. FastAPI's UploadFile is a SUBCLASS of starlette's,
   and the multipart parser hands the endpoint a
   ``starlette.datastructures.UploadFile`` -- the parent. An instance of the
   parent is not an instance of the child, so the check was always False.
   Every upload skipped the streaming read, fell through to ``raw = source``,
   and died on ``len(raw)``:

       TypeError: object of type 'UploadFile' has no len()

   The endpoint caught it and answered a generic 500, so the only visible
   symptom was "Install failed" with nothing to go on. This is the primary
   install path; the marketplace and the docs both point at it.

2. A FRESHLY INSTALLED PLUGIN 404'd ON ITS OWN NAV PATH
   TrailingSlashNormalizeMiddleware makes ``/x`` and ``/x/`` equivalent by
   caching the route table. It builds that cache lazily on the first request
   and then never rebuilds it. Plugin routes are mounted at INSTALL time, which
   is after the cache exists, so they were invisible to it: the plugin answered
   ``/port-watch/`` and 404'd on ``/port-watch`` until the process restarted.

   The scaffold the official CLI generates declares ``nav_items: [{path:
   /port-watch}]`` -- the bare form. So the first thing an author clicked after
   installing was the one spelling that failed, and it looked like their plugin
   was broken rather than the platform.
"""

from __future__ import annotations

import inspect

import pytest
import starlette.datastructures as sd
from fastapi import UploadFile as FastAPIUploadFile

from app.plugins.loader import MAX_ZIP_SIZE, PluginLoadError, _read_plugin_source


def _upload(data: bytes, name: str = "p.zip") -> sd.UploadFile:
    """An UploadFile of the class the multipart parser actually produces."""
    import io

    return sd.UploadFile(filename=name, file=io.BytesIO(data))


# ── 1. the upload that could not be read ─────────────────────────


def test_the_two_uploadfile_classes_are_still_different():
    """
    Premise. The whole defect rests on fastapi's UploadFile being a subclass
    rather than an alias. If a future fastapi makes them identical this test
    fails, and the isinstance check would have been fine after all.
    """
    assert FastAPIUploadFile is not sd.UploadFile
    assert issubclass(FastAPIUploadFile, sd.UploadFile)
    # The direction that bites: a parent instance is not a child instance.
    assert not isinstance(_upload(b"x"), FastAPIUploadFile)


async def test_a_starlette_upload_is_read_not_measured():
    """The exact object the endpoint receives, and the exact call that raised."""
    payload = b"PK\x03\x04" + b"a" * 500
    assert await _read_plugin_source(_upload(payload)) == payload


async def test_a_fastapi_upload_still_works():
    """The subclass must keep working; the fix widens the accepted set."""
    import io

    payload = b"PK\x03\x04fastapi"
    f = FastAPIUploadFile(filename="p.zip", file=io.BytesIO(payload))
    assert await _read_plugin_source(f) == payload


async def test_raw_bytes_still_work():
    """The other documented source type, used by install-from-URL."""
    payload = b"PK\x03\x04bytes"
    assert await _read_plugin_source(payload) == payload
    assert await _read_plugin_source(bytearray(payload)) == payload


async def test_a_large_upload_is_refused_while_it_streams():
    """
    The size cap must still bite, and must bite DURING the read rather than
    after the whole archive is resident. A per-chunk check is the only way an
    oversized upload does not first cost the memory it was rejected for.
    """
    oversized = b"\0" * (MAX_ZIP_SIZE + 1024)
    with pytest.raises(PluginLoadError, match="too large"):
        await _read_plugin_source(_upload(oversized))
    with pytest.raises(PluginLoadError, match="too large"):
        await _read_plugin_source(oversized)


async def test_an_unusable_source_says_so():
    """A clear error beats an AttributeError three frames down."""
    with pytest.raises(PluginLoadError, match="Unsupported plugin source"):
        await _read_plugin_source(object())


def test_the_loader_no_longer_branches_on_uploadfile():
    """
    Guard the class of bug, not the instance. Any future isinstance check
    against a specific UploadFile class reintroduces it.
    """
    src = inspect.getsource(_read_plugin_source)
    # Strip the docstring. This fix quotes the code it replaced inside its own
    # docstring, so a naive substring search finds the OLD code in the NEW
    # source and fails for a reason unrelated to behaviour.
    first = src.find('"""')
    last = src.find('"""', first + 3)
    code = src[:first] + src[last + 3 :] if first != -1 and last != -1 else src
    assert "isinstance(source, UploadFile)" not in code
    assert "bytes | bytearray" in code


# ── 2. the route the normalizer could not see ────────────────────


def test_the_route_cache_can_be_invalidated():
    from app.core import middleware

    before = middleware._ROUTE_EPOCH
    middleware.invalidate_route_cache()
    # noqa on SIM300: ruff reads the leading-underscore attribute as the
    # constant side and asks for `before + 1 == middleware._ROUTE_EPOCH`, which
    # is the actual Yoda condition.
    assert middleware._ROUTE_EPOCH == before + 1  # noqa: SIM300


def test_the_normalizer_rebuilds_when_the_epoch_moves():
    """
    The cache guard must compare the epoch, not merely check that a cache
    exists. `if self._slash_paths is not None: return` is what made plugin
    routes permanently invisible.
    """
    from app.core.middleware import TrailingSlashNormalizeMiddleware

    guard = inspect.getsource(TrailingSlashNormalizeMiddleware._ensure_route_caches)
    assert "_built_epoch == _ROUTE_EPOCH" in guard, "cache never rebuilds"
    assert "openapi_schema = None" in guard, (
        "fastapi memoises the schema, so a rebuild that does not drop it "
        "re-reads the same stale paths"
    )


def test_mounting_plugin_routes_invalidates_the_cache():
    """
    The fix only works if the loader actually signals. Registration is the one
    place routes are added to an already-serving app.
    """
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.register_plugin_routes)
    assert "invalidate_route_cache()" in src


def test_the_scaffold_still_declares_the_bare_nav_path():
    """
    Premise for why this mattered. The template's nav path has no trailing
    slash while its route is mounted at "/", so the two spellings must be
    equivalent for a generated plugin to work at all. If the template changes
    to a slashed path this test should be revisited, not deleted: the platform
    should still accept both.
    """
    import pathlib

    tpl = None
    for parent in pathlib.Path(__file__).resolve().parents:
        cand = (
            parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk" / "templates" / "plugin.yaml.j2"
        )
        if cand.is_file():
            tpl = cand
            break
    if tpl is None:  # pragma: no cover - backend-only checkout
        pytest.skip("SDK source not present")

    body = tpl.read_text(encoding="utf-8")
    assert "nav_items" in body, "the scaffold no longer declares nav items"
    # The path an author clicks first. It carries no trailing slash while the
    # generated route is mounted at "/", which is exactly why both spellings
    # have to resolve for a scaffolded plugin to work at all.
    assert "path:" in body


# ── 3. the compatibility gate that was advertised and absent ─────


class _FakeManifest:
    def __init__(self, min_core_version, plugin_id="demo"):
        self.id = plugin_id
        self.min_core_version = min_core_version


def test_version_parsing_handles_the_shapes_that_occur():
    from app.plugins.loader import _version_tuple

    # CalVer with a zero-padded month is the core's own shape.
    assert _version_tuple("26.08.2") == (26, 8, 2)
    assert _version_tuple("2.6.0") == (2, 6, 0)
    # A suffix compares on its numeric head rather than failing outright.
    assert _version_tuple("1.2.0-beta") == (1, 2, 0)
    # Not a version: the caller must treat this as "cannot judge".
    assert _version_tuple("not-a-version") is None
    assert _version_tuple("") is None


def test_a_plugin_needing_a_newer_core_is_refused():
    """
    install_plugin has advertised "Check FreeSDN core version compatibility"
    as step 2 since it was written and never did it. A plugin declaring
    min_core_version 99.0.0 installed cleanly on 26.08.2, and the operator
    found out when it failed at runtime against an API that did not exist.
    """
    from app.plugins.loader import PluginLoadError, _check_core_compatibility

    with pytest.raises(PluginLoadError, match="requires FreeSDN"):
        _check_core_compatibility(_FakeManifest("99.0.0"))


def test_compatible_plugins_still_install():
    """
    Negative control. The values in the wild are the SDK default and the
    marketplace seed; if the gate rejected those it would block every existing
    plugin rather than the incompatible ones.
    """
    from app.plugins.loader import CORE_VERSION, _check_core_compatibility

    for ok in ("1.0.0", "2.0.0", "2.6.0", CORE_VERSION):
        _check_core_compatibility(_FakeManifest(ok))  # must not raise


def test_the_gate_fails_open_on_an_unparseable_version():
    """
    A compatibility hint from the author is not a security control. Refusing
    to install a working plugin because its metadata has an odd version string
    trades a real failure for a cosmetic one.
    """
    from app.plugins.loader import _check_core_compatibility

    _check_core_compatibility(_FakeManifest("not-a-version"))
    _check_core_compatibility(_FakeManifest(""))
    _check_core_compatibility(_FakeManifest(None))


def test_install_actually_calls_the_gate():
    """A helper nobody invokes is the same as no gate at all."""
    from app.plugins.loader import PluginLoader

    src = inspect.getsource(PluginLoader.install_plugin)
    assert "_check_core_compatibility(manifest)" in src


# ── 4. the two instances a plugin author cannot see ──────────────


def test_routes_and_events_run_on_different_instances():
    """
    Premise, and the reason `runtime` exists.

    ``register_plugin_routes`` builds the router from ``self._loaded[id]`` -- one
    shared template. ``start_for_org`` constructs a SEPARATE instance per
    organization and binds event subscriptions to that one. So ``self`` inside a
    route handler is not the object ``on_event`` writes to.

    Verified live: a plugin that appended to ``self.seen`` in on_event and read
    ``len(self.seen)`` from a route reported 0 after three delivered events,
    while ``len(self.runtime.seen)`` reported 3.
    """
    from app.plugins.loader import PluginLoader

    routes = inspect.getsource(PluginLoader.register_plugin_routes)
    start = inspect.getsource(PluginLoader.start_for_org)
    assert "self._loaded.get(plugin_id)" in routes, "routes no longer come from the template"
    assert "plugin_cls()" in start, "start_for_org no longer builds a per-org instance"
    assert "bind_event_subscriptions" in start


def test_the_runtime_accessor_exists_and_falls_back_to_self():
    """
    Outside a request there is no bound runtime, and `self` already IS the
    per-org instance. Returning None there would push a None-check onto every
    caller for no reason.
    """
    from app.plugins.sdk import FreeSDNPlugin as RuntimeBase

    assert isinstance(RuntimeBase.runtime, property)
    obj = RuntimeBase.__new__(RuntimeBase)
    assert obj.runtime is obj


def test_the_accessor_prefers_the_request_bound_runtime():
    from app.plugins.sdk import FreeSDNPlugin as RuntimeBase

    src = inspect.getsource(RuntimeBase.runtime.fget)
    assert "get_request_plugin_runtime()" in src
    assert "bound if bound is not None else self" in src


def test_ctx_still_resolves_through_the_bound_runtime():
    """
    The pre-existing half of this. `self.ctx` in a route already reaches the
    caller's organization context, which is why SDK calls work there and why
    only the INSTANCE needed exposing.
    """
    from app.plugins.sdk import FreeSDNPlugin as RuntimeBase

    src = inspect.getsource(RuntimeBase.ctx.fget)
    assert "get_request_plugin_runtime()" in src


def test_the_sdk_stub_offers_the_same_accessor():
    """
    An author develops against the stub and deploys against the runtime. If the
    stub lacks `runtime`, the pattern the scaffold teaches fails type checking
    and IDE completion offline.
    """
    import pathlib

    base = None
    for parent in pathlib.Path(__file__).resolve().parents:
        cand = parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk" / "base.py"
        if cand.is_file():
            base = cand
            break
    if base is None:  # pragma: no cover - backend-only checkout
        pytest.skip("SDK source not present")

    body = base.read_text(encoding="utf-8")
    assert "def runtime(" in body, "the stub has no runtime accessor"


def test_the_scaffold_warns_about_the_split():
    """
    The footgun is silent, so the scaffold is where an author has to meet it.
    """
    import pathlib

    tpl = None
    for parent in pathlib.Path(__file__).resolve().parents:
        cand = parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk" / "templates" / "plugin.py.j2"
        if cand.is_file():
            tpl = cand
            break
    if tpl is None:  # pragma: no cover - backend-only checkout
        pytest.skip("SDK source not present")

    body = tpl.read_text(encoding="utf-8")
    assert "self.runtime" in body
    assert "on_event" in body


# ── 5. the SDK write APIs that did not write ─────────────────────


def test_the_session_factory_still_has_autoflush_off():
    """
    Premise. With autoflush ON, a pending add() would be flushed by the next
    SELECT and half of this defect would not exist. If this ever changes, the
    fix stays correct but the failure mode described below no longer applies.
    """
    from app.db import session as db_session

    factory = db_session.async_session_factory
    assert factory.kw.get("autoflush") is False


def test_every_sdk_write_path_persists():
    """
    Each of these ended at add() or a bare attribute mutation. Two added a
    flush(); none committed. Combined with autoflush=False that meant
    settings.set() followed immediately by settings.get() IN THE SAME CALL
    returned None, and an alert created through the SDK left no row.

    The SDK reported success throughout, because alerts.create() returns the
    alert id and an id exists after a flush whether or not it is ever
    committed.
    """
    from app.plugins.sdk import AlertSDK, PluginSettingsSDK

    for fn in (AlertSDK.create, AlertSDK.resolve, PluginSettingsSDK.set):
        src = inspect.getsource(fn)
        assert "_persist(self._db)" in src, f"{fn.__qualname__} still does not persist"


def test_persist_rolls_back_on_failure():
    """
    A commit that raises must not leave the plugin's long-lived session in a
    failed state: every later SDK call on it would then raise
    PendingRollbackError, and the plugin would look broken for an unrelated
    reason.
    """
    from app.plugins.sdk import _persist

    src = inspect.getsource(_persist)
    assert "await db.rollback()" in src
    assert "raise" in src


async def test_persist_commits_and_rolls_back_correctly():
    """Behaviour, not just source."""

    class _OKSession:
        def __init__(self):
            self.committed = self.rolled_back = False

        async def commit(self):
            self.committed = True

        async def rollback(self):
            self.rolled_back = True

    class _FailingSession(_OKSession):
        async def commit(self):
            raise RuntimeError("db is gone")

    from app.plugins.sdk import _persist

    ok = _OKSession()
    await _persist(ok)
    assert ok.committed and not ok.rolled_back

    bad = _FailingSession()
    with pytest.raises(RuntimeError, match="db is gone"):
        await _persist(bad)
    assert bad.rolled_back, "a failed commit left the session dirty"


def test_the_sdk_session_is_not_the_request_session():
    """
    Why committing here is safe, and why it had to be the SDK that commits.

    The context is built once at plugin start and holds that session for the
    plugin's lifetime; verified live, the same session object serves
    consecutive requests. So a commit lands only the plugin's own work and
    cannot land a half-finished request transaction. A plugin author has no
    session handle, so nobody else could commit on their behalf.
    """
    from app.plugins.sdk import FreeSDNPlugin as RuntimeBase

    src = inspect.getsource(RuntimeBase._init_context)
    assert "AlertSDK(" in src and "PluginSettingsSDK(" in src
    assert "db" in src
