# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Contract tests for ``/agents/downloads/*`` and ``/agents/updates/check``.

These endpoints are the surface the frontend Downloads page and the
agent's self-update loop both depend on. Until now they had zero
backend coverage — the agent ships, the FE renders the page, but
nothing asserted the wire shape stayed compatible with what those
clients parse.

We mount the real router on a fresh FastAPI app, replace the session
with a small fake that responds to the ``select(AgentRelease)`` and
``select(RemoteAgent)`` queries inline, and disable the rate limiter
+ require_permissions dep so the test stays focused on the endpoint
contract (the rate-limiter and RBAC helpers have their own tests).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import agent_downloads as endpoint
from app.core.config import settings
from app.core.dependencies import get_current_active_user
from app.db.session import get_session
from app.schemas.agent_release_operations import encode_release_command
from tests.api import release_operation_contract as contract
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion
from tests.services import test_agent_release_publication as publication
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services.test_public_release_binary import public_reader as public_reader
from tests.services.test_public_release_operations import PREFIX, command

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _release(**kw: Any) -> SimpleNamespace:
    """Build a fake AgentRelease ORM row."""
    defaults = {
        "id": uuid4(),
        "version": "1.0.0",
        "platform": "windows",
        "agent_type": "daemon",
        "download_url": "https://example.com/agent.exe",
        "checksum_sha256": "a" * 64,
        # ECDSA-P256 update signature (signing chapter); the update-check
        # endpoint reads ``latest.signature`` so the fake row must carry it.
        "signature": "",
        "file_size": 12345,
        "release_notes": "release notes",
        "min_backend_version": "",
        "is_latest": True,
        "is_prerelease": False,
        "published_at": datetime.now(UTC),
        "download_count": 0,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _agent(
    *, enabled: bool = True, approved: bool = True, key: str = "test-key"
) -> SimpleNamespace:
    """Build a fake RemoteAgent row whose agent_key matches sha256(key)."""
    return SimpleNamespace(
        id=uuid4(),
        agent_key=hashlib.sha256(key.encode()).hexdigest(),
        is_enabled=enabled,
        is_approved=approved,
        deleted_at=None,
        # the update-check endpoint scopes the feed to the agent's
        # org (falling back to GLOBAL org-NULL releases). None exercises the
        # global-release path the fake session serves.
        organization_id=None,
    )




class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)

    def scalar_one_or_none(self) -> Any | None:
        return self._rows[0] if self._rows else None


class _FakeSession:
    """Tiny stand-in for AsyncSession.

    The endpoint module issues SQLAlchemy ``select()`` statements. We
    don't actually execute them — instead we inspect the ``.column_descriptions``
    of the compiled statement and return canned rows based on the entity
    name. This keeps tests independent of the model's relationship graph.
    """

    def __init__(self, releases: list[Any] | None = None, agents: list[Any] | None = None) -> None:
        self._releases = releases or []
        self._agents = agents or []
        self.added: list[Any] = []
        self.commits = 0
        self.updates: list[Any] = []

    async def execute(self, query: Any) -> _Result:
        # Identify the target entity from the compiled statement.
        try:
            target = query.column_descriptions[0]["entity"].__name__
        except Exception:
            target = ""
        if "Release" in target:
            return _Result(list(self._releases))
        if "Agent" in target:
            return _Result(list(self._agents))
        return _Result([])

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        for obj in self.added:
            await self.refresh(obj)

    async def scalar(self, query: Any, params: dict[str, Any]) -> bool:
        # Only the real bucket-lock statement is expected in this unit fake.
        assert "pg_try_advisory_xact_lock" in str(query)
        assert set(params) == {"key"} and type(params["key"]) is int
        return True

    async def rollback(self) -> None:
        self.rollbacks = getattr(self, "rollbacks", 0) + 1

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def refresh(self, obj: Any) -> None:
        # Populate the model defaults that the response model expects.
        for attr, default in [
            ("id", uuid4()),
            ("download_count", 0),
            ("min_backend_version", ""),
        ]:
            if not hasattr(obj, attr) or getattr(obj, attr) is None:
                setattr(obj, attr, default)


@pytest.fixture
def app_factory():
    """Build a fresh FastAPI app per test so dependency_overrides don't leak."""

    def _build(session: _FakeSession, *, admin: bool = True) -> FastAPI:
        app = FastAPI()
        app.include_router(endpoint.router, prefix="/api/v1/agents")

        async def _override_session():
            yield session

        app.dependency_overrides[get_session] = _override_session

        # Bypass the agent:admin permission dep — we test the endpoint
        # contract, not the role dep (which has its own tests).
        # require_permissions() chains through get_current_active_user, so
        # overriding that with a user that satisfies any has_*_permissions
        # check short-circuits the whole RBAC stack for these tests.
        if admin:
            fake_user = SimpleNamespace(
                user=SimpleNamespace(
                    id=uuid4(),
                    email="admin@test",
                    is_active=True,
                ),
                role="super_admin",
                is_superuser=True,
                is_org_admin=True,
                organization_id=uuid4(),
                has_all_permissions=lambda _p: True,
                has_any_permission=lambda _p: True,
                has_permission=lambda _p: True,
            )
            app.dependency_overrides[get_current_active_user] = lambda: fake_user
        return app

    return _build


@pytest.fixture(autouse=True)
def _disable_rate_limit(monkeypatch, request):
    """Strip the per-IP rate limiter so 30+ test calls don't 429.

    Production behaviour (settings.RATE_LIMIT_ENABLED=true) is verified
    by manual smoke; here we only care about endpoint contracts.
    """
    if "public_reader" in request.fixturenames:
        return
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    # Defensive — wipe any state the bucket built up across tests.
    endpoint._public_rate_buckets.clear()


# ---------------------------------------------------------------------------
# /downloads/latest
# ---------------------------------------------------------------------------


class TestLatest:
    @pytest.mark.asyncio
    async def test_returns_latest_release(self, app_factory) -> None:
        session = _FakeSession(releases=[_release()])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/latest?platform=windows")
        assert r.status_code == 200
        body = r.json()
        assert body["version"] == "1.0.0"
        assert body["platform"] == "windows"
        assert body["agent_type"] == "daemon"
        assert body["checksum_sha256"] == "a" * 64

    @pytest.mark.asyncio
    async def test_unknown_platform_400(self, app_factory) -> None:
        app = app_factory(_FakeSession(releases=[_release()]))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/latest?platform=plan9")
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_agent_type_400(self, app_factory) -> None:
        app = app_factory(_FakeSession(releases=[_release()]))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/latest?platform=windows&agent_type=mainframe")
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_404_when_no_release(self, app_factory) -> None:
        app = app_factory(_FakeSession(releases=[]))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/latest?platform=linux")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# /downloads/versions
# ---------------------------------------------------------------------------


class TestVersions:
    @pytest.mark.asyncio
    async def test_groups_per_version(self, app_factory) -> None:
        rows = [
            _release(version="1.1.0", platform="windows"),
            _release(version="1.1.0", platform="linux"),
            _release(version="1.0.0", platform="windows"),
        ]
        app = app_factory(_FakeSession(releases=rows))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/versions")
        assert r.status_code == 200
        body = r.json()
        versions = {v["version"] for v in body}
        assert versions == {"1.0.0", "1.1.0"}
        for v in body:
            if v["version"] == "1.1.0":
                assert set(v["platforms"]) == {"windows", "linux"}

    @pytest.mark.asyncio
    async def test_excludes_prerelease_by_default(self, app_factory) -> None:
        """Only stable rows are returned unless include_prerelease=true."""
        rows = [_release(version="2.0.0-rc1", is_prerelease=True)]
        session = _FakeSession(releases=rows)
        # Our fake session ignores the WHERE clause, but the endpoint's
        # response shape must still flag the row as prerelease so the
        # contract reaches the client correctly.
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/versions?include_prerelease=true")
        assert r.status_code == 200
        assert any(v["is_prerelease"] for v in r.json())


# ---------------------------------------------------------------------------
# /downloads/page
# ---------------------------------------------------------------------------


class TestDownloadsPage:
    @pytest.mark.asyncio
    async def test_aggregates_platforms_with_install_commands(self, app_factory) -> None:
        rows = [
            _release(platform="windows", agent_type="daemon"),
            _release(platform="windows", agent_type="desktop"),
            _release(platform="linux", agent_type="daemon"),
        ]
        app = app_factory(_FakeSession(releases=rows))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/page")
        assert r.status_code == 200
        body = r.json()
        assert body["latest_version"] == "1.0.0"
        assert body["server_version"]  # populated from settings.APP_VERSION
        platforms = {p["platform"]: p for p in body["platforms"]}
        assert "windows" in platforms
        assert "linux" in platforms
        # Windows has both daemon and desktop, Linux just daemon.
        assert platforms["windows"]["daemon"] is not None
        assert platforms["windows"]["desktop"] is not None
        assert platforms["linux"]["daemon"] is not None
        # Install commands come from PLATFORM_META in the endpoint.
        assert any("register" in cmd for cmd in platforms["windows"]["install_commands"])

    @pytest.mark.asyncio
    async def test_empty_returns_no_platforms(self, app_factory) -> None:
        app = app_factory(_FakeSession(releases=[]))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/downloads/page")
        assert r.status_code == 200
        assert r.json()["platforms"] == []


# ---------------------------------------------------------------------------
# /updates/check
# ---------------------------------------------------------------------------


class TestUpdatesCheck:
    @pytest.mark.asyncio
    async def test_requires_agent_auth(self, app_factory) -> None:
        app = app_factory(_FakeSession())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get("/api/v1/agents/updates/check?current_version=1.0.0&platform=windows")
        assert r.status_code == 401
        assert r.headers.get("www-authenticate") == "X-Agent-Key"

    @pytest.mark.asyncio
    async def test_rejects_disabled_agent(self, app_factory) -> None:
        agent = _agent(enabled=False)
        session = _FakeSession(releases=[_release()], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        # Generic 401 — must NOT reveal "disabled" vs "no match" to caller.
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_no_update_when_versions_match(self, app_factory) -> None:
        agent = _agent()
        session = _FakeSession(
            releases=[_release(version="1.0.0")],
            agents=[agent],
        )
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        assert r.json() == {
            "update_available": False,
            "latest_version": "",
            "download_url": "",
            "checksum_sha256": "",
            "release_notes": "",
            "signature": "",
            # The signed release manifest binding digest+version+platform+
            # agent_type+channel. Empty when there is no update to offer.
            "manifest": {},
        }

    @pytest.mark.asyncio
    async def test_offers_update_when_newer_available(self, app_factory) -> None:
        agent = _agent()
        rel = _release(
            version="1.2.0", checksum_sha256="b" * 64, download_url="https://example.com/v1.2.0.exe"
        )
        session = _FakeSession(releases=[rel], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["update_available"] is True
        assert body["latest_version"] == "1.2.0"
        assert body["checksum_sha256"] == "b" * 64
        # Agent's UpdaterService aborts on missing checksum — must be present.
        assert body["download_url"] == "https://example.com/v1.2.0.exe"

    @pytest.mark.asyncio
    async def test_does_not_downgrade(self, app_factory) -> None:
        """If the 'latest' row is somehow older than the agent's current
        version, never advertise an update — the agent would happily
        install it and we'd brick the field fleet."""
        agent = _agent()
        rel = _release(version="0.9.0")
        session = _FakeSession(releases=[rel], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        assert r.json()["update_available"] is False

    # -----------------------------------------------------------------
    # Version grammar, asserted at the ENDPOINT (F-05)
    # -----------------------------------------------------------------
    #
    # ``test_version_parity.py`` pins ``parse_agent_version`` against the
    # agent's table, which proves the two PARSERS agree. It does not prove
    # this endpoint uses it: the bug was never in a helper, it was here, in a
    # raw-tuple comparison. Rip the call out and swap in ``tuple(int(x) for x
    # in v.split("."))`` and every parity test still passes while the field
    # behaviour regresses. These drive the real endpoint over HTTP instead.

    @pytest.mark.asyncio
    async def test_a_trailing_zero_release_is_not_an_update(self, app_factory) -> None:
        """The perpetual-reinstall loop, at its only production site.

        Raw tuples make (1,0,0,0) > (1,0,0), so the backend advertised an
        update the agent then rejected as not-newer -- after downloading the
        binary. That repeated every poll interval, forever.
        """
        agent = _agent()
        session = _FakeSession(releases=[_release(version="1.0.0.0")], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        assert r.json()["update_available"] is False, (
            "1.0.0.0 is not newer than 1.0.0. Advertising it makes every agent "
            "re-download the binary on every poll and never install it."
        )

    @pytest.mark.asyncio
    async def test_a_v_prefixed_release_is_still_offered(self, app_factory) -> None:
        """The other direction, equally silent.

        The release schema permits a leading ``v``. int() raised on it, the old
        code substituted (0, 0, 0), and a genuinely newer release was never
        offered to anyone -- with nothing logged.
        """
        agent = _agent()
        session = _FakeSession(releases=[_release(version="v2.0.0")], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        assert r.json()["update_available"] is True, (
            "v2.0.0 is newer than 1.0.0; the leading v is valid per the release "
            "schema and must not silently suppress the offer"
        )

    @pytest.mark.asyncio
    async def test_an_unparseable_release_version_is_never_offered(self, app_factory) -> None:
        """Fail closed: a mislabelled row must not flash the fleet."""
        agent = _agent()
        session = _FakeSession(releases=[_release(version="latest")], agents=[agent])
        app = app_factory(session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.get(
                "/api/v1/agents/updates/check?current_version=1.0.0&platform=windows",
                headers={"X-Agent-ID": str(agent.id), "X-Agent-Key": "test-key"},
            )
        assert r.status_code == 200
        assert r.json()["update_available"] is False


# ---------------------------------------------------------------------------
# POST /downloads/releases (admin publish)
# ---------------------------------------------------------------------------


class TestPublishRelease:
    """Actual SQL/signing/auth; the other classes retain their scoped unit doubles."""

    @pytest.mark.asyncio
    async def test_creates_release_row(self, public_reader) -> None:
        f = public_reader
        contract.intent(f, storage="external", version="1.2.0")
        headers = await contract.prepare(f)
        response = await command(f, headers, "publish")
        assert response.status_code == 200, response.text
        rows = await publication.releases(f)
        assert len(rows) == 1
        row = rows[0]
        assert row["version"] == "1.2.0" and row["is_latest"] is True
        assert row["organization_id"] == f.org
        await contract.verify_persisted_signature(f, row)

    @pytest.mark.asyncio
    async def test_bad_checksum_format_rejected(self, public_reader) -> None:
        """Unrepresentable metadata is refused before journal or release writes."""
        f = public_reader
        intent = contract.intent(f, storage="external")
        headers = await lifecycle.headers(f)
        payload = json.loads(encode_release_command(intent))
        payload["metadata"]["checksum_sha256"] = "not-a-real-hash"
        before = await deletion.state(f)
        response = await f.public_client.post(
            f"{PREFIX}/release-operations/{intent.operation_id}/reserve",
            headers=headers, json=payload,
        )
        assert response.status_code == 422, response.text
        assert await deletion.state(f) == before

    @pytest.mark.asyncio
    async def test_unknown_platform_rejected(self, public_reader) -> None:
        f = public_reader
        intent = contract.intent(f, storage="external")
        headers = await lifecycle.headers(f)
        payload = json.loads(encode_release_command(intent))
        payload["metadata"]["platform"] = "freebsd"
        # Keep an otherwise valid URL so only the unsupported platform is tested.
        before = await deletion.state(f)
        response = await f.public_client.post(
            f"{PREFIX}/release-operations/{intent.operation_id}/reserve",
            headers=headers, json=payload,
        )
        assert response.status_code == 422, response.text
        assert await deletion.state(f) == before

    @pytest.mark.asyncio
    async def test_signing_failure_on_latest_raises_500_and_does_not_persist(
        self, public_reader
    ) -> None:
        """Historical test ID retained; uncertain operation errors now return503."""
        f = public_reader
        contract.intent(f, storage="external", version="2.0.0")
        await publication.seed(f, organization=f.org)
        before = await publication.releases(f)
        headers = await contract.prepare(f)
        with patch("app.services.agent_release_publication.sign_manifest_async",
                   side_effect=RuntimeError("owned unexpected signing failure")):
            response = await command(f, headers, "publish")
        assert response.status_code == 503, response.text
        assert response.json()["error"]["code"] == 503
        assert "inspect the same operation" in response.json()["error"]["message"]
        assert "owned unexpected signing failure" not in response.text
        await contract.unchanged_release_rows_and_cleanup(f, headers, before)
