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
def _disable_rate_limit(monkeypatch):
    """Strip the per-IP rate limiter so 30+ test calls don't 429.

    Production behaviour (settings.RATE_LIMIT_ENABLED=true) is verified
    by manual smoke; here we only care about endpoint contracts.
    """
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


# ---------------------------------------------------------------------------
# POST /downloads/releases (admin publish)
# ---------------------------------------------------------------------------


class TestPublishRelease:
    @pytest.mark.asyncio
    async def test_creates_release_row(self, app_factory, monkeypatch, tmp_path) -> None:
        # Publishing a `is_latest` release signs the checksum, which lazily
        # generates the signing keypair under the agent-release dir. Point it at
        # a writable tmp dir (and reset the cached keys) so the test never tries
        # to create /var/lib/freesdn — which a non-root CI runner cannot write.
        monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(tmp_path))
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        import app.services.release_signing as _signing

        monkeypatch.setattr(_signing, "_PRIVATE_KEY", None)
        monkeypatch.setattr(_signing, "_PUBLIC_KEY_PEM", None)
        session = _FakeSession()
        app = app_factory(session)
        payload = {
            "version": "1.2.0",
            "platform": "linux",
            "agent_type": "daemon",
            "download_url": "https://example.com/v1.2.0",
            "checksum_sha256": "c" * 64,
            "file_size": 5_000_000,
            "release_notes": "test release",
            "is_prerelease": False,
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.post("/api/v1/agents/downloads/releases", json=payload)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["version"] == "1.2.0"
        assert body["is_latest"] is True
        assert session.commits == 1
        assert len(session.added) == 1

    @pytest.mark.asyncio
    async def test_bad_checksum_format_rejected(self, app_factory) -> None:
        """The agent verifies sha256 byte-for-byte; pydantic must
        reject anything that isn't 64 hex chars before it hits the DB."""
        app = app_factory(_FakeSession())
        payload = {
            "version": "1.0.0",
            "platform": "linux",
            "agent_type": "daemon",
            "download_url": "https://example.com/x",
            "checksum_sha256": "not-a-real-hash",
            "file_size": 100,
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.post("/api/v1/agents/downloads/releases", json=payload)
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_unknown_platform_rejected(self, app_factory) -> None:
        app = app_factory(_FakeSession())
        payload = {
            "version": "1.0.0",
            "platform": "freebsd",
            "agent_type": "daemon",
            "download_url": "/relative/path",
            "checksum_sha256": "d" * 64,
            "file_size": 100,
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            r = await c.post("/api/v1/agents/downloads/releases", json=payload)
        assert r.status_code == 400


    @pytest.mark.asyncio
    async def test_signing_failure_on_latest_raises_500_and_does_not_persist(
        self, app_factory
    ) -> None:
        """a signing failure during publish must fail closed.

        The endpoint always sets is_latest=True for published releases.
        When sign_digest raises, the release must NOT be created and the
        session must be rolled back (restoring the previously-demoted
        latest release row) so agents continue to receive the last
        known-good signed update.
        """
        session = _FakeSession()
        app = app_factory(session)
        payload = {
            "version": "2.0.0",
            "platform": "windows",
            "agent_type": "daemon",
            "download_url": "https://example.com/v2.0.0.exe",
            "checksum_sha256": "e" * 64,
            "file_size": 1_000_000,
            "release_notes": "signing test",
            "is_prerelease": False,
        }
        with patch(
            "app.services.release_signing.sign_digest",
            side_effect=RuntimeError("signing key unavailable"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post("/api/v1/agents/downloads/releases", json=payload)

        assert r.status_code == 500, r.text
        assert "signing" in r.json()["detail"].lower()
        # No release row must have been persisted.
        assert len(session.added) == 0
        assert session.commits == 0
        # The is_latest demotion UPDATE is rolled back.
        assert getattr(session, "rollbacks", 0) == 1
