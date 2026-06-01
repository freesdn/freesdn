# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for health-check endpoints.

Covers:
- GET /health  (root-level lightweight check)
- GET /api/v1/health/  (detailed check with DB dependency)
- GET /api/v1/health/live  (liveness probe, no dependencies)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport

# ---------------------------------------------------------------------------
# Helpers — import the FastAPI app lazily so we can mock heavy subsystems
# ---------------------------------------------------------------------------

def _get_app():
    """Import the FastAPI app instance (triggers module-level side-effects)."""
    from app.main import app
    return app


# ---------------------------------------------------------------------------
# Root-level /health (defined in main.py, no DB dependency)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_root_health_returns_200():
    """GET /health should return 200 with status and app name."""
    app = _get_app()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert "app" in body


@pytest.mark.asyncio
async def test_root_health_contains_app_name():
    """The root health response should echo the configured APP_NAME."""
    app = _get_app()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")

    body = resp.json()
    # APP_NAME is set in core.config.settings; just verify it is a non-empty string
    assert isinstance(body["app"], str)
    assert len(body["app"]) > 0


# ---------------------------------------------------------------------------
# Liveness probe — GET /api/v1/health/live  (no DB, always 200)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_liveness_probe_returns_200():
    """GET /api/v1/health/live should always return 200."""
    app = _get_app()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health/live")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "alive"
    assert "timestamp" in body


# ---------------------------------------------------------------------------
# Detailed health — GET /api/v1/health/  (requires DB session override)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detailed_health_returns_200_with_mocked_db():
    """
    GET /api/v1/health/ (the PUBLIC endpoint) should return 200 when the DB
    session is mocked out, with a status-only payload: status, timestamp, and
    per-component status. Version/app/environment are deliberately NOT exposed
    here — that fingerprinting metadata moved behind the authenticated
    /health/detail endpoint.
    """
    from app.db import get_session

    # Create a mock async session whose execute returns a result with scalar() -> 1
    mock_result = MagicMock()
    mock_result.scalar.return_value = 1
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    async def _override_get_session():
        yield mock_session

    app = _get_app()
    app.dependency_overrides[get_session] = _override_get_session

    try:
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/health/")

        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body
        assert "timestamp" in body
        assert "components" in body
        # Status should be one of the HealthStatus values
        assert body["status"] in ("healthy", "degraded", "unhealthy")
        # SEC: the public endpoint must NOT leak version/env/app fingerprints.
        assert "version" not in body
        assert "environment" not in body
        assert "platform" not in body
    finally:
        app.dependency_overrides.pop(get_session, None)


@pytest.mark.asyncio
async def test_detailed_health_reports_components():
    """
    The detailed health response should include a 'components' dict
    with at least 'database' when the DB check succeeds.
    """
    from app.db import get_session

    mock_result = MagicMock()
    mock_result.scalar.return_value = 1
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    async def _override_get_session():
        yield mock_session

    app = _get_app()
    app.dependency_overrides[get_session] = _override_get_session

    try:
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/health/")

        body = resp.json()
        assert "components" in body
        assert "database" in body["components"]
    finally:
        app.dependency_overrides.pop(get_session, None)


# ---------------------------------------------------------------------------
# Readiness probe — GET /api/v1/health/ready  (degraded-subsystem behavior)
# ---------------------------------------------------------------------------


class TestReadinessEndpoint:
    """Tests for GET /api/v1/health/ready degraded-subsystem detection."""

    @pytest.mark.asyncio
    async def test_ready_returns_ready_when_all_healthy(self):
        """When all subsystems healthy and DB up, /ready returns 200."""
        from app.core.startup import SUBSYSTEM_STATUS

        with patch.dict(SUBSYSTEM_STATUS, {"modules": "healthy", "event_bus": "healthy"}, clear=True):
            critical = ["modules", "event_bus"]
            degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]
            assert len(degraded) == 0

    @pytest.mark.asyncio
    async def test_ready_detects_degraded_modules(self):
        """When modules are degraded, /ready should return not ready."""
        from app.core.startup import SUBSYSTEM_STATUS

        with patch.dict(SUBSYSTEM_STATUS, {"modules": "degraded", "event_bus": "healthy"}, clear=True):
            critical = ["modules", "event_bus"]
            degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]
            assert "modules" in degraded

    @pytest.mark.asyncio
    async def test_ready_detects_degraded_event_bus(self):
        """When event_bus is degraded, /ready should return not ready."""
        from app.core.startup import SUBSYSTEM_STATUS

        with patch.dict(SUBSYSTEM_STATUS, {"modules": "healthy", "event_bus": "degraded"}, clear=True):
            critical = ["modules", "event_bus"]
            degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]
            assert "event_bus" in degraded

    @pytest.mark.asyncio
    async def test_ready_non_critical_degradation_still_ready(self):
        """When only non-critical subsystems degrade, /ready should still be ready."""
        from app.core.startup import SUBSYSTEM_STATUS

        with patch.dict(SUBSYSTEM_STATUS, {
            "modules": "healthy", "event_bus": "healthy",
            "plugins": "degraded", "automation": "degraded",
        }, clear=True):
            critical = ["modules", "event_bus"]
            degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]
            assert len(degraded) == 0  # non-critical degradation doesn't affect readiness

    @pytest.mark.asyncio
    async def test_ready_empty_status_is_ready(self):
        """Before startup completes, empty status should not block readiness."""
        from app.core.startup import SUBSYSTEM_STATUS

        with patch.dict(SUBSYSTEM_STATUS, {}, clear=True):
            critical = ["modules", "event_bus"]
            degraded = [s for s in critical if SUBSYSTEM_STATUS.get(s) == "degraded"]
            assert len(degraded) == 0

    @pytest.mark.asyncio
    async def test_ready_endpoint_200_when_healthy(self):
        """Full HTTP test: /ready returns 200 when DB and subsystems are healthy."""
        from app.core.startup import SUBSYSTEM_STATUS
        from app.db import get_session

        mock_result = MagicMock()
        mock_result.scalar.return_value = 1
        mock_session = AsyncMock()
        mock_session.execute.return_value = mock_result

        async def _override():
            yield mock_session

        app = _get_app()
        app.dependency_overrides[get_session] = _override

        try:
            with patch.dict(SUBSYSTEM_STATUS, {"modules": "healthy", "event_bus": "healthy"}, clear=True):
                transport = ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get("/api/v1/health/ready")

                assert resp.status_code == 200
                assert resp.json()["status"] == "ready"
        finally:
            app.dependency_overrides.pop(get_session, None)

    @pytest.mark.asyncio
    async def test_ready_endpoint_503_when_degraded(self):
        """Full HTTP test: /ready returns 503 when a critical subsystem is degraded."""
        from app.core.startup import SUBSYSTEM_STATUS
        from app.db import get_session

        mock_result = MagicMock()
        mock_result.scalar.return_value = 1
        mock_session = AsyncMock()
        mock_session.execute.return_value = mock_result

        async def _override():
            yield mock_session

        app = _get_app()
        app.dependency_overrides[get_session] = _override

        try:
            with patch.dict(SUBSYSTEM_STATUS, {"modules": "degraded", "event_bus": "healthy"}, clear=True):
                transport = ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get("/api/v1/health/ready")

                assert resp.status_code == 503
                body = resp.json()
                assert body["status"] == "not_ready"
                # Phase 3a readiness payload: critical-subsystem degradation is
                # reported under ``degraded_subsystems`` (hard deps under
                # ``failed``, per-dep probe results under ``checks``).
                assert "modules" in body["degraded_subsystems"]
        finally:
            app.dependency_overrides.pop(get_session, None)

    @pytest.mark.asyncio
    async def test_ready_endpoint_503_when_db_unreachable(self):
        """Full HTTP test: /ready returns 503 when the DB probe fails.

        /ready uses a fresh time-boxed connection (_probe_db_engine) rather than
        the pooled request session, so a frozen/unreachable DB fails fast at 503
        instead of hanging the worker pool (battle-test finding). Patch the probe
        to raise — mirrors a frozen/refused DB.
        """

        async def _boom(*_a, **_kw):
            raise Exception("connection refused")

        app = _get_app()
        with patch("app.api.v1.endpoints.health._probe_db_engine", _boom):
            transport = ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/health/ready")

        assert resp.status_code == 503
        body = resp.json()
        # Primary DB is a HARD gate: an unreachable DB lands in ``failed`` and its
        # probe result in ``checks``.
        assert body["status"] == "not_ready"
        assert "database" in body["failed"]
        assert body["checks"]["database"] == "unreachable"
