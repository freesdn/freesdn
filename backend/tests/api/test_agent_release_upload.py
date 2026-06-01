# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the release upload + serve endpoints.

Smoke-test the version regex + version-string filename sanitization
without actually writing files. Live binary-upload verification
happens in the deployment-runbook section.
"""

from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import agent_release_upload as upload_endpoint
from app.api.v1.endpoints.agent_release_upload import (
    _VERSION_PATTERN,
    _binary_path,
)
from app.core.dependencies import get_current_active_user
from app.db.session import get_session


class TestVersionPattern:
    @pytest.mark.parametrize(
        "version",
        ["1.0.0", "1.0.0-beta", "1.0.0+build5", "v1.0", "0.0.1"],
    )
    def test_accepts_valid_versions(self, version: str) -> None:
        assert _VERSION_PATTERN.match(version)

    @pytest.mark.parametrize(
        "version",
        ["", "1.0/etc/passwd", "1.0 0", "a" * 51, "v1.0;rm -rf /"],
    )
    def test_rejects_invalid_versions(self, version: str) -> None:
        assert not _VERSION_PATTERN.match(version)


class TestBinaryPath:
    """The filename sanitizer must reject directory-traversal payloads
    even before checksum verification — uploads run as a privileged
    process, so an `../../etc/cron.d/x` payload would be catastrophic."""

    def test_strips_path_traversal_segments(self, tmp_path, monkeypatch) -> None:
        from uuid import uuid4

        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        rid = uuid4()
        path = _binary_path(rid, "../../etc/passwd")
        # Path resolves inside tmp_path — the slashes that would have
        # escaped collapse to underscores. The literal `.` chars are
        # preserved (they're not the dangerous part), but `/` and `\`
        # are stripped so no real traversal happens.
        resolved = path.resolve()
        assert str(resolved).startswith(str(tmp_path.resolve()))
        assert "/" not in path.name
        assert "\\" not in path.name

    def test_normal_filenames_preserved(self, tmp_path, monkeypatch) -> None:
        from uuid import uuid4

        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        rid = uuid4()
        path = _binary_path(rid, "freesdn-agent-1.0.0.exe")
        assert "freesdn-agent-1.0.0.exe" in path.name
        assert str(rid) in path.name

    def test_filename_length_capped(self, tmp_path, monkeypatch) -> None:
        from uuid import uuid4

        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        rid = uuid4()
        super_long = "a" * 500 + ".exe"
        path = _binary_path(rid, super_long)
        # Total filename minus the "{uuid}-" prefix should be <= 128 chars
        suffix = path.name.split("-", 5)[-1]
        assert len(suffix) <= 128


# ---------------------------------------------------------------------------
# fail closed on signing failure for latest releases
# ---------------------------------------------------------------------------


class _FakeUploadSession:
    """Minimal AsyncSession stand-in for upload endpoint tests."""

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.commits = 0

    async def execute(self, query: Any) -> Any:  # noqa: ARG002
        # The upload endpoint issues an UPDATE to demote previous is_latest;
        # return an empty result — it's a fire-and-forget UPDATE.
        return type(
            "R",
            (),
            {
                "scalar_one_or_none": lambda _: None,
                "scalars": lambda _: type("S", (), {"all": lambda _: []})(),
            },
        )()

    async def commit(self) -> None:
        self.commits += 1

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def refresh(self, obj: Any) -> None:
        for attr, default in [("id", uuid4()), ("download_count", 0), ("min_backend_version", "")]:
            if not hasattr(obj, attr) or getattr(obj, attr) is None:
                setattr(obj, attr, default)


def _build_upload_app(session: _FakeUploadSession, *, tmp_path: Any) -> FastAPI:
    """Mount the upload router with fakes wired in."""
    app = FastAPI()
    app.include_router(upload_endpoint.router, prefix="/api/v1/agents")

    async def _override_session():
        yield session

    fake_user = SimpleNamespace(
        user=SimpleNamespace(id=uuid4(), email="admin@test", is_active=True),
        role="super_admin",
        is_superuser=True,
        is_org_admin=True,
        organization_id=None,  # super_admin → global release
        has_all_permissions=lambda _p: True,
        has_any_permission=lambda _p: True,
        has_permission=lambda _p: True,
    )
    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_active_user] = lambda: fake_user
    return app


class TestSigningFailureOnUpload:
    """upload path must fail closed when signing raises."""

    @pytest.mark.asyncio
    async def test_signing_failure_on_latest_raises_500_and_does_not_persist(
        self, tmp_path, monkeypatch
    ) -> None:
        """When sign_digest raises and is_latest=True (the default), the upload
        endpoint must return HTTP 500 and leave no release row in the DB and no
        binary file on disk.
        """
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        session = _FakeUploadSession()
        app = _build_upload_app(session, tmp_path=tmp_path)

        binary_content = b"fake-agent-binary"
        with patch(
            "app.services.release_signing.sign_digest",
            side_effect=RuntimeError("signing key unavailable"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/api/v1/agents/releases/upload",
                    data={
                        "version": "3.0.0",
                        "platform": "linux",
                        "agent_type": "daemon",
                        "is_latest": "true",
                        "is_prerelease": "false",
                    },
                    files={
                        "file": ("agent-linux", BytesIO(binary_content), "application/octet-stream")
                    },
                )

        assert r.status_code == 500, r.text
        assert "signing" in r.json()["detail"].lower()
        # No DB row created.
        assert len(session.added) == 0
        assert session.commits == 0
        # No artifact left on disk.
        leftover = list(tmp_path.glob("*-agent-linux"))
        assert leftover == [], f"Expected no leftover binary; found: {leftover}"

    @pytest.mark.asyncio
    async def test_signing_failure_on_non_latest_proceeds_unsigned(
        self, tmp_path, monkeypatch
    ) -> None:
        """When is_latest=False (explicit test artifact), signing failure is
        tolerated: the release is created with signature=None.
        """
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
        session = _FakeUploadSession()
        app = _build_upload_app(session, tmp_path=tmp_path)

        binary_content = b"fake-agent-binary-test"
        with patch(
            "app.services.release_signing.sign_digest",
            side_effect=RuntimeError("signing key unavailable"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/api/v1/agents/releases/upload",
                    data={
                        "version": "3.0.0-test",
                        "platform": "linux",
                        "agent_type": "daemon",
                        "is_latest": "false",
                        "is_prerelease": "true",
                    },
                    files={
                        "file": (
                            "agent-linux-test",
                            BytesIO(binary_content),
                            "application/octet-stream",
                        )
                    },
                )

        assert r.status_code == 201, r.text
        body = r.json()
        assert body["is_latest"] is False
        assert body["signature"] is None
        # The binary is on disk (not cleaned up).
        leftover = list(tmp_path.glob("*-agent-linux-test"))
        assert len(leftover) == 1
