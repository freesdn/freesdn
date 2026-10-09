# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retained pure filename/version contracts and real public upload failures.

The operation protocol keeps acknowledged bytes after failed publication until
explicit same-intent cancellation and cleanup. No deployed keys are used.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.api.v1.endpoints.agent_release_upload import _VERSION_PATTERN, _binary_path
from app.services.release_signing import SigningKeyError
from tests.api import release_operation_contract as contract
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_publication as publication
from tests.services import test_agent_release_upload_stream as upload
from tests.services.test_public_release_binary import public_reader as public_reader
from tests.services.test_public_release_operations import command


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


class TestSigningFailureOnUpload:
    """Signing errors never publish a latest release or silently replace it."""

    @pytest.mark.asyncio
    async def test_signing_failure_on_latest_raises_500_and_does_not_persist(
        self, public_reader, monkeypatch
    ) -> None:
        """Unexpected signer exceptions retain the upload, with no release commit."""
        f = public_reader
        contract.intent(f)
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

    @pytest.mark.asyncio
    async def test_signing_failure_on_non_latest_proceeds_unsigned(
        self, public_reader, monkeypatch
    ) -> None:
        """Only an explicit non-latest owned release permits known key failure."""
        f = public_reader
        contract.intent(f, latest=False)
        old_id = await publication.seed(f, organization=f.org)
        before = await publication.releases(f)
        headers = await contract.prepare(f)
        with patch("app.services.agent_release_publication.sign_manifest_async",
                   side_effect=SigningKeyError("owned key unavailable")):
            response = await command(f, headers, "publish")
        assert response.status_code == 200, response.text
        rows = await publication.releases(f)
        assert len(rows) == len(before) + 1
        assert next(r for r in rows if r["id"] == old_id) == before[0]
        row = next(r for r in rows if r["id"] == f.publication.release_id)
        assert row["is_latest"] is False and row["signature"] is None
        assert row["organization_id"] == f.org
        assert upload.payload(f).read_bytes() == f.data

    @pytest.mark.asyncio
    async def test_known_signing_unavailability_keeps_previous_latest_and_retained_payload(
        self, public_reader
    ) -> None:
        f = public_reader
        contract.intent(f)
        await publication.seed(f, organization=f.org)
        before = await publication.releases(f)
        headers = await contract.prepare(f)
        with patch("app.services.agent_release_publication.sign_manifest_async",
                   side_effect=SigningKeyError("owned key unavailable")):
            response = await command(f, headers, "publish")
        assert response.status_code == 503, response.text
        await contract.unchanged_release_rows_and_cleanup(f, headers, before)

    @pytest.mark.asyncio
    async def test_unexpected_non_latest_signing_error_never_downgrades_to_unsigned(
        self, public_reader
    ) -> None:
        f = public_reader
        contract.intent(f, latest=False)
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
