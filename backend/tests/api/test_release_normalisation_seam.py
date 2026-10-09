# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""What gets SIGNED must equal what gets PERSISTED.

The publish handler signs a manifest describing the release. The update-check
endpoint does not store that manifest -- it REBUILDS it from the stored row and
verifies the stored signature against the rebuild. So any field transformed
between signing and persistence silently breaks every update:

  * ``platform``/``agent_type`` -- the row was persisted ``.lower()``-ed while
    the manifest was signed with the caller's raw strings, so publishing
    "Linux"/"Daemon" produced a signature over bytes the rebuild could never
    reproduce;
  * ``checksum_sha256`` -- the schema accepts ``[a-fA-F0-9]{64}``; the manifest
    lower-cased the digest before signing while the row kept it raw, so an
    upload with an uppercase checksum could never install.

Both failed the same way in the field: the agent downloaded the binary, verified
the signature, got a mismatch, and refused -- reporting a signature failure for a
release that was perfectly legitimate. Nothing in the backend logged anything.

These tests assert the ROUND TRIP rather than either end of it, which is the only
form that catches a divergence: a test of the signing side alone passes happily
while persistence disagrees, and vice versa.
"""

from __future__ import annotations

import pytest

from app.services import release_signing
from app.services.release_signing import (
    build_release_manifest,
    sign_manifest,
    verify_manifest,
)
from tests.api import release_operation_contract as contract
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_publication as publication
from tests.services.test_public_release_binary import public_reader as public_reader
from tests.services.test_public_release_operations import command


@pytest.fixture(autouse=True)
def isolated_signing_key(tmp_path, monkeypatch, request):
    """Use real signing with a private test key, never production storage.

    Hosted runners cannot write /var/lib/freesdn. An externally supplied key
    directory or a key cached by an earlier test must not mask that assumption.
    """
    if "public_reader" in request.fixturenames:
        return
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(tmp_path))
    monkeypatch.setattr(release_signing, "_PRIVATE_KEY", None)
    monkeypatch.setattr(release_signing, "_PUBLIC_KEY_PEM", None)


#: Exactly what the publish handler does to the caller's input before it uses
#: the values for validation, signing and persistence alike.
def _normalise(platform: str, agent_type: str, checksum: str) -> tuple[str, str, str]:
    return platform.lower(), agent_type.lower(), checksum.lower()


MIXED_CASE_INPUTS = [
    ("Linux", "Daemon", "A" * 64),
    ("WINDOWS", "GUI", "aBcD" * 16),
    ("Darwin", "daemon", "0123456789AbCdEf" * 4),
    ("linux", "daemon", "f" * 64),  # already normalised: must still round-trip
]


@pytest.mark.parametrize("platform,agent_type,checksum", MIXED_CASE_INPUTS)
def test_a_signed_release_verifies_against_the_row_that_was_stored(
    platform: str, agent_type: str, checksum: str
) -> None:
    """The core regression, as a round trip.

    Fails before the fix: the manifest is signed with the raw values and the
    rebuild uses the stored ones, so verify_manifest returns False.
    """
    norm_platform, norm_agent_type, norm_checksum = _normalise(platform, agent_type, checksum)

    # --- publish: sign the manifest, then persist the row ---
    signature = sign_manifest(
        build_release_manifest(
            digest_hex=norm_checksum,
            version="1.2.3",
            platform=norm_platform,
            agent_type=norm_agent_type,
            channel="stable",
        )
    )
    stored = {
        "checksum_sha256": norm_checksum,
        "version": "1.2.3",
        "platform": norm_platform,
        "agent_type": norm_agent_type,
        "channel": "stable",
        "signature": signature,
    }

    # --- update-check: rebuild the manifest from the STORED row ---
    rebuilt = build_release_manifest(
        digest_hex=stored["checksum_sha256"],
        version=stored["version"],
        platform=stored["platform"],
        agent_type=stored["agent_type"],
        channel=stored["channel"],
    )

    assert verify_manifest(rebuilt, stored["signature"]) is True, (
        f"a release published as {platform!r}/{agent_type!r} with checksum "
        f"{checksum[:8]}... cannot be verified from its own stored row. The "
        "agent downloads the binary and then refuses it as a signature mismatch."
    )


def test_normalisation_is_idempotent() -> None:
    """Applying it twice must not change the bytes.

    The publish handler normalises once and reuses the locals; if any later edit
    re-normalises a value that is already normalised, this must stay a no-op or
    the signature and the row diverge again.
    """
    once = _normalise("Linux", "Daemon", "A" * 64)
    assert _normalise(*once) == once


def test_a_case_difference_really_does_break_verification() -> None:
    """Proves the round-trip test above has teeth.

    If the manifest ignored case, the test would pass whether or not the fix
    were present. It does not: sign one casing, rebuild with another, and
    verification fails -- which is exactly the field symptom.
    """
    signed = sign_manifest(
        build_release_manifest(
            digest_hex="a" * 64,
            version="1.2.3",
            platform="Linux",  # raw, as the buggy publish path signed it
            agent_type="daemon",
            channel="stable",
        )
    )
    rebuilt_from_row = build_release_manifest(
        digest_hex="a" * 64,
        version="1.2.3",
        platform="linux",  # lower-cased, as the row stored it
        agent_type="daemon",
        channel="stable",
    )
    assert verify_manifest(rebuilt_from_row, signed) is False, (
        "the manifest must be case-sensitive, or these tests prove nothing"
    )


# ---------------------------------------------------------------------------
# The other half: raw query parameters (F-08)
# ---------------------------------------------------------------------------
#
# ``list_releases`` takes ``platform``/``agent_type`` straight off the query
# string and compares them to columns that are persisted lower-cased. It had a
# ``.lower()`` for exactly that reason. A find-and-replace removing the
# now-redundant ``.lower()`` from the PUBLISH handler -- redundant there because
# that handler normalises into locals first -- stripped it here too, where it is
# load-bearing. ``?platform=Linux`` then compared "Linux" against "linux" and the
# admin release list came back empty with a 200.


class _CapturingSession:
    """Captures the statement instead of running it."""

    def __init__(self) -> None:
        self.statement = None

    async def execute(self, statement):  # noqa: ANN001
        self.statement = statement

        class _Result:
            def mappings(self_inner):  # noqa: N805
                class _S:
                    def all(self_s):  # noqa: N805
                        return []

                return _S()

        return _Result()


def _bound_literals(statement) -> list[str]:  # noqa: ANN001
    """The string values the WHERE clause will actually compare against."""
    compiled = statement.compile(compile_kwargs={"literal_binds": True})
    return [v for v in compiled.params.values() if isinstance(v, str)] or _from_sql(str(compiled))


def _from_sql(sql: str) -> list[str]:
    import re

    return re.findall(r"'([^']*)'", sql)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw,expected",
    [("Linux", "linux"), ("WINDOWS", "windows"), ("Darwin", "darwin"), ("linux", "linux")],
)
async def test_the_admin_release_filter_matches_lower_cased_rows(raw: str, expected: str) -> None:
    """Fails before the fix: the query compares 'Linux', the rows hold 'linux'."""
    from app.api.v1.endpoints.agent_release_upload import _list_visible_releases as list_releases

    class _SuperUser:
        organization_id = None
        is_superuser = True
        role = "super_admin"

    session = _CapturingSession()
    await list_releases(current_user=_SuperUser(), session=session, platform=raw)

    literals = _bound_literals(session.statement)
    assert expected in literals, (
        f"?platform={raw} must query for {expected!r} to match the stored row; "
        f"the query compares against {literals!r}"
    )
    assert raw not in literals or raw == expected, (
        f"the raw query parameter {raw!r} reached the WHERE clause unnormalised"
    )


# The generic round-trip cases above retain their original values and assertions.
# This actual HTTP/SQL test replaces the obsolete AST inspection of upload_release.
# Supported publication names differ from the generic manifest's arbitrary text.


@pytest.mark.asyncio
@pytest.mark.parametrize("platform,agent_type,checksum", [
    ("Linux", "Daemon", "A" * 64),
    ("WINDOWS", "DESKTOP", "aBcD" * 16),
    ("MacOS", "daemon", "0123456789AbCdEf" * 4),
    ("linux", "daemon", "f" * 64),
])
async def test_the_publish_handler_normalises_before_it_signs(
    public_reader, platform, agent_type, checksum
) -> None:
    f = public_reader
    contract.intent(f, storage="external", platform=platform,
                    agent_type=agent_type, checksum=checksum)
    headers = await contract.prepare(f)
    response = await command(f, headers, "publish")
    assert response.status_code == 200, response.text
    rows = await publication.releases(f)
    assert len(rows) == 1
    row = rows[0]
    assert row["platform"] == platform.lower()
    assert row["agent_type"] == agent_type.lower()
    assert row["checksum_sha256"] == checksum.lower()
    assert row["organization_id"] == f.org
    await contract.verify_persisted_signature(f, row)
