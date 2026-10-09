"""Native UUID and purpose-binding regression contracts; not SQL/auth proof."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from asyncpg.pgproto.pgproto import UUID as DriverUUID

from app.core.agent_signing_binding import signing_commitment
from app.schemas.agent_downloads import AgentReleaseCreate
from app.services.agent_release_cleanup import _record
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_promotion import release_bucket_key
from app.services.agent_release_request import ReleasePublicationRequest, _uuid

OPERATION = UUID("11111111-1111-4111-8111-111111111111")
RELEASE = UUID("22222222-2222-4222-8222-222222222222")
ORGANIZATION = UUID("33333333-3333-4333-8333-333333333333")
ACTOR = UUID("44444444-4444-4444-8444-444444444444")
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def publication(kind):
    return ReleasePublicationRequest.create(
        operation_id=kind(str(OPERATION)), release_id=kind(str(RELEASE)),
        organization_id=kind(str(ORGANIZATION)), storage_kind="external",
        payload=AgentReleaseCreate(
            version="1.0.0", platform="Linux", agent_type="Daemon",
            download_url="https://artifacts.example.invalid/agent", checksum_sha256="a" * 64,
            file_size=5, release_notes="original metadata",
        ), is_latest=True, filename=None,
    )


@pytest.mark.parametrize("kind", [UUID, DriverUUID])
def test_publication_identity_representation_does_not_change_retained_commitment(kind):
    request = publication(kind)
    standard = publication(UUID)
    assert all(type(getattr(request, name)) is UUID for name in (
        "operation_id", "release_id", "organization_id",
    ))
    assert request == standard
    assert request.metadata_bytes == standard.metadata_bytes
    assert request.request_bytes() == standard.request_bytes()
    assert request.request_sha256() == standard.request_sha256()


@pytest.mark.parametrize("kind", [UUID, DriverUUID])
def test_deletion_capture_preserves_native_identifier_values_and_exact_metadata(kind):
    base = publication(UUID)
    row = {**base.metadata(), "id": kind(str(RELEASE)), "organization_id": kind(str(ORGANIZATION)),
           "signature": None, "published_at": NOW}
    captured = ReleaseDeletionRequest.capture(operation_id=kind(str(OPERATION)), release=row)
    standard = ReleaseDeletionRequest.capture(
        operation_id=OPERATION, release={**row, "id": RELEASE, "organization_id": ORGANIZATION},
    )
    assert captured == standard and captured.metadata_bytes == standard.metadata_bytes
    assert all(type(getattr(captured, name)) is UUID for name in (
        "operation_id", "release_id", "organization_id",
    ))


@pytest.mark.parametrize("kind", [UUID, DriverUUID])
def test_retained_SQL_record_becomes_canonical_without_mutating_the_input(kind):
    request = publication(UUID)
    row = {
        "operation_id": kind(str(OPERATION)), "format_version": 1, "kind": "publish",
        "release_id": kind(str(RELEASE)), "organization_id": kind(str(ORGANIZATION)),
        "requested_by": kind(str(ACTOR)), "last_transition_by": kind(str(ACTOR)),
        "storage_kind": "external", "artifact_id": None, "request_bytes": request.request_bytes(),
        "request_sha256": request.request_sha256(), "expected_sha256": "a" * 64, "expected_size": 5,
        "phase": "reserved", "decision": None, "transition_sequence": 0,
        "created_at": NOW, "prepared_at": None, "decided_at": None, "cleaned_at": None,
    }
    original_values = tuple(row.values())
    checked = _record(row)
    assert checked == row and tuple(row.values()) == original_values
    for name in ("operation_id", "release_id", "organization_id", "requested_by", "last_transition_by"):
        assert type(checked[name]) is UUID and checked[name].bytes == row[name].bytes
    assert type(row["requested_by"]) is kind


@pytest.mark.parametrize("kind", [UUID, DriverUUID])
def test_organization_bucket_is_independent_of_native_UUID_representation(kind):
    assert release_bucket_key(kind(str(ORGANIZATION)), "linux", "daemon") == release_bucket_key(
        ORGANIZATION, "linux", "daemon",
    )


@pytest.mark.parametrize("value", [
    UUID(int=0), DriverUUID(str(UUID(int=0))), None, True, 1,
    str(ORGANIZATION), ORGANIZATION.bytes, object(),
])
def test_UUID_boundary_refuses_zero_unrelated_types_and_text_coercion(value):
    with pytest.raises(ValueError):
        _uuid(value)


def test_only_nullable_identity_accepts_none():
    assert _uuid(None, nullable=True) is None
    with pytest.raises(ValueError):
        _uuid(str(ORGANIZATION), nullable=True)


def test_key_binding_remains_distinct_from_all_existing_purposes_and_state_changes():
    synthetic_key = b"owned synthetic purpose-binding key" * 2
    data = {"id": ORGANIZATION, "active": True, "scopes": ["agent:admin"]}
    domains = ("account", "provider", "command", "authority", "key")
    bindings = {purpose: signing_commitment(data, key=synthetic_key, domain=purpose) for purpose in domains}
    assert len(set(bindings.values())) == len(domains)
    assert bindings["key"] != signing_commitment({**data, "active": False}, key=synthetic_key, domain="key")
    assert bindings["key"] != signing_commitment({**data, "scopes": ["agent:read"]}, key=synthetic_key, domain="key")


@pytest.mark.parametrize("domain", [None, "", "KEY", "arbitrary", True])
def test_unknown_commitment_purposes_are_still_refused(domain):
    with pytest.raises(ValueError):
        signing_commitment({}, key=b"owned synthetic purpose-binding key" * 2, domain=domain)
