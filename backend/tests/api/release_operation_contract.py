"""Actual public-operation helpers, with owned SQL and no authority doubles.

These assertions concern the retained-operation contract. Successful external
publication verifies signed metadata, not downloaded third-party contents.
"""

import base64
import hashlib
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.schemas.agent_downloads import AgentReleaseCreate
from app.services.agent_release_request import ReleasePublicationRequest
from app.services.release_signing import build_release_manifest, canonical_manifest_bytes
from tests.services import test_agent_release_publication as publication
from tests.services import test_agent_release_upload_stream as upload
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services.test_public_release_operations import PREFIX, command


def intent(f, *, storage="owned", latest=True, platform="linux", agent_type="daemon",
           checksum=None, version="1.2.0"):
    f.data = b"owned-publication-contract-payload"
    release_id = uuid4()
    external = storage == "external"
    payload = AgentReleaseCreate(
        version=version, platform=platform, agent_type=agent_type,
        download_url="https://example.invalid/owned-agent" if external
        else f"{PREFIX}/releases/{release_id}/binary",
        checksum_sha256=checksum or hashlib.sha256(f.data).hexdigest(),
        file_size=len(f.data), release_notes="retained publication contract",
        is_prerelease=False,
    )
    f.publication = ReleasePublicationRequest.create(
        operation_id=uuid4(), release_id=release_id, organization_id=f.org,
        storage_kind=storage, payload=payload, is_latest=latest,
        filename=None if external else "owned-agent",
    )
    return f.publication


async def prepare(f):
    headers = await lifecycle.headers(f)
    reserved = await command(f, headers, "reserve")
    assert reserved.status_code == 200, reserved.text
    if f.publication.storage_kind == "owned":
        response = await f.public_client.post(
            f"{PREFIX}/release-operations/{f.publication.operation_id}/upload",
            headers={**headers, "Content-Type": upload.CONTENT_TYPE},
            content=upload.prefix(f.publication) + f.data + upload.suffix(),
        )
        assert response.status_code == 200, response.text
        assert response.json()["result"]["phase"] == "prepared"
        assert upload.payload(f).read_bytes() == f.data
    return headers


async def unchanged_release_rows_and_cleanup(f, headers, before):
    """A failed publication retains prepared bytes until explicit cancellation."""
    assert await publication.releases(f) == before
    if f.publication.storage_kind == "owned":
        assert upload.payload(f).read_bytes() == f.data
    cancelled = await command(f, headers, "cancel")
    assert cancelled.status_code == 200, cancelled.text
    cleaned = await command(f, headers, "cleanup")
    assert cleaned.status_code == 200, cleaned.text
    assert cleaned.json()["result"]["complete"] is True
    assert await publication.releases(f) == before
    if f.publication.storage_kind == "owned":
        assert not upload.payload(f).exists()


async def verify_persisted_signature(f, row):
    """Independent ECDSA verification using the actual public-key HTTP route."""
    response = await f.public_client.get(f"{PREFIX}/releases/public-key")
    assert response.status_code == 200
    key = serialization.load_pem_public_key(response.content)
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert isinstance(key.curve, ec.SECP256R1)
    manifest = build_release_manifest(
        digest_hex=row["checksum_sha256"], version=row["version"],
        platform=row["platform"], agent_type=row["agent_type"],
        channel="prerelease" if row["is_prerelease"] else "stable",
    )
    key.verify(base64.b64decode(row["signature"], validate=True),
               canonical_manifest_bytes(manifest), ec.ECDSA(hashes.SHA256()))
