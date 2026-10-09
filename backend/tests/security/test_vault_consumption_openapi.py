"""Generated-client contracts for consuming fresh vault permissions."""

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

from app.api.v1.endpoints.backups import router
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from app.services.vault_export_public_download import _MAX_BODY

CASES = [("/", "post"), ("/{backup_id}/download", "get"),
         ("/{backup_id}/vault-observation", "post"), ("/{backup_id}/vault-download", "post")]
PREFIX = "/owned/backups"


@pytest.fixture
def contract():
    application = FastAPI()
    application.include_router(router, prefix=PREFIX)
    return application.openapi()


def operation(contract, path, method="post"):
    return contract["paths"][PREFIX + path][method]


@pytest.mark.parametrize("path,method", CASES)
def test_proof_header_is_documented_without_requiring_it_for_configuration_snapshots(contract, path, method):
    op = operation(contract, path, method)
    headers = {p["name"]: p for p in op.get("parameters", []) if p["in"] == "header"}
    assert "X-FreeSDN-Vault-Proof" in headers
    proof = headers["X-FreeSDN-Vault-Proof"]
    assert proof["required"] == ("vault-" in path)
    assert proof["schema"]["minLength"] == 1 and proof["schema"]["maxLength"] == 8192
    assert proof["schema"]["writeOnly"] is True
    assert "secret-free" in proof["description"] and "URL" in proof["description"]


@pytest.mark.parametrize("path,method", CASES)
def test_archive_operations_document_both_captured_browser_identifiers(contract, path, method):
    headers = {p["name"]: p for p in operation(contract, path, method).get("parameters", []) if p["in"] == "header"}
    assert {"X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization"} <= set(headers)
    assert all(headers[n]["required"] is False for n in ("X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization"))


@pytest.mark.parametrize("path", ["/{backup_id}/vault-observation", "/{backup_id}/vault-download"])
def test_legacy_command_body_is_bounded_and_never_carries_proof(contract, path):
    op = operation(contract, path)
    assert "requestBody" in op
    body = op["requestBody"]
    assert body["required"] is True and str(_MAX_BODY) in body["description"]
    schema = body["content"]["application/json"]["schema"]
    expected = {"legacy_acknowledged"} | ({"observed_identity"} if path.endswith("vault-download") else set())
    assert set(schema["properties"]) == set(schema["required"]) == expected
    assert schema["additionalProperties"] is False
    assert schema["properties"]["legacy_acknowledged"] == {"type": "boolean", "const": True}
    if "observed_identity" in expected:
        identity = schema["properties"]["observed_identity"]
        assert identity["additionalProperties"] is False
        assert set(identity["properties"]) == set(identity["required"]) == {"version", "bytes", "sha256"}
        assert identity["properties"]["version"]["const"] == 1
        assert identity["properties"]["bytes"]["maximum"] == MAX_BACKUP_IMPORT_BYTES


@pytest.mark.parametrize("path", ["/{backup_id}/vault-observation", "/{backup_id}/vault-download"])
def test_legacy_documentation_does_not_add_eager_body_dependencies(path):
    route = next(r for r in router.routes if isinstance(r, APIRoute) and r.path == path)
    assert route.body_field is None
    stack = [route.dependant]
    while stack:
        item = stack.pop()
        assert item.body_params == []
        stack.extend(item.dependencies)


@pytest.mark.parametrize("path,method", [("/{backup_id}/download", "get"), ("/{backup_id}/vault-download", "post")])
def test_download_success_is_binary_and_exposes_integrity_not_an_empty_JSON_model(contract, path, method):
    response = operation(contract, path, method)["responses"]["200"]
    assert set(response["content"]) == {"application/octet-stream"}
    assert response["content"]["application/octet-stream"]["schema"] == {"type": "string", "format": "binary"}
    assert {"Content-Disposition", "X-FreeSDN-Artifact-Integrity"} <= set(response["headers"])
    if path.endswith("vault-download"):
        assert response["headers"]["X-FreeSDN-Artifact-Integrity"]["schema"]["enum"] == ["legacy_unverified"]


def test_legacy_observation_response_preserves_expiry_and_never_claims_historical_authenticity(contract):
    response = operation(contract, "/{backup_id}/vault-observation")["responses"]["200"]["content"]["application/json"]["schema"]
    assert response.get("type") == "object"
    assert set(response["required"]) == set(response["properties"]) == {"operation", "proof", "artifact_integrity", "observed_identity", "authentication_expires_at"}
    assert response["properties"]["operation"]["const"] == "download_legacy"
    assert response["properties"]["artifact_integrity"]["const"] == "legacy_unverified"
    assert response["properties"]["authentication_expires_at"]["type"] == "integer"


def test_creation_retains_existing_typed_body_and_201_backup_response(contract):
    op = operation(contract, "/")
    assert op["requestBody"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/BackupCreate"
    assert op["responses"]["201"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/BackupResponse"
    assert "200" not in op["responses"]
