"""Consumer-visible command contracts and the no-eager-body-parse boundary."""

from copy import deepcopy

import pytest
from fastapi import FastAPI
from fastapi.openapi.models import OpenAPI

from app.api.v1.endpoints.vault_export import (
    VaultConfirmationPolicy,
    create_vault_confirmation_router,
)
from app.schemas.backup import BackupCreate
from app.schemas.vault_export import MAX_CONFIRMATION_BYTES

PREFIX = "/owned-api/v2/auth/vault-export"
ACTIONS = [
    ("local", "/authorize/local"),
    ("ldap", "/identity/ldap"),
    ("oidc_start", "/identity/oidc/start"),
    ("oidc_complete", "/identity/oidc/complete"),
    ("external", "/authorize/external"),
]


@pytest.fixture
def contract():
    router = create_vault_confirmation_router(VaultConfirmationPolicy())
    application = FastAPI()
    application.include_router(router, prefix=PREFIX)
    return router, application.openapi()


def operation(contract, path):
    return contract[1]["paths"][PREFIX + path]["post"]


def body_schema(contract, path):
    op = operation(contract, path)
    assert "requestBody" in op, "A generated client needs an explicit confirmation request body"
    body = op["requestBody"]
    assert body["required"] is True and set(body["content"]) == {"application/json"}
    return body["content"]["application/json"]["schema"]


@pytest.mark.parametrize("action,path", ACTIONS)
def test_public_contract_has_bounded_action_body(contract, action, path):
    schema = body_schema(contract, path)
    expected = {
        "local": ({"intent", "password"}, {"mfa_code"}),
        "ldap": ({"intent", "password"}, set()),
        "oidc_start": ({"intent"}, set()),
        "oidc_complete": ({"intent", "state", "code"}, set()),
        "external": ({"intent", "identity_token"}, {"mfa_code"}),
    }
    required, optional = expected[action]
    assert set(schema["required"]) == required
    assert set(schema["properties"]) == required | optional
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    for name, maximum in {"password": 1024, "state": 8192, "code": 8192, "identity_token": 8192}.items():
        if name in required:
            field = schema["properties"][name]
            assert field["type"] == "string" and field["minLength"] == 1 and field["maxLength"] == maximum
            assert field["writeOnly"] is True
    if optional:
        field = schema["properties"]["mfa_code"]
        text = next(v for v in field["anyOf"] if v.get("type") == "string")
        assert text["minLength"] == 1 and text["maxLength"] == 10 and field["writeOnly"] is True
        assert {"type": "null"} in field["anyOf"]
    assert str(MAX_CONFIRMATION_BYTES) in operation(contract, path)["requestBody"]["description"]


@pytest.mark.parametrize("action,path", ACTIONS)
def test_public_contract_documents_success_tokens(contract, action, path):
    response = operation(contract, path)["responses"]["200"]["content"]["application/json"]["schema"]
    expected = {"authorize_url", "state", "expires_at"} if action == "oidc_start" else (
        {"identity_token", "expires_at"} if action in {"ldap", "oidc_complete"} else {"proof"})
    assert response.get("type") == "object", "An untyped success body hides purpose-bound token responses"
    assert set(response["required"]) == set(response["properties"]) == expected
    assert response["additionalProperties"] is False
    for name in expected:
        assert response["properties"][name]["type"] == ("integer" if name == "expires_at" else "string")
    assert {"400", "401", "403", "408", "409", "413", "415", "422", "429", "500", "503"} <= set(operation(contract, path)["responses"])


@pytest.mark.parametrize("action,path", ACTIONS)
def test_public_contract_documents_captured_browser_context(contract, action, path):
    headers = {p["name"]: p for p in operation(contract, path).get("parameters", []) if p["in"] == "header"}
    for name in ("X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization"):
        assert name in headers
        field = headers[name]
        assert field["required"] is False and field["schema"]["minLength"] == field["schema"]["maxLength"] == 36
        assert "both" in field["description"] and "no authority" in field["description"]


@pytest.mark.parametrize("action,path", ACTIONS)
def test_documentation_does_not_add_body_dependencies(contract, action, path):
    route = next(route for route in contract[0].routes if route.path == path)
    assert route.body_field is None
    stack = [route.dependant]
    while stack:
        item = stack.pop()
        assert item.body_params == [], "Automatic body parsing would precede bounded manual reads"
        stack.extend(item.dependencies)


def test_creation_intent_keeps_shared_backup_constraints_and_explicit_secret_choice(contract):
    schema = body_schema(contract, "/authorize/local")
    creation = next(v for v in schema["properties"]["intent"]["oneOf"] if v["properties"]["kind"]["const"] == "create")
    backup = creation["properties"]["backup"]
    # Compare at the same framework export boundary: FastAPI excludes null
    # defaults from conventional Body models too, without dropping null types.
    ordinary = FastAPI()

    @ordinary.post("/ordinary")
    async def ordinary_backup(request: BackupCreate):
        return None

    original = ordinary.openapi()["components"]["schemas"]["BackupCreate"]
    assert set(backup["properties"]) == set(original["properties"])
    assert backup["properties"]["include_secrets"] == {"type": "boolean", "const": True}
    assert set(backup["required"]) == set(original["required"]) | {"include_secrets"}
    assert backup["additionalProperties"] is False
    for name, field in original["properties"].items():
        if name == "include_secrets":
            continue
        expected = deepcopy(field)
        if name == "passphrase":
            expected["writeOnly"] = True
        assert backup["properties"][name] == expected


def test_export_intent_never_accepts_client_minted_legacy_permission(contract):
    intent = body_schema(contract, "/authorize/local")["properties"]["intent"]
    by_kind = {v["properties"]["kind"]["const"]: v for v in intent["oneOf"]}
    assert set(by_kind) == {"create", "download_recorded", "observe_legacy"}
    for kind, fields in [("create", {"kind", "backup"}), ("download_recorded", {"kind", "backup_id"}),
                         ("observe_legacy", {"kind", "backup_id", "legacy_acknowledged"})]:
        branch = by_kind[kind]
        assert branch["additionalProperties"] is False and set(branch["properties"]) == set(branch["required"]) == fields
    assert by_kind["observe_legacy"]["properties"]["legacy_acknowledged"] == {"type": "boolean", "const": True}
    identity = by_kind["download_recorded"]["properties"]["backup_id"]
    assert identity["not"] == {"const": "00000000-0000-0000-0000-000000000000"}
    assert identity["pattern"] == "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


def test_spec_is_valid_and_all_references_resolve(contract):
    spec = contract[1]
    OpenAPI.model_validate(spec)
    stack = [spec]
    while stack:
        value = stack.pop()
        if isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, dict):
            if "$ref" in value:
                reference = value["$ref"]
                assert reference.startswith("#/")
                target = spec
                for component in reference[2:].split("/"):
                    target = target[component.replace("~1", "/").replace("~0", "~")]
                assert isinstance(target, dict)
            stack.extend(value.values())


def test_generating_docs_does_not_change_ordinary_backup_defaults(contract):
    assert contract[1]["paths"]
    request = BackupCreate(name="ordinary configuration")
    assert request.include_secrets is False and request.passphrase is None
    assert BackupCreate.model_json_schema()["properties"]["include_secrets"]["default"] is False
