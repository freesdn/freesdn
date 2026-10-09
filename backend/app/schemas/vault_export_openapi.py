# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Documentation metadata for the bounded manual confirmation parser.

This does not attach a FastAPI Body dependency or deserialize a request. The
route still authenticates first and enforces byte/time/reader limits before
strict decoding. Schema validation cannot prove current authority or freshness.
"""

from copy import deepcopy
from typing import Any, Literal, cast

from pydantic.json_schema import JsonSchemaValue

from app.schemas.backup import BackupCreate
from app.schemas.vault_export import MAX_CONFIRMATION_BYTES, ConfirmationAction


def _object(properties: dict[str, JsonSchemaValue], required: list[str]) -> JsonSchemaValue:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _text(maximum: int | None = None, *, secret: bool = False) -> JsonSchemaValue:
    value: JsonSchemaValue = {"type": "string", "minLength": 1}
    if maximum is not None:
        value["maxLength"] = maximum
    if secret:
        value["writeOnly"] = True
    return value


def _inline_schema(schema: JsonSchemaValue) -> JsonSchemaValue:
    """Keep nested BackupCreate definitions resolvable in an inline operation."""
    definitions = schema.get("$defs", {})

    def visit(value: Any, parents: tuple[str, ...] = ()) -> Any:
        if isinstance(value, list):
            return [visit(v, parents) for v in value]
        if not isinstance(value, dict):
            return value
        own = {k: visit(v, parents) for k, v in value.items() if k not in ("$defs", "$ref")}
        if "$ref" not in value:
            return own
        reference = value["$ref"]
        if (
            not reference.startswith("#/$defs/")
            or reference in parents
            or len(parents) >= 32
            or reference[8:] not in definitions
        ):
            raise ValueError("Vault command documentation has an unsupported schema reference")
        resolved = visit(definitions[reference[8:]], parents + (reference,))
        return {**resolved, **own}

    return cast(JsonSchemaValue, visit(deepcopy(schema)))


def _intent_schema() -> JsonSchemaValue:
    backup = _inline_schema(BackupCreate.model_json_schema())
    backup["additionalProperties"] = False
    backup["properties"]["include_secrets"] = {"type": "boolean", "const": True}
    backup["required"] = list(dict.fromkeys([*backup.get("required", []), "include_secrets"]))
    # The archive passphrase is an input secret even in generated clients/docs.
    backup["properties"]["passphrase"]["writeOnly"] = True
    identity = {
        "type": "string",
        "minLength": 36,
        "maxLength": 36,
        "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        "not": {"const": "00000000-0000-0000-0000-000000000000"},
    }
    return {
        "oneOf": [
            _object(
                {"kind": {"const": "create", "type": "string"}, "backup": backup},
                ["kind", "backup"],
            ),
            _object(
                {"kind": {"const": "download_recorded", "type": "string"}, "backup_id": identity},
                ["kind", "backup_id"],
            ),
            _object(
                {
                    "kind": {"const": "observe_legacy", "type": "string"},
                    "backup_id": identity,
                    "legacy_acknowledged": {"type": "boolean", "const": True},
                },
                ["kind", "backup_id", "legacy_acknowledged"],
            ),
        ],
        "description": "A legacy download permission is obtained only through the server's subsequent artifact observation exchange.",
    }


def confirmation_openapi(action: ConfirmationAction) -> dict[str, Any]:
    """Describe supported commands without changing their bounded runtime path."""
    fields: dict[ConfirmationAction, tuple[dict[str, JsonSchemaValue], list[str], bool]] = {
        "local": ({"password": _text(1024, secret=True)}, ["password"], True),
        "ldap": ({"password": _text(1024, secret=True)}, ["password"], False),
        "oidc_start": ({}, [], False),
        "oidc_complete": (
            {"state": _text(8192, secret=True), "code": _text(8192, secret=True)},
            ["state", "code"],
            False,
        ),
        "external": ({"identity_token": _text(8192, secret=True)}, ["identity_token"], True),
    }
    if action not in fields:
        raise ValueError("Unsupported vault confirmation action")
    extra, required, mfa = fields[action]
    properties = {"intent": _intent_schema(), **extra}
    if mfa:
        properties["mfa_code"] = {
            "anyOf": [_text(10, secret=True), {"type": "null"}],
            "writeOnly": True,
        }
    if action == "oidc_start":
        response = _object(
            {"authorize_url": _text(), "state": _text(), "expires_at": {"type": "integer"}},
            ["authorize_url", "state", "expires_at"],
        )
    elif action in {"ldap", "oidc_complete"}:
        response = _object(
            {"identity_token": _text(), "expires_at": {"type": "integer"}},
            ["identity_token", "expires_at"],
        )
    else:
        response = _object({"proof": _text()}, ["proof"])
    return {
        "description": "Requires current unscoped platform-administrator authority and fresh factors. "
        "Browser callers send both captured account/organization headers. "
        "Never place passwords, passphrases or confirmation tokens in a URL. "
        "The parser rejects duplicate JSON keys, nonfinite numbers and unknown fields. "
        "The server rechecks authority, operation binding and expiry after waits; "
        "confirmation does not itself export an archive. Responses must not be cached.",
        "parameters": [
            {
                "in": "header",
                "name": name,
                "required": False,
                "description": "Send both captured browser identifiers together; they assert equality and grant no authority.",
                "schema": _intent_schema()["oneOf"][1]["properties"]["backup_id"],
            }
            for name in ("X-FreeSDN-Vault-Actor", "X-FreeSDN-Vault-Organization")
        ],
        "requestBody": {
            "required": True,
            "description": f"Identity-encoded JSON, at most {MAX_CONFIRMATION_BYTES} wire bytes; 10-second read deadline and bounded concurrent readers.",
            "content": {"application/json": {"schema": _object(properties, ["intent", *required])}},
        },
        "responses": {
            "200": {
                "description": "Fresh confirmation completed; tokens remain purpose-bound and expire.",
                "content": {"application/json": {"schema": response}},
            },
            **{
                str(code): {"description": description}
                for code, description in {
                    400: "Invalid browser context or declared request length.",
                    401: "Current authentication or fresh confirmation refused or expired.",
                    403: "Required authority or CSRF protection not satisfied.",
                    408: "Confirmation request-body deadline exceeded.",
                    409: "Initiating account, organization or operation changed; start again.",
                    413: "Request exceeds the byte bound.",
                    415: "Unsupported content type or content encoding.",
                    422: "Invalid command; input and validation internals are not echoed.",
                    429: "Rate limit reached.",
                    500: "Confirmation unavailable.",
                    503: "Capacity, rate-limit service or trusted provider configuration unavailable.",
                }.items()
            },
        },
    }


def requirements_openapi() -> dict[str, Any]:
    """Document factor hints without adding request parsing or permission."""
    headers = {
        "Cache-Control": {"schema": {"type": "string", "const": "private, no-store"}},
        "Pragma": {"schema": {"type": "string", "const": "no-cache"}},
    }
    statuses = {
        200: "Current supported confirmation factors; this hint grants no permission or proof.",
        400: "Incomplete or invalid captured browser context.",
        401: "Current authentication refused or expired.",
        403: "Current unscoped platform-administrator authority is required.",
        409: "Initiating account or organization changed; start again.",
        422: "Invalid action or framework input; rejected values are not echoed.",
        429: "Rate limit reached.",
        500: "Confirmation requirements unavailable.",
        503: "Current authority snapshot or required capacity unavailable.",
    }
    return {
        "description": "Read the current supported confirmation method and MFA requirement. "
        "This hint grants no identity or export permission and does not verify provider connectivity. "
        "Browser callers send both captured account/organization headers. "
        "The callback is explicit server configuration, never derived from Host or Origin. "
        "No passwords, archive passphrases or confirmation tokens belong in this GET request. "
        "Subsequent confirmation and consumption must revalidate current authority and freshness. "
        "Responses must not be cached.",
        "parameters": confirmation_openapi("local")["parameters"],
        "responses": {
            str(status): {"description": description, "headers": deepcopy(headers)}
            for status, description in statuses.items()
        },
    }


def vault_consumption_openapi(
    action: Literal["create", "download_recorded", "observe_legacy", "download_legacy"],
) -> dict[str, Any]:
    """Describe conditional proof requirements and the legacy observation flow."""
    from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES

    if action not in {"create", "download_recorded", "observe_legacy", "download_legacy"}:
        raise ValueError("Unsupported vault consumption action")
    legacy = action in {"observe_legacy", "download_legacy"}
    common = confirmation_openapi("local")
    parameters = common["parameters"] + [
        {
            "in": "header",
            "name": "X-FreeSDN-Vault-Proof",
            "required": legacy,
            "description": "One-use purpose-bound proof from fresh confirmation. Required for full vaults; "
            "ordinary secret-free configuration snapshots do not require it. "
            "Never send it in a URL or request body.",
            "schema": _text(8192, secret=True),
        }
    ]
    output: dict[str, Any] = {
        "parameters": parameters,
        "description": "Full vault operations require fresh confirmation and current unscoped platform-administrator authority. "
        "The server consumes the proof and rechecks authority/expiry after waits and storage reads. "
        "Current legacy-byte observation never proves historical authenticity or renews authentication. "
        "Secret-free configuration snapshots retain their existing authorization policy.",
    }
    if action == "create":
        return output
    identity = _object(
        {
            "version": {"type": "integer", "const": 1},
            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_BACKUP_IMPORT_BYTES},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        ["version", "bytes", "sha256"],
    )
    headers = {
        "Cache-Control": {"schema": {"type": "string"}},
        "X-FreeSDN-Artifact-Integrity": {
            "schema": {
                "type": "string",
                "enum": ["legacy_unverified"] if legacy else ["verified", "legacy_unverified"],
            }
        },
    }
    if legacy:
        properties: dict[str, JsonSchemaValue] = {
            "legacy_acknowledged": {"type": "boolean", "const": True}
        }
        if action == "download_legacy":
            properties["observed_identity"] = identity
        output["requestBody"] = {
            "required": True,
            "description": "Identity-encoded JSON, at most 2048 wire bytes and a 10-second read deadline. Duplicate/unknown keys and nonfinite numbers are refused. Proof is header-only.",
            "content": {"application/json": {"schema": _object(properties, list(properties))}},
        }
    if action == "observe_legacy":
        response = _object(
            {
                "operation": {"type": "string", "const": "download_legacy"},
                "proof": _text(),
                "artifact_integrity": {"type": "string", "const": "legacy_unverified"},
                "observed_identity": identity,
                "authentication_expires_at": {"type": "integer"},
            },
            [
                "operation",
                "proof",
                "artifact_integrity",
                "observed_identity",
                "authentication_expires_at",
            ],
        )
        content = {"application/json": {"schema": response}}
    else:
        content = {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
        headers["Content-Disposition"] = {"schema": {"type": "string"}}
    output["responses"] = {
        "200": {
            "description": "Current bytes observed."
            if action == "observe_legacy"
            else "Archive bytes; retain the reported integrity classification.",
            "headers": headers,
            "content": content,
        },
        **{code: value for code, value in common["responses"].items() if code != "200"},
    }
    return output
