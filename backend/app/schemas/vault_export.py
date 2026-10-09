# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded fresh-confirmation commands; no client-authored authority receipts."""

import json
from dataclasses import dataclass
from typing import Literal, Never, TypedDict, cast
from uuid import UUID

from app.schemas.backup import BackupCreate
from app.services.vault_export_operation_state import ExportIntent

MAX_CONFIRMATION_BYTES = 131072
ConfirmationAction = Literal["local", "ldap", "oidc_start", "oidc_complete", "external"]


def _invalid() -> ValueError:
    # Do not include input, passwords, provider codes or Pydantic errors.
    return ValueError("Invalid vault confirmation command")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def _constant(_value: str) -> Never:
    raise _invalid()


def _text(value: object, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise _invalid()
    return value


def _uuid(value: object) -> UUID:
    _text(value, 36)
    result = UUID(cast(str, value))
    if str(result) != value or result.int == 0:
        raise _invalid()
    return result


def _intent(value: object) -> ExportIntent:
    if type(value) is not dict:
        raise _invalid()
    kind = value.get("kind")
    if kind == "create":
        if set(value) != {"kind", "backup"} or type(value["backup"]) is not dict:
            raise _invalid()
        data = value["backup"]
        if set(data) - set(BackupCreate.model_fields) or data.get("include_secrets") is not True:
            raise _invalid()
        # JSON-mode strict validation accepts canonical JSON UUID strings while
        # refusing string booleans/numeric coercions. Preserve BackupCreate's
        # defaults and all existing passphrase/device/retention bounds.
        backup = BackupCreate.model_validate_json(json.dumps(data, allow_nan=False), strict=True)
        return ExportIntent.creation(backup)
    if kind == "download_recorded":
        if set(value) != {"kind", "backup_id"}:
            raise _invalid()
        return ExportIntent.download(_uuid(value["backup_id"]), operation=kind)
    if kind == "observe_legacy":
        if set(value) != {"kind", "backup_id", "legacy_acknowledged"}:
            raise _invalid()
        if value["legacy_acknowledged"] is not True:
            raise _invalid()
        return ExportIntent.download(
            _uuid(value["backup_id"]), operation=kind, legacy_acknowledged=True
        )
    # A legacy-download proof can arise only from the consumed, server-observed
    # artifact exchange. No HTTP claim can substitute for that observation.
    raise _invalid()


@dataclass(frozen=True, repr=False)
class VaultConfirmationCommand:
    intent: ExportIntent
    password: str | None = None
    mfa_code: str | None = None
    state: str | None = None
    code: str | None = None
    identity_token: str | None = None


class VaultConfirmationArguments(TypedDict, total=False):
    password: str
    mfa_code: str
    state: str
    code: str
    identity_token: str


def decode_vault_confirmation(raw: bytes, action: ConfirmationAction) -> VaultConfirmationCommand:
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CONFIRMATION_BYTES:
            raise _invalid()
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        if type(body) is not dict:
            raise _invalid()
        fields = {
            "local": ({"intent", "password"}, {"mfa_code"}),
            "ldap": ({"intent", "password"}, set()),
            "oidc_start": ({"intent"}, set()),
            "oidc_complete": ({"intent", "state", "code"}, set()),
            "external": ({"intent", "identity_token"}, {"mfa_code"}),
        }
        required, optional = fields[action]
        if not required <= set(body) or set(body) - required - optional:
            raise _invalid()
        intent = _intent(body["intent"])
        arguments: dict[str, str] = {}
        for name, maximum in (
            ("password", 1024),
            ("mfa_code", 10),
            ("state", 8192),
            ("code", 8192),
            ("identity_token", 8192),
        ):
            if name in body:
                value = body[name]
                if name == "mfa_code" and value is None:
                    continue
                arguments[name] = _text(value, maximum)
        return VaultConfirmationCommand(intent, **cast(VaultConfirmationArguments, arguments))
    except Exception:
        raise _invalid() from None
