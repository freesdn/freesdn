# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Credential Pydantic Schemas
==========================================

Request/Response schemas for credential entities.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.core import CredentialScope, CredentialType


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


def _validate_options_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    # 8 KiB is plenty for vendor-specific knobs (site_key, api_port,
    # etc). Without this an attacker could persist a 1 MB JSONB blob
    # to bloat the credentials table.
    if size > 8 * 1024:
        raise ValueError(f"options exceeds 8192 bytes (got {size})")
    return v


class CredentialCreate(BaseSchema):
    """Create a new credential."""

    name: str = Field(min_length=1, max_length=255)
    # Every text/secret field was previously unbounded; only ``name``
    # had a cap. PEM keys can run ~3 KB so secret fields are sized
    # accordingly; ``description`` / ``vendor`` are bounded to
    # operator-realistic sizes.
    description: str | None = Field(None, max_length=2000)
    credential_type: CredentialType = CredentialType.BASIC_AUTH
    scope: CredentialScope = CredentialScope.GLOBAL
    vendor: str | None = Field(None, max_length=128)
    site_id: UUID | None = None
    username: str | None = Field(None, max_length=512)
    password: str | None = Field(None, max_length=16384)  # Will be stored encrypted
    api_key: str | None = Field(None, max_length=16384)
    token: str | None = Field(None, max_length=16384)
    snmp_community: str | None = Field(None, max_length=512)
    # SSH key / cert support — FE was sending these as part of
    # ``ssh_key`` credentials but the create endpoint silently
    # dropped them, leaving SSH-key credentials broken at every
    # vendor that needed one.
    ssh_private_key: str | None = Field(None, max_length=16384)
    certificate: str | None = Field(None, max_length=16384)
    is_default: bool = False
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("options")
    @classmethod
    def _options_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_options_size(v) or v


class CredentialUpdate(BaseSchema):
    """Update an existing credential."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    credential_type: CredentialType | None = None
    scope: CredentialScope | None = None
    vendor: str | None = Field(None, max_length=128)
    site_id: UUID | None = None
    username: str | None = Field(None, max_length=512)
    password: str | None = Field(None, max_length=16384)
    api_key: str | None = Field(None, max_length=16384)
    token: str | None = Field(None, max_length=16384)
    snmp_community: str | None = Field(None, max_length=512)
    ssh_private_key: str | None = Field(None, max_length=16384)
    certificate: str | None = Field(None, max_length=16384)
    is_default: bool | None = None
    options: dict[str, Any] | None = None

    @field_validator("options")
    @classmethod
    def _options_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_options_size(v)


class CredentialResponse(BaseSchema):
    """Credential response (passwords are never exposed)."""

    id: UUID
    name: str
    description: str | None
    credential_type: CredentialType
    scope: CredentialScope
    vendor: str | None
    site_id: UUID | None
    username: str | None
    is_default: bool
    is_active: bool
    last_used: datetime | None
    last_test_result: str | None
    options: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    # Computed
    devices_count: int = 0


class CredentialTestRequest(BaseSchema):
    """Test a credential against a target."""

    # ``target_ip`` was ``str`` with no constraint — accepted URL-shape
    # injections like ``trusted.com/admin?x=`` or ``user:pass@evil.com``.
    # Capped at 253 chars (DNS max) + restricted to
    # ``[A-Za-z0-9.:_\-\[\]]`` so an attacker can't smuggle URL
    # operators (``@`` / ``/`` / ``?`` / ``#``) into the request
    # path built downstream.
    target_ip: str = Field(..., min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.:_\-\[\]]+$")
    # IANA ports are 1-65535. ``port=-1`` or ``999999`` previously
    # produced "Test failed: " (empty error) — Python's int parse
    # accepted them and httpx rejected silently.
    port: int | None = Field(None, ge=1, le=65535)
    driver_id: str | None = Field(None, max_length=64)
    verify_ssl: bool = True
    # Explicit opt-in for HTTP fallback. Default ``False`` because the
    # previous behaviour silently fell through to HTTP on any HTTPS
    # failure, leaking the decrypted basic-auth username + password in
    # cleartext over the wire.
    allow_plaintext_http: bool = False


class CredentialTestResponse(BaseSchema):
    """Result of credential test."""

    success: bool
    message: str
    device_info: dict[str, Any] | None = None
    capabilities: list[str] = Field(default_factory=list)
