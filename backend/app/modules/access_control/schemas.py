# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Access Control Module Pydantic Schemas
=================================================

Request/response schemas for the Access Control API.

NOTE (C3): These schemas back the explicit field whitelist the API uses
when accepting Door / Credential / Cardholder / Schedule / Controller
input. Replacing the previous ``dict[str, Any]`` body parameters closes
a mass-assignment hole that let callers set foreign-key columns
(``site_id``, ``controller_id``, ``cardholder_id``) belonging to other
organizations.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# =============================================================================
# Door schemas
# =============================================================================


class DoorCreate(BaseModel):
    """Validated body for ``POST /access/doors``.

    NOTE (C1): ``site_id`` + ``controller_id`` are accepted from the body
    but the service pre-validates they belong to the caller's org before
    creating the row.
    """

    model_config = ConfigDict(extra="forbid")

    site_id: UUID
    controller_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    door_number: int = Field(1, ge=1, le=65535)
    unlock_time: int = Field(5, ge=1, le=300)
    held_open_time: int = Field(30, ge=1, le=3600)
    default_schedule_id: UUID | None = None
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=50)
    settings: dict[str, Any] = Field(default_factory=dict)


class DoorUpdate(BaseModel):
    """Validated body for ``PATCH /access/doors/{id}``.

    Note that FK columns are intentionally omitted — once a door is
    created, moving it between sites/controllers should be a separate
    explicit operation, not a casual PATCH.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    door_number: int | None = Field(None, ge=1, le=65535)
    unlock_time: int | None = Field(None, ge=1, le=300)
    held_open_time: int | None = Field(None, ge=1, le=3600)
    default_schedule_id: UUID | None = None
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=50)
    settings: dict[str, Any] | None = None


# =============================================================================
# Credential schemas
# =============================================================================


class CredentialCreate(BaseModel):
    """Validated body for ``POST /access/credentials``.

    NOTE (C2): ``pin`` is hashed at the service layer (Argon2id) before
    persistence; ``card_number`` + ``facility_code`` are encrypted via
    Fernet. Callers MUST send plaintext here — the model never returns
    these values back out.
    """

    model_config = ConfigDict(extra="forbid")

    cardholder_id: UUID
    credential_type: str = Field(..., min_length=1, max_length=50)
    card_number: str | None = Field(None, max_length=100)
    facility_code: str | None = Field(None, max_length=20)
    pin: str | None = Field(None, min_length=4, max_length=32)
    is_active: bool = True
    activation_date: date | None = None
    expiration_date: date | None = None
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pin")
    @classmethod
    def _pin_digits(cls, v: str | None) -> str | None:
        # Keypad PINs are numeric in practice; reject control chars but
        # accept anything else to leave room for alpha-PIN credentials.
        if v is not None and not v.isprintable():
            raise ValueError("pin must contain only printable characters")
        return v


class CredentialUpdate(BaseModel):
    """Validated body for ``PATCH /access/credentials/{id}``.

    ``cardholder_id`` is omitted — re-assigning a credential to a
    different cardholder should go through an explicit transfer flow.
    """

    model_config = ConfigDict(extra="forbid")

    credential_type: str | None = Field(None, min_length=1, max_length=50)
    card_number: str | None = Field(None, max_length=100)
    facility_code: str | None = Field(None, max_length=20)
    pin: str | None = Field(None, min_length=4, max_length=32)
    is_active: bool | None = None
    activation_date: date | None = None
    expiration_date: date | None = None
    settings: dict[str, Any] | None = None


class AccessCredentialResponse(BaseModel):
    """Safe wire representation for an AccessCredential.

    the credential routes previously returned the raw ORM object
    (no response_model), serializing the Argon2id ``pin`` hash and the Fernet
    ``card_number`` / ``facility_code`` ciphertext to anyone with the
    lowest-tier ``access.view`` permission. This allowlist NEVER includes those
    columns; presence is surfaced via the has_* flags so the UI can still show
    "PIN set" without the secret.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cardholder_id: UUID
    credential_type: str
    is_active: bool
    activation_date: date | None = None
    expiration_date: date | None = None
    last_used: datetime | None = None
    last_door_id: UUID | None = None
    settings: dict[str, Any] = Field(default_factory=dict)
    has_pin: bool = False
    has_card_number: bool = False
    has_facility_code: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AccessCredentialListResponse(BaseModel):
    """Paginated wrapper for credential listings (no sensitive columns)."""

    items: list[AccessCredentialResponse]
    total: int


# =============================================================================
# Cardholder schemas
# =============================================================================


class CardholderCreate(BaseModel):
    """Validated body for ``POST /access/cardholders``."""

    model_config = ConfigDict(extra="forbid")

    site_id: UUID
    user_id: UUID | None = None
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: str | None = Field(None, max_length=255)
    phone: str | None = Field(None, max_length=50)
    employee_id: str | None = Field(None, max_length=50)
    department: str | None = Field(None, max_length=100)
    title: str | None = Field(None, max_length=100)
    is_active: bool = True
    activation_date: date | None = None
    expiration_date: date | None = None
    photo_url: str | None = Field(None, max_length=500)
    settings: dict[str, Any] = Field(default_factory=dict)


class CardholderUpdate(BaseModel):
    """Validated body for ``PATCH /access/cardholders/{id}``."""

    model_config = ConfigDict(extra="forbid")

    first_name: str | None = Field(None, min_length=1, max_length=100)
    last_name: str | None = Field(None, min_length=1, max_length=100)
    email: str | None = Field(None, max_length=255)
    phone: str | None = Field(None, max_length=50)
    employee_id: str | None = Field(None, max_length=50)
    department: str | None = Field(None, max_length=100)
    title: str | None = Field(None, max_length=100)
    is_active: bool | None = None
    activation_date: date | None = None
    expiration_date: date | None = None
    photo_url: str | None = Field(None, max_length=500)
    settings: dict[str, Any] | None = None


# =============================================================================
# Schedule schemas
# =============================================================================


class ScheduleCreate(BaseModel):
    """Validated body for ``POST /access/schedules``."""

    model_config = ConfigDict(extra="forbid")

    site_id: UUID
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    is_24_7: bool = False
    intervals: list[dict[str, Any]] = Field(default_factory=list)
    honor_holidays: bool = True
    is_active: bool = True


class ScheduleUpdate(BaseModel):
    """Validated body for ``PATCH /access/schedules/{id}``."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    is_24_7: bool | None = None
    intervals: list[dict[str, Any]] | None = None
    honor_holidays: bool | None = None
    is_active: bool | None = None


# =============================================================================
# Controller schemas
# =============================================================================


class ControllerCreate(BaseModel):
    """Validated body for ``POST /access/controllers``."""

    model_config = ConfigDict(extra="forbid")

    site_id: UUID
    device_controller_id: UUID | None = None
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    ip_address: str = Field(..., min_length=1, max_length=45)
    port: int = Field(80, ge=1, le=65535)
    mac_address: str | None = Field(None, max_length=17)
    vendor: str | None = Field(None, max_length=100)
    model: str | None = Field(None, max_length=100)
    firmware_version: str | None = Field(None, max_length=50)
    serial_number: str | None = Field(None, max_length=100)
    door_capacity: int = Field(4, ge=1, le=128)
    reader_capacity: int = Field(8, ge=1, le=256)
    settings: dict[str, Any] = Field(default_factory=dict)


class ControllerUpdate(BaseModel):
    """Validated body for ``PATCH /access/controllers/{id}``."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4096)
    ip_address: str | None = Field(None, min_length=1, max_length=45)
    port: int | None = Field(None, ge=1, le=65535)
    mac_address: str | None = Field(None, max_length=17)
    vendor: str | None = Field(None, max_length=100)
    model: str | None = Field(None, max_length=100)
    firmware_version: str | None = Field(None, max_length=50)
    serial_number: str | None = Field(None, max_length=100)
    door_capacity: int | None = Field(None, ge=1, le=128)
    reader_capacity: int | None = Field(None, ge=1, le=256)
    settings: dict[str, Any] | None = None
