# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Access Control Module Models
==========================================

Database models for physical access control.

NOTE (C2): Card numbers, facility codes, and PINs were previously stored
plaintext despite a misleading "# Hashed" comment. They are now:

  * ``AccessCredential.pin``           — Argon2id hash (verify via
    :func:`app.core.security.verify_password`).
  * ``AccessCredential.card_number``   — Fernet-encrypted at rest
    (:func:`app.core.crypto.encrypt_credential`).
  * ``AccessCredential.facility_code`` — Fernet-encrypted at rest.

Use the ``set_pin`` / ``set_card_number`` / ``set_facility_code`` helpers
to assign plaintext, and the ``get_card_number`` / ``get_facility_code``
helpers to read it back. ``verify_pin`` checks a plaintext PIN against
the stored hash. The raw column attributes still exist for SQLAlchemy
serialization but should NOT be read directly outside this module.
"""

from datetime import date, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.core.security import get_password_hash, verify_password
from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin


class DoorStatus(StrEnum):
    """Door status."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    OPEN = "open"
    FORCED = "forced"
    HELD_OPEN = "held_open"
    OFFLINE = "offline"


class CredentialType(StrEnum):
    """Credential type."""

    CARD = "card"
    PIN = "pin"
    CARD_PIN = "card_pin"
    FINGERPRINT = "fingerprint"
    FACE = "face"
    MOBILE = "mobile"


class EventType(StrEnum):
    """Access event type."""

    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    DOOR_FORCED = "door_forced"
    DOOR_HELD_OPEN = "door_held_open"
    DOOR_UNLOCKED = "door_unlocked"
    DOOR_LOCKED = "door_locked"
    ALARM = "alarm"


class AccessController(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Access Control Panel/Controller.
    """

    __tablename__ = "controllers"
    __table_args__ = (
        Index("ix_access_controllers_site_id", "site_id"),
        {"schema": "access"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_controller_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Connection
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=80)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    # Device Info
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Capacity
    door_capacity: Mapped[int] = mapped_column(Integer, default=4)
    reader_capacity: Mapped[int] = mapped_column(Integer, default=8)

    # Status
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    doors: Mapped[list["Door"]] = relationship("Door", back_populates="controller")
    readers: Mapped[list["Reader"]] = relationship("Reader", back_populates="controller")


class Door(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Physical door.
    """

    __tablename__ = "doors"
    __table_args__ = (
        Index("ix_doors_site_id", "site_id"),
        Index("ix_doors_controller_id", "controller_id"),
        Index("ix_doors_status", "status"),
        {"schema": "access"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    controller_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.controllers.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    door_number: Mapped[int] = mapped_column(Integer, default=1)

    # Status
    status: Mapped[str] = mapped_column(String(20), default=DoorStatus.OFFLINE.value)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status_change: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Configuration
    unlock_time: Mapped[int] = mapped_column(Integer, default=5)  # seconds
    held_open_time: Mapped[int] = mapped_column(Integer, default=30)  # seconds before alarm

    # Schedule
    default_schedule_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.schedules.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Location
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    floor: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Relationships
    controller: Mapped["AccessController"] = relationship(
        "AccessController", back_populates="doors"
    )
    readers: Mapped[list["Reader"]] = relationship("Reader", back_populates="door")
    events: Mapped[list["AccessEvent"]] = relationship("AccessEvent", back_populates="door")


class Reader(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Card/credential reader.
    """

    __tablename__ = "readers"
    __table_args__ = (
        Index("ix_readers_door_id", "door_id"),
        Index("ix_readers_controller_id", "controller_id"),
        {"schema": "access"},
    )

    # Foreign Keys
    controller_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.controllers.id", ondelete="CASCADE"),
        nullable=False,
    )
    door_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.doors.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    reader_number: Mapped[int] = mapped_column(Integer, default=1)
    reader_type: Mapped[str] = mapped_column(String(50), default="entry")  # entry, exit

    # Technology
    credential_type: Mapped[str] = mapped_column(String(50), default=CredentialType.CARD.value)

    # Status
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    controller: Mapped["AccessController"] = relationship(
        "AccessController", back_populates="readers"
    )
    door: Mapped["Door"] = relationship("Door", back_populates="readers")


class Cardholder(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Person with access credentials.
    """

    __tablename__ = "cardholders"
    __table_args__ = (
        Index("ix_cardholders_site_id", "site_id"),
        Index("ix_cardholders_employee_id", "employee_id"),
        {"schema": "access"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Personal Info
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Employment
    employee_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    department: Mapped[str | None] = mapped_column(String(100), nullable=True)
    title: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Access
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    activation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiration_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # Photo
    photo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    credentials: Mapped[list["AccessCredential"]] = relationship(
        "AccessCredential", back_populates="cardholder"
    )


# Renamed from ``Credential`` to disambiguate from
# ``app.models.core.Credential`` (vendor/device credentials). Both classes
# inherit from the same SQLAlchemy ``Base`` and a shared registry, so they
# must have unique class names — otherwise relationship strings like
# ``relationship("Credential")`` are ambiguous and SA raises
# ``InvalidRequestError`` at first ORM access.
class AccessCredential(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Access credential (card, PIN, biometric, etc.) for physical access control.
    """

    __tablename__ = "credentials"
    __table_args__ = (
        Index("ix_credentials_cardholder_id", "cardholder_id"),
        Index("ix_credentials_card_number", "card_number"),
        {"schema": "access"},
    )

    # Foreign Keys
    cardholder_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.cardholders.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Credential Info
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # NOTE (C2): card_number + facility_code are Fernet ciphertexts at rest.
    # Length widened to 512 to accommodate the base64 token (a Fernet token
    # for a typical card number is ~100-180 chars). Use the helper methods
    # below — never assign plaintext directly to these attributes.
    card_number: Mapped[str | None] = mapped_column(String(512), nullable=True)
    facility_code: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # NOTE (C2): pin is an Argon2id hash. Argon2id digests are ~95 chars,
    # we keep 255 chars of headroom for future algorithm migration.
    pin: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    activation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiration_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # Last Usage
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_door_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    cardholder: Mapped["Cardholder"] = relationship("Cardholder", back_populates="credentials")

    # ── Encryption / hash helpers (C2) ──────────────────────────────────────
    def set_pin(self, plaintext: str | None) -> None:
        """Hash a plaintext PIN with Argon2id and store it.

        Pass ``None`` to clear the PIN.
        """
        if plaintext is None or plaintext == "":
            self.pin = None
            return
        self.pin = get_password_hash(plaintext)

    def verify_pin(self, plaintext: str) -> bool:
        """Return True if ``plaintext`` matches the stored PIN hash.

        NOTE (H6): When a /verify_pin endpoint is implemented (or wired
        into a door-controller integration callback), it MUST be placed
        behind :class:`app.core.middleware.RateLimitMiddleware` keyed by
        ``(door_id, credential_id)`` to prevent keypad brute-force.
        """
        if not self.pin or not plaintext:
            return False
        try:
            return verify_password(plaintext, self.pin)
        except Exception:
            return False

    def set_card_number(self, plaintext: str | None) -> None:
        """Encrypt a plaintext card number with Fernet and store it."""
        if plaintext is None or plaintext == "":
            self.card_number = None
            return
        self.card_number = encrypt_credential(plaintext)

    def get_card_number(self) -> str | None:
        """Return the decrypted card number, or ``None`` if unset."""
        if not self.card_number:
            return None
        # Tolerate legacy plaintext rows written before migration 013.
        if not is_encrypted(self.card_number):
            return self.card_number
        try:
            return decrypt_credential(self.card_number)
        except ValueError:
            return None

    def set_facility_code(self, plaintext: str | None) -> None:
        """Encrypt a plaintext facility code with Fernet and store it."""
        if plaintext is None or plaintext == "":
            self.facility_code = None
            return
        self.facility_code = encrypt_credential(plaintext)

    def get_facility_code(self) -> str | None:
        """Return the decrypted facility code, or ``None`` if unset."""
        if not self.facility_code:
            return None
        if not is_encrypted(self.facility_code):
            return self.facility_code
        try:
            return decrypt_credential(self.facility_code)
        except ValueError:
            return None

    # ── Presence flags ────────────────────────────────────────
    # Let API responses indicate whether a secret is set WITHOUT ever exposing
    # the Argon2id PIN hash or the Fernet card/facility ciphertext.
    @property
    def has_pin(self) -> bool:
        return bool(self.pin)

    @property
    def has_card_number(self) -> bool:
        return bool(self.card_number)

    @property
    def has_facility_code(self) -> bool:
        return bool(self.facility_code)


class AccessSchedule(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Access time schedule/time zone.
    """

    __tablename__ = "schedules"
    __table_args__ = (
        Index("ix_schedules_site_id", "site_id"),
        {"schema": "access"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Schedule Type
    is_24_7: Mapped[bool] = mapped_column(Boolean, default=False)

    # Time Intervals (JSON array of intervals)
    # Example: [{"day": "monday", "start": "08:00", "end": "18:00"}]
    intervals: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Holiday handling
    honor_holidays: Mapped[bool] = mapped_column(Boolean, default=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AccessEvent(Base, UUIDMixin):
    """
    Access event log entry.
    """

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_access_events_door_id", "door_id"),
        Index("ix_access_events_timestamp", "timestamp"),
        Index("ix_access_events_event_type", "event_type"),
        Index("ix_access_events_credential_id", "credential_id"),
        # Tamper-evidence hash-chain index — mirrors migration 015.
        Index(
            "ix_access_events_row_hmac", "row_hmac", postgresql_where=text("row_hmac IS NOT NULL")
        ),
        {"schema": "access"},
    )

    # Foreign Keys
    door_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.doors.id", ondelete="SET NULL"),
        nullable=True,
    )
    credential_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    cardholder_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("access.cardholders.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Event Info
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Card Data
    card_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Details
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Acknowledgement
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # NOTE (H1): Tamper-evidence hash chain — see ``AuditLogRecord`` for
    # the canonical pattern. ``prev_hash`` is the previous chained row's
    # HMAC; ``row_hmac`` is HMAC-SHA256 of ``prev_hash || canonical_json``
    # keyed by ``settings.AUDIT_HMAC_KEY``. Both are nullable so existing
    # rows (and any rows written before migration 013) remain valid; the
    # validator reports them as ``unchained`` rather than tampered.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Relationships
    door: Mapped["Door | None"] = relationship("Door", back_populates="events")
