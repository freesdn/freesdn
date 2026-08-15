# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Agent Download Schemas
=====================================

Request/Response schemas for agent release management and downloads.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# =============================================================================
# Agent Release
# =============================================================================


class AgentReleaseCreate(BaseSchema):
    """Admin request to publish a new agent release."""

    version: str = Field(min_length=1, max_length=50, examples=["0.4.0"])
    platform: str = Field(min_length=1, max_length=50, examples=["windows"])
    agent_type: str = Field(default="daemon", max_length=50, examples=["daemon", "desktop"])
    download_url: str = Field(min_length=1, max_length=500)
    checksum_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    # ``file_size`` is metadata only (actual bytes verified by the
    # SHA256 above) but a 10 EB ``file_size`` shown in the FE would
    # look bogus. Cap at 10 GiB which is far past any sane agent.
    file_size: int = Field(ge=0, le=10 * 1024**3)
    # ``release_notes`` was unbounded — a 100 KB blob was happily
    # 201'd and re-rendered on every Downloads-page load.
    release_notes: str = Field(default="", max_length=20000)
    min_backend_version: str = Field(default="", max_length=50)
    is_prerelease: bool = False

    @field_validator("download_url")
    @classmethod
    def validate_download_url(cls, v: str) -> str:
        # SECURITY: previously accepted ``http://`` plaintext. Agents
        # download a signed binary from this URL and execute it — a
        # plaintext URL allows a MITM to swap the installer with a
        # malicious one. The SHA256 in ``checksum_sha256`` is meant to
        # catch that BUT the checksum itself comes from the same admin
        # response shape, so a compromised admin endpoint could ship
        # matching {url, checksum} pairs. Defense in depth: require
        # HTTPS (or a relative path mounted by this backend) at the
        # input layer.
        if v.startswith("/"):
            return v
        if v.startswith("https://"):
            return v
        if v.startswith("http://"):
            raise ValueError(
                "download_url must use https:// (plaintext HTTP allows "
                "MITM swap of the agent installer binary)"
            )
        raise ValueError("download_url must be a relative path or an https:// URL")


class AgentReleaseResponse(BaseSchema):
    """Full agent release record."""

    id: UUID
    version: str
    platform: str
    agent_type: str
    download_url: str
    checksum_sha256: str
    signature: str | None = None
    file_size: int
    release_notes: str
    min_backend_version: str
    is_latest: bool
    is_prerelease: bool
    published_at: datetime
    download_count: int


class AgentReleaseSummary(BaseSchema):
    """Compact release info for version listings."""

    version: str
    platforms: list[str] = Field(default_factory=list)
    agent_types: list[str] = Field(default_factory=list)
    release_date: datetime
    is_latest: bool
    is_prerelease: bool


class AgentReleaseLatest(BaseSchema):
    """Response for "latest release" queries."""

    version: str
    platform: str
    agent_type: str
    download_url: str
    checksum_sha256: str
    file_size: int
    release_notes: str


# =============================================================================
# Update Check
# =============================================================================


class AgentUpdateCheckResponse(BaseSchema):
    """Response for agent self-update check."""

    update_available: bool
    latest_version: str = ""
    download_url: str = ""
    checksum_sha256: str = ""
    release_notes: str = ""
    # ECDSA-P256 signature of the SHA-256 (base64 ASN.1 DER). Empty on
    # legacy releases that pre-date the signing chapter — agent treats
    # empty as "skip signature verify" for backward compat.
    signature: str = ""


# =============================================================================
# Install Instructions
# =============================================================================


class PlatformInstallInfo(BaseSchema):
    """Install instructions and download link for a single platform."""

    platform: str
    display_name: str
    icon: str = ""
    daemon: AgentReleaseLatest | None = None
    desktop: AgentReleaseLatest | None = None
    install_commands: list[str] = Field(default_factory=list)


class DownloadsPageResponse(BaseSchema):
    """Aggregated response for the frontend Downloads page."""

    platforms: list[PlatformInstallInfo] = Field(default_factory=list)
    latest_version: str = ""
    server_version: str = ""
