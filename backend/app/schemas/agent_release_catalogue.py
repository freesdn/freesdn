# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Finite catalogue observations, not signature verification or mutation grants."""

from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class LegacyCatalogueRecord(BaseModel):
    """Keep the old response fields; reject rather than silently truncate a row."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    id: UUID
    version: StrictStr = Field(max_length=50)
    platform: StrictStr = Field(max_length=50)
    agent_type: StrictStr = Field(max_length=50)
    download_url: StrictStr = Field(max_length=500)
    checksum_sha256: StrictStr = Field(max_length=64)
    signature: StrictStr | None = Field(max_length=4096)
    file_size: StrictInt = Field(ge=0, le=10737418240)
    release_notes: StrictStr = Field(max_length=20000)
    min_backend_version: StrictStr = Field(max_length=50)
    is_latest: StrictBool
    is_prerelease: StrictBool
    published_at: AwareDatetime
    download_count: StrictInt = Field(ge=0, le=2147483647)


class CatalogueRecord(LegacyCatalogueRecord):
    organization_id: UUID | None


class CataloguePage(BaseModel):
    """Keyset navigation is an observation, not a transaction across pages."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    items: list[CatalogueRecord] = Field(max_length=100)
    limit: StrictInt = Field(ge=1, le=100)
    has_more: StrictBool
    next_published_at: AwareDatetime | None
    next_id: UUID | None
