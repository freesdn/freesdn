# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Immutable deployment bounds; neither SaaS entitlements nor free-disk proof."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.core.agent_release_storage_root import canonical_release_storage_path

if TYPE_CHECKING:
    from app.core.config import Settings


@dataclass(frozen=True, repr=False)
class ReleaseRuntimePolicy:
    legacy_root: str
    managed_root: str
    global_history: int
    organization_history: int
    global_owned_bytes: int
    organization_owned_bytes: int

    def __post_init__(self) -> None:
        canonical_release_storage_path(self.legacy_root)
        canonical_release_storage_path(self.managed_root)
        if self.managed_root == self.legacy_root or self.legacy_root.startswith(
            self.managed_root + "/"
        ):
            raise ValueError("Managed release storage must not contain or replace legacy storage")
        for value in (
            self.global_history,
            self.organization_history,
            self.global_owned_bytes,
            self.organization_owned_bytes,
        ):
            if type(value) is not int or not 1 <= value <= 9223372036854775807:
                raise ValueError("Release storage budgets require positive bounded integers")
        if (
            self.organization_history > self.global_history
            or self.organization_owned_bytes > self.global_owned_bytes
        ):
            raise ValueError("Organization release budgets cannot exceed deployment budgets")

    @classmethod
    def from_settings(cls, settings: Settings) -> ReleaseRuntimePolicy:
        legacy = settings.FREESDN_AGENT_RELEASE_DIR
        root = settings.FREESDN_AGENT_MANAGED_RELEASE_DIR or legacy + "/.managed-v1"
        return cls(
            legacy,
            root,
            settings.FREESDN_AGENT_RELEASE_GLOBAL_HISTORY_LIMIT,
            settings.FREESDN_AGENT_RELEASE_ORG_HISTORY_LIMIT,
            settings.FREESDN_AGENT_RELEASE_GLOBAL_BYTE_LIMIT,
            settings.FREESDN_AGENT_RELEASE_ORG_BYTE_LIMIT,
        )
