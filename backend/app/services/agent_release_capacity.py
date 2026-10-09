# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Declared payload accounting, not physical disk or retained-history quotas."""

from sqlalchemy import exists
from sqlalchemy.sql.elements import ColumnElement

from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease


def charged_owned_publications() -> ColumnElement[bool]:
    """Count each birth once until its exact authorized cleanup is recorded.

    The caller must retain the journal table fence. Only the owned cleanup service
    may record cleaned after actual storage verification; metadata alone is not a
    disk measurement, and restore/reconciliation must not infer storage from it.
    """
    publication = AgentReleaseOperation.__table__
    c = publication.c
    d = publication.alias("completed_owned_deletion").c
    live = exists().where(AgentRelease.id == c.release_id).correlate(publication)
    deleted_and_cleaned = (
        exists()
        .where(
            c.phase == "decided",
            c.decision == "published",
            d.kind == "delete",
            d.storage_kind == "owned",
            d.phase == "cleaned",
            d.decision == "deleted",
            d.release_id == c.release_id,
            d.artifact_id == c.artifact_id,
            d.organization_id.is_not_distinct_from(c.organization_id),
            d.expected_sha256 == c.expected_sha256,
            d.expected_size == c.expected_size,
            ~live,
        )
        .correlate(publication)
    )
    return (
        (c.kind == "publish")
        & (c.storage_kind == "owned")
        & (c.phase != "cleaned")
        & ~deleted_and_cleaned
    )
