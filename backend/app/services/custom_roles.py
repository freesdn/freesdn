# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Custom Roles Service
==================================

Org-scoped CRUD for DB-backed custom RBAC roles (``core.custom_roles``).

System roles (defined in ``app.core.dependencies``) are NOT stored here — the
roles endpoint synthesizes them and merges them with this service's output for
the list view. This service only manages persisted custom roles, always scoped
to a single organization. System roles can never be edited or deleted through
it.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CustomRole

logger = logging.getLogger(__name__)

_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def _slugify(value: str) -> str:
    """Normalize an arbitrary name to a slug (lowercase, dash-separated)."""
    s = value.strip().lower().replace(" ", "-")
    s = _SLUG_RE.sub("", s)
    return s.strip("-") or "role"


class CustomRoleService:
    """Service for managing org-scoped custom roles."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_for_org(self, organization_id: UUID) -> list[CustomRole]:
        """Return all (non-deleted) custom roles for an organization."""
        result = await self.session.execute(
            select(CustomRole)
            .where(
                CustomRole.organization_id == organization_id,
                CustomRole.deleted_at.is_(None),
            )
            .order_by(CustomRole.level.desc(), CustomRole.name.asc())
        )
        return list(result.scalars().all())

    async def get_for_org(self, role_id: UUID, organization_id: UUID) -> CustomRole | None:
        """Fetch a single custom role, org-scoped. Returns None if not found."""
        result = await self.session.execute(
            select(CustomRole).where(
                CustomRole.id == role_id,
                CustomRole.organization_id == organization_id,
                CustomRole.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def _slug_taken(
        self,
        organization_id: UUID,
        slug: str,
        exclude_id: UUID | None = None,
    ) -> bool:
        stmt = select(CustomRole.id).where(
            CustomRole.organization_id == organization_id,
            CustomRole.slug == slug,
            CustomRole.deleted_at.is_(None),
        )
        if exclude_id is not None:
            stmt = stmt.where(CustomRole.id != exclude_id)
        result = await self.session.execute(stmt)
        return result.first() is not None

    async def create(
        self,
        *,
        organization_id: UUID,
        name: str,
        permissions: list[str],
        slug: str | None = None,
        description: str | None = None,
        level: int = 50,
        is_default: bool = False,
        created_by: UUID | None = None,
    ) -> CustomRole:
        """Create a new org-scoped custom role."""
        final_slug = _slugify(slug or name)

        if await self._slug_taken(organization_id, final_slug):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A role with slug '{final_slug}' already exists in this organization",
            )

        role = CustomRole(
            organization_id=organization_id,
            name=name.strip(),
            slug=final_slug,
            description=(description or "").strip() or None,
            permissions=list(permissions or []),
            level=max(1, min(100, level)),
            is_default=is_default,
            is_system=False,
            created_by=created_by,
            updated_by=created_by,
        )
        self.session.add(role)
        await self.session.commit()
        await self.session.refresh(role)
        logger.info(
            "Custom role created: org=%s slug=%s id=%s",
            organization_id,
            final_slug,
            role.id,
        )
        return role

    async def update(
        self,
        *,
        role_id: UUID,
        organization_id: UUID,
        updated_by: UUID | None = None,
        name: str | None = None,
        slug: str | None = None,
        description: str | None = None,
        permissions: list[str] | None = None,
        level: int | None = None,
        is_default: bool | None = None,
    ) -> CustomRole:
        """Update an existing org-scoped custom role.

        Raises 404 if the role does not exist within the org.
        """
        role = await self.get_for_org(role_id, organization_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Custom role not found",
            )

        if name is not None:
            role.name = name.strip()
        if slug is not None:
            new_slug = _slugify(slug)
            if new_slug != role.slug and await self._slug_taken(
                organization_id, new_slug, exclude_id=role.id
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"A role with slug '{new_slug}' already exists in this organization",
                )
            role.slug = new_slug
        if description is not None:
            role.description = description.strip() or None
        if permissions is not None:
            role.permissions = list(permissions)
        if level is not None:
            role.level = max(1, min(100, level))
        if is_default is not None:
            role.is_default = is_default

        role.updated_by = updated_by
        await self.session.commit()
        await self.session.refresh(role)
        return role

    async def delete(self, *, role_id: UUID, organization_id: UUID) -> None:
        """Soft-delete an org-scoped custom role. Raises 404 if not found."""
        role = await self.get_for_org(role_id, organization_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Custom role not found",
            )
        role.deleted_at = datetime.now(UTC)
        await self.session.commit()
        logger.info("Custom role deleted: org=%s id=%s", organization_id, role_id)
