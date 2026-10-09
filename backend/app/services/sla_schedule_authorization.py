# SPDX-License-Identifier: AGPL-3.0-only
"""Keep scheduled reports within the authority explicitly approved for them."""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.dependencies import CurrentUser, _load_user_permissions
from app.core.tenancy import tenant_filter
from app.models.core import User
from app.models.sla import SLAPolicy, SLAReportSchedule
from app.services.sla import SLAMonitoringService


class ScheduleAuthorizationError(RuntimeError):
    """The schedule needs review and explicit approval by an authorized user."""


def approval_scope(user: CurrentUser) -> dict[str, Any]:
    """Capture the approving credential's ceiling, including restricted API keys."""
    return {
        "version": 1,
        "actor_id": str(user.id),
        "permissions": [p for p in ("config:read", "config:write") if user.has_permission(p)],
        "site_ids": sorted(str(site) for site in user.accessible_site_ids)
        if user.is_site_limited
        else None,
    }


async def capture_schedule_approval(
    db: AsyncSession, user: CurrentUser, org_id: UUID, policy_ids: list[str]
) -> dict[str, Any]:
    scope = approval_scope(user)
    ids = {UUID(str(value)) for value in policy_ids}
    rows = (
        await db.execute(
            select(SLAPolicy.id, SLAPolicy.scope, SLAPolicy.scope_id).where(
                tenant_filter(SLAPolicy, user),
                SLAPolicy.organization_id == org_id,
                SLAPolicy.id.in_(ids),
            )
        )
    ).all()
    if {row.id for row in rows} != ids:
        raise ScheduleAuthorizationError("policy_scope_changed")
    scope["policy_scopes"] = {
        str(row.id): {"scope": row.scope, "scope_id": str(row.scope_id)} for row in rows
    }
    return scope


class SchedulePrincipal(CurrentUser):
    """An approved site ceiling still applies if its actor is later promoted."""

    limited: bool = False

    @property
    def is_site_limited(self) -> bool:
        return self.limited


async def authorize_schedule(db: AsyncSession, schedule: SLAReportSchedule) -> CurrentUser:
    scope = schedule.execution_scope
    if not isinstance(scope, dict) or scope.get("version") != 1:
        raise ScheduleAuthorizationError("approval_required")
    try:
        actor_id = UUID(scope["actor_id"])
        permissions = scope["permissions"]
        sites = scope["site_ids"]
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
            raise ValueError("invalid permission ceiling")
        if sites is not None and not isinstance(sites, list):
            raise ValueError("invalid site ceiling")
        ceiling = {UUID(site) for site in sites} if sites is not None else None
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ScheduleAuthorizationError("approval_required") from exc

    # Authentication lookup by stored identity, deliberately not by organization:
    # platform admins may approve a schedule in a different organization.
    user = (
        await db.execute(
            select(User)
            .options(selectinload(User.site_access))
            .where(User.id == actor_id, User.deleted_at.is_(None), User.is_active.is_(True))
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if user is None:
        raise ScheduleAuthorizationError("actor_unavailable")
    grants = {grant.site_id for grant in user.site_access}
    live = CurrentUser(user, await _load_user_permissions(user), accessible_site_ids=grants)
    approved = SchedulePrincipal(user, permissions, scoped=True)
    if not live.has_permission("config:write") or not approved.has_permission("config:write"):
        raise ScheduleAuthorizationError("permission_revoked")
    if not live.is_superuser and live.organization_id != schedule.organization_id:
        raise ScheduleAuthorizationError("organization_changed")

    if ceiling is not None:
        # Removing the last explicit grant must not resurrect an old schedule as
        # unrestricted through the application's legacy zero-grant convention.
        approved.limited = True
        approved._accessible_site_ids = ceiling if live.is_org_admin else ceiling & grants
    elif live.is_site_limited:
        approved.limited = True
        approved._accessible_site_ids = grants

    try:
        ids = {UUID(str(value)) for value in schedule.sla_policy_ids}
    except (ValueError, TypeError) as exc:
        raise ScheduleAuthorizationError("policy_scope_changed") from exc
    if not ids and approved.is_site_limited:
        raise ScheduleAuthorizationError("policy_scope_changed")
    if ids:
        # Tenant filtering uses the live principal (including platform admin
        # authority); the saved site ceiling is an additional, narrower filter.
        query = select(SLAPolicy.id, SLAPolicy.scope, SLAPolicy.scope_id).where(
            tenant_filter(SLAPolicy, live),
            SLAPolicy.organization_id == schedule.organization_id,
            SLAPolicy.id.in_(ids),
        )
        predicate = SLAMonitoringService._policy_grant_predicate(approved)
        if predicate is not None:
            query = query.where(predicate)
        rows = (await db.execute(query)).all()
        visible = {row.id for row in rows}
        current_scopes = {
            str(row.id): {"scope": row.scope, "scope_id": str(row.scope_id)} for row in rows
        }
        if visible != ids or current_scopes != scope.get("policy_scopes"):
            raise ScheduleAuthorizationError("policy_scope_changed")
    return approved
