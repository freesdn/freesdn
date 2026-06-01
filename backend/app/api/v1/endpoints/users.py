# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - User Endpoints
============================

User management endpoints (admin only).
"""

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import (
    is_unscoped_org_admin,
    is_unscoped_superuser,
    validate_role_assignment,
)
from app.core.security import get_password_hash
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models import Organization, User, UserRole
from app.schemas import (
    PaginatedResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)

# Roles that hold admin authority over an org (i.e. losing the last
# one would orphan the org's user management surface).
_ADMIN_ROLES = (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN)

logger = logging.getLogger(__name__)


async def _audit_user_change(
    *,
    session: AsyncSession,
    request: Request,
    action: str,
    actor: User,
    target: User,
    changes: dict[str, Any] | None = None,
) -> None:
    """Best-effort audit-log for an admin account-management change.

    Routes through ``AuditService.log`` so account create / update / delete
    events join the SAME tamper-evident hash-chain as every other audit_logs
    row, and runs on the request session so the audit row commits (and rolls
    back) atomically with the change. Admin user mutations previously wrote no
    audit trail at all, so the Security Audit page never saw account changes.
    """
    try:
        from app.services.audit import AuditService

        await AuditService(session).log(
            action=action,
            resource_type="user",
            resource_id=target.id,
            resource_name=getattr(target, "email", None),
            actor_id=actor.id,
            actor_email=getattr(actor, "email", None),
            organization_id=getattr(target, "organization_id", None),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            request_path=request.url.path,
            request_method=request.method,
            changes=changes or None,
        )
    except Exception:
        logger.debug("user-change audit write skipped", exc_info=True)


async def _count_active_admins(
    session: AsyncSession, organization_id: Any, exclude_user_id: UUID
) -> int:
    """Number of other ACTIVE admins in the org (excluding ``exclude_user_id``).

    Shared between DELETE, PATCH ``is_active=false``, and PATCH role-
    demote so all three paths apply the same last-admin guarantee.
    """
    result = await session.execute(
        select(func.count(User.id)).where(
            User.organization_id == organization_id,
            User.role.in_(_ADMIN_ROLES),
            User.id != exclude_user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
    )
    return result.scalar() or 0


async def _count_active_super_admins(session: AsyncSession, exclude_user_id: UUID) -> int:
    """Platform-wide count of OTHER active, non-deleted ``super_admin`` users.

    Unlike :func:`_count_active_admins`, this is deliberately NOT org-scoped. A
    ``super_admin`` may have ``organization_id=NULL`` (the orphaned platform-admin
    state the first-run setup flow can leave behind), and the org-scoped guards
    short-circuit on a NULL org — which would let the sole super_admin be deleted
    or demoted and silently re-open the unauthenticated ``/setup/admin`` endpoint
    (full platform takeover). This count is independent of ``organization_id`` so
    the last super_admin can never be removed, demoted, or disabled.
    """
    result = await session.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.SUPER_ADMIN,
            User.id != exclude_user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
    )
    return result.scalar() or 0


async def _assert_not_last_super_admin(session: AsyncSession, user: User, action: str) -> None:
    """Block removing/demoting/disabling the final platform super_admin.

    No-op for non-super_admin users. For a super_admin, refuses the operation
    when it would drop the platform-wide active super_admin count to zero —
    independent of ``organization_id``, so an org-NULL sole super_admin can't be
    removed and silently re-open the unauthenticated first-run setup endpoint.
    """
    if user.role != UserRole.SUPER_ADMIN:
        return
    if await _count_active_super_admins(session, exclude_user_id=user.id) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot {action} the last super admin of the platform",
        )


router = APIRouter()


def require_admin(current_user: User) -> User:
    """Check if user has admin privileges."""
    if not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def require_user_write(current_user: User, permission: str) -> User:
    """Admin gate for user-management WRITES that also honors a scoped
    credential's permission ceiling.

    SECURITY (scope-ceiling): the raw :func:`require_admin` role check ignores the
    API-key scope ceiling — a scoped key (e.g. minted ``network:read`` only) by a
    super_admin / org_admin still passed via its raw role and could create / update
    / delete users, escaping the deliberately-narrowed credential.

    Per the canonical pattern documented on ``is_unscoped_org_admin`` we gate as
    ``has_permission(perm) OR is_unscoped_org_admin``:

      * An UNSCOPED super_admin / org_admin keeps the EXACT role-based access they
        had under ``require_admin`` (no regression — org_admin need not carry the
        fine-grained ``user:*`` permission in the catalog; e.g. delete stays open
        to an unscoped org_admin even though ``user:delete`` is not in its list).
      * A SCOPED principal must explicitly hold *permission*, so a narrowed key can
        no longer mint / modify / delete users via its raw role.

    Non-admin principals (and scoped keys lacking the permission) get the same
    403 ``require_admin`` always produced.
    """
    has_perm = bool(getattr(current_user, "has_permission", None)) and current_user.has_permission(
        permission
    )
    if has_perm or is_unscoped_org_admin(current_user):
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin privileges required",
    )


def _role_str(role: Any) -> str:
    """Coerce a role value (UserRole enum / str / None) to its string name."""
    if role is None:
        return ""
    if hasattr(role, "value"):
        return str(role.value)
    return str(role)


@router.get("/", response_model=PaginatedResponse)
async def list_users(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
) -> Any:
    """
    List users with pagination.

    - Super admins see all users
    - Org admins see users in their organization
    """
    require_admin(current_user)

    # Build query based on user role
    query = select(User).where(User.deleted_at.is_(None))

    # Canonical tenant scoping (app.core.tenancy): org filter + per-user site grant
    # in one place. Behavior-identical to the prior hand-rolled
    # is_unscoped_superuser / organization_id idiom for every principal.
    query = query.where(tenant_filter(User, current_user))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await session.scalar(count_query) or 0

    # Get paginated results
    offset = (page - 1) * per_page
    result = await session.execute(
        query.order_by(User.created_at.desc()).offset(offset).limit(per_page)
    )
    users = result.scalars().all()

    return PaginatedResponse.create(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    user_data: UserCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Create a new user.

    - Super admins can create users in any organization
    - Org admins can only create users in their organization
    """
    # Scope-aware admin gate: an unscoped super_admin / org_admin keeps its
    # existing role-based access; a scoped key must explicitly hold user:create.
    require_user_write(current_user, "user:create")

    # Check email uniqueness among LIVE users only — the unique index is partial
    # (deleted_at IS NULL), so an email freed by a soft-deleted user is reusable.
    result = await session.execute(
        select(User).where(User.email == user_data.email, User.deleted_at.is_(None))
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # SECURITY: enforce strict role hierarchy — a caller can only
    # assign roles STRICTLY LOWER than their own. This prevents an org_admin
    # from minting an 'admin' (which holds organization:* cross-org perms)
    # and escaping tenant isolation.
    caller_role = _role_str(current_user.role)
    target_role = _role_str(user_data.role)
    validate_role_assignment(caller_role, target_role)

    # Non-super-admins can only create users inside their own organization.
    # scope-aware — a SCOPED super_admin key is org-confined here (it
    # must not mint accounts in another tenant), even though its role is super_admin.
    if not is_unscoped_superuser(current_user):
        if user_data.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot create users in a different organization",
            )

    # super_admin can assign to any org, but the org must EXIST.
    # Previously a stale/typo'd UUID either FK-violated to a 500
    # or (if FK was SET NULL) was silently persisted.
    if user_data.organization_id is not None:
        org_check = await session.execute(
            select(Organization.id).where(
                Organization.id == user_data.organization_id,
            )
        )
        if org_check.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        # M2: enforce per-tier seat caps on the real user-provisioning
        # path. Sites/controllers/devices already gate on _check_quota; this
        # endpoint did not, so an org_admin could mint users past their tier's
        # max_users/max_admins. _check_quota takes a SELECT ... FOR UPDATE on
        # the org row (TOCTOU-safe) and raises HTTPException(403) on overflow.
        # It runs in the same transaction as the flush below, so the lock is
        # held until commit.
        from app.services.organization import OrganizationService

        is_admin = target_role in ("org_admin", "super_admin")
        await OrganizationService(session)._check_quota(
            user_data.organization_id,
            "admins" if is_admin else "users",
        )

    user = User(
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        role=user_data.role,
        organization_id=user_data.organization_id,
        created_by=current_user.id,
    )

    session.add(user)
    # Defense-in-depth on the SELECT-then-INSERT race: two concurrent
    # POSTs with the same email both pass the uniqueness check, both
    # call flush(); one wins, the other previously bubbled an
    # IntegrityError → 500. Translate to a clean 409.
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already registered",
        ) from exc
    await session.refresh(user)

    await _audit_user_change(
        session=session,
        request=request,
        action="user.create",
        actor=current_user,
        target=user,
        changes={"role": _role_str(user.role)},
    )
    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get user by ID."""
    require_admin(current_user)

    result = await session.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check access
    if not is_unscoped_superuser(current_user):  # scope-aware
        if user.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )

    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: UUID,
    user_data: UserUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Update user."""
    # Scope-aware admin gate: an unscoped super_admin / org_admin keeps its
    # existing role-based access; a scoped key must explicitly hold user:update.
    require_user_write(current_user, "user:update")

    result = await session.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    caller_role = _role_str(current_user.role)

    # Check access. scope-aware — a SCOPED super_admin key is org-confined
    # here (no cross-tenant user read/mutate), even though its role is super_admin.
    if not is_unscoped_superuser(current_user):
        if user.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )

    # SECURITY: if the caller is attempting to change the target's
    # role, enforce strict role hierarchy — both on the CURRENT role of the
    # target (can't modify equals/superiors) AND the NEW role being assigned
    # (can't elevate anyone to caller-level or above).
    if user_data.role is not None:
        current_target_role = _role_str(user.role)
        new_target_role = _role_str(user_data.role)
        validate_role_assignment(caller_role, current_target_role)
        validate_role_assignment(caller_role, new_target_role)

    update_data = user_data.model_dump(exclude_unset=True)

    # SECURITY: prevent self-lockout — disabling yourself via PATCH used
    # to return 200 and immediately invalidate your own session on the
    # next request. Match the "Cannot delete yourself" guard on DELETE.
    if user_id == current_user.id and update_data.get("is_active") is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable yourself",
        )

    # SECURITY: last-admin guard on PATCH. The DELETE path already
    # blocks deleting the last active admin; without the same guard on
    # PATCH a single API call could orphan the org via either
    # ``is_active=false`` or a role demote out of the admin set.
    demote_out_of_admin = (
        user_data.role is not None
        and user.role in _ADMIN_ROLES
        and user_data.role not in _ADMIN_ROLES
    )
    disable_admin = (
        update_data.get("is_active") is False and user.role in _ADMIN_ROLES and user.is_active
    )
    # Global last-super_admin invariant, independent of organization_id: a
    # super_admin with organization_id=NULL slips past the org-scoped guard
    # below, and removing the final one re-opens the unauthenticated
    # /setup/admin endpoint (platform takeover).
    if demote_out_of_admin or disable_admin:
        await _assert_not_last_super_admin(session, user, "disable or demote")
    if (demote_out_of_admin or disable_admin) and user.organization_id:
        remaining = await _count_active_admins(
            session,
            user.organization_id,
            exclude_user_id=user.id,
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable or demote the last admin of this organization",
            )

    # SECURITY: re-check email / username uniqueness when changing. The
    # DB unique constraint would reject the write anyway but raise
    # IntegrityError → 500. A clean SELECT-then-409 gives operators a
    # readable error and frees the DB session for the next request.
    for unique_field in ("email", "username"):
        new_value = update_data.get(unique_field)
        if new_value is not None and new_value != getattr(user, unique_field):
            dup = await session.execute(
                select(User.id).where(
                    getattr(User, unique_field) == new_value,
                    User.id != user.id,
                    User.deleted_at.is_(None),
                )
            )
            if dup.scalar_one_or_none() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"{unique_field.title()} already registered",
                )

    # Update fields — allowlist to prevent privilege escalation.
    # ``role`` is only allowed through after the validate_role_assignment
    # hierarchy checks above have passed. ``timezone`` was previously
    # in the allowlist but ``UserUpdate`` doesn't declare it — dead
    # entry, dropped.
    _ALLOWED_UPDATE_FIELDS = {
        "full_name",
        "username",
        "email",
        "is_active",
        "language",
        "role",
    }
    for field, value in update_data.items():
        if field not in _ALLOWED_UPDATE_FIELDS:
            continue  # Silently ignore non-allowed fields
        setattr(user, field, value)

    # SECURITY: bump token_version on security-sensitive mutations so
    # the target user's existing JWTs are rejected by the central auth
    # dep. Previously a disabled / demoted user kept elevated session
    # auth until natural expiry.
    if "is_active" in update_data or "role" in update_data:
        user.token_version = (getattr(user, "token_version", 0) or 0) + 1

    user.updated_by = current_user.id
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already registered",
        ) from exc
    await session.refresh(user)

    await _audit_user_change(
        session=session,
        request=request,
        action="user.update",
        actor=current_user,
        target=user,
        changes={
            k: (v.value if hasattr(v, "value") else v)
            for k, v in update_data.items()
            if k in _ALLOWED_UPDATE_FIELDS
        },
    )
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Soft delete user."""
    # Scope-aware admin gate: an unscoped super_admin / org_admin keeps its
    # existing role-based access (org_admin delete stays open even though
    # user:delete isn't in its catalog); a scoped key must explicitly hold it.
    require_user_write(current_user, "user:delete")

    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself",
        )

    result = await session.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check access
    if not is_unscoped_superuser(current_user):  # scope-aware
        if user.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )

    # Global last-super_admin invariant (independent of organization_id): an
    # org-NULL sole super_admin must not be soft-deleted, or the unauthenticated
    # /setup/admin endpoint re-opens. See _assert_not_last_super_admin.
    await _assert_not_last_super_admin(session, user, "delete")

    # SECURITY: prevent deleting the last org_admin (would orphan the org).
    # Same helper now backs the PATCH last-admin guard.
    if user.role in _ADMIN_ROLES and user.organization_id:
        remaining = await _count_active_admins(
            session,
            user.organization_id,
            exclude_user_id=user.id,
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last admin of this organization",
            )

    # Soft delete + bump token_version so any in-flight JWT the deleted
    # user holds is rejected on the next request.
    user.deleted_at = datetime.now(UTC)
    user.token_version = (getattr(user, "token_version", 0) or 0) + 1
    user.updated_by = current_user.id
    await _audit_user_change(
        session=session,
        request=request,
        action="user.delete",
        actor=current_user,
        target=user,
    )
    await session.commit()
