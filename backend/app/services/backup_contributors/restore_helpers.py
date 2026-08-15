# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Shared restore primitives for module contributors.

VoIP / Cameras / Firewall contributors all need the same insert-or-
update loop with tenant guards, FK-orphan guards, nullable-FK nulling,
and blocked-field stripping. This module factors that into one
``restore_records`` function so the per-module contributors stay small
and the tenant-isolation invariants live in exactly one place.

Guard model:

  - ``RejectGuard(field, valid, reason)`` — if the record's ``field``
    value is NOT in ``valid``, the record is REJECTED (skipped + a
    warning). Two reasons:
      * ``"cross-tenant"`` — the field references a resource outside
        the caller's org (e.g. a site_id / organization_id not in the
        org). This is the tenant-isolation boundary.
      * ``"orphan"`` — the field references a parent that wasn't
        restored (e.g. an extension whose pbx_id has no matching PBX).

  - ``NullableFK(field, valid)`` — if the record's ``field`` value is
    present but NOT in ``valid``, the field is set to None rather than
    rejecting the whole record (e.g. extension.user_id pointing at a
    user not in this org → null it, keep the extension).

  - ``force_org`` — when set, ``organization_id`` is forced to this
    value on every insert (defense-in-depth for models with a direct
    org column; mirrors the Core contributor's H4 invariant).

Returns the set of successfully-restored ids so a child table can
validate its FK against the parents restored in the same pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from .protocol import RestoreResult


# Always stripped — identity + soft-delete bookkeeping must never be
# overwritten by a restore (the id is preserved separately so child FKs
# resolve; timestamps are managed by the DB / mixins).
_BASE_BLOCKED = frozenset({"created_at", "updated_at", "deleted_at"})


@dataclass
class RejectGuard:
    field: str
    valid: set[str]
    reason: str  # "cross-tenant" | "orphan"


@dataclass
class NullableFK:
    field: str
    valid: set[str]


def _reject_warning(resource: str, pk: Any, guard: RejectGuard, value: Any) -> str:
    if guard.reason == "cross-tenant":
        return f"{resource} {pk}: {guard.field} not in this organization — rejected (cross-tenant)."
    # orphan
    return (
        f"{resource} {pk}: {guard.field} {value} not found among restored "
        f"parents — skipped (orphan)."
    )


async def restore_records(
    session: AsyncSession,
    *,
    model_cls: type,
    records: list[dict[str, Any]],
    result: RestoreResult,
    resource: str,
    dry_run: bool,
    overwrite: bool,
    force_org: UUID | None = None,
    reject_guards: list[RejectGuard] | None = None,
    nullable_fks: list[NullableFK] | None = None,
    blocked_fields: set[str] | None = None,
    preserve_id: bool = True,
) -> set[str]:
    """Insert/update one resource's records into the DB.

    Mutates ``result`` in place (``result.created/updated/skipped[resource]``
    + ``result.warnings``). Returns the set of restored ids.
    """
    blocked = _BASE_BLOCKED | (blocked_fields or set())
    reject_guards = reject_guards or []
    nullable_fks = nullable_fks or []

    created = updated = skipped = 0
    restored_ids: set[str] = set()

    for rec in records:
        pk = rec.get("id")
        if not pk:
            skipped += 1
            continue

        # Reject guards (tenant + orphan).
        rejected = False
        for guard in reject_guards:
            if str(rec.get(guard.field)) not in guard.valid:
                skipped += 1
                result.warnings.append(
                    _reject_warning(resource, pk, guard, rec.get(guard.field)),
                )
                rejected = True
                break
        if rejected:
            continue

        # Build clean column set.
        clean = {k: v for k, v in rec.items() if hasattr(model_cls, k) and k not in blocked}

        # Nullable-FK validation: null dangling references.
        for nfk in nullable_fks:
            val = clean.get(nfk.field)
            if val is not None and str(val) not in nfk.valid:
                clean[nfk.field] = None

        # Force org on models with a direct organization_id column.
        if force_org is not None and hasattr(model_cls, "organization_id"):
            clean["organization_id"] = force_org

        existing = await session.get(model_cls, pk)
        if existing is not None:
            if overwrite and not dry_run:
                for k, v in clean.items():
                    if k != "id":
                        setattr(existing, k, v)
                updated += 1
            else:
                skipped += 1
            restored_ids.add(str(pk))
            continue

        # Insert path.
        if not dry_run:
            if preserve_id:
                clean["id"] = pk
            try:
                session.add(model_cls(**clean))
                await session.flush()
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                result.warnings.append(
                    f"{resource} {pk}: insert failed ({exc}).",
                )
                continue
        created += 1
        restored_ids.add(str(pk))

    result.created[resource] = created
    result.updated[resource] = updated
    result.skipped[resource] = skipped
    return restored_ids


__all__ = ["NullableFK", "RejectGuard", "restore_records"]
