# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Plan an organization-scoped configuration merge before mutating ORM rows."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Controller, Credential, Device, Site, User, UserRole
from app.models.enterprise import SiteGroup


class ConfigImportError(ValueError):
    """A reviewed import refusal; never wrap database or uploaded value text."""


_MODELS = {"sites": Site, "controllers": Controller, "devices": Device, "users": User}
_SYSTEM_FIELDS = {
    "id",
    "organization_id",
    "created_at",
    "updated_at",
    "created_by",
    "updated_by",
    "deleted_at",
}
_USER_PROFILE_FIELDS = {"full_name", "language", "preferences"}
_USER_CREATE_FIELDS = _USER_PROFILE_FIELDS | {"email", "username"}


def _uuid(value: Any) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise ConfigImportError("Import contains an invalid resource identifier.") from None


@dataclass
class _Row:
    model: Any
    identifier: UUID
    existing: Any
    values: dict[str, Any]
    apply: bool

    def value(self, key: str) -> Any:
        if self.apply and key in self.values:
            return self.values[key]
        return getattr(self.existing, key, None) if self.existing is not None else None


@dataclass
class ConfigImportPlan:
    summary: dict[str, dict[str, int]] = field(default_factory=dict)
    rows: dict[tuple[Any, UUID], _Row] = field(default_factory=dict)
    new_disabled_users: int = 0

    def apply(self, session: AsyncSession) -> None:
        """Apply only after the entire plan and its references were validated."""
        for row in self.rows.values():
            if not row.apply:
                continue
            if row.existing is None:
                session.add(row.model(id=row.identifier, **row.values))
            else:
                for key, value in row.values.items():
                    setattr(row.existing, key, value)


def _fields(model: Any, record: dict[str, Any], existing: Any) -> dict[str, Any]:
    """Only mapped columns can travel; relationships and Python attributes cannot."""
    values: dict[str, Any] = {}
    user_fields = _USER_CREATE_FIELDS if existing is None else _USER_PROFILE_FIELDS
    for prop in model.__mapper__.column_attrs:
        key, column = prop.key, prop.columns[0]
        if key not in record or key in _SYSTEM_FIELDS:
            continue
        if model is User and key not in user_fields:
            continue
        value = record[key]
        if value is None:
            if not column.nullable:
                raise ConfigImportError("Import contains an empty required field.")
        else:
            try:
                kind = column.type.python_type
            except NotImplementedError:
                kind = None
            if kind is UUID:
                value = _uuid(value)
            elif kind is datetime:
                try:
                    value = value if isinstance(value, datetime) else datetime.fromisoformat(value)
                except (TypeError, ValueError):
                    raise ConfigImportError("Import contains an invalid timestamp.") from None
            elif kind in (str, bool, int, float):
                valid = isinstance(value, kind)
                if kind in (int, float) and isinstance(value, bool):
                    valid = False
                if kind is float and isinstance(value, int) and not isinstance(value, bool):
                    valid = True
                if not valid:
                    raise ConfigImportError("Import contains a field with an invalid type.")
            if isinstance(column.type, JSON):
                expected = list if model is Site and key == "subnets" else dict
                if not isinstance(value, expected):
                    raise ConfigImportError("Import contains invalid structured configuration.")
            length = getattr(column.type, "length", None)
            if length and isinstance(value, str) and len(value) > length:
                raise ConfigImportError("Import contains a field that exceeds its size limit.")
        values[key] = value

    if existing is None:
        for prop in model.__mapper__.column_attrs:
            column = prop.columns[0]
            if prop.key in _SYSTEM_FIELDS or (model is User and prop.key not in user_fields):
                continue
            if not column.nullable and column.default is None and column.server_default is None:
                if values.get(prop.key) is None:
                    raise ConfigImportError("Import is missing a required resource field.")
    return values


async def plan_config_import(
    session: AsyncSession,
    data: dict[str, Any],
    organization_id: UUID,
    *,
    overwrite_existing: bool,
    dry_run: bool,
    controller_secret_fields: tuple[str, ...],
) -> ConfigImportPlan:
    """Validate ownership, references and input types without writing any rows.

    Applying callers lock existing resources and references until commit/rollback.
    A dry run takes no row locks and is advisory; application always plans again.
    Database uniqueness and concurrent insertion still require a successful commit.
    """
    if not isinstance(data, dict):
        raise ConfigImportError("Import resource data must be an object.")
    organization_id = _uuid(organization_id)
    plan = ConfigImportPlan()
    cache: dict[tuple[Any, UUID], Any] = {}

    async def load(model: Any, identifier: UUID) -> Any:
        key = (model, identifier)
        if key not in cache:
            query = (
                select(model)
                .where(model.id == identifier)
                .execution_options(populate_existing=True)
            )
            if not dry_run:
                query = query.with_for_update()
            cache[key] = (await session.execute(query)).scalars().first()
        return cache[key]

    async def owned(model: Any, row: Any) -> bool:
        if row is None or getattr(row, "deleted_at", None) is not None:
            return False
        if model in (Controller, Device):
            site = await load(Site, row.site_id)
            return await owned(Site, site)
        return getattr(row, "organization_id", None) == organization_id

    async def reference(model: Any, identifier: Any) -> _Row:
        if identifier is None:
            raise ConfigImportError("Import is missing a required resource reference.")
        identifier = _uuid(identifier)
        pending = plan.rows.get((model, identifier))
        if pending is not None:
            return pending
        existing = await load(model, identifier)
        if not await owned(model, existing):
            raise ConfigImportError("Import references a missing or out-of-scope resource.")
        return _Row(model, identifier, existing, {}, False)

    for resource, model in _MODELS.items():
        records = data.get(resource, [])
        if not isinstance(records, list):
            raise ConfigImportError("Import resource sections must contain lists of records.")
        if not records:
            continue
        summary = {"created": 0, "updated": 0, "skipped": 0, "rejected_cross_org": 0}
        plan.summary[resource] = summary
        for record in records:
            if not isinstance(record, dict):
                raise ConfigImportError("Import contains a record that is not an object.")
            identifier = _uuid(record.get("id"))
            key = (model, identifier)
            if key in plan.rows:
                raise ConfigImportError("Import contains duplicate resource identifiers.")
            recorded_org = record.get("organization_id")
            if recorded_org is not None and _uuid(recorded_org) != organization_id:
                raise ConfigImportError("Import contains a record from another organization.")
            existing = await load(model, identifier)
            if existing is not None and not await owned(model, existing):
                raise ConfigImportError("Import would change an out-of-scope or deleted resource.")
            apply = existing is None or overwrite_existing
            values = _fields(model, record, existing) if apply else {}
            if existing is None and model in (Site, User):
                values["organization_id"] = organization_id
            if existing is None and model is User:
                # A config snapshot is not account recovery. This sentinel is
                # deliberately not a password hash; verification always fails.
                values.update(
                    hashed_password="!", role=UserRole.VIEWER, is_active=False, is_verified=False
                )
                plan.new_disabled_users += 1
            if apply and model is Controller and "config" in values:
                if not isinstance(values["config"], dict):
                    raise ConfigImportError("Import controller configuration must be an object.")
                config = {
                    k: v for k, v in values["config"].items() if k not in controller_secret_fields
                }
                if existing is not None:
                    for secret in controller_secret_fields:
                        if secret in (existing.config or {}):
                            config[secret] = existing.config[secret]
                values["config"] = config
            row = _Row(model, identifier, existing, values, apply)
            plan.rows[key] = row
            summary["created" if existing is None else "updated" if apply else "skipped"] += 1

    # Validate against the complete planned graph, including newly created IDs.
    # References cannot rely on another row that was silently skipped or rejected.
    for row in plan.rows.values():
        if not row.apply:
            continue
        if row.model is Site and row.value("site_group_id") is not None:
            await reference(SiteGroup, row.value("site_group_id"))
        if row.model in (Controller, Device):
            site = await reference(Site, row.value("site_id"))
            if site.value("organization_id") != organization_id:
                raise ConfigImportError("Import references a site from another organization.")
            controller_id = row.value("controller_id") if row.model is Device else None
            if controller_id is not None:
                controller = await reference(Controller, controller_id)
                if _uuid(controller.value("site_id")) != site.identifier:
                    raise ConfigImportError(
                        "Import device and controller must belong to the same site."
                    )
            credential_id = row.value("credential_id")
            if credential_id is not None:
                credential = await reference(Credential, credential_id)
                credential_site = credential.value("site_id")
                if credential_site is not None and _uuid(credential_site) != site.identifier:
                    raise ConfigImportError("Import credential is scoped to a different site.")
        if row.model is Controller and row.existing is not None:
            if row.value("site_id") != row.existing.site_id:
                query = (
                    select(Device)
                    .where(Device.controller_id == row.identifier)
                    .execution_options(populate_existing=True)
                )
                if not dry_run:
                    query = query.with_for_update()
                for device in (await session.execute(query)).scalars().all():
                    pending = plan.rows.get((Device, device.id))
                    final_site = pending.value("site_id") if pending is not None else device.site_id
                    if _uuid(final_site) != _uuid(row.value("site_id")):
                        raise ConfigImportError(
                            "Import would leave a controller's devices in another site."
                        )
    return plan
