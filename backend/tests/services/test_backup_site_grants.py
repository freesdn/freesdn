# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A restore must reinstate per-user site grants, or it hands out authority.

Background
----------
``core.user_site_access`` is the junction table behind the per-user site
grants: a site_admin can be pinned to one site, optionally read-only, without
changing their global role. No contributor collected it, so it was in no
``.fsdn`` and no ``.fsdnvault``.

That omission is not "a table is missing" -- it is a privilege ESCALATION,
because the runtime is deliberately fail-OPEN on an empty grant set
(``CurrentUser.is_site_limited`` is ``bool(self._accessible_site_ids)``).
Fail-open is right for an UPGRADE, where nobody has grants yet and nobody
should be locked out. On a RESTORE it means the user row comes back with its
role intact and its cage gone: ``can_access_site`` returns True for every site
in the org and the per-grant ``access_level`` cap ('read') is gone with it.

Both paths that recreate users force it: ``restore_from_backup`` sets
``restore_users=True`` for any vault, and ``restore_fresh_instance_from_vault``
-- the documented bare-metal recovery, reachable before any admin exists --
passes it explicitly. So the documented DR procedure silently promoted a
read-only single-site technician to an unrestricted site_admin over the whole
organization, and reported "completed".
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

from app.core.dependencies import CurrentUser
from app.models import UserSiteAccess
from app.services.backup import BackupService

ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
GRANTED_SITE = uuid.uuid4()
OTHER_SITE = uuid.uuid4()
FOREIGN_SITE = uuid.uuid4()
TECHNICIAN = uuid.uuid4()


# ── collect ──────────────────────────────────────────────────────


class _Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows

    def first(self):
        return self._rows[0] if self._rows else None


class _CollectSession:
    """Answers only the user_site_access query; every other table is empty."""

    def __init__(self, grants: list) -> None:
        self.grants = grants

    async def execute(self, query):
        return _Result(self.grants if "core.user_site_access" in str(query) else [])


def _grant(access_level: str | None = "read") -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=TECHNICIAN,
        site_id=GRANTED_SITE,
        access_level=access_level,
    )


async def _collect(*, include_users: bool = True, include_secrets: bool = False) -> dict:
    svc = BackupService.__new__(BackupService)
    svc.db = _CollectSession([_grant()])
    svc.org_id = ORG
    payload = await BackupService.collect_backup_data(
        svc,
        organization_id=ORG,
        include_users=include_users,
        include_secrets=include_secrets,
    )
    return payload.get("data", payload)


async def test_a_vault_carries_the_site_grants() -> None:
    """The section did not exist at all; this is the whole omission in one assert.

    Mutation caught: deleting the ``data["user_site_access"] = [...]`` block in
    collect_backup_data (the pre-fix state).
    """
    data = await _collect(include_secrets=True)
    assert "user_site_access" in data, "a .fsdnvault still omits the per-user site grants"
    assert len(data["user_site_access"]) == 1


async def test_the_access_level_cap_travels_with_the_grant() -> None:
    """A grant restored without its access_level is a read-only technician
    restored with write authority over the site they were pinned to.

    Mutation caught: dropping ``access_level`` from the collected dict.
    """
    rec = (await _collect())["user_site_access"][0]
    assert rec["access_level"] == "read"
    assert rec["user_id"] == str(TECHNICIAN)
    assert rec["site_id"] == str(GRANTED_SITE)


async def test_grants_are_omitted_when_users_are() -> None:
    """A backup taken with users excluded must not carry grants either -- they
    reference user rows that are not in the archive.

    Mutation caught: collecting grants outside the ``if include_users:`` block.
    """
    data = await _collect(include_users=False)
    assert "user_site_access" not in data


# ── restore ──────────────────────────────────────────────────────


class _RestoreSession:
    """Minimal AsyncSession stand-in for ``_restore_data``.

    ``execute`` answers the two id-set queries ``_restorable_ids`` issues and
    the duplicate lookup on the grant's unique key. ``add`` records what the
    restore would insert.
    """

    def __init__(self, *, live_site_ids: list = (), live_user_ids: list = ()) -> None:
        self.added: list[Any] = []
        self._live_site_ids = list(live_site_ids)
        self._live_user_ids = list(live_user_ids)

    async def get(self, model_cls, pk):
        return None

    async def execute(self, query):
        text = str(query)
        if "core.user_site_access" in text:
            return _Result([])  # no colliding grant on this instance
        if "FROM core.sites" in text:
            return _Result(self._live_site_ids)
        if "FROM core.users" in text:
            return _Result(self._live_user_ids)
        return _Result([])

    def add(self, obj) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


async def _restore(payload: dict, *, restore_users: bool = True) -> _RestoreSession:
    session = _RestoreSession(
        live_site_ids=[GRANTED_SITE, OTHER_SITE],
        live_user_ids=[TECHNICIAN],
    )
    svc = BackupService.__new__(BackupService)
    svc.db = session
    svc.org_id = ORG
    await BackupService._restore_data(
        svc,
        payload,
        dry_run=False,
        overwrite_existing=True,
        restore_devices=False,
        restore_users=restore_users,
        include_secrets=True,
    )
    return session


def _payload(grants: list[dict]) -> dict:
    return {"sites": [], "controllers": [], "users": [], "user_site_access": grants}


async def test_restore_reinstates_the_site_limit_it_used_to_flatten() -> None:
    """The finding end to end: restore the archived grant, rebuild the principal
    from what the restore actually produced, and confirm the technician is
    caged again.

    Before the fix ``restore_map`` had no ``user_site_access`` entry, so
    ``session.added`` was empty, ``accessible_site_ids`` was ``set()``,
    ``is_site_limited`` was False and ``can_access_site(OTHER_SITE)`` returned
    True -- an unrestricted site_admin.

    Mutation caught: removing ``("user_site_access", UserSiteAccess)`` from
    restore_map, or restoring the row without its access_level.
    """
    session = await _restore(
        _payload(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(TECHNICIAN),
                    "site_id": str(GRANTED_SITE),
                    "access_level": "read",
                }
            ]
        )
    )

    grants = [o for o in session.added if isinstance(o, UserSiteAccess)]
    assert grants, "the restore created no UserSiteAccess row"

    principal = CurrentUser(
        user=SimpleNamespace(
            id=TECHNICIAN,
            organization_id=ORG,
            role="site_admin",
            is_superuser=False,
        ),
        permissions=["devices:read", "devices:write"],
        accessible_site_ids={uuid.UUID(str(g.site_id)) for g in grants},
        site_access_levels={uuid.UUID(str(g.site_id)): g.access_level for g in grants},
    )

    assert principal.is_site_limited is True
    assert principal.can_access_site(GRANTED_SITE) is True
    assert principal.can_access_site(OTHER_SITE) is False
    # The 'read' cap came back with the grant, not just the membership.
    assert principal.has_site_permission("devices:write", GRANTED_SITE) is False
    assert principal.has_site_permission("devices:read", GRANTED_SITE) is True


async def test_zero_grants_is_fail_open_which_is_why_the_omission_escalated() -> None:
    """Pins the fail-open the fix depends on. If this ever flips to
    deny-by-default, the restore gap stops being an escalation and this file's
    reasoning needs rewriting -- so it should fail loudly rather than quietly
    become stale.
    """
    principal = CurrentUser(
        user=SimpleNamespace(
            id=TECHNICIAN,
            organization_id=ORG,
            role="site_admin",
            is_superuser=False,
        ),
        permissions=["devices:write"],
        accessible_site_ids=set(),
    )
    assert principal.is_site_limited is False
    assert principal.can_access_site(OTHER_SITE) is True


async def test_grants_are_not_restored_when_users_are_not() -> None:
    """A config-snapshot restore leaves users alone (restore_users defaults
    False), so it must leave their grants alone too -- otherwise it would apply
    one instance's access model to another instance's accounts.

    Mutation caught: appending ``user_site_access`` to restore_map
    unconditionally instead of inside ``if restore_users:``.
    """
    session = await _restore(
        _payload(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(TECHNICIAN),
                    "site_id": str(GRANTED_SITE),
                    "access_level": "read",
                }
            ]
        ),
        restore_users=False,
    )
    assert [o for o in session.added if isinstance(o, UserSiteAccess)] == []


async def test_a_grant_aimed_at_a_foreign_site_is_refused() -> None:
    """user_site_access has no organization_id column, so the generic H4
    cross-org reject is blind to it: a grant naming another org's site would
    both escape tenant scope and blow up the flush on the FK, taking the whole
    core section's savepoint down with it.

    Mutation caught: deleting the ``grant_targets`` check in _restore_data.
    """
    session = await _restore(
        _payload(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(TECHNICIAN),
                    "site_id": str(FOREIGN_SITE),  # neither live here nor in the payload
                    "access_level": "admin",
                }
            ]
        )
    )
    assert [o for o in session.added if isinstance(o, UserSiteAccess)] == []


def test_grants_are_restored_after_the_users_they_reference() -> None:
    """UserSiteAccess.user_id FKs core.users. Restoring grants first leaves the
    row dangling on a fresh-instance recovery, where the user does not exist yet.

    Mutation caught: moving the append above ``("users", User)``.
    """
    import inspect

    src = inspect.getsource(BackupService._restore_data)
    assert '("user_site_access", UserSiteAccess)' in src
    assert src.index('("users", User)') < src.index('("user_site_access", UserSiteAccess)')
