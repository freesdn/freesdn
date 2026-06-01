# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Security service
=============================================

Read-and-stage for the MikroTik security-control surfaces:

- Users (RouterOS console / API accounts)
- Certificates (PKI store, sign / import / revoke)
- SNMP (settings + communities)
- RADIUS (servers + incoming-CoA settings)

Supported features::

    mikrotik.security.user                 create | update | delete
    mikrotik.security.certificate          create | update | delete
    mikrotik.security.certificate_sign     create                   (target_id = cert id)
    mikrotik.security.certificate_import   create                   (payload = file/passphrase)
    mikrotik.security.certificate_revoke   create                   (target_id = cert id)
    mikrotik.security.snmp_settings        update                   (singleton)
    mikrotik.security.snmp_community       create | update | delete
    mikrotik.security.radius_server        create | update | delete
    mikrotik.security.radius_incoming      update                   (singleton)

Production safety: every write is staged. The applier passes
``force=True`` so the read-only gate at the client layer lets the
sanctioned write through.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# Per-(controller_id, "user", name) async lock cache (bounded LRU).
#
# The user-create idempotency check below is a read-then-write
# pattern: two concurrent applies of the same "add admin foo" change
# can both observe an absent user and both POST to /user. The lock
# below funnels concurrent applies through a single critical section
# so only the first wins and the second sees the row this side of
# the await on get_users().
#
# Bound (CORR-CRIT): the previous unbounded ``dict`` grew one entry
# per unique ``(controller_id, "user", name)`` ever observed and
# never evicted — slow leak on long-lived processes. An
# :class:`OrderedDict`-based LRU with a 512-entry cap drops the
# oldest key when the cap is reached. Eviction risk: if the same
# unique key is evicted mid-await, the next request would create a
# fresh lock and could race with the in-progress one. That requires
# 512+ in-flight concurrent user creates against *different* users
# on the same controller — not a realistic scenario; if it ever
# became one we'd promote to a Redis advisory lock and drop the
# in-process cache entirely.
#
# Note: this lock is **process-local**. Multi-worker / multi-pod
# deployments would still race on this code path — distributed dedup
# would need a Redis advisory lock keyed on
# ``(controller_id, "user", name)``. We don't ship that yet because
# all current deployments are single-process FastAPI workers; the
# lock here is enough to close the gap on a single uvicorn worker
# even with --workers > 1 collapsed onto one process.
_USER_CREATE_LOCKS_MAX = 512
_USER_CREATE_LOCKS: OrderedDict[tuple[str, str, str], asyncio.Lock] = OrderedDict()
_USER_CREATE_LOCK_LOCK = asyncio.Lock()


async def _get_user_create_lock(controller_id: UUID, name: str) -> asyncio.Lock:
    """Return the per-name asyncio.Lock for user-create idempotency.

    Case-insensitive: RouterOS treats ``Admin`` and
    ``admin`` as the same account, so the lock key must collapse case
    or two staged changes that differ only in case can race past each
    other.
    """
    key = (str(controller_id), "user", name.lower())
    async with _USER_CREATE_LOCK_LOCK:
        lock = _USER_CREATE_LOCKS.get(key)
        if lock is None:
            # Evict oldest if cap reached.
            while len(_USER_CREATE_LOCKS) >= _USER_CREATE_LOCKS_MAX:
                _USER_CREATE_LOCKS.popitem(last=False)
            lock = asyncio.Lock()
            _USER_CREATE_LOCKS[key] = lock
        else:
            # Mark as recently used by moving to the end.
            _USER_CREATE_LOCKS.move_to_end(key)
        return lock


# Allowlist of payload keys accepted by the
# ``mikrotik.security.certificate_sign`` feature. RouterOS' POST
# /certificate/sign accepts a small fixed set of fields; rejecting
# anything else closes a passthrough hole that would let an operator
# inject arbitrary RouterOS attributes via the staged-change UI.
_CERT_SIGN_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "ca",
        "ca-crl-host",
        "days-valid",
        "key-passphrase",
    }
)


# RouterOS-specific keys are now covered by the central
# ``redact_secrets`` helper: the shared strip-list
# normalises hyphens and lists ``private_key_file``,
# ``shared_secret``, ``auth_secret``, ``auth_password``,
# ``encryption_password``, etc. Single-pass redaction here — the
# per-service ``_mask_routeros`` helper was deleted to remove the
# double-walk perf cost.


def _redact_items(items: list[Any]) -> list[Any]:
    """Single-pass redaction via the central strip-list."""
    return [redact_secrets(i) for i in items]


def _redact_item(item: Any) -> Any:
    return redact_secrets(item)


_APPLY: dict[tuple[str, str], str] = {
    # Users
    ("mikrotik.security.user", "create"): "add_user",
    ("mikrotik.security.user", "update"): "update_user",
    ("mikrotik.security.user", "delete"): "delete_user",
    # Certificates
    ("mikrotik.security.certificate", "create"): "add_certificate",
    ("mikrotik.security.certificate", "update"): "update_certificate",
    ("mikrotik.security.certificate", "delete"): "delete_certificate",
    # Certificate actions (sign / import / revoke). All three are
    # modeled as ``create`` because they each produce a side-effect
    # on the controller and there's no canonical "update" verb.
    ("mikrotik.security.certificate_sign", "create"): "sign_certificate",
    ("mikrotik.security.certificate_import", "create"): "import_certificate",
    ("mikrotik.security.certificate_revoke", "create"): "revoke_certificate",
    # SNMP — singleton settings + communities + v3 users
    ("mikrotik.security.snmp_settings", "update"): "update_snmp_settings",
    ("mikrotik.security.snmp.settings", "update"): "update_snmp_settings",
    ("mikrotik.security.snmp_community", "create"): "add_snmp_community",
    ("mikrotik.security.snmp_community", "update"): "update_snmp_community",
    ("mikrotik.security.snmp_community", "delete"): "delete_snmp_community",
    # SNMP trap targets — verb-routed under feature ``snmp.trap_target``.
    # The applier dispatches to add_/update_/delete_snmp_trap_target
    # based on operation (RouterOS exposes add/remove only, with
    # update modelled as a remove+add round trip below).
    ("mikrotik.security.snmp.trap_target", "create"): "add_snmp_trap_target",
    ("mikrotik.security.snmp.trap_target", "update"): "add_snmp_trap_target",
    ("mikrotik.security.snmp.trap_target", "delete"): "remove_snmp_trap_target",
    # SNMPv3 users.
    ("mikrotik.security.snmp.v3_user", "create"): "add_snmp_user",
    ("mikrotik.security.snmp.v3_user", "update"): "update_snmp_user",
    ("mikrotik.security.snmp.v3_user", "delete"): "delete_snmp_user",
    # RADIUS
    ("mikrotik.security.radius_server", "create"): "add_radius_server",
    ("mikrotik.security.radius_server", "update"): "update_radius_server",
    ("mikrotik.security.radius_server", "delete"): "delete_radius_server",
    ("mikrotik.security.radius_incoming", "update"): "update_radius_incoming_settings",
}

_SINGLETON_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.security.snmp_settings",
        # alias — frontend uses dotted ``snmp.settings`` namespace.
        "mikrotik.security.snmp.settings",
        "mikrotik.security.radius_incoming",
    }
)

# Features that take ``payload`` directly and dispatch to a single
# client method via the _APPLY table regardless of operation. The
# canonical CRUD verbs (create / update / delete) still mean different
# wire ops to the client method, but the applier doesn't need a
# per-operation branch — the method itself knows what to do.
_SNMP_TRAP_TARGET_FEATURE = "mikrotik.security.snmp.trap_target"
_SNMP_V3_USER_FEATURE = "mikrotik.security.snmp.v3_user"

_ROW_SCOPED_FEATURES: frozenset[str] = frozenset(
    {
        "mikrotik.security.user",
        "mikrotik.security.certificate",
        "mikrotik.security.snmp_community",
        "mikrotik.security.radius_server",
    }
)


class GatewayMikrotikSecurityService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik security surfaces."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_users(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_users()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_certificates(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_certificates()),
            "fetched_at": datetime.now(UTC),
        }

    async def get_snmp_settings(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "item": _redact_item(await client.get_snmp_settings()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_snmp_communities(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        # Community strings are themselves secrets — RouterOS surfaces
        # them in the ``name`` field. Strip the value entirely so the
        # UI can't display credential-equivalent material. We DO need
        # a stable identifier for the UI to render rows distinctly,
        # so we expose ``display_name`` derived from the addresses
        # field (which is non-secret routing info). Falls back to
        # ``"<community>@<addresses>"`` with the name truncated when
        # addresses are absent.
        items = await client.get_snmp_communities()
        masked = []
        for item in items:
            if isinstance(item, dict):
                row = dict(item)
                original_name = row.get("name", "")
                addresses = row.get("addresses", "") or row.get("address", "")
                # Prefer the first comma-separated address as the
                # human-readable identifier — typical RouterOS
                # ``addresses`` values are "0.0.0.0/0" or a list.
                display: str
                if addresses:
                    first_addr = addresses.split(",")[0].strip()
                    display = first_addr or addresses
                elif original_name:
                    # Truncate the original name to prevent leaking
                    # the full community string via display_name;
                    # show first 2 chars plus a marker.
                    truncated = original_name[:2] + "***" if len(original_name) > 2 else "***"
                    display = f"{truncated}@unscoped"
                else:
                    display = "<unnamed>"
                row["display_name"] = display
                if "name" in row:
                    row["name"] = "***"
                masked.append(redact_secrets(row))
            else:
                masked.append(item)
        return {
            "controller_id": controller_id,
            "items": masked,
            "fetched_at": datetime.now(UTC),
        }

    async def list_radius_servers(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_radius_servers()),
            "fetched_at": datetime.now(UTC),
        }

    async def get_radius_incoming(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "item": _redact_item(await client.get_radius_incoming_settings()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_snmp_trap_targets(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[str]:
        """Return the SNMP ``trap-target`` comma-list as a typed list.

        backend wiring: consumes the client method
        ``get_snmp_trap_targets``. The hosts are non-secret routing
        info; no redaction is needed.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        try:
            return list(await client.get_snmp_trap_targets())
        except Exception:
            return []

    async def list_snmp_v3_users(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the SNMPv3 user table with auth/encryption passwords
        redacted via the central :func:`redact_secrets` strip-list."""
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        try:
            rows = await client.get_snmp_users()
        except Exception:
            return []
        return _redact_items(rows or [])

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # Singleton config: PATCH the whole thing.
            if c.feature in _SINGLETON_FEATURES:
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                return await method(payload, force=True)

            # SNMP trap target — operation-routed:
            # ``create``/``update`` → add (idempotent on the router),
            # ``delete`` → remove. The FE model
            # (``MikroTikSnmpTrapTarget``) sends an entity-shaped
            # payload ``{address, port, version, community}`` because
            # that matches what most other vendors model. RouterOS
            # stores trap targets as a single comma-list field on
            # /snmp — we only need the host address out of it.
            # Accept either shape: legacy ``{host: ...}`` or the
            # FE-3 entity shape ``{address: ...}``.
            if c.feature == _SNMP_TRAP_TARGET_FEATURE:
                p = payload or {}
                host = p.get("host") or p.get("address")
                if not isinstance(host, str) or not host.strip():
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} requires payload {{host: str}} or {{address: str}}"
                        ),
                    )
                return await method(host, force=True)

            # SNMPv3 user — payload-shaped CRUD; target_id required on
            # update / delete (RouterOS row id).
            if c.feature == _SNMP_V3_USER_FEATURE:
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation in ("update", "delete") and not target_id:
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.operation!r} on {c.feature!r} requires target_id (snmp user id)"
                        ),
                    )
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)

            # Certificate sign — POST { number=target_id, ... }. The
            # client method signature is sign_certificate(cid, data?).
            if c.feature == "mikrotik.security.certificate_sign":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (the certificate to sign)"),
                    )
                # Allowlist sign payload keys — RouterOS' /certificate/sign
                # accepts a tightly bounded set; rejecting anything else
                # closes a passthrough hole. NEVER log key-passphrase.
                bad_keys = [k for k in payload if k not in _CERT_SIGN_ALLOWED_KEYS]
                if bad_keys:
                    raise HTTPException(
                        400,
                        detail=(
                            f"certificate_sign payload has disallowed "
                            f"keys: {sorted(bad_keys)!r}; allowed = "
                            f"{sorted(_CERT_SIGN_ALLOWED_KEYS)!r}"
                        ),
                    )
                return await method(target_id, payload, force=True)

            # Certificate import — POST { file, passphrase, ... }. No id.
            if c.feature == "mikrotik.security.certificate_import":
                return await method(payload, force=True)

            # Certificate revoke — POST { number=target_id }. The client
            # method signature is revoke_certificate(cid).
            if c.feature == "mikrotik.security.certificate_revoke":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (the certificate to revoke)"),
                    )
                return await method(target_id, force=True)

            # Row-scoped CRUD: create(payload), update(id, payload),
            # delete(id).
            if c.feature in _ROW_SCOPED_FEATURES:
                if c.operation == "create":
                    # Idempotency guard for user creation — without
                    # this, two concurrent applies of an "add admin"
                    # change can create duplicate accounts and leave
                    # the operator unable to know which one is theirs.
                    #
                    # The TOCTOU window between get_users() and the
                    # subsequent POST is closed by a per-
                    # (controller_id, "user", name) asyncio.Lock so
                    # the read-then-write happens under serialised
                    # access. The lock cache lives in this module's
                    # process; a multi-process deployment would still
                    # need a distributed advisory lock (Redis
                    # SETNX-style) for full safety.
                    if c.feature == "mikrotik.security.user":
                        new_name = (payload or {}).get("name")
                        if new_name and isinstance(new_name, str):
                            # case-insensitive dedup
                            # check. RouterOS treats ``Admin`` /
                            # ``admin`` / ``ADMIN`` as the same
                            # account name. Comparing raw strings
                            # would let two staged changes with
                            # different cases slip past the lock.
                            normalised = new_name.lower()
                            lock = await _get_user_create_lock(c.controller_id, new_name)
                            async with lock:
                                existing = await client.get_users()
                                for row in existing or []:
                                    if (
                                        isinstance(row, dict)
                                        and isinstance(row.get("name"), str)
                                        and row["name"].lower() == normalised
                                    ):
                                        raise HTTPException(
                                            409,
                                            detail=(
                                                f"user {new_name!r} already "
                                                "exists on the controller — "
                                                "refusing to create a "
                                                "duplicate"
                                            ),
                                        )
                                return await method(payload, force=True)
                    return await method(payload, force=True)
                if c.operation == "update":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"update on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"delete on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, force=True)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply
