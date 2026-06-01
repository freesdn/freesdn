# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Build an adapter for cassette record-or-replay (shared by *_cassette tests).

REPLAY (default): construct the adapter DISCONNECTED via the broad adapter
registry (all 13 vendor families), with the caller's dummy connection params —
the HTTP boundary is served from the cassette, so host/creds are irrelevant.

RECORD (FREESDN_RECORD_FIXTURES=1): build from REAL connection params, two ways:

  1. Explicit env (universal — works for every adapter family, ideal for VMs):
       FREESDN_RECORD_HOST=...  FREESDN_RECORD_USERNAME=...  FREESDN_RECORD_PASSWORD=...
       (optional)  FREESDN_RECORD_PORT=...  FREESDN_RECORD_USE_SSL=true|false
     The owner sets these for the device/VM under test; recordings still land in
     FREESDN_CASSETTE_DIR (off-repo, enforced) and are never committed.

  2. If no FREESDN_RECORD_HOST is set, fall back to the matching ``Controller``
     row in the DB, decrypting credentials IN-PROCESS (no secrets on the command
     line) — convenient for controllers already connected in FreeSDN
     (omada / opnsense / proxmox / unifi).

Run RECORD in your lab against the real device; everywhere else REPLAYs.
"""

from __future__ import annotations

import os
from typing import Any


def _env_bool(name: str) -> bool | None:
    v = os.environ.get(name)
    if v is None:
        return None
    return v.strip().lower() in ("1", "true", "yes", "on")


def _build_disconnected(controller_type: str, **kwargs: Any):
    """Construct (but do not connect) any registered adapter, uniformly."""
    from app.adapters.registry import get_adapter_registry

    reg = get_adapter_registry()
    host = kwargs.pop("host", "")
    username = kwargs.pop("username", "") or ""
    password = kwargs.pop("password", "") or ""
    return reg.create_adapter(
        controller_type, host=host, username=username, password=password, **kwargs
    )


async def cassette_adapter(controller_type: str, **replay_kwargs: Any):
    from tests.fixtures_harness import recording_enabled

    # ── REPLAY ──────────────────────────────────────────────────────────────
    if not recording_enabled():
        # Disconnected; the cassette injects the transport on connect().
        return _build_disconnected(controller_type, **replay_kwargs)

    # ── RECORD (lab only) ───────────────────────────────────────────────────
    # 1) Universal env-params path (all families). The replay_kwargs supply the
    #    structural defaults (port / use_ssl / verify_ssl / mode); env overrides
    #    host + credentials (+ optional port / use_ssl) with the real device.
    env_host = os.environ.get("FREESDN_RECORD_HOST")
    if env_host:
        params: dict[str, Any] = dict(replay_kwargs)
        params["host"] = env_host
        params["username"] = os.environ.get("FREESDN_RECORD_USERNAME", "")
        params["password"] = os.environ.get("FREESDN_RECORD_PASSWORD", "")
        if os.environ.get("FREESDN_RECORD_PORT"):
            params["port"] = int(os.environ["FREESDN_RECORD_PORT"])
        ssl_override = _env_bool("FREESDN_RECORD_USE_SSL")
        if ssl_override is not None:
            params["use_ssl"] = ssl_override
        return _build_disconnected(controller_type, **params)

    # 2) Controller-DB fallback: build from the live controller row, creds
    #    decrypted in-process (omada / opnsense / proxmox / unifi).
    from sqlalchemy import select

    from app.core.crypto import decrypt_credential, is_encrypted
    from app.db.models import Controller
    from app.db.session import CelerySessionLocal

    def _dec(v: str | None) -> str:
        if not v:
            return ""
        return decrypt_credential(v) if is_encrypted(v) else v

    async with CelerySessionLocal() as s:
        ctrl = (
            (
                await s.execute(
                    select(Controller).where(
                        Controller.controller_type == controller_type,
                        Controller.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .first()
        )
        assert ctrl is not None, (
            f"no '{controller_type}' controller in the DB to record from, and no "
            "FREESDN_RECORD_HOST set — connect the device first OR pass "
            "FREESDN_RECORD_HOST/USERNAME/PASSWORD (the universal record path)."
        )
        kw: dict[str, Any] = {
            "port": ctrl.port,
            "use_ssl": ctrl.use_ssl,
            "verify_ssl": ctrl.verify_ssl,
            "mode": ctrl.connection_mode,
        }
        if ctrl.connection_mode == "cloud":
            kw.update(
                client_id=ctrl.client_id or "",
                client_secret=_dec(ctrl.client_secret),
                omada_id=ctrl.omada_id or "",
                cloud_region=ctrl.cloud_region or "",
            )
        return _build_disconnected(
            ctrl.type,
            host=ctrl.host,
            username=ctrl.username or "",
            password=_dec(ctrl.password),
            **kw,
        )
