# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The one-time code that authorizes first-run setup.

Until the first super administrator exists, the setup wizard is open to anyone
who can reach the web interface, and the first client to complete it became
the administrator. Until then, every setup request that changes something
needs this code as well: the installer prints it, and
``docker compose --env-file .env.<tier> exec api python -m app.setup.setup_code``
shows it. The API log names that command but never holds the code itself:
logs are often forwarded to places other people can read.

The code lives in ``core.platform_settings`` (key ``setup_code``), so every API
worker and replica sees the same one, and it is created on first use. It is
deleted when setup completes; after that the setup gate is closed anyway.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import secrets

from fastapi import HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from app.db.session import AsyncSessionLocal
from app.models.core import User, UserRole
from app.models.platform_settings import PlatformSetting

logger = logging.getLogger(__name__)

SETUP_CODE_KEY = "setup_code"
SETUP_CODE_HEADER = "X-FreeSDN-Setup-Code"
SHOW_COMMAND = "docker compose --env-file .env.<tier> exec api python -m app.setup.setup_code"
# 32 symbols without 0/O and 1/I, so a code read off a terminal types cleanly.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_announced = False


def _new_code() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(20))  # 100 bits
    return "-".join(raw[i : i + 5] for i in range(0, 20, 5))


def _normalize(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch in _ALPHABET)


async def ensure_setup_code() -> str:
    """The current setup code, created on first use (safe across workers)."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            insert(PlatformSetting)
            .values(key=SETUP_CODE_KEY, value={"code": _new_code()})
            .on_conflict_do_nothing(index_elements=["key"])
        )
        value = await db.scalar(
            select(PlatformSetting.value).where(PlatformSetting.key == SETUP_CODE_KEY)
        )
        await db.commit()
    return str((value or {}).get("code", ""))


async def announce_setup_code() -> None:
    """Say how to show the code, once per process, for installs without install.sh."""
    global _announced
    if _announced:
        return
    _announced = True
    await ensure_setup_code()
    logger.warning(
        "FreeSDN is not set up yet. The setup wizard needs a one-time setup code; show it with: %s",
        SHOW_COMMAND,
    )


def supplied_setup_code(request: Request) -> str:
    """FastAPI dependency: the setup code a request carries (empty if none)."""
    return request.headers.get(SETUP_CODE_HEADER, "")


async def verify_setup_code(supplied: object) -> None:
    """Refuse a setup step that does not carry the current setup code."""
    supplied = supplied if isinstance(supplied, str) else ""
    expected = await ensure_setup_code()
    if not (
        supplied and expected and hmac.compare_digest(_normalize(supplied), _normalize(expected))
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This setup step needs the setup code. The installer printed it; "
                f"you can also show it with: {SHOW_COMMAND}"
            ),
        )


async def clear_setup_code() -> None:
    """Forget the code once setup is complete (best effort)."""
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(PlatformSetting).where(PlatformSetting.key == SETUP_CODE_KEY))
            await db.commit()
    except Exception:  # noqa: BLE001 - the setup gate is already closed
        logger.warning("Could not remove the used setup code", exc_info=True)


async def _main() -> int:
    async with AsyncSessionLocal() as db:
        admins = await db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == UserRole.SUPER_ADMIN, User.deleted_at.is_(None))
        )
    if admins:
        print("Setup is complete; no setup code is needed.")
        return 0
    print(await ensure_setup_code())
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
