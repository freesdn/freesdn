# SPDX-License-Identifier: AGPL-3.0-only
"""First-run setup needs the one-time setup code.

Reported by review for 26.11.2 and disclosed as a known issue: until the first
super administrator existed, the first client to complete the setup form on a
fresh install became that administrator. Every setup step that changes
something now needs the code the installer prints. Real PostgreSQL.
"""

from __future__ import annotations

import logging
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.core import User, UserRole
from app.models.platform_settings import PlatformSetting
from app.setup import setup_code

pytestmark = pytest.mark.real_setup_code

ADMIN = {
    "email": "first@admin.com",
    "username": "firstadmin",
    "password": "StrongPassword123!",
    "first_name": "First",
    "last_name": "Admin",
}


@pytest.fixture(autouse=True)
async def _fresh_install(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch):
    await db_session.execute(delete(User).where(User.role == UserRole.SUPER_ADMIN))
    await db_session.flush()
    await setup_code.clear_setup_code()
    monkeypatch.setattr(setup_code, "_announced", False)
    yield
    await setup_code.clear_setup_code()


async def _stored_code() -> object:
    async with AsyncSessionLocal() as db:
        return await db.scalar(
            select(PlatformSetting.value).where(PlatformSetting.key == setup_code.SETUP_CODE_KEY)
        )


async def test_admin_creation_is_refused_without_the_setup_code(async_client) -> None:
    """Fails on 26.11.2: the first client to post this became super admin."""
    response = await async_client.post("/api/v1/setup/admin", json=ADMIN)
    assert response.status_code == 403
    assert "setup code" in response.text


async def test_a_wrong_setup_code_is_refused(async_client) -> None:
    await setup_code.ensure_setup_code()
    response = await async_client.post(
        "/api/v1/setup/admin", json=ADMIN, headers={setup_code.SETUP_CODE_HEADER: "WRONG-CODE"}
    )
    assert response.status_code == 403


async def test_the_setup_code_creates_the_admin_and_is_then_removed(async_client) -> None:
    code = await setup_code.ensure_setup_code()
    typed = code.lower().replace("-", " ")  # read off a terminal, typed loosely
    response = await async_client.post(
        "/api/v1/setup/admin", json=ADMIN, headers={setup_code.SETUP_CODE_HEADER: typed}
    )
    assert response.status_code in (200, 201), response.text
    assert response.json()["success"] is True
    assert await _stored_code() is None


async def test_anonymous_wizard_steps_need_the_code_too(async_client) -> None:
    response = await async_client.post(
        "/api/v1/setup/modules",
        json={"enabled_modules": [], "organization_id": str(uuid4())},
    )
    assert response.status_code == 403
    assert "setup code" in response.text


async def test_status_needs_no_code_and_the_log_never_holds_it(async_client, caplog) -> None:
    """Logs are often forwarded where other people can read them."""
    with caplog.at_level(logging.WARNING, logger="app.setup.setup_code"):
        first = await async_client.get("/api/v1/setup/status")
        await async_client.get("/api/v1/setup/status")
    assert first.status_code == 200 and first.json()["is_complete"] is False
    code = await setup_code.ensure_setup_code()
    assert not [r for r in caplog.records if code in r.getMessage()]
    announced = [r for r in caplog.records if setup_code.SHOW_COMMAND in r.getMessage()]
    assert len(announced) == 1


async def test_the_read_only_checks_need_no_code(async_client) -> None:
    """Fails on the first 26.11.3 candidate: the wizard calls GET /welcome
    before it can show the code field, so every fresh install was locked out."""
    for path in ("/api/v1/setup/welcome", "/api/v1/setup/database"):
        response = await async_client.get(path)
        assert response.status_code == 200, (path, response.text)


async def test_every_worker_sees_the_same_code() -> None:
    assert await setup_code.ensure_setup_code() == await setup_code.ensure_setup_code()
