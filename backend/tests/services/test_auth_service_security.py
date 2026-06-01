# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.security import get_password_hash
from app.services.auth import AuthService, TokenInvalidError


@pytest.mark.asyncio
async def test_refresh_tokens_rejects_stale_token_version() -> None:
    user_id = uuid4()
    user = SimpleNamespace(
        id=user_id,
        organization_id=None,
        role="admin",
        token_version=3,
        is_active=True,
        deleted_at=None,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    service = AuthService(mock_db)

    with patch(
        "app.services.auth.decode_token",
        new=AsyncMock(return_value={"type": "refresh", "sub": str(user_id), "tv": 2}),
    ):
        with pytest.raises(TokenInvalidError):
            await service.refresh_tokens("stale-refresh-token")


@pytest.mark.asyncio
async def test_change_password_bumps_token_version() -> None:
    user = SimpleNamespace(
        id=uuid4(),
        hashed_password=get_password_hash("CurrentP@ssw0rd!"),
        token_version=7,
    )
    mock_db = AsyncMock()

    service = AuthService(mock_db)

    with patch(
        "app.models.api_keys.revoke_user_api_keys",
        new=AsyncMock(return_value=0),
    ):
        changed = await service.change_password(
            user,
            current_password="CurrentP@ssw0rd!",
            new_password="NewSecureP@ssw0rd1!",
        )

    assert changed is True
    assert user.token_version == 8
    mock_db.commit.assert_awaited_once()
