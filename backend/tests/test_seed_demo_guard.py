# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The demo-data seeder must refuse to run against a production environment.

``seed_demo_data.py`` ships in the public tree and writes well-known demo
credentials, so a hard production guard keeps it from ever creating the
``admin@example.com`` / ``demo`` account on a real deployment.
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.config import settings
from scripts import seed_demo_data


def test_seed_refuses_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(SystemExit, match="production"):
        asyncio.run(seed_demo_data.main())
