# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Explicit successful coordination fixture for unrelated Fabric chain tests."""

import time

from app.core.fabric.negotiator import Negotiator


class SharedClaims:
    """Only the SET NX expiry behavior needed by positive chain fixtures."""

    def __init__(self):
        self.expiry = {}

    async def set(self, key, value, *, nx, ex):
        assert nx is True and value == "1" and ex > 0
        now = time.monotonic()
        if self.expiry.get(key, 0) > now:
            return None
        self.expiry[key] = now + ex
        return True


def coordinated_negotiator(*args, **kwargs):
    engine = Negotiator(*args, **kwargs)
    engine._redis = SharedClaims()
    return engine
