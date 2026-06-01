# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - In-Memory TTL Cache
===================================

Simple async-safe TTL cache for rarely-changing adapter data
(firmware status, system info, installed packages, etc.).

Not distributed — suitable for single-process API servers.
For multi-worker deployments, use Redis-backed cache instead.
"""

import time
from typing import Any


class TTLCache:
    """Lightweight in-memory cache with per-key TTL."""

    def __init__(self, default_ttl: float = 60.0, max_size: int = 2000):
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        if len(self._store) >= self.max_size:
            self._evict()
        self._store[key] = (time.monotonic() + (ttl or self.default_ttl), value)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def invalidate_prefix(self, prefix: str) -> None:
        keys = [k for k in self._store if k.startswith(prefix)]
        for k in keys:
            del self._store[k]

    def clear(self) -> None:
        self._store.clear()

    def _evict(self) -> None:
        """Remove expired entries; if still full, drop oldest 25%."""
        now = time.monotonic()
        self._store = {k: v for k, v in self._store.items() if v[0] > now}
        if len(self._store) >= self.max_size:
            sorted_keys = sorted(self._store, key=lambda k: self._store[k][0])
            for k in sorted_keys[: len(sorted_keys) // 4]:
                del self._store[k]


# Module-level singleton — 60s default TTL, 2000 entries max
adapter_cache = TTLCache(default_ttl=60, max_size=2000)
