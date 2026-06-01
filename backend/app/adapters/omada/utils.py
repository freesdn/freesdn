# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Omada adapter utilities.
"""

from __future__ import annotations

import asyncio
import fnmatch
import re
import time
from collections import OrderedDict
from typing import Any


def normalize_mac(mac: str | None) -> str:
    """Normalize MAC to uppercase colon-separated format."""
    if not mac:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(clean) != 12:
        return mac.upper()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2)).upper()


def parse_version(version: str | None) -> tuple[int, int, int]:
    """
    Parse Omada version string into a comparable tuple.

    Accepts values like "5.14.30.7" and returns (5, 14, 30).
    """
    if not version:
        return (0, 0, 0)
    nums = re.findall(r"\d+", version)
    major = int(nums[0]) if len(nums) > 0 else 0
    minor = int(nums[1]) if len(nums) > 1 else 0
    patch = int(nums[2]) if len(nums) > 2 else 0
    return (major, minor, patch)


def is_version_below_fully_supported(major: int, minor: int) -> bool:
    """True only for the legacy 5.x line below the 5.9 "fully supported" floor.

    The floor is a property of the 5.x line. Newer majors (6.x+) RESET the
    minor counter, so a bare ``minor < 9`` check wrongly flagged v6.2 — which
    is newer than 5.14 — as below the floor and logged a spurious
    ``unsupported_version`` warning. Scope the floor to its own major.
    """
    from app.adapters.omada.constants import (
        FULLY_SUPPORTED_MINOR_MIN,
        MIN_SUPPORTED_MAJOR,
    )

    return major == MIN_SUPPORTED_MAJOR and minor < FULLY_SUPPORTED_MINOR_MIN


class TokenBucketRateLimiter:
    """Simple async token bucket limiter."""

    def __init__(self, tokens_per_second: float, bucket_size: int):
        self.tokens_per_second = max(tokens_per_second, 0.01)
        self.bucket_size = max(bucket_size, 1)
        self._tokens = float(bucket_size)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill_unlocked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(
            float(self.bucket_size),
            self._tokens + elapsed * self.tokens_per_second,
        )
        self._last_refill = now

    async def acquire(self, timeout: float = 30.0) -> bool:
        """Wait for one token. Returns False on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            async with self._lock:
                self._refill_unlocked()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
            await asyncio.sleep(0.05)
        return False

    @property
    def available_tokens(self) -> int:
        return int(max(self._tokens, 0))


class SimpleCache:
    """Small in-memory TTL cache with lightweight LRU eviction."""

    def __init__(self, max_entries: int = 1024):
        self.max_entries = max_entries
        self._items: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _prune_expired(self) -> None:
        """Walk every entry and drop expired keys.

        Reserved for explicit/maintenance use. Hot-path lookups now
        evict expired keys lazily inside :meth:`get` / :meth:`set` —
        walking the full cache on every operation was O(n) and turned
        the cache into the bottleneck once a few hundred keys
        accumulated.
        """
        now = time.monotonic()
        expired = [k for k, (expires_at, _) in self._items.items() if expires_at <= now]
        for key in expired:
            self._items.pop(key, None)

    def get(self, key: str) -> Any | None:
        # Lazy expiry: only inspect the requested key. Old expired
        # entries elsewhere in the OrderedDict get reclaimed via the
        # LRU pop in ``set`` once we cross ``max_entries``, which is
        # the common eviction path.
        item = self._items.get(key)
        if item is None:
            self._misses += 1
            return None
        expires_at, value = item
        if expires_at <= time.monotonic():
            self._items.pop(key, None)
            self._misses += 1
            return None
        self._hits += 1
        self._items.move_to_end(key)
        return value

    def set(self, key: str, value: Any, ttl: int) -> None:
        # Lazy expiry: do not scan the whole cache on every write.
        # LRU eviction below caps memory; an aggregate pruning sweep
        # is reserved for ``_prune_expired``-on-demand callers.
        expires_at = time.monotonic() + max(ttl, 0)
        self._items[key] = (expires_at, value)
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)

    def invalidate(self, pattern: str) -> int:
        keys = [k for k in self._items if fnmatch.fnmatch(k, pattern)]
        for key in keys:
            self._items.pop(key, None)
        return len(keys)

    def clear(self) -> None:
        self._items.clear()

    @property
    def stats(self) -> dict[str, float | int]:
        total = self._hits + self._misses
        hit_rate = (self._hits / total) if total else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._items),
            "hit_rate": round(hit_rate, 4),
        }
