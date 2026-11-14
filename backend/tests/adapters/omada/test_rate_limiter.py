# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Omada client's token bucket serves waiters first come, first served.

During a live soak a sync's per-client detail fan-out waited on the limiter and
some reads failed with "rate limit wait timed out" after 30 s: every waiter polled
every 50 ms and took whichever token appeared, so one could lose every race.
"""

from __future__ import annotations

import asyncio

from app.adapters.omada.utils import TokenBucketRateLimiter


async def test_rate_limiter_grants_tokens_in_arrival_order():
    limiter = TokenBucketRateLimiter(tokens_per_second=50.0, bucket_size=1)
    order: list[int] = []

    async def take(i: int) -> None:
        assert await limiter.acquire(timeout=2.0)
        order.append(i)

    await asyncio.gather(*(take(i) for i in range(12)))

    assert order == list(range(12))


async def test_rate_limiter_gives_up_without_waiting_past_its_deadline():
    limiter = TokenBucketRateLimiter(tokens_per_second=0.5, bucket_size=1)
    assert await limiter.acquire(timeout=1.0)

    loop = asyncio.get_running_loop()
    started = loop.time()
    assert await limiter.acquire(timeout=0.3) is False
    assert loop.time() - started < 0.25  # the next token is 2 s away: no wait
