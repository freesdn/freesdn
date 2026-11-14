# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The shared per-device breaker opens across polls, probes once, and fails open."""

from __future__ import annotations

import pytest

from app.core.device_breaker import CLOSED, HALF_OPEN, OPEN, DeviceBreaker


class RedisDouble:
    def __init__(self) -> None:
        self.rows: dict[str, str] = {}

    def get(self, key):
        return self.rows.get(key)

    def set(self, key, value, *, ex=None, nx=False):
        if nx and key in self.rows:
            return None
        self.rows[key] = value
        return True

    def delete(self, *keys):
        for key in keys:
            self.rows.pop(key, None)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def env():
    redis, clock = RedisDouble(), Clock()

    def make(**kw):
        return DeviceBreaker(redis_factory=lambda: redis, clock=clock, **kw)

    return make, redis, clock


def test_two_failed_cycles_open_it_and_polls_are_skipped(env) -> None:
    make, _, clock = env
    b = make(failure_threshold=2, base_cooldown=100, max_cooldown=1000)
    assert b.check("gw").allowed
    assert b.record_failure("gw", "ReadTimeout").state == CLOSED
    assert b.check("gw").allowed
    tripped = b.record_failure("gw", "ReadTimeout")
    assert tripped.state == OPEN and 90 <= tripped.retry_after <= 110

    clock.now += 30
    d = b.check("gw")
    assert not d.allowed and d.state == OPEN and d.retry_after > 0
    assert "ReadTimeout" in d.skip_message() and "paused" in d.skip_message()


def test_one_probe_after_cooldown_and_success_closes(env) -> None:
    make, _, clock = env
    b = make(failure_threshold=1, base_cooldown=100, max_cooldown=1000)
    b.record_failure("gw", "x")
    clock.now += 111
    first, second = b.check("gw"), b.check("gw")
    assert first.allowed and first.probe and first.state == HALF_OPEN
    assert not second.allowed and second.state == HALF_OPEN  # one probe at a time
    b.record_success("gw")
    assert b.check("gw").state == CLOSED
    assert b.status("gw") == {}


def test_a_failed_probe_doubles_the_cooldown_up_to_the_cap(env) -> None:
    make, _, clock = env
    b = make(failure_threshold=1, base_cooldown=100, max_cooldown=350)
    cooldowns = []
    for _ in range(4):
        d = b.record_failure("gw", "x")
        cooldowns.append(d.retry_after)
        clock.now += d.retry_after + 1
        assert b.check("gw").probe
    assert 90 <= cooldowns[0] <= 110
    assert 180 <= cooldowns[1] <= 220
    assert all(c <= 350 * 1.1 for c in cooldowns)
    assert cooldowns[3] >= 350 * 0.9


def test_devices_are_independent(env) -> None:
    make, _, _ = env
    b = make(failure_threshold=1)
    b.record_failure("gw-a", "x")
    assert not b.check("gw-a").allowed
    assert b.check("gw-b").allowed


def test_state_is_shared_between_breaker_instances(env) -> None:
    """Two worker processes = two instances over one Redis."""
    make, _, _ = env
    make(failure_threshold=1).record_failure("gw", "x")
    assert not make(failure_threshold=1).check("gw").allowed


def test_redis_failure_fails_open() -> None:
    def broken():
        raise ConnectionError("valkey down")

    b = DeviceBreaker(redis_factory=broken)
    assert b.check("gw").allowed
    assert b.record_failure("gw", "x").allowed
    b.record_success("gw")
