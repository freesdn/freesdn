# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A Celery worker's health is not a DNS question.

The setup wizard probes each shipped service. For anything with an exposed port
it opens a TCP connection; for a port-less service it fell back to
``socket.getaddrinfo(name, None)``.

That is the wrong signal for a Celery worker, which is a BROKER CONSUMER: it
dials out to Redis and nothing ever dials it. It is also a false NEGATIVE under
the VPN overlay -- a container sharing another container's network namespace has
no endpoint of its own, so Docker's embedded DNS never registers its name and the
lookup fails for a perfectly healthy worker. That was already the shipped
behaviour for ``api`` under that overlay; moving the workers into the sidecar
namespace (the F-03 fix) would have extended the false alarm to them, telling an
operator their workers were down at the exact moment VPN mode started working.

``control.ping()`` answers what the operator is actually asking: is a worker
consuming? Verified against the running dev stack, where it returns
``[{'celery@<host>': {'ok': 'pong'}}]``.
"""

from __future__ import annotations

import pytest

from app.setup.service import _BROKER_CONSUMERS, _a_worker_is_consuming


def test_the_worker_services_are_classified_as_broker_consumers() -> None:
    """Both worker tiers, or the pro/max split reintroduces the false alarm."""
    assert {"worker", "worker-io"} <= _BROKER_CONSUMERS


@pytest.mark.asyncio
async def test_a_replying_worker_is_reported_consuming(monkeypatch) -> None:
    from app.core import celery_app as celery_module

    def _pong(**_kwargs):
        return [{"celery@abc123": {"ok": "pong"}}]

    monkeypatch.setattr(celery_module.celery_app.control, "ping", _pong)
    assert await _a_worker_is_consuming() is True


@pytest.mark.asyncio
async def test_no_reply_means_not_consuming(monkeypatch) -> None:
    """An empty ping is the real negative -- no worker is on the broker."""
    from app.core import celery_app as celery_module

    def _no_reply(**_kwargs):
        return []

    monkeypatch.setattr(celery_module.celery_app.control, "ping", _no_reply)
    assert await _a_worker_is_consuming() is False


@pytest.mark.asyncio
async def test_a_broker_failure_is_not_consuming_rather_than_an_exception(
    monkeypatch,
) -> None:
    """This powers a status row, so it must never break the setup wizard.

    Mutation this catches: removing the except arm, which turns an unreachable
    broker into a 500 on the setup screen an operator is using to diagnose it.
    """
    from app.core import celery_app as celery_module

    def _boom(**_kwargs):
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr(celery_module.celery_app.control, "ping", _boom)
    assert await _a_worker_is_consuming() is False


@pytest.mark.asyncio
async def test_the_probe_does_not_block_the_event_loop(monkeypatch) -> None:
    """control.ping is synchronous and waits out its timeout.

    Called directly it would stall every other request on the setup screen for
    the duration. Asserted by thread identity, not by timing -- a timing ratio
    depends on host timer granularity and this repo has already shipped one test
    that passed on Linux and failed on Windows for exactly that reason.
    """
    import threading

    from app.core import celery_app as celery_module

    loop_thread = threading.get_ident()
    seen: list[int] = []

    def _record(**_kwargs):
        seen.append(threading.get_ident())
        return [{"celery@x": {"ok": "pong"}}]

    monkeypatch.setattr(celery_module.celery_app.control, "ping", _record)
    await _a_worker_is_consuming()

    assert seen, "the ping was never called"
    assert seen[0] != loop_thread, (
        f"control.ping ran on the event loop thread ({loop_thread}); it is a "
        "blocking call and must be offloaded"
    )


def test_the_probe_actually_uses_the_ping_not_a_dns_lookup() -> None:
    """Pin the CALL SITE, not just the helper.

    Mutation this catches: deleting the _BROKER_CONSUMERS branch from
    _check_docker_services so a worker falls through to getaddrinfo again. Every
    test above would still pass -- they exercise _a_worker_is_consuming in
    isolation, and the helper stays perfectly correct while nothing calls it.

    That is the exact shape an external reviewer flagged in this repo: a test
    pinning a helper while the defect lives at the call site, so reverting the
    endpoint left the suite green. I wrote it again here and only caught it by
    mutating; this is the assertion that would have failed.
    """
    import inspect

    from app.setup.service import SetupService

    src = inspect.getsource(SetupService)
    assert "_BROKER_CONSUMERS" in src, (
        "the service probe no longer routes broker consumers to the ping; a "
        "healthy worker sharing the VPN sidecar's namespace will be reported "
        "unreachable because Docker never registers a DNS name for it"
    )
    assert "_a_worker_is_consuming()" in src, "the probe no longer awaits the broker ping"
