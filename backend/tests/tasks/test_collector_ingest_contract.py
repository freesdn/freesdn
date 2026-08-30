# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Three collector controls that were rendered in the UI and did nothing.

NOTE ON LOCATION: these cover ``app/modules/collector/`` and belong beside
``tests/modules/collector/``. They live here only because this change set's
file ownership put ``tests/tasks/`` in the same hands as the collector module;
move them when that is no longer true.

1. THE SNMP COMMUNITY WAS READ, PASSED ONE FUNCTION DEEP, AND DROPPED
   ``CollectorManager.start`` read ``config.snmp_community`` and called
   ``_start_snmp(port, community, allowlist)``. ``_start_snmp`` declared
   ``community: str`` and never referenced it -- ``SNMPTrapReceiver.__init__``
   had no ``community`` parameter for it to reach -- and the parser skipped the
   community bytes without decoding them. So the editable "Community" box on
   the Observability page, sitting next to a port and an enable toggle that
   both work, changed nothing: every trap from any address inside the CIDR
   allowlist was accepted whatever community it carried. ruff could not see the
   unused argument because ARG001-ARG004 are globally ignored
   (backend/pyproject.toml).

2. THE LOG EXPLORER'S "INFO" FILTER COULD NEVER MATCH A ROW
   ``SyslogReceiver`` stores the RFC 5424 name, and severity 6 is
   "informational" in ``SEVERITY_NAMES``. The UI dropdown, and this endpoint's
   own OpenAPI description, said "info", and ``search_logs`` applies severity as
   an exact equality predicate. Filtering to Info returned an empty table and a
   total of 0 over a store that may hold millions of informational rows, and
   looked exactly like "no informational logs were received".

3. THE SUPPRESSION COUNTERS HAD NO READER
   ``CollectorEventPublisher.stats()`` was called from nowhere in app/.
   ``CollectorManager.status()`` -- the only thing behind GET
   /collector/status -- built its dict from the three receivers and never
   touched the publisher, so published / suppressed_by_severity /
   suppressed_by_rate / suppressed_no_org were incremented into an object no
   endpoint could reach. That is the exact diagnostic the module docstring says
   it exists to provide: an operator whose collector-triggered rule never fires
   needs to tell "nothing arrived" from "we muted it".
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest

from app.modules.collector.api import _canonical_severity
from app.modules.collector.models import CollectorLog
from app.modules.collector.services.events import SEVERITY_ORDER, CollectorEventPublisher
from app.modules.collector.services.manager import CollectorManager, build_allowlist
from app.modules.collector.services.snmp_trap import SNMPTrapReceiver, _extract_community
from app.modules.collector.services.syslog import SEVERITY_NAMES, SyslogReceiver

# ── BER helpers: build a real SNMPv2c trap, not a hand-waved byte string ─────


def _tlv(tag: int, payload: bytes) -> bytes:
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + payload


def _int(value: int) -> bytes:
    n = max(1, (value.bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(n, "big"))


def v2c_trap(community: bytes, *, oid: str = "1.3.6.1.6.3.1.1.5.3") -> bytes:
    """A minimally valid SNMPv2c trap carrying one varbind."""
    oid_bytes = bytes([0x2B]) + bytes(int(p) for p in oid.split(".")[2:])
    varbind = _tlv(0x30, _tlv(0x06, oid_bytes) + _tlv(0x05, b""))
    pdu = _tlv(0xA7, _int(1) + _int(0) + _int(0) + _tlv(0x30, varbind))
    return _tlv(0x30, _int(1) + _tlv(0x04, community) + pdu)


class _RecordingSession:
    def __init__(self, added: list[Any]) -> None:
        self._added = added

    def add(self, obj: Any) -> None:
        self._added.append(obj)

    async def commit(self) -> None:
        pass

    async def __aenter__(self) -> _RecordingSession:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _receiver(community: str | None, added: list[Any]) -> SNMPTrapReceiver:
    return SNMPTrapReceiver(
        session_factory=lambda: _RecordingSession(added),
        allowlist=build_allowlist(["10.0.0.0/8"]),
        community=community,
    )


# ── 1. the SNMP community ───────────────────────────────────────────────────


def test_extract_community_reads_the_configured_value_back() -> None:
    """The parser skipped these bytes by length without ever decoding them.

    Mutation this catches: any off-by-one in the version/community TLV walk --
    the returned bytes stop matching what was encoded.
    """
    assert _extract_community(v2c_trap(b"s3cret-community")) == b"s3cret-community"
    assert _extract_community(b"not-a-ber-message") is None
    assert _extract_community(b"") is None


def test_trap_with_the_wrong_community_is_dropped_and_counted() -> None:
    """This is the assertion that fails on the shipped code.

    Before the fix ``SNMPTrapReceiver`` had no ``community`` parameter at all,
    so this constructor call raises TypeError; with the parameter present but
    unused, the trap is stored anyway and ``added`` is non-empty.
    """
    added: list[Any] = []
    receiver = _receiver("s3cret", added)

    asyncio.run(receiver._handle(v2c_trap(b"public"), "10.0.0.7"))

    assert added == [], "a trap with the wrong community was stored"
    assert receiver._rejected_community == 1
    # Counted apart from the allowlist rejects, so an operator can tell a
    # misconfigured device from an unauthorised source.
    assert receiver._rejected_packets == 0


def test_trap_with_the_right_community_is_stored() -> None:
    """The guard must not be a blanket drop -- verify the accept path too."""
    added: list[Any] = []
    receiver = _receiver("s3cret", added)

    asyncio.run(receiver._handle(v2c_trap(b"s3cret"), "10.0.0.7"))

    assert len(added) == 1
    assert isinstance(added[0], CollectorLog)
    assert receiver._rejected_community == 0


def test_no_configured_community_accepts_any_trap() -> None:
    """Empty/None is the explicit "accept any community" setting.

    Deployments that never touched the field must not start silently dropping
    traps the moment validation lands.
    """
    added: list[Any] = []
    receiver = _receiver(None, added)

    asyncio.run(receiver._handle(v2c_trap(b"whatever-they-send"), "10.0.0.7"))

    assert len(added) == 1
    assert receiver._rejected_community == 0


def test_community_never_reaches_the_stored_record(caplog: pytest.LogCaptureFixture) -> None:
    """the community is a device credential.

    ``CollectorLog.message`` is free text returned by /collector/logs to any
    ``collector.logs.read`` holder, and the key-based redact_secrets cannot mask
    it. Reading the value to compare it must not make it storable or loggable.

    Mutation this catches: putting the decoded community into the message (the
    obvious "helpful" change) or into the rejection log line.
    """
    added: list[Any] = []
    receiver = _receiver("s3cret", added)
    secret = b"s3cret"

    with caplog.at_level("DEBUG"):
        asyncio.run(receiver._handle(v2c_trap(secret), "10.0.0.7"))
        asyncio.run(receiver._handle(v2c_trap(b"wrong-one"), "10.0.0.7"))

    (stored,) = added
    assert secret.decode() not in (stored.message or "")
    assert "<redacted>" in (stored.message or "")
    assert secret.decode() not in caplog.text
    assert "wrong-one" not in caplog.text


def test_manager_hands_the_configured_community_to_the_receiver() -> None:
    """The argument existed and went nowhere; prove it now arrives.

    Mutation this catches: dropping ``community=community`` from the
    ``SNMPTrapReceiver(...)`` call in CollectorManager._start_snmp, which is
    exactly the shape of the original defect.
    """
    manager = CollectorManager(session_factory=lambda: _RecordingSession([]))
    config = SimpleNamespace(
        snmp_enabled=True,
        snmp_port=0,  # ephemeral: bind must succeed without root
        snmp_community="from-the-database",
        syslog_enabled=False,
        netflow_enabled=False,
        allowed_source_ips=["10.0.0.0/8"],
    )

    async def _run() -> None:
        await manager.start(config)
        try:
            assert manager._snmp_receiver is not None, "receiver failed to bind"
            assert manager._snmp_receiver._community == b"from-the-database"
        finally:
            await manager.stop()

    asyncio.run(_run())


# ── 2. the severity vocabulary ──────────────────────────────────────────────


class _CapturingSession:
    """Records every statement search_logs executes, and answers plausibly."""

    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> Any:
        self.statements.append(statement)
        return SimpleNamespace(
            scalar=lambda: 0,
            scalars=lambda: SimpleNamespace(all=list),
        )


def _search_logs_sql(severity: str) -> str:
    """Drive the real endpoint and return the SQL of the row query it built."""
    from app.modules.collector.api import search_logs

    session = _CapturingSession()
    user = SimpleNamespace(
        has_permission=lambda _perm: True,
        organization_id=UUID("11111111-1111-1111-1111-111111111111"),
    )
    # Every Query()-defaulted parameter has to be supplied: called directly
    # (rather than through the FastAPI router) the defaults are unresolved
    # ``Query`` objects, and _parse_time would choke on one.
    asyncio.run(
        search_logs(
            user,  # type: ignore[arg-type]
            session,  # type: ignore[arg-type]
            source_type=None,
            severity=severity,
            device_id=None,
            start_time=None,
            end_time=None,
            q=None,
            page=1,
            size=50,
        )
    )
    # [0] is the COUNT wrapper, [1] the paged row query; both carry the filter.
    assert len(session.statements) == 2
    return str(session.statements[-1].compile(compile_kwargs={"literal_binds": True}))


@pytest.mark.parametrize(
    ("datagram", "parser"),
    [
        (b"<14>Aug 26 22:00:00 sw1 sshd: session opened", "_parse_rfc3164"),
        (b"<134>1 2026-08-26T22:00:00Z fw1 filterlog - - - state created", "_parse_rfc5424"),
    ],
)
def test_info_filter_matches_what_the_receiver_actually_stores(
    datagram: bytes, parser: str
) -> None:
    """Real datagram through the real parser; real query through the real endpoint.

    Both ends are taken from production code, so this cannot pass by
    re-deriving the mapping it is checking: the left-hand side is whatever
    SyslogReceiver decided to store, the right-hand side is whatever
    ``search_logs`` compiled into its WHERE clause.

    Mutation this catches: drop ``_canonical_severity`` from the ``severity``
    condition in search_logs and the compiled query goes back to comparing
    against 'info', which no stored row carries.
    """
    receiver = SyslogReceiver()
    parsed = getattr(receiver, parser)(datagram.decode())
    assert parsed is not None
    stored = parsed["severity"]
    assert stored == "informational", "the receiver stopped storing RFC 5424 names"

    sql = _search_logs_sql("info")
    assert f"severity = '{stored}'" in sql, (
        f"the Log Explorer's 'info' filter compiled to {sql!r}, which matches "
        f"no row: the receiver stores {stored!r}."
    )


def test_canonical_severity_reaches_the_query_unchanged() -> None:
    """A caller who already uses the stored spelling must not be rewritten."""
    assert "severity = 'informational'" in _search_logs_sql("informational")
    assert "severity = 'warning'" in _search_logs_sql("warning")


def test_every_severity_alias_resolves_to_a_storable_name() -> None:
    """An alias that maps to a name no receiver emits is a silent empty filter."""
    storable = set(SEVERITY_NAMES.values())
    for shorthand in ("info", "warn", "err", "crit", "emerg", "panic"):
        assert _canonical_severity(shorthand) in storable, (
            f"alias {shorthand!r} maps to {_canonical_severity(shorthand)!r}, "
            f"which the receivers never store"
        )


def test_canonical_names_pass_through_unchanged() -> None:
    """Normalising must not rewrite a value the receivers already store."""
    for name in SEVERITY_NAMES.values():
        assert _canonical_severity(name) == name
    # Both severity vocabularies in the module must agree, or the automation
    # bridge's floor and the log filter disagree about the same word.
    assert set(SEVERITY_NAMES.values()) == set(SEVERITY_ORDER)


def test_unknown_severity_is_not_silently_widened() -> None:
    """A typo must return nothing, not everything."""
    assert _canonical_severity("bogus") == "bogus"


# ── 3. the suppression counters ─────────────────────────────────────────────


def _record(**over: Any) -> dict[str, Any]:
    base = {
        "organization_id": "11111111-1111-1111-1111-111111111111",
        "device_id": "22222222-2222-2222-2222-222222222222",
        "severity": "debug",
        "app_name": "sshd",
        "message": "chatty",
    }
    base.update(over)
    return base


def test_manager_exposes_the_publisher_counters() -> None:
    """The counters existed and nothing could read them.

    Mutation this catches: delete ``CollectorManager.event_stats`` or stop
    returning ``self._publisher.stats()`` from it, and the suppression that
    just happened becomes invisible again.
    """
    manager = CollectorManager(session_factory=lambda: _RecordingSession([]))

    # Below the default "warning" floor: suppressed, and the only observable
    # for the operator is this counter -- the severity-floor path logs nothing.
    published = asyncio.run(manager._publisher.publish("syslog", _record()))

    assert published is False
    stats = manager.event_stats()
    assert stats["suppressed_by_severity"] == 1
    assert stats["published"] == 0
    assert stats["severity_floor"] == "warning"


def test_status_endpoint_carries_the_counters() -> None:
    """GET /collector/status is the surface an operator actually has."""
    from app.modules.collector import api as collector_api
    from app.modules.collector.services import manager as manager_module

    real = manager_module.get_collector_manager
    fake = CollectorManager(session_factory=lambda: _RecordingSession([]))
    manager_module.get_collector_manager = lambda: fake  # type: ignore[assignment]
    try:
        user = SimpleNamespace(has_permission=lambda _perm: True)
        payload = asyncio.run(collector_api.collector_status(user))  # type: ignore[arg-type]
    finally:
        manager_module.get_collector_manager = real  # type: ignore[assignment]

    assert set(payload) == {"services", "events"}
    assert "suppressed_by_rate" in payload["events"]
    # The services dict must stay one-entry-per-UDP-service: health_check and
    # the frontend both treat every value in it as a service record.
    assert set(payload["services"]) == {"snmp_trap", "syslog", "netflow"}
    assert all("running" in v for v in payload["services"].values())


def test_rate_cap_suppression_is_distinguishable_from_severity_suppression() -> None:
    """The three causes of silence must not collapse into one number."""

    class _FakeRedis:
        def __init__(self) -> None:
            self._counts: dict[str, int] = {}

        async def incr(self, key: str) -> int:
            self._counts[key] = self._counts.get(key, 0) + 1
            return self._counts[key]

        async def expire(self, *_a: Any, **_k: Any) -> None:
            return None

    pub = CollectorEventPublisher(redis=_FakeRedis(), rate_limit=1, rate_window_seconds=300)

    async def _run() -> None:
        await pub.publish("syslog", _record(severity="critical"))
        await pub.publish("syslog", _record(severity="critical"))
        await pub.publish("syslog", _record(severity="debug"))
        await pub.publish("syslog", _record(organization_id=None, severity="critical"))

    asyncio.run(_run())

    stats = pub.stats()
    assert stats["published"] == 1
    assert stats["suppressed_by_rate"] == 1
    assert stats["suppressed_by_severity"] == 1
    assert stats["suppressed_no_org"] == 1


def test_module_health_check_degrades_when_nothing_is_bound() -> None:
    """It returned a hard "healthy" in the same dict that said nothing was running.

    Mutation this catches: put the literal ``"status": "healthy"`` back and
    this fails on the started-but-unbound case, which is exactly what a port
    conflict or a missing CAP_NET_BIND_SERVICE produces (both are swallowed by
    CollectorManager._start_* with a warning).
    """
    from app.modules.collector.module import CollectorModule
    from app.modules.collector.services import manager as manager_module

    fake = CollectorManager(session_factory=lambda: _RecordingSession([]))
    real = manager_module.get_collector_manager
    manager_module.get_collector_manager = lambda: fake  # type: ignore[assignment]
    try:
        module = CollectorModule()

        # Never started: no org asked for collection, so nothing is wrong.
        assert asyncio.run(module.health_check())["status"] == "healthy"

        # Started, but every receiver failed to bind.
        fake._running = True
        degraded = asyncio.run(module.health_check())
        assert degraded["status"] == "degraded"
        assert degraded["checks"]["any_service_running"] is False
        assert "events" in degraded["checks"]
    finally:
        manager_module.get_collector_manager = real  # type: ignore[assignment]
