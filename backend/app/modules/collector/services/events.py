# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Putting collector signals onto the event bus.

Until now the collector was a dead end. ``SyslogReceiver._process`` and
``SNMPTrapReceiver._handle`` both resolve the source IP to a device, write a
``CollectorLog`` row, and stop. Nothing was published, ``collector.*`` existed
only as permission strings, and the automation engine fires on exactly two
things -- an event-bus event or a manual button (``IMPLEMENTED_TRIGGER_TYPES``).

So no observability signal could trigger an automation rule. A device could
report a failing power supply over syslog and there was no way to make anything
happen about it: the log was searchable, and that was all. This module is the
missing join.

**Why it was not simply done before.** Publishing every line is not viable. One
chatty firewall emits thousands of messages a second, and the bus fans out to
Redis, the WebSocket forwarder and every automation rule. The bus's own dedup
(``_locally_dispatched_ids``) only stops the same event being dispatched twice;
it is no defence against volume. So this bridge has two gates, and both matter:

* a **severity floor** -- by default only ``warning`` and above is published,
  which removes the informational bulk that makes up most of syslog;
* a **rate cap** per source, so one flapping device cannot storm the engine.

Suppressed messages are counted and the counters are readable, because a bridge
that silently drops signals is worse than no bridge -- an operator who writes a
rule and sees nothing fire needs to be able to tell "no message matched" from
"your device is shouting and we muted it".

NetFlow is deliberately not bridged. Flow records have no severity and arrive at
a completely different rate; a useful flow trigger is a question about
aggregates, not individual records, and pretending otherwise would put a
trigger on the UI that no operator could use.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.events import EventType

logger = logging.getLogger(__name__)

__all__ = [
    "COLLECTOR_EVENT_TYPES",
    "SEVERITY_ORDER",
    "CollectorEventPublisher",
]

#: Syslog severities, most severe first. RFC 5424 numbers them 0..7 with 0 the
#: worst, so "at or above ``warning``" means a NUMBER LESS THAN OR EQUAL TO 4 --
#: the inversion is the easiest thing to get backwards here.
SEVERITY_ORDER: dict[str, int] = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "informational": 6,
    "debug": 7,
}

#: What this module can publish. Registered in ``EVENT_CATEGORIES`` so the
#: integrations UI, the webhook validator and plugin manifests all accept them;
#: an event a subscriber cannot name is one nobody can use.
COLLECTOR_EVENT_TYPES: dict[str, str] = {
    # Spelled via EventType so there is exactly one definition of each name.
    # They were literals here first, and the offered-vs-published ratchet
    # promptly reported both as phantoms: it scans the enum and literal
    # publish() arguments, and an event published through a dispatch table is
    # invisible to both. The ratchet was right to complain -- a name only this
    # module knows is one a plugin author cannot discover either.
    "syslog": EventType.COLLECTOR_SYSLOG_RECEIVED.value,
    "snmp_trap": EventType.COLLECTOR_TRAP_RECEIVED.value,
}

_DEFAULT_SEVERITY_FLOOR = "warning"
_DEFAULT_RATE_LIMIT = 12
_DEFAULT_RATE_WINDOW_SECONDS = 60.0
#: Distinct (org, device, app, severity) buckets tracked at once. Mirrors the
#: source-IP resolver's ceiling in manager.py -- same reason, same order of
#: magnitude, and a real fleet has nowhere near this many live sources.
_DEFAULT_MAX_TRACKED_SOURCES = 4096


class CollectorEventPublisher:
    """Publishes qualifying collector records onto the event bus.

    Deliberately holds no database session and no Redis handle: it is called
    from the receive path, which is latency-sensitive and must never be blocked
    by the bus. Every failure is swallowed and logged -- a bus problem must not
    cost an operator the log line, which is already committed by the time this
    runs.
    """

    def __init__(
        self,
        *,
        severity_floor: str = _DEFAULT_SEVERITY_FLOOR,
        rate_limit: int = _DEFAULT_RATE_LIMIT,
        rate_window_seconds: float = _DEFAULT_RATE_WINDOW_SECONDS,
        max_tracked_sources: int = _DEFAULT_MAX_TRACKED_SOURCES,
        redis: Any = None,
    ) -> None:
        self._floor = SEVERITY_ORDER.get(severity_floor, SEVERITY_ORDER[_DEFAULT_SEVERITY_FLOOR])
        self._floor_name = severity_floor
        self._rate_limit = rate_limit
        self._window = rate_window_seconds

        # BOUNDED. ``app_name`` and ``severity`` come off the wire, so the key
        # space is device-controlled: any allowlisted host can mint a new bucket
        # per message by varying its app name. Unbounded, that is a memory leak
        # with a remote trigger -- measured at 20,000 keys / 3.3 MB from one
        # device, with nothing ever evicting them.
        #
        # Evicted in true LRU order, which matters here: dropping the oldest by
        # INSERTION (the cheaper trick used by the source-IP cache next door)
        # would eventually evict a flooding device's own bucket and hand it a
        # fresh budget, so the limiter would leak exactly the traffic it exists
        # to cap. A hot key must stay hot.
        self._buckets: dict[tuple, list[float]] = {}
        self._max_buckets = max_tracked_sources
        self.published = 0
        self.suppressed_by_severity = 0
        self.suppressed_by_rate = 0
        self.suppressed_no_org = 0
        # Times the cluster-wide cap fell back to the local bucket alone.
        self.cap_degraded = 0
        # Injectable so the cluster-wide path can be exercised deterministically.
        # It reached for the real client at first use, which made unit tests
        # talk to whatever Redis happened to be running and share window keys
        # with each other -- tests polluting tests through a live dependency.
        self._redis: Any = redis

    # ── the two gates ───────────────────────────────────────────

    def _passes_severity(self, parsed: dict[str, Any]) -> bool:
        """Whether this record is severe enough to be worth waking rules for.

        An UNPARSEABLE severity publishes. A message whose severity could not be
        read is not evidence that it is unimportant, and silently dropping the
        malformed ones would hide exactly the devices worth paying attention to.
        """
        severity = parsed.get("severity")
        if severity is None:
            return True
        rank = SEVERITY_ORDER.get(str(severity).lower())
        if rank is None:
            return True
        return rank <= self._floor

    def _passes_rate(self, parsed: dict[str, Any], now: float) -> bool:
        """One flapping device must not be able to storm the automation engine.

        Keyed per device AND per severity AND per app: a router repeating one
        interface flap is throttled without muting a genuinely different message
        from the same box, which a per-device-only key would do.
        """
        # Deliberately NOT keyed on app_name. It is free text off the wire, so
        # including it makes the key space device-controlled -- and that is not
        # merely a memory problem, it is a bypass: a host can mint unique app
        # names until its own bucket is evicted, then resume flooding with a
        # fresh budget. Demonstrated before this was changed.
        #
        # What is left is trustworthy. organization_id and device_id come from
        # the source-IP resolver (a database lookup, not the packet), and
        # severity is the 3-bit PRI field, so it is always one of eight names.
        # The table is therefore bounded by the size of the real fleet.
        #
        # The cost is that two apps on one device logging at the same severity
        # share a budget. Severity still separates the cases that matter: a
        # routine warning storm cannot mute a critical from the same box.
        key = (
            parsed.get("organization_id"),
            parsed.get("device_id"),
            parsed.get("severity"),
        )
        window_start = now - self._window
        recent = [t for t in self._buckets.pop(key, ()) if t >= window_start]

        if len(recent) >= self._rate_limit:
            self._buckets[key] = recent  # re-inserted at the end: still hot
            return False

        recent.append(now)
        self._buckets[key] = recent
        self._evict_if_needed(window_start)
        return True

    def _evict_if_needed(self, window_start: float) -> None:
        """Keep the bucket table bounded.

        Expired buckets go first -- they carry no budget, so dropping them costs
        nothing. Only if that is not enough does it drop the least recently used,
        and because every touch pops-and-reinserts, insertion order IS recency.
        """
        if len(self._buckets) <= self._max_buckets:
            return

        for key in [
            k for k, times in self._buckets.items() if not times or times[-1] < window_start
        ]:
            del self._buckets[key]
            if len(self._buckets) <= self._max_buckets:
                return

        for key in list(self._buckets)[: len(self._buckets) - self._max_buckets]:
            del self._buckets[key]

    async def _within_cap(self, parsed: dict[str, Any]) -> bool:
        """The cap, enforced across every process that binds the listener.

        Both receivers bind with ``reuse_port=True`` so a config reload can
        rebind seamlessly. The side effect is that when the collector module
        starts inside the API process -- which it does, per organization, from
        ``module.on_start`` -- EVERY gunicorn worker binds, and the kernel
        load-balances datagrams between them. ``WEB_CONCURRENCY`` defaults to 2.

        A purely in-process counter therefore gave each worker its own budget:
        the cap was silently 2x, and a device sending twice the limit passed
        completely because each worker only ever saw half of it. That is the
        same per-process-state-under-fan-out defect the Fabric audit traced 23
        bugs to.

        The local bucket runs FIRST and is kept, for two reasons: it costs
        nothing, and it means Redis is consulted at most ``rate_limit`` times
        per window per source rather than once per packet. Redis then enforces
        the real ceiling across workers.

        Fail-open on a Redis outage, matching the automation engine's
        idempotency lock: for a monitoring platform, publishing a duplicate
        event during an outage is safer than going deaf to a device that is
        reporting a fault.
        """
        if not self._passes_rate(parsed, time.monotonic()):
            return False

        window = int(time.time() // self._window)
        key = (
            f"collector:rate:{parsed.get('organization_id')}:"
            f"{parsed.get('device_id')}:{parsed.get('severity')}:{window}"
        )
        try:
            from app.core.redis_client import get_async_redis

            if self._redis is None:
                self._redis = get_async_redis(decode_responses=True)
            count = await self._redis.incr(key)
            if count == 1:
                # Only the first writer pays for the TTL. The key already rolls
                # on its own -- the window number is part of it -- so this is
                # not protecting against a pinned key, it is saving a second
                # round trip on every subsequent message in the window. In the
                # receive path that is the difference between one Redis call
                # per source per window and two per packet.
                await self._redis.expire(key, int(self._window) + 1)
            if count > self._rate_limit:
                # The caller owns the counter -- incrementing here too would
                # double-count every message the cluster-wide gate rejects, and
                # a stats surface that overstates suppression is exactly the
                # thing an operator would use to conclude the cap is misfiring.
                return False
        except Exception as exc:
            self.cap_degraded += 1
            logger.debug("collector.event.cap_local_only: %s", exc)

        return True

    # ── the publish path ────────────────────────────────────────

    async def publish(self, source_type: str, parsed: dict[str, Any]) -> bool:
        """Publish one collector record if it clears both gates.

        Returns whether it was published, which is what the receivers' counters
        and the tests assert on.
        """
        event_type = COLLECTOR_EVENT_TYPES.get(source_type)
        if event_type is None:
            return False

        # Fail closed on tenancy. Both downstream consumers already drop an
        # org-less event -- the automation engine (fail-closed org filter) and
        # the WebSocket router (drops events with no organization_id) -- so one
        # published here can only ever be dead weight on the 'system' scope. It
        # is refused at the source so a future consumer that is NOT fail-closed
        # cannot turn this into a cross-tenant leak.
        if not parsed.get("organization_id"):
            self.suppressed_no_org += 1
            return False

        if not self._passes_severity(parsed):
            self.suppressed_by_severity += 1
            return False

        if not await self._within_cap(parsed):
            self.suppressed_by_rate += 1
            logger.info(
                "collector.event.rate_limited device_id=%s severity=%s limit=%d/%.0fs",
                parsed.get("device_id"),
                parsed.get("severity"),
                self._rate_limit,
                self._window,
            )
            return False

        try:
            from app.core.events import Event, EventCategory, event_bus

            org_id = parsed.get("organization_id")
            await event_bus.publish(
                Event(
                    event_type=event_type,
                    category=EventCategory.SYSTEM,
                    source="collector",
                    organization_id=str(org_id) if org_id else None,
                    payload=self.build_payload(source_type, parsed),
                )
            )
        except Exception as exc:
            # The log row is already committed. A bus failure must not turn a
            # stored message into a lost one, or take down the receive loop.
            logger.warning("collector.event.publish_failed type=%s: %s", event_type, exc)
            return False

        self.published += 1
        return True

    @staticmethod
    def build_payload(source_type: str, parsed: dict[str, Any]) -> dict[str, Any]:
        """The shape an automation condition matches against.

        Flat and predictably named, because ``Condition`` addresses fields by
        dotted path and an operator writing a rule has to guess these correctly
        from the UI. ``severity_number`` is included alongside the name so a
        rule can say "worse than error" with a numeric comparison instead of
        enumerating names -- the ordering is not obvious from the strings, and
        it runs backwards.
        """
        severity = parsed.get("severity")
        return {
            "source_type": source_type,
            "organization_id": str(parsed["organization_id"])
            if parsed.get("organization_id")
            else None,
            "device_id": str(parsed["device_id"]) if parsed.get("device_id") else None,
            "source_ip": parsed.get("source_ip"),
            "severity": severity,
            "severity_number": SEVERITY_ORDER.get(str(severity).lower()) if severity else None,
            "facility": parsed.get("facility"),
            "hostname": parsed.get("hostname"),
            "app_name": parsed.get("app_name"),
            "message": parsed.get("message"),
        }

    def stats(self) -> dict[str, Any]:
        """Counters, so a rule that never fires can be diagnosed.

        Without these the only observable is silence, and silence has three
        different causes here: nothing arrived, it arrived below the floor, or
        it arrived and was throttled.
        """
        return {
            "published": self.published,
            "suppressed_by_severity": self.suppressed_by_severity,
            "suppressed_by_rate": self.suppressed_by_rate,
            "suppressed_no_org": self.suppressed_no_org,
            "cap_degraded": self.cap_degraded,
            "tracked_sources": len(self._buckets),
            "severity_floor": self._floor_name,
            "rate_limit_per_window": self._rate_limit,
            "rate_window_seconds": self._window,
        }
