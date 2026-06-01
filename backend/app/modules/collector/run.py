# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — standalone collector runner (dedicated UDP listener process)
======================================================================

Runs the SNMP-trap / Syslog / NetFlow UDP receivers as ONE dedicated process,
separate from the gunicorn API workers.

Why a dedicated service (the honest gap this closes)
----------------------------------------------------
The receivers were only ever started *inside* the API process via the module
``on_start`` hook. That deployment cannot reliably accept external UDP:

* Under multi-worker gunicorn only one worker can bind a given UDP port (the
  rest degrade gracefully, but their ``/health`` view of the collector is then
  inconsistent).
* The API container is intentionally capless, non-root and read-only, so it
  cannot bind the privileged syslog/SNMP ports (514 / 162) at all.

A single dedicated, non-root process binds the listeners and makes them
externally reachable. It needs neither root nor a Linux capability: the
``collector`` compose service sets the namespaced
``net.ipv4.ip_unprivileged_port_start=0`` sysctl so the unprivileged user can
bind 514 / 162. This is the "dedicated collector-service deployment" the
capability record referenced. Deploy it with the ``collector`` compose profile
(``COMPOSE_PROFILES=...,collector``), which publishes the UDP ports.

Receivers are GLOBAL and attribute each datagram to an org by resolving the
source IP to a known Device (see ``SourceResolver``). The per-org
``CollectorConfig`` rows are therefore merged into one listen profile: the union
of enabled protocols and the union of source-IP allowlists. The *listen ports*
are owned by the deployment (the ``COLLECTOR_*_PORT`` env the compose service
also publishes) so the published container ports can never diverge from the
bound ports; the per-org DB port is only the default. Config changes are picked
up by a periodic re-read; a reload that fails to (re)bind is retried on the next
poll rather than silently leaving a receiver down. SIGTERM / SIGINT shut the
receivers down cleanly.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

logger = logging.getLogger("app.modules.collector.run")

# How often to re-read CollectorConfig so a UI toggle is picked up without a
# restart. A change to the merged listen profile triggers a receiver reload.
_POLL_INTERVAL_SECONDS = 30.0

# Liveness marker touched each poll; the compose healthcheck checks its mtime.
_HEARTBEAT = Path(os.getenv("COLLECTOR_HEARTBEAT_FILE", "/tmp/collector.alive"))


async def _load_merged_config(db: Any) -> SimpleNamespace | None:
    """Merge every eligible org's ``CollectorConfig`` into one listen profile.

    Only orgs that are active AND have the ``collector`` module enabled are
    considered. Returns ``None`` when no eligible org has any receiver enabled
    (the process then idles, still polling, until one is turned on).

    Receivers listen on ONE port per protocol globally (first enabled org wins
    the port); packets are attributed to the right org downstream by source-IP
    resolution, so this is correct for the single-org appliance and sane for
    multi-org.
    """
    from sqlalchemy import select

    from app.models.core import Organization
    from app.modules.collector.models import CollectorConfig
    from app.modules.models import OrganizationModule

    active_orgs = {
        row[0]
        for row in (
            await db.execute(
                select(Organization.id).where(
                    Organization.is_active.is_(True),
                    Organization.deleted_at.is_(None),
                )
            )
        ).all()
    }
    collector_orgs = {
        row[0]
        for row in (
            await db.execute(
                select(OrganizationModule.organization_id).where(
                    OrganizationModule.module_id == "collector",
                    OrganizationModule.is_enabled.is_(True),
                )
            )
        ).all()
    }
    eligible = active_orgs & collector_orgs
    if not eligible:
        return None

    configs = (
        (
            await db.execute(
                select(CollectorConfig)
                .where(CollectorConfig.organization_id.in_(eligible))
                .order_by(CollectorConfig.organization_id)
            )
        )
        .scalars()
        .all()
    )
    if not configs:
        return None

    merged = SimpleNamespace(
        snmp_enabled=False,
        snmp_port=162,
        snmp_community="public",
        syslog_enabled=False,
        syslog_port=514,
        netflow_enabled=False,
        netflow_port=2055,
        allowed_source_ips=[],
    )
    allow: set[str] = set()
    for c in configs:
        if c.snmp_enabled and not merged.snmp_enabled:
            merged.snmp_enabled = True
            merged.snmp_port = c.snmp_port
            merged.snmp_community = c.snmp_community
        if c.syslog_enabled and not merged.syslog_enabled:
            merged.syslog_enabled = True
            merged.syslog_port = c.syslog_port
        if c.netflow_enabled and not merged.netflow_enabled:
            merged.netflow_enabled = True
            merged.netflow_port = c.netflow_port
        for cidr in c.allowed_source_ips or []:
            allow.add(cidr)
    merged.allowed_source_ips = sorted(allow)

    # The deployment (compose env) owns the LISTEN ports — the same COLLECTOR_*_PORT
    # the compose service publishes — so the published container ports can never
    # diverge from the bound ports. The per-org DB port is only the fallback.
    merged.syslog_port = _port_from_env("COLLECTOR_SYSLOG_PORT", merged.syslog_port)
    merged.snmp_port = _port_from_env("COLLECTOR_SNMP_PORT", merged.snmp_port)
    merged.netflow_port = _port_from_env("COLLECTOR_NETFLOW_PORT", merged.netflow_port)

    if not (merged.snmp_enabled or merged.syslog_enabled or merged.netflow_enabled):
        return None
    return merged


def _profile_key(cfg: SimpleNamespace | None) -> tuple:
    """A comparable signature of the listen profile, to detect changes."""
    if cfg is None:
        return ()
    return (
        cfg.snmp_enabled,
        cfg.snmp_port,
        cfg.snmp_community,
        cfg.syslog_enabled,
        cfg.syslog_port,
        cfg.netflow_enabled,
        cfg.netflow_port,
        tuple(cfg.allowed_source_ips),
    )


def _port_from_env(name: str, default: int) -> int:
    """Listen port from the deployment env, falling back to the per-org default."""
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("collector.run: ignoring invalid %s=%r; using %d", name, raw, default)
        return default


def _all_receivers_bound(manager: Any, cfg: SimpleNamespace) -> bool:
    """True when every protocol enabled in ``cfg`` has a running receiver.

    A UDP rebind can momentarily lose the port to the still-closing previous
    socket (the manager swallows that ``OSError``); this lets the caller detect a
    partial bind and retry instead of committing a profile whose receivers are
    silently down.
    """
    status = manager.status()
    return all(
        (not enabled) or status.get(key, {}).get("running", False)
        for enabled, key in (
            (cfg.syslog_enabled, "syslog"),
            (cfg.snmp_enabled, "snmp_trap"),
            (cfg.netflow_enabled, "netflow"),
        )
    )


async def _run() -> None:
    from app.db.session import AsyncSessionLocal
    from app.modules.collector.services.manager import get_collector_manager

    manager = get_collector_manager()
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:  # pragma: no cover — non-POSIX fallback
            pass

    current_key: tuple = ()
    started = False

    while not stop_event.is_set():
        try:
            async with AsyncSessionLocal() as db:
                merged = await _load_merged_config(db)
            new_key = _profile_key(merged)
            if new_key != current_key:
                if merged is None:
                    if started:
                        await manager.stop()
                        started = False
                    current_key = new_key
                    logger.info("collector.run listen profile applied: (idle)")
                else:
                    if started:
                        await manager.reload_config(merged)
                    else:
                        await manager.start(merged)
                        started = True
                    # Commit the new profile only if every enabled receiver
                    # actually bound; otherwise leave current_key unchanged so the
                    # next poll retries. A transient bind failure (a UDP rebind
                    # racing the still-closing previous socket, or a momentary port
                    # conflict) then self-heals instead of silently dropping ingest
                    # until the next config change.
                    if _all_receivers_bound(manager, merged):
                        current_key = new_key
                        logger.info("collector.run listen profile applied: %s", new_key)
                    else:
                        logger.warning(
                            "collector.run: not all enabled receivers bound; retrying next poll"
                        )
        except Exception:
            logger.exception("collector.run config poll failed")

        try:
            _HEARTBEAT.touch()
        except OSError:  # pragma: no cover — heartbeat is best-effort
            pass

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_POLL_INTERVAL_SECONDS)
        except TimeoutError:
            pass

    logger.info("collector.run shutting down receivers...")
    try:
        await manager.stop()
    except Exception:  # pragma: no cover — best-effort shutdown
        logger.exception("collector.run shutdown error")


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger.info("FreeSDN collector runner starting (dedicated UDP listener process)")
    asyncio.run(_run())


if __name__ == "__main__":
    main()
