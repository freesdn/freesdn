# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Celery Tasks
================================

Background tasks for VPN integration:
- sync_vpn_connections: Sync live VPN state into the database
- check_vpn_health: Record health checks + detect state transitions + alert
- auto_reconnect: Auto-reconnect failed VPN connections with backoff
- check_tunnel_health: Monitor site-to-site tunnel health
- purge_old_vpn_health_checks: Clean up old health check data
- purge_old_vpn_events: Clean up old VPN event log entries
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.db.session import get_logdb_celery_factory
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)

# LogDB session factory for time-series writes (mandatory — requires LOGDB_URL)
# Lazy: defers RuntimeError to task execution, not module import
_logdb_factory = None


def _get_logdb():
    global _logdb_factory
    if _logdb_factory is None:
        _logdb_factory = get_logdb_celery_factory()
    return _logdb_factory


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="vpn.sync_vpn_connections",
    soft_time_limit=120,
    time_limit=180,
)
def sync_vpn_connections(self) -> dict[str, Any]:
    """
    Sync live VPN connections (Tailscale / WireGuard) into the database.
    Runs periodically to keep connection state up-to-date.
    """

    async def _run() -> dict[str, Any]:
        from app.services.vpn_integration import PersistentVPNService as svc

        synced = 0
        errors = 0

        async with AsyncSessionLocal() as session:
            try:
                connections = await svc.sync_live_connections(session)
                synced = len(connections) if connections else 0
                await session.commit()
                logger.info("Synced %d VPN connections", synced)
            except Exception as e:
                logger.error("Failed to sync VPN connections: %s", e)
                errors += 1
                await session.rollback()

        return {
            "synced": synced,
            "errors": errors,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="vpn.check_vpn_health", soft_time_limit=120, time_limit=180
)
def check_vpn_health(self) -> dict[str, Any]:
    """
    Record health checks for all active VPN connections.
    Detects state transitions (healthy→unhealthy, unhealthy→healthy)
    and fires alerts via VPNAlertService.
    """
    # Skip if another instance is already running
    from app.core.redis_client import get_sync_redis

    _lock_redis = None
    _lock_acquired = False
    try:
        _lock_redis = get_sync_redis()
        if not _lock_redis.set("vpn:check_vpn_health:lock", "1", nx=True, ex=300):
            _lock_redis.close()
            return {"skipped": True, "reason": "lock_held"}
        _lock_acquired = True
    except Exception:
        pass

    async def _run() -> dict[str, Any]:
        from app.services.vpn_alerts import VPNAlertService
        from app.services.vpn_integration import (
            PersistentVPNService as svc,
        )
        from app.services.vpn_integration import (
            TailscaleService,
        )

        checked = 0
        errors = 0
        alerts_fired = 0

        async with AsyncSessionLocal() as session:
            try:
                # Only process connections with org_id set (tenant isolation)
                from sqlalchemy import select as sa_select

                from app.models.vpn import VPNConnectionRecord as ConnModel

                stmt = sa_select(ConnModel).where(ConnModel.organization_id.isnot(None))
                conn_result = await session.execute(stmt)
                connections = list(conn_result.scalars().all())
                ts = TailscaleService()
                alert_svc = VPNAlertService(session)
                now = datetime.now(UTC)

                # Filter to connections that are due for a health check
                eligible: list[tuple[Any, str]] = []  # (conn, target)
                for conn in connections:
                    target = conn.endpoint or conn.remote_ip
                    if not target:
                        continue
                    # Respect per-connection health_check_interval
                    if conn.extra_data and conn.extra_data.get("last_health_check_at"):
                        try:
                            last_check = datetime.fromisoformat(
                                conn.extra_data["last_health_check_at"]
                            )
                            interval = conn.extra_data.get("health_check_interval", 300)
                            if (now - last_check).total_seconds() < interval:
                                continue
                        except (ValueError, TypeError):
                            pass
                    eligible.append((conn, target))

                # Phase 1: Parallel pings (bounded concurrency)
                sem = asyncio.Semaphore(20)

                async def _ping(target: str) -> float | None:
                    async with sem:
                        return await ts.ping(target)

                ping_tasks = [_ping(t) for _, t in eligible]
                ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)

                # Phase 2: Sequential DB updates (shared session)
                # Write health check records to LogDB (time-series)
                async with _get_logdb()() as logdb:
                    for (conn, target), ping_result in zip(eligible, ping_results, strict=False):
                        try:
                            latency = None if isinstance(ping_result, Exception) else ping_result
                            is_healthy = latency is not None

                            was_healthy = conn.status == "connected"
                            latency_threshold = float(
                                (conn.extra_data or {}).get("latency_threshold_ms", 200)
                            )
                            was_degraded = conn.latency_ms and conn.latency_ms > latency_threshold

                            # Write health check to LogDB (time-series)
                            await svc.record_health_check(
                                logdb,
                                connection_id=conn.id,
                                site_id=None,
                                is_healthy=is_healthy,
                                latency_ms=latency,
                                status="connected" if is_healthy else "error",
                                error_message=None if is_healthy else f"Ping to {target} failed",
                                rx_bytes=conn.rx_bytes or 0,
                                tx_bytes=conn.tx_bytes or 0,
                            )
                            checked += 1

                            # Track last check time (primary DB)
                            extra = dict(conn.extra_data or {})
                            extra["last_health_check_at"] = now.isoformat()
                            conn.extra_data = extra

                            # Detect state transitions and fire alerts (primary DB)
                            if was_healthy and not is_healthy:
                                conn.status = "error"
                                await alert_svc.on_connection_down(
                                    conn,
                                    f"Health check failed: ping to {target} timed out",
                                )
                                alerts_fired += 1
                            elif not was_healthy and is_healthy:
                                # Reaching the endpoint/remote-IP is NOT proof a
                                # tunnel-based VPN is actually up — the public
                                # endpoint is reachable over the internet whether
                                # or not the tunnel is established. Auto-promoting
                                # those types to 'connected' here would silently
                                # undo the honest connect-time status, so only fire
                                # the restored alert and leave status to the connect
                                # action / tunnel status. Promote only types whose
                                # reachability == liveness.
                                if conn.vpn_type not in (
                                    "openvpn",
                                    "wireguard",
                                    "netbird",
                                    "tailscale",
                                ):
                                    conn.status = "connected"
                                    conn.connected_at = datetime.now(UTC)
                                await alert_svc.on_connection_restored(conn, latency_ms=latency)
                                alerts_fired += 1
                            elif (
                                is_healthy
                                and latency
                                and latency > latency_threshold
                                and not was_degraded
                            ):
                                await alert_svc.on_health_degraded(conn, latency)
                                alerts_fired += 1

                        except Exception as e:
                            logger.warning(
                                "Health check failed for connection %s: %s",
                                conn.id,
                                e,
                            )
                            errors += 1

                    await logdb.commit()

                await session.commit()
                logger.info(
                    "VPN health checks: %d ok, %d errors, %d alerts",
                    checked,
                    errors,
                    alerts_fired,
                )
            except Exception as e:
                logger.error("VPN health check task failed: %s", e)
                await session.rollback()

        return {
            "checked": checked,
            "errors": errors,
            "alerts_fired": alerts_fired,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    try:
        return asyncio.run(_run())
    finally:
        if _lock_redis:
            try:
                if _lock_acquired:
                    _lock_redis.delete("vpn:check_vpn_health:lock")
                _lock_redis.close()
            except Exception:
                pass


@celery_app.task(
    bind=True, base=FreeSDNTask, name="vpn.auto_reconnect", soft_time_limit=120, time_limit=180
)
def auto_reconnect(self) -> dict[str, Any]:
    """
    Auto-reconnect failed VPN connections with exponential backoff.
    Runs every 1 minute. Manages backoff state per connection.
    """

    async def _run() -> dict[str, Any]:
        from app.services.vpn_reconnect import VPNReconnectService

        # Skip-if-running guard to prevent duplicate reconnect attempts
        _lock_redis = None
        try:
            from app.core.redis_client import get_sync_redis

            _lock_redis = get_sync_redis()
            if not _lock_redis.set("vpn:auto_reconnect:lock", "1", nx=True, ex=120):
                logger.debug("auto_reconnect: skipped, another instance is running")
                return {"skipped": True, "reason": "lock_held"}
        except Exception:
            pass  # If Redis unavailable, proceed without lock

        try:
            async with AsyncSessionLocal() as session:
                try:
                    reconnect_svc = VPNReconnectService(session)
                    result = await reconnect_svc.check_and_reconnect()
                    await session.commit()
                    logger.info(
                        "VPN auto-reconnect: %d attempted, %d succeeded, %d failed, %d exhausted",
                        result.get("attempted", 0),
                        result.get("succeeded", 0),
                        result.get("failed", 0),
                        result.get("exhausted", 0),
                    )
                    return result
                except Exception as e:
                    logger.error("VPN auto-reconnect task failed: %s", e)
                    await session.rollback()
                    return {"error": str(e), "timestamp": datetime.now(UTC).isoformat()}
        finally:
            # Release lock and close Redis client
            if _lock_redis:
                try:
                    _lock_redis.delete("vpn:auto_reconnect:lock")
                    _lock_redis.close()
                except Exception:
                    pass

    return asyncio.run(_run())


@celery_app.task(
    bind=True, base=FreeSDNTask, name="vpn.check_tunnel_health", soft_time_limit=120, time_limit=180
)
def check_tunnel_health(self) -> dict[str, Any]:
    """
    Monitor site-to-site tunnel health.
    Pings remote gateways for active tunnels, updates status on failure.
    """

    async def _run() -> dict[str, Any]:
        import ipaddress as _ipaddress

        from sqlalchemy import select

        # Skip-if-running guard (same pattern as check_vpn_health)
        from app.core.redis_client import get_sync_redis
        from app.models.vpn import SiteToSiteTunnel
        from app.services.vpn_alerts import VPNAlertService

        _lock_redis_t = None
        _lock_acquired_t = False
        try:
            _lock_redis_t = get_sync_redis()
            if not _lock_redis_t.set("vpn:check_tunnel_health:lock", "1", nx=True, ex=300):
                _lock_redis_t.close()
                return {"skipped": True, "reason": "lock_held"}
            _lock_acquired_t = True
        except Exception:
            pass

        checked = 0
        errors = 0
        status_changes = 0

        def _is_valid_ip(addr: str) -> bool:
            """Reject hostnames — only allow valid IPv4/IPv6 addresses."""
            try:
                _ipaddress.ip_address(addr.strip())
                return True
            except (ValueError, AttributeError):
                return False

        async with AsyncSessionLocal() as session:
            try:
                # Tenant isolation: only process tunnels with org_id
                result = await session.execute(
                    select(SiteToSiteTunnel).where(
                        SiteToSiteTunnel.status.in_(["active", "error"]),
                        SiteToSiteTunnel.organization_id.isnot(None),
                    )
                )
                tunnels = list(result.scalars().all())
                alert_svc = VPNAlertService(session)

                # Collect eligible tunnels and their health check IPs
                eligible_tunnels: list[tuple[Any, str]] = []
                for tunnel in tunnels:
                    config_a = tunnel.config_a or {}
                    config_b = tunnel.config_b or {}
                    health_ip = (
                        config_a.get("health_check_ip")
                        or config_b.get("health_check_ip")
                        or config_a.get("endpoint")
                        or config_b.get("endpoint")
                    )
                    if health_ip and _is_valid_ip(str(health_ip)):
                        eligible_tunnels.append((tunnel, str(health_ip)))

                # Phase 1: Parallel pings (bounded concurrency)
                sem = asyncio.Semaphore(10)

                async def _ping_ip(ip: str) -> bool:
                    async with sem:
                        try:
                            proc = await asyncio.create_subprocess_exec(
                                "ping",
                                "-c",
                                "1",
                                "-W",
                                "3",
                                ip,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            await asyncio.wait_for(proc.communicate(), timeout=5)
                            return proc.returncode == 0
                        except Exception:
                            return False

                ping_tasks = [_ping_ip(ip) for _, ip in eligible_tunnels]
                ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)

                # Phase 2: Sequential DB updates
                from app.models.vpn import VPNHealthCheck

                async with _get_logdb()() as logdb:
                    for (tunnel, health_ip), ping_result in zip(
                        eligible_tunnels, ping_results, strict=False
                    ):
                        try:
                            is_healthy = ping_result is True
                            checked += 1

                            # Record tunnel health check to LogDB (time-series)
                            health_record = VPNHealthCheck(
                                time=datetime.now(UTC),
                                connection_id=None,
                                tunnel_id=tunnel.id,
                                site_id=tunnel.site_a_id,
                                is_healthy=is_healthy,
                                latency_ms=None,
                                status="active" if is_healthy else "error",
                                error_message=None if is_healthy else f"Ping to {health_ip} failed",
                                rx_bytes=0,
                                tx_bytes=0,
                                peer_count=0,
                            )
                            logdb.add(health_record)

                            old_status = tunnel.status
                            new_status = "active" if is_healthy else "error"

                            if old_status != new_status:
                                tunnel.status = new_status
                                tunnel.last_health_check = datetime.now(UTC)
                                if not is_healthy:
                                    tunnel.error_message = f"Health check to {health_ip} failed"
                                else:
                                    tunnel.error_message = None

                                await alert_svc.on_tunnel_status_change(
                                    tunnel_id=tunnel.id,
                                    organization_id=tunnel.organization_id,
                                    old_status=old_status,
                                    new_status=new_status,
                                    error_message=tunnel.error_message,
                                )
                                status_changes += 1
                            else:
                                tunnel.last_health_check = datetime.now(UTC)

                        except Exception as e:
                            logger.warning("Tunnel health check failed for %s: %s", tunnel.id, e)
                            errors += 1

                    await logdb.commit()

                await session.commit()
                logger.info(
                    "S2S tunnel health: %d checked, %d errors, %d status changes",
                    checked,
                    errors,
                    status_changes,
                )
            except Exception as e:
                logger.error("Tunnel health check task failed: %s", e)
                await session.rollback()

        try:
            return {
                "checked": checked,
                "errors": errors,
                "status_changes": status_changes,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        finally:
            if _lock_redis_t:
                try:
                    if _lock_acquired_t:
                        _lock_redis_t.delete("vpn:check_tunnel_health:lock")
                    _lock_redis_t.close()
                except Exception:
                    pass

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="vpn.purge_old_vpn_health_checks",
    soft_time_limit=300,
    time_limit=360,
)
def purge_old_vpn_health_checks(self, retention_days: int = 30) -> dict[str, Any]:
    """
    Delete VPN health check data older than retention period.
    TimescaleDB retention policy handles this, but we add an explicit fallback.
    """

    async def _run() -> dict[str, Any]:
        from app.services.vpn_integration import PersistentVPNService as svc

        async with _get_logdb()() as logdb:
            try:
                purged = await svc.purge_old_health_checks(
                    logdb,
                    retention_days=retention_days,
                )
                await logdb.commit()
                logger.info("Purged %d old VPN health checks", purged)
                return {
                    "purged": purged,
                    "retention_days": retention_days,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            except Exception as e:
                logger.error("VPN health check purge failed: %s", e)
                await logdb.rollback()
                return {"error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="vpn.scan_vpn_certificates",
    soft_time_limit=120,
    time_limit=180,
)
def scan_vpn_certificates(self) -> dict[str, Any]:
    """
    Scan all VPN configs for X.509 certificates and update metadata.
    Runs daily to keep cert expiry tracking up-to-date.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import select as _select

        from app.models.vpn import SiteVPNConfiguration
        from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

        total_scanned = 0
        total_updated = 0
        total_errors = 0

        async with AsyncSessionLocal() as session:
            try:
                # Collect all distinct org IDs that have cert-bearing VPN configs (single query)
                org_result = await session.execute(
                    _select(SiteVPNConfiguration.organization_id)
                    .where(SiteVPNConfiguration.vpn_type.in_(["openvpn", "ipsec"]))
                    .distinct()
                )
                org_ids = [row[0] for row in org_result.all() if row[0]]

                cert_svc = VPNCertLifecycleService(session)
                for org_id in org_ids:
                    result = await cert_svc.scan_certificates(org_id)
                    total_scanned += result.get("scanned", 0)
                    total_updated += result.get("updated", 0)
                    total_errors += result.get("errors", 0)

                await session.commit()
                logger.info(
                    "VPN cert scan: %d scanned, %d updated, %d errors",
                    total_scanned,
                    total_updated,
                    total_errors,
                )
                return {
                    "scanned": total_scanned,
                    "updated": total_updated,
                    "errors": total_errors,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            except Exception as e:
                logger.error("VPN cert scan task failed: %s", e)
                await session.rollback()
                return {"error": str(e)}

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="vpn.purge_old_vpn_events",
    soft_time_limit=300,
    time_limit=360,
)
def purge_old_vpn_events(self, retention_days: int = 90) -> dict[str, Any]:
    """
    Delete VPN event log entries older than retention period.
    Default: 90 days.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import text

        async with AsyncSessionLocal() as session:
            try:
                cutoff = datetime.now(UTC) - timedelta(days=retention_days)
                result = await session.execute(
                    text("DELETE FROM vpn.vpn_events WHERE created_at < :cutoff"),
                    {"cutoff": cutoff},
                )
                purged = int(result.rowcount or 0)
                await session.commit()
                logger.info("Purged %d old VPN events", purged)
                return {
                    "purged": purged,
                    "retention_days": retention_days,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            except Exception as e:
                logger.error("VPN event purge failed: %s", e)
                await session.rollback()
                return {"error": str(e)}

    return asyncio.run(_run())
