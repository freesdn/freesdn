# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Application Classifier (DPI)
==========================================

Port+protocol based traffic classification with O(1) lookup.
Classifies NetFlow records into application names and categories.
"""

import logging
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.collector.models import (
    AppCategory,
    ApplicationClassificationRule,
)

logger = logging.getLogger(__name__)


# Built-in classification rules: (protocol, port) → (app_name, category)
BUILTIN_RULES: list[tuple[int, int, str, str]] = [
    # Web
    (6, 80, "HTTP", AppCategory.WEB),
    (6, 443, "HTTPS", AppCategory.WEB),
    (6, 8080, "HTTP Proxy", AppCategory.WEB),
    (6, 8443, "HTTPS Alt", AppCategory.WEB),
    # DNS
    (17, 53, "DNS", AppCategory.DNS),
    (6, 53, "DNS/TCP", AppCategory.DNS),
    (6, 853, "DNS-over-TLS", AppCategory.DNS),
    (17, 853, "DNS-over-TLS", AppCategory.DNS),
    # Email
    (6, 25, "SMTP", AppCategory.EMAIL),
    (6, 465, "SMTPS", AppCategory.EMAIL),
    (6, 587, "SMTP Submission", AppCategory.EMAIL),
    (6, 110, "POP3", AppCategory.EMAIL),
    (6, 995, "POP3S", AppCategory.EMAIL),
    (6, 143, "IMAP", AppCategory.EMAIL),
    (6, 993, "IMAPS", AppCategory.EMAIL),
    # Conferencing / VoIP
    (17, 3478, "STUN/TURN", AppCategory.CONFERENCING),
    (17, 3479, "STUN/TURN", AppCategory.CONFERENCING),
    (17, 3480, "STUN/TURN", AppCategory.CONFERENCING),
    (17, 19302, "Google STUN", AppCategory.CONFERENCING),
    (17, 8801, "Zoom Media", AppCategory.CONFERENCING),
    (17, 8802, "Zoom Media", AppCategory.CONFERENCING),
    (6, 8801, "Zoom Signaling", AppCategory.CONFERENCING),
    # VoIP
    (6, 5060, "SIP", AppCategory.VOIP),
    (17, 5060, "SIP", AppCategory.VOIP),
    (6, 5061, "SIP/TLS", AppCategory.VOIP),
    (17, 5004, "RTP", AppCategory.VOIP),
    # Streaming
    (6, 1935, "RTMP", AppCategory.STREAMING),
    (6, 554, "RTSP", AppCategory.STREAMING),
    (17, 554, "RTSP", AppCategory.STREAMING),
    # File Transfer
    (6, 21, "FTP", AppCategory.FILE_TRANSFER),
    (6, 22, "SSH/SFTP", AppCategory.FILE_TRANSFER),
    (6, 445, "SMB", AppCategory.FILE_TRANSFER),
    (6, 139, "NetBIOS/SMB", AppCategory.FILE_TRANSFER),
    (6, 2049, "NFS", AppCategory.FILE_TRANSFER),
    # Database
    (6, 3306, "MySQL", AppCategory.DATABASE),
    (6, 5432, "PostgreSQL", AppCategory.DATABASE),
    (6, 27017, "MongoDB", AppCategory.DATABASE),
    (6, 6379, "Redis", AppCategory.DATABASE),
    (6, 1433, "MSSQL", AppCategory.DATABASE),
    (6, 1521, "Oracle", AppCategory.DATABASE),
    # VPN
    (17, 1194, "OpenVPN", AppCategory.VPN_TUNNEL),
    (17, 4500, "IPsec NAT-T", AppCategory.VPN_TUNNEL),
    (17, 500, "IKE", AppCategory.VPN_TUNNEL),
    (17, 51820, "WireGuard", AppCategory.VPN_TUNNEL),
    # Infrastructure
    (17, 123, "NTP", AppCategory.INFRASTRUCTURE),
    (17, 161, "SNMP", AppCategory.INFRASTRUCTURE),
    (17, 162, "SNMP Trap", AppCategory.INFRASTRUCTURE),
    (6, 179, "BGP", AppCategory.INFRASTRUCTURE),
    (17, 514, "Syslog", AppCategory.INFRASTRUCTURE),
    (17, 67, "DHCP Server", AppCategory.INFRASTRUCTURE),
    (17, 68, "DHCP Client", AppCategory.INFRASTRUCTURE),
    (17, 69, "TFTP", AppCategory.INFRASTRUCTURE),
    # Security
    (6, 1812, "RADIUS Auth", AppCategory.SECURITY),
    (17, 1812, "RADIUS Auth", AppCategory.SECURITY),
    (6, 1813, "RADIUS Acct", AppCategory.SECURITY),
    (17, 1813, "RADIUS Acct", AppCategory.SECURITY),
    (6, 389, "LDAP", AppCategory.SECURITY),
    (6, 636, "LDAPS", AppCategory.SECURITY),
    (6, 88, "Kerberos", AppCategory.SECURITY),
    # Gaming
    (17, 27015, "Steam/Valve", AppCategory.GAMING),
    (17, 3074, "Xbox Live", AppCategory.GAMING),
    (17, 3478, "PlayStation", AppCategory.GAMING),
    # IoT
    (6, 1883, "MQTT", AppCategory.IOT),
    (6, 8883, "MQTT/TLS", AppCategory.IOT),
    (17, 5683, "CoAP", AppCategory.IOT),
]


class ApplicationClassifier:
    """
    Port+protocol based traffic classification with O(1) lookup.

    Usage:
        classifier = ApplicationClassifier()
        await classifier.load_rules(session)
        app_name, app_category = classifier.classify(6, 443)
        # → ("HTTPS", "web")
    """

    def __init__(self) -> None:
        # (protocol, port) → (app_name, app_category)
        self._port_map: dict[tuple[int, int], tuple[str, str]] = {}
        self._loaded: bool = False

    async def load_rules(self, session: AsyncSession, organization_id: UUID | None = None) -> None:
        """Load all rules into memory. Called once at startup."""
        # 1. Load built-in rules
        for proto, port, name, category in BUILTIN_RULES:
            self._port_map[(proto, port)] = (name, category)

        # 2. Load custom rules from DB (override built-in by priority)
        try:
            query = (
                select(ApplicationClassificationRule)
                .where(ApplicationClassificationRule.enabled)
                .order_by(
                    ApplicationClassificationRule.priority.desc()
                )  # higher priority last = overrides
            )
            if organization_id is not None:
                query = query.where(
                    or_(
                        ApplicationClassificationRule.is_system,
                        ApplicationClassificationRule.organization_id == organization_id,
                    )
                )
            else:
                query = query.where(ApplicationClassificationRule.is_system)

            result = await session.execute(query)
            custom_rules = result.scalars().all()
            for rule in custom_rules:
                if rule.port is not None and rule.protocol is not None:
                    self._port_map[(rule.protocol, rule.port)] = (
                        rule.name,
                        rule.app_category,
                    )
                # Handle port ranges
                if rule.port_range_start is not None and rule.port_range_end is not None:
                    range_size = rule.port_range_end - rule.port_range_start + 1
                    if range_size > 1000:
                        logger.warning(
                            "Skipping rule %s: port range too large (%d)", rule.name, range_size
                        )
                        continue
                    proto = rule.protocol or 6
                    for p in range(rule.port_range_start, rule.port_range_end + 1):
                        self._port_map[(proto, p)] = (rule.name, rule.app_category)

            logger.info(
                "Application classifier loaded: %d rules (%d built-in + %d custom)",
                len(self._port_map),
                len(BUILTIN_RULES),
                len(custom_rules),
            )
        except Exception:
            logger.warning("Failed to load custom DPI rules from DB", exc_info=True)

        self._loaded = True

    def classify(self, protocol: int, dest_port: int | None) -> tuple[str | None, str | None]:
        """
        O(1) lookup: returns (app_name, app_category) or (None, None).
        """
        if dest_port is None:
            return (None, None)
        return self._port_map.get((protocol, dest_port), (None, None))

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def rule_count(self) -> int:
        return len(self._port_map)


async def seed_builtin_rules(session: AsyncSession) -> int:
    """Seed built-in classification rules into the database (idempotent)."""
    existing = await session.execute(
        select(ApplicationClassificationRule.id).where(
            ApplicationClassificationRule.is_system,
        )
    )
    if existing.scalars().first():
        return 0  # Already seeded

    count = 0
    for proto, port, name, category in BUILTIN_RULES:
        rule = ApplicationClassificationRule(
            organization_id=None,
            name=name,
            app_category=category,
            protocol=proto,
            port=port,
            is_system=True,
            priority=50,
            enabled=True,
        )
        session.add(rule)
        count += 1

    await session.flush()
    logger.info("Seeded %d built-in DPI classification rules", count)
    return count
