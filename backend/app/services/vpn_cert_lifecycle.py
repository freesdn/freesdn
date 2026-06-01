# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Certificate Lifecycle Service
====================================================

Scans OpenVPN / IPsec site VPN configurations for embedded X.509
certificates, extracts metadata (subject, issuer, expiry, fingerprint),
persists it on the SiteVPNConfiguration row, and surfaces upcoming
expirations with severity-based alerting.
"""

from __future__ import annotations

import contextlib
import logging
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import Site
from app.models.vpn import SiteVPNConfiguration

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PEM extraction patterns
# ---------------------------------------------------------------------------

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)

# OpenVPN inline tags that may contain certs: <cert>, <ca>, <extra-certs>
_OVPN_CERT_TAG_RE = re.compile(
    r"<(?:cert|ca|extra-certs)>\s*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)\s*</(?:cert|ca|extra-certs)>",
    re.DOTALL,
)

# Fallback regex for extracting dates from PEM text (ASN.1 UTCTime / GeneralizedTime)
_ASN1_DATE_RE = re.compile(
    r"Not (?:Before|After)\s*:\s*(.+)",
)


class VPNCertLifecycleService:
    """Track X.509 certificate metadata and expiration across VPN configs."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_certificates(self, org_id: UUID) -> dict:
        """
        Scan all site VPN configs for embedded certificates.

        For OpenVPN configs: parse ``openvpn_config_content`` looking for
        ``<cert>...</cert>`` or ``<ca>...</ca>`` PEM blocks.

        For IPsec configs: look for PEM blocks in ``cert_metadata``
        if it contains a ``pem`` key, or in any text field that stores
        certificate data.

        Updates ``cert_metadata`` and ``cert_expires_at`` columns on each
        SiteVPNConfiguration row where a certificate is found.

        Returns ``{"scanned": int, "updated": int, "errors": int}``.

        Site-scoped: a site-limited caller only scans
        and mutates configs for sites they hold a grant for — never sibling-site
        ``SiteVPNConfiguration`` rows in the same org. The guard reads the
        request-scoped contextvar; it is a no-op for super_admin / org_admin /
        grant-less callers and in background context (the daily Celery scan).
        """
        from app.core.site_access import site_ids_for_request

        stmt = (
            select(SiteVPNConfiguration)
            .where(SiteVPNConfiguration.organization_id == org_id)
            .where(SiteVPNConfiguration.vpn_type.in_(["openvpn", "ipsec"]))
        )
        granted_site_ids = site_ids_for_request()
        if granted_site_ids is not None:
            stmt = stmt.where(SiteVPNConfiguration.site_id.in_(granted_site_ids))
        result = await self._db.execute(stmt)
        configs: list[SiteVPNConfiguration] = list(result.scalars().all())

        scanned = 0
        updated = 0
        errors = 0

        for cfg in configs:
            scanned += 1
            try:
                pem_certs = self._extract_certs_for_config(cfg)
                if not pem_certs:
                    continue

                # Use the *leaf* certificate (first one found in <cert> or
                # first PEM block) for metadata / expiry tracking.  The CA
                # cert typically has a much longer validity.
                best_meta: dict | None = None
                earliest_expiry: datetime | None = None

                for pem in pem_certs:
                    meta = self._parse_cert_metadata(pem)
                    if meta is None:
                        continue

                    not_after = meta.get("not_after")
                    if not_after is None:
                        continue

                    expiry = _parse_iso(not_after)
                    if expiry is None:
                        continue

                    # Track the certificate that expires soonest (leaf cert
                    # is almost always the first, but be safe).
                    if earliest_expiry is None or expiry < earliest_expiry:
                        earliest_expiry = expiry
                        best_meta = meta

                if best_meta and earliest_expiry:
                    cfg.cert_metadata = best_meta
                    cfg.cert_expires_at = earliest_expiry
                    updated += 1

            except Exception:
                logger.exception(
                    "Failed to scan certificate for VPN config %s",
                    cfg.id,
                )
                errors += 1

        if updated:
            await self._db.flush()

        return {"scanned": scanned, "updated": updated, "errors": errors}

    async def get_expiring_certs(
        self,
        org_id: UUID,
        days_ahead: int = 30,
    ) -> list[dict]:
        """
        Return site VPN configs whose certificate expires within
        *days_ahead* days, ordered by soonest expiry first.

        Each item contains:
        ``{config_id, site_id, site_name, vpn_type, cert_subject,
          expires_at, days_remaining, severity}``

        Severity levels:
        - ``critical``: expires in < 1 day (or already expired)
        - ``error``:    1-7 days remaining
        - ``warning``:  7-30 days remaining
        - ``info``:     > 30 days remaining
        """
        from app.core.site_access import site_ids_for_request

        now = datetime.now(UTC)
        horizon = now + timedelta(days=days_ahead)

        stmt = (
            select(SiteVPNConfiguration, Site.name.label("site_name"))
            .join(Site, SiteVPNConfiguration.site_id == Site.id)
            .where(SiteVPNConfiguration.organization_id == org_id)
            .where(SiteVPNConfiguration.cert_expires_at.is_not(None))
            .where(SiteVPNConfiguration.cert_expires_at < horizon)
            .order_by(SiteVPNConfiguration.cert_expires_at.asc())
        )
        # Site-grant scoping: a site-limited caller
        # must not see cert subjects / expiry / site names of sibling sites.
        granted_site_ids = site_ids_for_request()
        if granted_site_ids is not None:
            stmt = stmt.where(SiteVPNConfiguration.site_id.in_(granted_site_ids))
        result = await self._db.execute(stmt)
        rows = result.all()

        alerts: list[dict] = []
        for row in rows:
            cfg: SiteVPNConfiguration = row[0]
            site_name: str = row[1]

            expires_at: datetime = cfg.cert_expires_at  # type: ignore[assignment]
            delta = expires_at - now
            days_remaining = max(int(delta.total_seconds() / 86400), 0)

            cert_subject = None
            if cfg.cert_metadata and isinstance(cfg.cert_metadata, dict):
                cert_subject = cfg.cert_metadata.get("subject")

            severity = _severity_for_days(days_remaining)

            alerts.append(
                {
                    "config_id": str(cfg.id),
                    "site_id": str(cfg.site_id),
                    "site_name": site_name,
                    "vpn_type": cfg.vpn_type,
                    "cert_subject": cert_subject,
                    "expires_at": expires_at.isoformat(),
                    "days_remaining": days_remaining,
                    "severity": severity,
                }
            )

        return alerts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_certs_for_config(
        self,
        cfg: SiteVPNConfiguration,
    ) -> list[str]:
        """Return PEM cert strings found in *cfg*."""
        pems: list[str] = []

        # OpenVPN: look in openvpn_config_content
        if cfg.openvpn_config_content:
            pems.extend(self._extract_pem_from_ovpn(cfg.openvpn_config_content))

        # IPsec / generic: if cert_metadata already has a "pem" key (e.g.
        # uploaded via API), parse that directly.
        if cfg.cert_metadata and isinstance(cfg.cert_metadata, dict):
            existing_pem = cfg.cert_metadata.get("pem")
            if isinstance(existing_pem, str) and "BEGIN CERTIFICATE" in existing_pem:
                pems.extend(_PEM_BLOCK_RE.findall(existing_pem))

        return pems

    def _extract_pem_from_ovpn(self, content: str) -> list[str]:
        """Extract PEM certificate blocks from OpenVPN config content.

        Looks for ``<cert>...</cert>``, ``<ca>...</ca>``, and
        ``<extra-certs>...</extra-certs>`` inline tags first, then falls
        back to bare PEM blocks anywhere in the file.
        """
        pems: list[str] = []

        # Prefer tagged blocks (more specific)
        tagged = _OVPN_CERT_TAG_RE.findall(content)
        if tagged:
            for block in tagged:
                # A single tag may contain multiple concatenated PEM certs
                pems.extend(_PEM_BLOCK_RE.findall(block))

        # Fallback: any PEM block in the file that wasn't already captured
        if not pems:
            pems = _PEM_BLOCK_RE.findall(content)

        return pems

    def _parse_cert_metadata(self, pem_data: str) -> dict | None:
        """
        Parse a PEM-encoded X.509 certificate and return metadata.

        Returns ``{issuer, subject, serial, not_before, not_after,
        fingerprint}`` or ``None`` on failure.

        Tries the ``cryptography`` library first (rich parsing), then
        falls back to the stdlib ``ssl`` module.
        """
        # --- Strategy 1: cryptography library (preferred) ----------------
        try:
            return self._parse_with_cryptography(pem_data)
        except Exception:
            logger.debug("cryptography cert parser failed, trying ssl", exc_info=True)

        # --- Strategy 2: stdlib ssl module --------------------------------
        try:
            return self._parse_with_ssl(pem_data)
        except Exception:
            logger.debug("ssl cert parser failed, trying regex", exc_info=True)

        # --- Strategy 3: regex date extraction (last resort) -------------
        try:
            return self._parse_with_regex(pem_data)
        except Exception:
            logger.debug("All cert parse strategies failed")
            return None

    # ---- cryptography lib ------------------------------------------------

    @staticmethod
    def _parse_with_cryptography(pem_data: str) -> dict:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_pem_x509_certificate(pem_data.encode())

        def _rdn_string(name: x509.Name) -> str:
            parts = []
            for attr in name:
                parts.append(f"{attr.oid._name}={attr.value}")
            return ", ".join(parts)

        fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")

        return {
            "issuer": _rdn_string(cert.issuer),
            "subject": _rdn_string(cert.subject),
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint": fingerprint,
        }

    # ---- stdlib ssl fallback ---------------------------------------------

    @staticmethod
    def _parse_with_ssl(pem_data: str) -> dict:
        import os
        import ssl
        import tempfile

        # ssl.PEM_cert_to_DER_cert only handles the raw base64 portion,
        # but _ssl._test_decode_cert needs a file.  Write to a temp file.
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            os.write(fd, pem_data.encode())
            os.close(fd)
            cert_dict = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)

        def _format_dn(tuples: tuple) -> str:
            parts = []
            for rdn in tuples:
                for key, value in rdn:
                    parts.append(f"{key}={value}")
            return ", ".join(parts)

        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")

        # Convert OpenSSL date strings to ISO format
        not_before = _ssl_date_to_iso(not_before_str)
        not_after = _ssl_date_to_iso(not_after_str)

        # ssl module doesn't give us a fingerprint easily, compute from DER
        import hashlib

        der_bytes = ssl.PEM_cert_to_DER_cert(pem_data)
        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))

        return {
            "issuer": _format_dn(cert_dict.get("issuer", ())),
            "subject": _format_dn(cert_dict.get("subject", ())),
            "serial": str(cert_dict.get("serialNumber", "")),
            "not_before": not_before,
            "not_after": not_after,
            "fingerprint": fingerprint,
        }

    # ---- regex fallback --------------------------------------------------

    @staticmethod
    def _parse_with_regex(pem_data: str) -> dict | None:
        """Last-resort: decode base64, search for printable date strings."""
        import base64
        import hashlib

        # Extract the base64 payload
        lines = pem_data.strip().splitlines()
        b64_lines = [ln.strip() for ln in lines if not ln.strip().startswith("-----")]
        if not b64_lines:
            return None

        try:
            der_bytes = base64.b64decode("".join(b64_lines))
        except Exception:
            return None

        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))

        # Try to find ASN.1 UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime
        # (YYYYMMDDHHMMSSZ) patterns in raw DER bytes.
        utc_time_re = re.compile(rb"\x17\x0d(\d{12}Z)")
        gen_time_re = re.compile(rb"\x18\x0f(\d{14}Z)")

        dates: list[datetime] = []

        for match in utc_time_re.finditer(der_bytes):
            raw = match.group(1).decode()
            try:
                dt = datetime.strptime(raw, "%y%m%d%H%M%SZ").replace(
                    tzinfo=UTC,
                )
                dates.append(dt)
            except ValueError:
                pass

        for match in gen_time_re.finditer(der_bytes):
            raw = match.group(1).decode()
            try:
                dt = datetime.strptime(raw, "%Y%m%d%H%M%SZ").replace(
                    tzinfo=UTC,
                )
                dates.append(dt)
            except ValueError:
                pass

        if len(dates) < 2:
            return None

        # ASN.1 validity is always not_before then not_after in sequence
        not_before = dates[0]
        not_after = dates[1]

        return {
            "issuer": None,
            "subject": None,
            "serial": None,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "fingerprint": fingerprint,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _severity_for_days(days_remaining: int) -> str:
    """Map days-until-expiry to severity level."""
    if days_remaining < 1:
        return "critical"
    if days_remaining <= 7:
        return "error"
    if days_remaining <= 30:
        return "warning"
    return "info"


def _parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 datetime string, return None on failure."""
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


def _ssl_date_to_iso(ssl_date: str) -> str:
    """Convert an OpenSSL-style date string to ISO-8601.

    Example input: ``'Jan  5 09:34:00 2024 GMT'``
    """
    if not ssl_date:
        return ""
    try:
        dt = datetime.strptime(ssl_date, "%b %d %H:%M:%S %Y %Z")
        dt = dt.replace(tzinfo=UTC)
        return dt.isoformat()
    except ValueError:
        return ssl_date
