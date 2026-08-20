# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Provisioning Service
========================================

GDMS-style zero-touch phone provisioning engine.

Manages the full provisioning lifecycle:
  1. Config templates → per-phone XML generation
  2. HTTP endpoint for phones to pull configs (cfg{MAC}.xml)
  3. Provisioning status tracking
  4. Config diff detection for smart re-provisioning
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID
from xml.etree.ElementTree import Element, SubElement, tostring

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.grandstream.constants import (
    P_ACCOUNT_ACTIVE,
    P_ACCOUNT_NAME,
    P_AUTH_ID,
    P_AUTH_PASSWORD,
    P_DISPLAY_NAME,
    P_SIP_USER_ID,
)
from app.core.crypto import decrypt_credential

logger = logging.getLogger(__name__)

# Default provisioning directory
_PROVISION_DIR = Path("/data/provisioning/voip")

# Max config file size (128KB — typical phone config is 2-10KB)
_MAX_CONFIG_SIZE = 128 * 1024


class ProvisioningError(Exception):
    """Provisioning operation error."""

    pass


class ProvisioningService:
    """
    GDMS-style phone provisioning service.

    Generates per-phone XML configs from templates, manages config files
    on disk for HTTP serving, and tracks provisioning state.
    """

    def __init__(
        self,
        db: AsyncSession,
        provision_dir: str | Path | None = None,
        organization_id: UUID | None = None,
    ):
        self.db = db
        self.provision_dir = Path(provision_dir) if provision_dir else _PROVISION_DIR
        self.organization_id = organization_id

    def _sites_for_org(self):
        """Subquery of site IDs for the current organization (∩ per-user site
        grants when the request's caller is site-limited)."""
        from sqlalchemy import select as sa_select

        from app.core.site_access import site_ids_for_request
        from app.models.core import Site

        q = sa_select(Site.id).where(
            Site.organization_id == self.organization_id,
            Site.deleted_at.is_(None),
        )
        ids = site_ids_for_request()
        if ids is not None:
            q = q.where(Site.id.in_(ids))
        return q.subquery()

    # -------------------------------------------------------------------------
    # Template Management
    # -------------------------------------------------------------------------

    async def list_templates(
        self,
        site_id: UUID | None = None,
        vendor: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Any], int]:
        """List config templates with optional filters. Returns (items, total)."""
        from app.modules.voip.models import ConfigTemplate

        base = select(ConfigTemplate).where(ConfigTemplate.deleted_at.is_(None))

        # Organization isolation
        if self.organization_id:
            base = base.where(ConfigTemplate.site_id.in_(select(self._sites_for_org().c.id)))

        if site_id:
            base = base.where(ConfigTemplate.site_id == site_id)
        if vendor:
            base = base.where(ConfigTemplate.vendor == vendor)

        count_result = await self.db.execute(select(func.count()).select_from(base.subquery()))
        total = count_result.scalar_one()

        query = base.order_by(ConfigTemplate.name).limit(limit).offset(offset)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_template(self, template_id: UUID) -> Any:
        """Get a config template by ID."""
        from app.modules.voip.models import ConfigTemplate

        query = select(ConfigTemplate).where(
            ConfigTemplate.id == template_id,
            ConfigTemplate.deleted_at.is_(None),
        )

        # Organization isolation
        if self.organization_id:
            query = query.where(ConfigTemplate.site_id.in_(select(self._sites_for_org().c.id)))

        result = await self.db.execute(query)
        template = result.scalar_one_or_none()
        if not template:
            raise ProvisioningError(f"Template not found: {template_id}")
        return template

    async def create_template(self, data: dict[str, Any]) -> Any:
        """Create a new config template.

        defence-in-depth site validation at the service layer.
        The target ``site_id`` must belong to this org AND (for a site-limited
        request caller) be within the per-user grant set. ``_sites_for_org``
        already intersects ``site_ids_for_request()`` via the request-scoped
        contextvar, so a single membership check covers both. Raises
        ``ProvisioningError`` (the endpoint maps this to a 404 — no oracle).
        """
        from app.modules.voip.models import ConfigTemplate

        site_id = data.get("site_id")
        if self.organization_id and site_id is not None:
            allowed = (
                await self.db.execute(
                    select(self._sites_for_org().c.id).where(self._sites_for_org().c.id == site_id)
                )
            ).scalar_one_or_none()
            if allowed is None:
                raise ProvisioningError(f"Site not accessible: {site_id}")

        template = ConfigTemplate(**data)
        self.db.add(template)
        await self.db.commit()
        await self.db.refresh(template)
        logger.info("Created config template: %s", template.name)
        return template

    async def update_template(self, template_id: UUID, data: dict[str, Any]) -> Any:
        """Update a config template."""
        template = await self.get_template(template_id)

        for key, value in data.items():
            if value is not None and hasattr(template, key):
                setattr(template, key, value)

        await self.db.commit()
        await self.db.refresh(template)
        logger.info("Updated config template: %s", template.name)
        return template

    async def delete_template(self, template_id: UUID) -> bool:
        """Soft-delete a config template."""
        template = await self.get_template(template_id)
        template.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def get_template_phone_count(self, template_id: UUID) -> int:
        """Get the number of phones using a template."""
        from app.modules.voip.models import Phone

        result = await self.db.execute(
            select(func.count(Phone.id)).where(
                Phone.config_template_id == template_id,
                Phone.deleted_at.is_(None),
            )
        )
        return result.scalar_one()

    async def get_template_phone_counts(self, template_ids: list[UUID]) -> dict[UUID, int]:
        """Batch phone counts keyed by template ID (single GROUP BY query).

        Used by the templates list endpoint so the "Phones" column can
        be populated without an N+1 per-template count. IDs not present
        in the result map simply have no phones (caller defaults to 0).
        """
        from app.modules.voip.models import Phone

        if not template_ids:
            return {}
        result = await self.db.execute(
            select(Phone.config_template_id, func.count(Phone.id))
            .where(
                Phone.config_template_id.in_(template_ids),
                Phone.deleted_at.is_(None),
            )
            .group_by(Phone.config_template_id)
        )
        return {row[0]: row[1] for row in result.all()}

    # -------------------------------------------------------------------------
    # Config Generation
    # -------------------------------------------------------------------------

    async def generate_phone_config(
        self,
        phone_id: UUID,
        write_file: bool = True,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Generate provisioning config for a single phone.

        Merges template settings with phone-specific overrides to produce
        a vendor-appropriate XML config file.

        ``force`` rewrites the config file even when the rendered XML is
        byte-identical to the stored checksum. Without it, a re-provision
        after the file was deleted, truncated or corrupted on disk is a
        silent no-op: the checksum still matches, so nothing is written and
        the phone keeps pulling whatever is (or is not) there.

        Returns:
            {xml: str, checksum: str, file_path: str | None}
        """
        from app.modules.voip.models import ConfigTemplate, Phone, ProvisionStatus

        # Load phone with template.
        #
        # scope the phone lookup through ``_sites_for_org()`` which
        # folds BOTH the org filter AND the request-scoped per-user site grant
        # (``site_ids_for_request()``). Without it, the authed provision path
        # (``POST /phones/{id}/provision``) re-generated config for a phone in a
        # SIBLING site of the same org for a site-limited operator. The
        # unauthenticated MAC-pull path (``get_config_for_mac``) runs with no
        # request user, so the grant no-ops and only the resolved-tenant org
        # filter applies (correct).
        phone_q = select(Phone).where(Phone.id == phone_id, Phone.deleted_at.is_(None))
        if self.organization_id:
            phone_q = phone_q.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        result = await self.db.execute(phone_q)
        phone = result.scalar_one_or_none()
        if not phone:
            raise ProvisioningError(f"Phone not found: {phone_id}")

        if not phone.mac_address:
            raise ProvisioningError(f"Phone {phone_id} has no MAC address")

        # Load template if assigned
        template = None
        if phone.config_template_id:
            t_result = await self.db.execute(
                select(ConfigTemplate).where(
                    ConfigTemplate.id == phone.config_template_id,
                    ConfigTemplate.deleted_at.is_(None),
                )
            )
            template = t_result.scalar_one_or_none()

        # Generate vendor-specific XML
        vendor = (phone.vendor or "grandstream").lower()
        if vendor == "grandstream":
            xml_content = self._generate_grandstream_xml(phone, template)
        elif vendor == "yealink":
            xml_content = self._generate_yealink_xml(phone, template)
        else:
            xml_content = self._generate_generic_xml(phone, template)

        # Calculate checksum
        checksum = hashlib.sha256(xml_content.encode("utf-8")).hexdigest()

        # Check if config changed
        config_changed = phone.config_checksum != checksum

        file_path = None
        if write_file and (config_changed or force):
            file_path = await self._write_config_file(phone.mac_address, vendor, xml_content)

        # Update phone provisioning state
        phone.config_checksum = checksum
        phone.provision_status = ProvisionStatus.GENERATED.value
        phone.last_provisioned_at = datetime.now(UTC)
        if file_path:
            phone.provisioning_url = f"/provisioning/voip/{Path(file_path).name}"

        await self.db.commit()

        return {
            "xml": xml_content,
            "checksum": checksum,
            "file_path": file_path,
            "config_changed": config_changed,
            "forced": bool(force and not config_changed),
            "phone_id": str(phone_id),
            "mac_address": phone.mac_address,
        }

    async def generate_config_preview(
        self,
        phone_id: UUID,
    ) -> str:
        """Generate config XML preview without writing to disk or updating DB."""
        from app.modules.voip.models import ConfigTemplate, Phone

        # scope the phone lookup by org + per-user site grant (via
        # _sites_for_org, which intersects site_ids_for_request). The preview
        # endpoint (GET /phones/{id}/config-preview) previously returned the
        # rendered config XML for a sibling-site phone to a site-limited viewer.
        phone_q = select(Phone).where(Phone.id == phone_id, Phone.deleted_at.is_(None))
        if self.organization_id:
            phone_q = phone_q.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        result = await self.db.execute(phone_q)
        phone = result.scalar_one_or_none()
        if not phone:
            raise ProvisioningError(f"Phone not found: {phone_id}")

        template = None
        if phone.config_template_id:
            t_result = await self.db.execute(
                select(ConfigTemplate).where(ConfigTemplate.id == phone.config_template_id)
            )
            template = t_result.scalar_one_or_none()

        vendor = (phone.vendor or "grandstream").lower()
        if vendor == "grandstream":
            return self._generate_grandstream_xml(phone, template)
        elif vendor == "yealink":
            return self._generate_yealink_xml(phone, template)
        return self._generate_generic_xml(phone, template)

    async def bulk_generate_configs(
        self,
        phone_ids: list[UUID] | None = None,
        site_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Generate configs for multiple phones.

        If phone_ids is None and site_id is provided, generates for all
        managed phones at that site.
        """
        from app.modules.voip.models import Phone, PhoneLifecycleState

        # scope the candidate set by org + per-user site grant via
        # _sites_for_org() (folds site_ids_for_request). Without it, a
        # site-limited operator passing sibling-site phone_ids — or a site_id
        # they aren't granted — would (re)provision phones outside their grant.
        # No-op for super/org admin and unset org.
        if phone_ids:
            phone_q = select(Phone).where(
                Phone.id.in_(phone_ids),
                Phone.deleted_at.is_(None),
            )
        elif site_id:
            phone_q = select(Phone).where(
                Phone.site_id == site_id,
                Phone.lifecycle_state.in_(
                    [
                        PhoneLifecycleState.MANAGED.value,
                        PhoneLifecycleState.ONBOARDING.value,
                    ]
                ),
                Phone.deleted_at.is_(None),
            )
        else:
            raise ProvisioningError("Must provide phone_ids or site_id")

        if self.organization_id:
            phone_q = phone_q.where(Phone.site_id.in_(select(self._sites_for_org().c.id)))
        result = await self.db.execute(phone_q)

        phones = list(result.scalars().all())
        generated = 0
        errors = 0
        changed = 0
        error_details: list[dict[str, str]] = []

        for phone in phones:
            try:
                result_data = await self.generate_phone_config(phone.id, write_file=True)
                generated += 1
                if result_data.get("config_changed"):
                    changed += 1
            except Exception as exc:
                errors += 1
                error_details.append(
                    {
                        "phone_id": str(phone.id),
                        "mac": phone.mac_address or "unknown",
                        "error": f"Config generation failed ({type(exc).__name__})",
                    }
                )
                logger.warning("Config generation failed for %s: %s", phone.mac_address, exc)

        return {
            "total": len(phones),
            "generated": generated,
            "changed": changed,
            "errors": errors,
            "error_details": error_details,
        }

    # -------------------------------------------------------------------------
    # Config Retrieval (for HTTP provisioning endpoint)
    # -------------------------------------------------------------------------

    async def get_config_for_mac(self, mac_address: str) -> tuple[str, str] | None:
        """
        Get the provisioning config XML for a phone by MAC address.

        Called by the HTTP provisioning endpoint when a phone requests
        its config file (e.g. GET /provisioning/cfg000b82123456.xml).

        Returns (xml_content, content_type) or None if not found.
        """
        from app.modules.voip.models import Phone, ProvisionStatus

        normalized = mac_address.replace("-", "").replace(":", "").replace(".", "").lower()
        colon_mac = ":".join(normalized[i : i + 2] for i in range(0, 12, 2))

        result = await self.db.execute(
            select(Phone).where(
                Phone.mac_address == colon_mac,
                Phone.deleted_at.is_(None),
            )
        )
        phone = result.scalar_one_or_none()
        if not phone:
            logger.debug("Provisioning request for unknown MAC: %s", mac_address)
            return None

        # Update last_seen on config pull
        phone.last_seen = datetime.now(UTC)
        phone.status = "online"

        # Try reading from file first
        vendor = (phone.vendor or "grandstream").lower()
        file_path = self._config_file_path(colon_mac, vendor)
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8")
            phone.provision_status = ProvisionStatus.APPLIED.value
            await self.db.commit()
            return content, "application/xml"

        # Generate on-the-fly
        try:
            result_data = await self.generate_phone_config(phone.id, write_file=True)
            phone.provision_status = ProvisionStatus.APPLIED.value
            await self.db.commit()
            return result_data["xml"], "application/xml"
        except ProvisioningError:
            return None

    # -------------------------------------------------------------------------
    # Vendor-Specific XML Generators
    # -------------------------------------------------------------------------

    def _generate_grandstream_xml(self, phone: Any, template: Any | None) -> str:
        """Generate Grandstream-style gs_provision XML."""
        p_values: dict[str, str] = {}

        # Apply template settings
        if template:
            # SIP settings
            sip = template.sip_settings or {}
            if sip.get("server"):
                p_values["P47"] = sip["server"]  # SIP Server
            if sip.get("port"):
                p_values["P48"] = str(sip["port"])  # SIP Port
            if sip.get("transport"):
                transport_map = {"udp": "0", "tcp": "1", "tls": "2"}
                p_values["P130"] = transport_map.get(sip["transport"], "0")
            if sip.get("outbound_proxy"):
                p_values["P2327"] = sip["outbound_proxy"]
            if sip.get("registration_expiry"):
                p_values["P32"] = str(sip["registration_expiry"])

            # Network settings
            net = template.network_settings or {}
            if net.get("vlan_id"):
                p_values["P51"] = str(net["vlan_id"])
            if net.get("ntp_server"):
                p_values["P30"] = net["ntp_server"]
            if net.get("syslog_server"):
                p_values["P207"] = net["syslog_server"]

            # Feature settings
            feat = template.feature_settings or {}
            if feat.get("admin_password"):
                p_values["P2"] = feat["admin_password"]
            if feat.get("timezone"):
                p_values["P64"] = feat["timezone"]
            if feat.get("language"):
                lang_map = {"en": "0", "zh": "1", "es": "4", "fr": "5", "de": "10"}
                p_values["P1362"] = lang_map.get(feat["language"], "0")

            # Provisioning settings
            prov = template.provisioning_settings or {}
            if prov.get("server_url"):
                p_values["P237"] = prov["server_url"]
            if prov.get("upgrade_server"):
                p_values["P192"] = prov["upgrade_server"]

            # Line key settings
            for lk in template.line_key_settings or []:
                idx = lk.get("index", 0)
                if lk.get("mode"):
                    mode_map = {"blf": "1", "speed_dial": "2", "line": "0"}
                    p_values[f"P323{idx}"] = mode_map.get(lk["mode"], "0")
                if lk.get("value"):
                    p_values[f"P324{idx}"] = lk["value"]
                if lk.get("label"):
                    p_values[f"P325{idx}"] = lk["label"]

            # Raw P-value overrides
            for key, val in (template.raw_overrides or {}).items():
                p_values[key] = str(val)

        # Phone-specific SIP account (from extension).
        #
        # The P-value map is authoritative in adapters/grandstream/constants.py.
        # This block previously carried comments shifted one row against it, and
        # the mislabelling had a real consequence: P34 is the Authenticate
        # PASSWORD, not the Auth ID, and it was being set to the extension
        # NUMBER. A factory phone pulling cfg{mac}.xml therefore registered with
        # its own extension as the password and was rejected by the PBX. P271
        # (account active) was never emitted at all, so the account stayed off,
        # and the display name landed in P270 (Account Name) instead of P3.
        if phone.extension:
            ext = phone.extension
            p_values[P_SIP_USER_ID] = ext.extension_number  # P35
            p_values[P_AUTH_ID] = ext.extension_number  # P36
            p_values[P_DISPLAY_NAME] = ext.display_name or ext.extension_number  # P3
            p_values[P_ACCOUNT_NAME] = ext.display_name or ext.extension_number  # P270
            p_values[P_ACCOUNT_ACTIVE] = "1"  # P271

            # Auth password. Omit rather than emit a wrong credential: a phone
            # with no P34 fails to register visibly, whereas the old behaviour
            # sent the extension number and looked like a PBX-side auth fault.
            if getattr(phone, "sip_password_enc", None):
                try:
                    p_values[P_AUTH_PASSWORD] = decrypt_credential(phone.sip_password_enc)  # P34
                except ValueError:
                    logger.error(
                        "Phone %s: cannot decrypt sip_password_enc; omitting P34 from "
                        "provisioning config so the failure is visible at registration",
                        phone.id,
                    )
            else:
                logger.warning(
                    "Phone %s has no stored SIP password; provisioning config omits P34 "
                    "and the phone will not register until one is set",
                    phone.id,
                )

        # Phone-specific overrides from settings JSONB
        phone_overrides = phone.settings.get("p_values", {})
        for key, val in phone_overrides.items():
            p_values[key] = str(val)

        # Build XML
        root = Element("gs_provision")
        root.set("version", "1")
        config = SubElement(root, "config")
        config.set("version", "1")

        for p_key in sorted(p_values.keys()):
            elem = SubElement(config, p_key)
            elem.text = p_values[p_key]

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")

    def _generate_yealink_xml(self, phone: Any, template: Any | None) -> str:
        """Generate Yealink-style XML provisioning config."""
        root = Element("y000000000000")  # Will be overridden by filename

        # Apply template settings
        if template:
            sip = template.sip_settings or {}
            if sip.get("server"):
                acct = SubElement(root, "account")
                acct.set("idx", "1")
                server = SubElement(acct, "server_host")
                server.text = sip["server"]
                if sip.get("port"):
                    port_elem = SubElement(acct, "server_port")
                    port_elem.text = str(sip["port"])

            net = template.network_settings or {}
            if net.get("ntp_server"):
                local = SubElement(root, "local_time")
                ntp = SubElement(local, "ntp_server1")
                ntp.text = net["ntp_server"]

            feat = template.feature_settings or {}
            if feat.get("admin_password"):
                security = SubElement(root, "security")
                pw = SubElement(security, "admin_password")
                pw.text = feat["admin_password"]

        # Phone-specific SIP registration
        if phone.extension:
            ext = phone.extension
            acct = root.find("account") or SubElement(root, "account")
            acct.set("idx", "1")
            SubElement(acct, "label").text = ext.display_name or ext.extension_number
            SubElement(acct, "display_name").text = ext.display_name or ext.extension_number
            SubElement(acct, "user_name").text = ext.extension_number
            SubElement(acct, "auth_name").text = ext.extension_number

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")

    def _generate_generic_xml(self, phone: Any, template: Any | None) -> str:
        """Generate a generic SIP phone XML config (documentation-style)."""
        root = Element("phone_config")
        root.set("vendor", phone.vendor or "unknown")
        root.set("model", phone.model or "unknown")
        root.set("mac", phone.mac_address or "")

        if template:
            sip = template.sip_settings or {}
            if sip:
                sip_elem = SubElement(root, "sip")
                for key, val in sip.items():
                    elem = SubElement(sip_elem, key)
                    elem.text = str(val)

        if phone.extension:
            ext_elem = SubElement(root, "account")
            ext_elem.set("index", "1")
            SubElement(ext_elem, "extension").text = phone.extension.extension_number
            SubElement(ext_elem, "display_name").text = (
                phone.extension.display_name or phone.extension.extension_number
            )

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")

    # -------------------------------------------------------------------------
    # File Management
    # -------------------------------------------------------------------------

    async def _write_config_file(self, mac_address: str, vendor: str, content: str) -> str:
        """Write config file to provisioning directory."""
        if len(content) > _MAX_CONFIG_SIZE:
            raise ProvisioningError(
                f"Config file exceeds maximum size ({len(content)} > {_MAX_CONFIG_SIZE})"
            )

        file_path = self._config_file_path(mac_address, vendor)
        # Containment assertion (defense-in-depth): the resolved path must stay
        # inside provision_dir, catching any future filename-construction bug.
        resolved = file_path.resolve()
        base = self.provision_dir.resolve()
        if base != resolved and base not in resolved.parents:
            raise ProvisioningError("config path escapes provisioning directory")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        logger.info("Wrote provisioning config: %s", file_path)
        return str(file_path)

    def _config_file_path(self, mac_address: str, vendor: str) -> Path:
        """Get the file path for a phone's config file."""
        clean_mac = mac_address.replace(":", "").replace("-", "").replace(".", "").lower()

        # SECURITY: the MAC becomes a filename, so it MUST be
        # exactly 12 hex chars. Without this, a phone created/imported with
        # mac_address='../../../tmp/evil' escapes provision_dir on write
        # (arbitrary-file-write as the backend process). Phone MACs ingested
        # from controller/DHCP scans bypass the schema validator, so enforce at
        # this sink too.
        if not re.fullmatch(r"[0-9a-f]{12}", clean_mac):
            raise ProvisioningError(f"Invalid MAC for config path: {mac_address!r}")

        if vendor == "grandstream":
            filename = f"cfg{clean_mac}.xml"
        elif vendor == "yealink":
            filename = f"y{clean_mac}.cfg"
        else:
            filename = f"{clean_mac}.xml"

        return self.provision_dir / filename

    async def cleanup_orphaned_configs(self, site_id: UUID) -> int:
        """Remove config files for phones that no longer exist in DB."""
        from app.modules.voip.models import Phone

        result = await self.db.execute(
            select(Phone.mac_address).where(
                Phone.site_id == site_id,
                Phone.deleted_at.is_(None),
                Phone.mac_address.isnot(None),
            )
        )
        active_macs = {row[0].replace(":", "").lower() for row in result.all()}

        removed = 0
        if self.provision_dir.exists():
            for config_file in self.provision_dir.glob("*.xml"):
                # Extract MAC from filename
                mac_match = re.search(r"([0-9a-f]{12})", config_file.stem)
                if mac_match and mac_match.group(1) not in active_macs:
                    config_file.unlink()
                    removed += 1
                    logger.info("Removed orphaned config: %s", config_file.name)

        return removed
