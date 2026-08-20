# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Data Import/Export Service
==========================================

Service for full system import/export with:
- Unified export format (JSON/YAML)
- Full system or selective export
- Import with conflict resolution (skip/overwrite/merge)
- Import from UniFi/Meraki/generic formats
- Validation/preview before import
- Rollback mechanism for failed imports
"""

from __future__ import annotations

import io
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import func, select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.import_export import ExportJob, ImportJob

from app.models.devices import normalize_device_type

logger = logging.getLogger(__name__)

# Directory for temporary import/export files
DATA_DIR = Path("/tmp/freesdn_data")
DATA_DIR.mkdir(parents=True, exist_ok=True)


# Maximum rows exported per entity type to prevent OOM on large databases
EXPORT_ROW_LIMIT = 10_000


class DataImportExportService:
    """
    Service for full system data import/export.
    """

    # =========================================================================
    # Export Jobs
    # =========================================================================

    @staticmethod
    async def create_export_job(
        session: AsyncSession,
        *,
        export_format: str = "json",
        scope: str = "full",
        entity_types: list[str] | None = None,
        entity_filters: dict[str, Any] | None = None,
        organization_id: UUID | None = None,
        site_ids: list[UUID] | None = None,
        created_by: UUID | None = None,
    ) -> ExportJob:
        """Create a new export job record."""
        from app.models.import_export import ExportJob, JobStatus

        job = ExportJob(
            status=JobStatus.PENDING,
            export_format=export_format,
            scope=scope,
            entity_types=entity_types or [],
            entity_filters=entity_filters or {},
            organization_id=organization_id,
            site_ids=[str(s) for s in site_ids] if site_ids else [],
            created_by=created_by,
        )
        session.add(job)
        await session.flush()
        return job

    @staticmethod
    async def get_export_job(
        session: AsyncSession,
        job_id: UUID,
    ) -> ExportJob | None:
        from app.models.import_export import ExportJob

        result = await session.execute(select(ExportJob).where(ExportJob.id == job_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_export_jobs(
        session: AsyncSession,
        created_by: UUID | None = None,
        limit: int = 20,
    ) -> tuple[list[ExportJob], int]:
        from app.models.import_export import ExportJob

        base = select(ExportJob)
        count_base = select(func.count(ExportJob.id))

        if created_by:
            base = base.where(ExportJob.created_by == created_by)
            count_base = count_base.where(ExportJob.created_by == created_by)

        total = (await session.execute(count_base)).scalar_one()
        result = await session.execute(base.order_by(ExportJob.created_at.desc()).limit(limit))
        return list(result.scalars().all()), total

    @staticmethod
    async def run_export(
        session: AsyncSession,
        job_id: UUID,
    ) -> dict[str, Any]:
        """
        Execute an export job. Collects entities and writes to file.
        Called by Celery task.
        """
        from app.models.import_export import ExportJob, JobStatus

        job = (
            await session.execute(select(ExportJob).where(ExportJob.id == job_id))
        ).scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        job.status = JobStatus.IN_PROGRESS
        await session.flush()

        try:
            data = await DataImportExportService._collect_export_data(session, job)
            job.total_entities = data.get("total_entities", 0)
            job.exported_entities = job.total_entities

            # Serialize
            if job.export_format == "yaml":
                try:
                    import yaml

                    content = yaml.dump(data, default_flow_style=False, allow_unicode=True)
                except ImportError:
                    content = json.dumps(data, indent=2, default=str)
            else:
                content = json.dumps(data, indent=2, default=str)

            content_bytes = content.encode("utf-8")

            # Write file
            filename = f"export_{job.id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
            ext = "yaml" if job.export_format == "yaml" else "json"
            filepath = DATA_DIR / f"{filename}.{ext}"
            filepath.write_bytes(content_bytes)

            job.file_path = str(filepath)
            job.file_size_bytes = len(content_bytes)
            job.download_url = f"/api/v1/data/exports/{job.id}/download"
            job.progress_pct = 100.0
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(UTC)
            await session.flush()

            return {
                "status": "completed",
                "entities": job.exported_entities,
                "file_size": job.file_size_bytes,
            }

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            await session.flush()
            logger.error("Export job %s failed: %s", job_id, e)
            raise

    @staticmethod
    async def _collect_export_data(
        session: AsyncSession,
        job: ExportJob,
    ) -> dict[str, Any]:
        """Collect all entities for export based on scope."""
        from app.models.core import Controller, Organization, Site, User
        from app.models.devices import Device, DevicePort

        data: dict[str, Any] = {
            "format_version": "2.0",
            "exported_at": datetime.now(UTC).isoformat(),
            "scope": job.scope,
            "entities": {},
            "total_entities": 0,
        }

        scope = job.scope
        entity_types = job.entity_types or []

        total = 0

        # SECURITY (tenant isolation): every query below is constrained to the
        # job's organization. Sites/Users/Agents/VPN carry organization_id
        # directly; Controllers and Devices link to the org only through their
        # Site; DevicePorts only through their Device. Without these predicates
        # the export returned EVERY tenant's data to any org_admin (cross-tenant
        # data breach). org_id is always set by the endpoint (_org_id(user)
        # raises if absent), so unconditional scoping is correct.
        org_id = job.organization_id
        org_sites_subq = select(Site.id).where(Site.organization_id == org_id).scalar_subquery()
        org_devices_subq = (
            select(Device.id).where(Device.site_id.in_(org_sites_subq)).scalar_subquery()
        )

        # --- Organizations ---
        if scope in ("full", "custom") and (scope == "full" or "organizations" in entity_types):
            orgs = (
                (
                    await session.execute(
                        select(Organization)
                        .where(Organization.id == org_id)
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["organizations"] = [
                {
                    "id": str(o.id),
                    "name": o.name,
                    "slug": getattr(o, "slug", None),
                    "description": getattr(o, "description", None),
                }
                for o in orgs
            ]
            total += len(data["entities"]["organizations"])

        # --- Sites ---
        if scope in ("full", "sites", "custom") and (scope != "custom" or "sites" in entity_types):
            stmt = select(Site).where(Site.organization_id == org_id)
            if job.site_ids:
                stmt = stmt.where(Site.id.in_([UUID(s) for s in job.site_ids if s]))
            stmt = stmt.limit(EXPORT_ROW_LIMIT)
            sites = (await session.execute(stmt)).scalars().all()
            data["entities"]["sites"] = [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "organization_id": str(s.organization_id) if s.organization_id else None,
                    "address": getattr(s, "address", None),
                    "timezone": getattr(s, "timezone", None),
                    "metadata": getattr(s, "metadata", None),
                }
                for s in sites
            ]
            total += len(data["entities"]["sites"])

        # --- Controllers ---
        if scope in ("full", "controllers", "custom") and (
            scope != "custom" or "controllers" in entity_types
        ):
            controllers = (
                (
                    await session.execute(
                        select(Controller)
                        .where(Controller.site_id.in_(org_sites_subq))
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["controllers"] = [
                {
                    "id": str(c.id),
                    "name": c.name,
                    "controller_type": str(c.controller_type),
                    "host": getattr(c, "host", None),
                    "port": getattr(c, "port", None),
                    "site_id": str(c.site_id) if c.site_id else None,
                    "status": str(c.status) if c.status else None,
                }
                for c in controllers
            ]
            total += len(data["entities"]["controllers"])

        # --- Devices ---
        if scope in ("full", "devices", "custom") and (
            scope != "custom" or "devices" in entity_types
        ):
            devices = (
                (
                    await session.execute(
                        select(Device)
                        .where(Device.site_id.in_(org_sites_subq))
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["devices"] = [
                {
                    "id": str(d.id),
                    "name": d.name,
                    "device_type": str(d.device_type) if d.device_type else None,
                    "mac_address": getattr(d, "mac_address", None),
                    "ip_address": getattr(d, "ip_address", None),
                    "model": getattr(d, "model", None),
                    "firmware_version": getattr(d, "firmware_version", None),
                    "site_id": str(d.site_id) if getattr(d, "site_id", None) else None,
                    "controller_id": str(d.controller_id)
                    if getattr(d, "controller_id", None)
                    else None,
                    "status": str(d.status) if d.status else None,
                    "config": getattr(d, "config", None),
                    "metadata": getattr(d, "metadata", None),
                }
                for d in devices
            ]
            total += len(data["entities"]["devices"])

            # Ports
            ports = (
                (
                    await session.execute(
                        select(DevicePort)
                        .where(DevicePort.device_id.in_(org_devices_subq))
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["device_ports"] = [
                {
                    "id": str(p.id),
                    "device_id": str(p.device_id),
                    "port_number": getattr(p, "port_number", None),
                    "name": getattr(p, "name", None),
                    "port_type": str(p.port_type) if getattr(p, "port_type", None) else None,
                    "status": str(p.status) if p.status else None,
                    "speed": getattr(p, "speed", None),
                    "vlan_id": getattr(p, "vlan_id", None),
                }
                for p in ports
            ]
            total += len(data["entities"]["device_ports"])

        # --- Users (sanitized, no passwords) ---
        if scope in ("full", "users", "custom") and (scope != "custom" or "users" in entity_types):
            users = (
                (
                    await session.execute(
                        select(User)
                        .where(User.organization_id == org_id, User.deleted_at.is_(None))
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["users"] = [
                {
                    "id": str(u.id),
                    "email": u.email,
                    "full_name": getattr(u, "full_name", None),
                    "role": str(u.role) if u.role else None,
                    "organization_id": str(u.organization_id)
                    if getattr(u, "organization_id", None)
                    else None,
                    "is_active": getattr(u, "is_active", True),
                }
                for u in users
            ]
            total += len(data["entities"]["users"])

        # --- Agents ---
        if scope in ("full", "agents", "custom") and (
            scope != "custom" or "agents" in entity_types
        ):
            from app.models.agents import RemoteAgent

            agents = (
                (
                    await session.execute(
                        select(RemoteAgent)
                        .where(RemoteAgent.organization_id == org_id)
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["agents"] = [
                {
                    "id": str(a.id),
                    "name": a.name,
                    "agent_type": str(a.agent_type) if a.agent_type else None,
                    "status": str(a.status) if a.status else None,
                    "site_id": str(a.site_id) if getattr(a, "site_id", None) else None,
                    "host": getattr(a, "host", None),
                    "version": getattr(a, "version", None),
                }
                for a in agents
            ]
            total += len(data["entities"]["agents"])

        # --- VPN ---
        if scope in ("full", "vpn", "custom") and (scope != "custom" or "vpn" in entity_types):
            from app.models.vpn import VPNConnectionRecord

            vpns = (
                (
                    await session.execute(
                        select(VPNConnectionRecord)
                        .where(VPNConnectionRecord.organization_id == org_id)
                        .limit(EXPORT_ROW_LIMIT)
                    )
                )
                .scalars()
                .all()
            )
            data["entities"]["vpn_connections"] = [
                {
                    "id": str(v.id),
                    "name": v.name,
                    "vpn_type": str(v.vpn_type) if v.vpn_type else None,
                    "status": str(v.status) if v.status else None,
                    "endpoint": getattr(v, "endpoint", None),
                    "metadata": getattr(v, "metadata", None),
                }
                for v in vpns
            ]
            total += len(data["entities"]["vpn_connections"])

        data["total_entities"] = total
        return data

    # =========================================================================
    # Import Jobs
    # =========================================================================

    @staticmethod
    async def create_import_job(
        session: AsyncSession,
        *,
        source_format: str = "freesdn",
        conflict_resolution: str = "skip",
        organization_id: UUID | None = None,
        original_filename: str | None = None,
        file_path: str | None = None,
        file_size_bytes: int | None = None,
        created_by: UUID | None = None,
    ) -> ImportJob:
        """Create a new import job record."""
        from app.models.import_export import ImportJob, JobStatus

        job = ImportJob(
            status=JobStatus.PENDING,
            source_format=source_format,
            conflict_resolution=conflict_resolution,
            organization_id=organization_id,
            original_filename=original_filename,
            file_path=file_path,
            file_size_bytes=file_size_bytes,
            created_by=created_by,
        )
        session.add(job)
        await session.flush()
        return job

    @staticmethod
    async def get_import_job(
        session: AsyncSession,
        job_id: UUID,
    ) -> ImportJob | None:
        from app.models.import_export import ImportJob

        result = await session.execute(select(ImportJob).where(ImportJob.id == job_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_import_jobs(
        session: AsyncSession,
        created_by: UUID | None = None,
        limit: int = 20,
    ) -> tuple[list[ImportJob], int]:
        from app.models.import_export import ImportJob

        base = select(ImportJob)
        count_base = select(func.count(ImportJob.id))

        if created_by:
            base = base.where(ImportJob.created_by == created_by)
            count_base = count_base.where(ImportJob.created_by == created_by)

        total = (await session.execute(count_base)).scalar_one()
        result = await session.execute(base.order_by(ImportJob.created_at.desc()).limit(limit))
        return list(result.scalars().all()), total

    @staticmethod
    async def validate_import_file(
        file_path: str,
        source_format: str = "freesdn",
    ) -> dict[str, Any]:
        """
        Validate an import file and return a preview.
        Does NOT require a DB session – purely file-based.
        """
        filepath = Path(file_path)
        if not filepath.exists():
            return {"valid": False, "errors": ["File not found"]}

        content = filepath.read_text(encoding="utf-8")

        try:
            if source_format in ("freesdn", "generic_json"):
                data = json.loads(content)
            elif source_format == "yaml":
                try:
                    import yaml

                    data = yaml.safe_load(content)
                except ImportError:
                    return {"valid": False, "errors": ["PyYAML not installed"]}
            elif source_format == "generic_csv":
                return DataImportExportService._validate_csv(content)
            elif source_format == "unifi":
                data = json.loads(content)
                return DataImportExportService._validate_unifi(data)
            elif source_format == "meraki":
                data = json.loads(content)
                return DataImportExportService._validate_meraki(data)
            else:
                return {"valid": False, "errors": [f"Unknown format: {source_format}"]}
        except (json.JSONDecodeError, Exception) as e:
            return {"valid": False, "errors": [f"Parse error: {str(e)}"]}

        return DataImportExportService._validate_freesdn(data)

    @staticmethod
    def _validate_freesdn(data: dict[str, Any]) -> dict[str, Any]:
        """Validate FreeSDN native export format."""
        errors = []
        warnings = []

        if "format_version" not in data:
            warnings.append("No format_version found; assuming v2.0")
        if "entities" not in data:
            errors.append("Missing 'entities' key")
            return {"valid": False, "errors": errors, "warnings": warnings}

        entities = data["entities"]
        entity_summary = {}
        total = 0
        preview = []

        for entity_type, items in entities.items():
            if not isinstance(items, list):
                warnings.append(f"Entity '{entity_type}' is not a list, skipping")
                continue
            entity_summary[entity_type] = len(items)
            total += len(items)

            # Preview first 3 items
            for item in items[:3]:
                preview.append(
                    {
                        "type": entity_type,
                        "name": item.get("name", item.get("email", item.get("id", "?"))),
                        "id": item.get("id"),
                    }
                )

        return {
            "valid": len(errors) == 0,
            "source_format": "freesdn",
            "total_entities": total,
            "entity_summary": entity_summary,
            "conflicts": [],
            "warnings": warnings,
            "errors": errors,
            "preview_entities": preview,
        }

    @staticmethod
    def _validate_csv(content: str) -> dict[str, Any]:
        """Validate a generic CSV import."""
        import csv as csv_mod

        reader = csv_mod.DictReader(io.StringIO(content))
        rows = list(reader)
        if not rows:
            return {"valid": False, "errors": ["CSV is empty"]}

        fields = reader.fieldnames or []
        return {
            "valid": True,
            "source_format": "generic_csv",
            "total_entities": len(rows),
            "entity_summary": {"rows": len(rows)},
            "conflicts": [],
            "warnings": [f"CSV fields: {', '.join(fields)}"],
            "errors": [],
            "preview_entities": [
                {
                    "type": "row",
                    "name": r.get("name", r.get("hostname", f"row-{i}")),
                    "id": r.get("id"),
                }
                for i, r in enumerate(rows[:5])
            ],
        }

    @staticmethod
    def _validate_unifi(data: dict[str, Any]) -> dict[str, Any]:
        """Validate a UniFi controller export."""
        warnings = []
        entities = {}
        total = 0

        # UniFi exports typically have data[].
        items = data if isinstance(data, list) else data.get("data", [])
        if not items:
            # Could be a site export with devices under "devices"
            for key in ("devices", "clients", "networks", "wlans"):
                if key in data:
                    count = len(data[key]) if isinstance(data[key], list) else 0
                    entities[key] = count
                    total += count
        else:
            entities["devices"] = len(items)
            total = len(items)

        if total == 0:
            warnings.append("No recognizable UniFi entities found")

        return {
            "valid": total > 0,
            "source_format": "unifi",
            "total_entities": total,
            "entity_summary": entities,
            "conflicts": [],
            "warnings": warnings,
            "errors": [] if total > 0 else ["No entities found in UniFi export"],
            "preview_entities": [],
        }

    @staticmethod
    def _validate_meraki(data: dict[str, Any]) -> dict[str, Any]:
        """Validate a Meraki dashboard export."""
        warnings = []
        entities = {}
        total = 0

        # Meraki exports can be a list of devices or an org export
        if isinstance(data, list):
            entities["devices"] = len(data)
            total = len(data)
        else:
            for key in ("networks", "devices", "ssids", "vlans", "clients"):
                if key in data:
                    count = len(data[key]) if isinstance(data[key], list) else 0
                    entities[key] = count
                    total += count

        if total == 0:
            warnings.append("No recognizable Meraki entities found")

        return {
            "valid": total > 0,
            "source_format": "meraki",
            "total_entities": total,
            "entity_summary": entities,
            "conflicts": [],
            "warnings": warnings,
            "errors": [] if total > 0 else ["No entities found in Meraki export"],
            "preview_entities": [],
        }

    # =========================================================================
    # Import Execution
    # =========================================================================

    @staticmethod
    async def run_import(
        session: AsyncSession,
        job_id: UUID,
    ) -> dict[str, Any]:
        """
        Execute an import job.
        Called by Celery task.
        """
        from app.models.import_export import ImportJob, JobStatus

        job = (
            await session.execute(select(ImportJob).where(ImportJob.id == job_id))
        ).scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        # Validate first
        job.status = JobStatus.VALIDATING
        await session.flush()

        if not job.file_path or not Path(job.file_path).exists():
            job.status = JobStatus.FAILED
            job.error_message = "Import file not found"
            await session.flush()
            return {"error": "File not found"}

        validation = await DataImportExportService.validate_import_file(
            job.file_path, job.source_format
        )
        job.validation_result = validation

        if not validation.get("valid", False):
            job.status = JobStatus.FAILED
            job.error_message = "; ".join(validation.get("errors", ["Validation failed"]))
            await session.flush()
            return {"error": job.error_message}

        # Parse file
        content = Path(job.file_path).read_text(encoding="utf-8")
        if job.source_format in ("freesdn", "generic_json"):
            data = json.loads(content)
        elif job.source_format == "generic_csv":
            import csv as csv_mod

            reader = csv_mod.DictReader(io.StringIO(content))
            data = {"entities": {"csv_rows": list(reader)}}
        else:
            data = json.loads(content)

        # Execute import
        job.status = JobStatus.IN_PROGRESS
        job.total_entities = validation.get("total_entities", 0)
        await session.flush()

        rollback_data: dict[str, list[str]] = {}
        imported = 0
        skipped = 0
        failed = 0
        errors: list[dict[str, Any]] = []

        try:
            if job.source_format == "freesdn":
                result = await DataImportExportService._import_freesdn(
                    session, data, job.conflict_resolution, job.organization_id
                )
            elif job.source_format == "unifi":
                result = await DataImportExportService._import_unifi(
                    session, data, job.conflict_resolution, job.organization_id
                )
            elif job.source_format == "meraki":
                result = await DataImportExportService._import_meraki(
                    session, data, job.conflict_resolution, job.organization_id
                )
            else:
                result = await DataImportExportService._import_generic(
                    session, data, job.conflict_resolution, job.organization_id
                )

            imported = result.get("imported", 0)
            skipped = result.get("skipped", 0)
            failed = result.get("failed", 0)
            errors = result.get("errors", [])
            rollback_data = result.get("rollback_data", {})

            job.imported_entities = imported
            job.skipped_entities = skipped
            job.failed_entities = failed
            job.errors = errors
            job.rollback_data = rollback_data
            job.result_summary = result.get("summary", {})
            job.progress_pct = 100.0
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(UTC)
            await session.flush()

            return {
                "status": "completed",
                "imported": imported,
                "skipped": skipped,
                "failed": failed,
            }

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            job.rollback_data = rollback_data
            await session.flush()
            logger.error("Import job %s failed: %s", job_id, e)
            raise

    @staticmethod
    async def _import_freesdn(
        session: AsyncSession,
        data: dict[str, Any],
        conflict_resolution: str,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Import FreeSDN native format."""
        from app.models.core import Controller, Site
        from app.models.devices import Device

        entities = data.get("entities", {})
        imported = 0
        skipped = 0
        failed = 0
        errors = []
        rollback_data: dict[str, list[str]] = {}
        # Remap exported (old) FK ids -> the ids that actually exist in THIS org
        # after import, so controllers/devices re-link to the right site /
        # controller instead of being created orphaned (site_id is NOT NULL, so
        # the previous code silently failed every controller/device). Resolving
        # FKs ONLY through these maps also preserves tenant isolation: an exported
        # site_id that isn't part of this import (e.g. a raw cross-tenant UUID) is
        # unmappable, so the child is rejected — never attached to an arbitrary site.
        site_id_map: dict[str, UUID] = {}
        controller_id_map: dict[str, UUID] = {}

        # Import sites
        for site_data in entities.get("sites", []):
            try:
                existing = None
                if site_data.get("id"):
                    from uuid import UUID as _UUID

                    try:
                        sid = _UUID(site_data["id"])
                        # SECURITY (tenant isolation): scope the conflict lookup
                        # to the importing org so an attacker-supplied UUID for
                        # another tenant's site cannot be matched and overwritten
                        # (IDOR). A non-matching id falls through to the insert
                        # path, which mints a brand-new site (new id) in the
                        # caller's org — no PK collision, no cross-tenant write.
                        existing = (
                            await session.execute(
                                select(Site).where(
                                    Site.id == sid,
                                    Site.organization_id == organization_id,
                                )
                            )
                        ).scalar_one_or_none()
                    except (ValueError, Exception):
                        pass

                if existing:
                    if site_data.get("id"):
                        site_id_map[str(site_data["id"])] = existing.id
                    if conflict_resolution == "skip":
                        skipped += 1
                        continue
                    elif conflict_resolution == "overwrite":
                        existing.name = site_data.get("name", existing.name)
                        await session.flush()
                        imported += 1
                    elif conflict_resolution == "merge":
                        if site_data.get("name"):
                            existing.name = site_data["name"]
                        await session.flush()
                        imported += 1
                else:
                    site = Site(
                        name=site_data["name"],
                        organization_id=organization_id,
                    )
                    session.add(site)
                    await session.flush()
                    if site_data.get("id"):
                        site_id_map[str(site_data["id"])] = site.id
                    rollback_data.setdefault("sites", []).append(str(site.id))
                    imported += 1
            except Exception as e:
                failed += 1
                errors.append({"entity": "site", "name": site_data.get("name"), "error": str(e)})

        # Import controllers
        for ctrl_data in entities.get("controllers", []):
            try:
                # Re-link to the imported site (org-scoped via site_id_map). A
                # controller whose site isn't part of this import can't be placed.
                old_site = ctrl_data.get("site_id")
                new_site_id = site_id_map.get(str(old_site)) if old_site else None
                if new_site_id is None:
                    failed += 1
                    errors.append(
                        {
                            "entity": "controller",
                            "name": ctrl_data.get("name"),
                            "error": "unresolved site_id (site not part of this import / not in your org)",
                        }
                    )
                    continue
                ctrl = Controller(
                    name=ctrl_data["name"],
                    controller_type=ctrl_data.get("controller_type", "generic"),
                    host=ctrl_data.get("host"),
                    port=ctrl_data.get("port"),
                    site_id=new_site_id,
                )
                session.add(ctrl)
                await session.flush()
                if ctrl_data.get("id"):
                    controller_id_map[str(ctrl_data["id"])] = ctrl.id
                rollback_data.setdefault("controllers", []).append(str(ctrl.id))
                imported += 1
            except Exception as e:
                failed += 1
                errors.append(
                    {"entity": "controller", "name": ctrl_data.get("name"), "error": str(e)}
                )

        # Import devices
        for dev_data in entities.get("devices", []):
            try:
                old_site = dev_data.get("site_id")
                new_site_id = site_id_map.get(str(old_site)) if old_site else None
                if new_site_id is None:
                    failed += 1
                    errors.append(
                        {
                            "entity": "device",
                            "name": dev_data.get("name"),
                            "error": "unresolved site_id (site not part of this import / not in your org)",
                        }
                    )
                    continue
                # controller_id is nullable: link if the controller came along in
                # this import, otherwise import the device unlinked rather than fail.
                old_ctrl = dev_data.get("controller_id")
                new_controller_id = controller_id_map.get(str(old_ctrl)) if old_ctrl else None
                device = Device(
                    name=dev_data["name"],
                    device_type=normalize_device_type(dev_data.get("device_type")),
                    mac_address=dev_data.get("mac_address"),
                    ip_address=dev_data.get("ip_address"),
                    model=dev_data.get("model"),
                    site_id=new_site_id,
                    controller_id=new_controller_id,
                )
                session.add(device)
                await session.flush()
                rollback_data.setdefault("devices", []).append(str(device.id))
                imported += 1
            except Exception as e:
                failed += 1
                errors.append({"entity": "device", "name": dev_data.get("name"), "error": str(e)})

        return {
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
            "errors": errors,
            "rollback_data": rollback_data,
            "summary": {
                "sites": len(entities.get("sites", [])),
                "controllers": len(entities.get("controllers", [])),
                "devices": len(entities.get("devices", [])),
            },
        }

    @staticmethod
    async def _import_unifi(
        session: AsyncSession,
        data: dict[str, Any],
        conflict_resolution: str,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Import UniFi controller export."""
        from app.models.devices import Device

        items = data if isinstance(data, list) else data.get("data", data.get("devices", []))
        imported = 0
        skipped = 0
        failed = 0
        errors = []
        rollback_data: dict[str, list[str]] = {}

        for item in items:
            try:
                name = item.get("name") or item.get("hostname") or item.get("mac", "unknown")
                device = Device(
                    name=name,
                    device_type=normalize_device_type(item.get("type")),
                    mac_address=item.get("mac"),
                    ip_address=item.get("ip"),
                    model=item.get("model"),
                    firmware_version=item.get("version"),
                )
                session.add(device)
                await session.flush()
                rollback_data.setdefault("devices", []).append(str(device.id))
                imported += 1
            except Exception as e:
                failed += 1
                errors.append({"entity": "device", "name": item.get("name"), "error": str(e)})

        return {
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
            "errors": errors,
            "rollback_data": rollback_data,
            "summary": {"unifi_devices": len(items)},
        }

    @staticmethod
    async def _import_meraki(
        session: AsyncSession,
        data: dict[str, Any],
        conflict_resolution: str,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Import Meraki dashboard export."""
        from app.models.devices import Device

        items = data if isinstance(data, list) else data.get("devices", [])
        imported = 0
        skipped = 0
        failed = 0
        errors = []
        rollback_data: dict[str, list[str]] = {}

        for item in items:
            try:
                name = item.get("name") or item.get("serial", "unknown")
                device = Device(
                    name=name,
                    device_type=normalize_device_type(item.get("productType") or item.get("model")),
                    mac_address=item.get("mac"),
                    ip_address=item.get("lanIp") or item.get("wan1Ip"),
                    model=item.get("model"),
                    firmware_version=item.get("firmware"),
                )
                session.add(device)
                await session.flush()
                rollback_data.setdefault("devices", []).append(str(device.id))
                imported += 1
            except Exception as e:
                failed += 1
                errors.append({"entity": "device", "name": item.get("name"), "error": str(e)})

        return {
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
            "errors": errors,
            "rollback_data": rollback_data,
            "summary": {"meraki_devices": len(items)},
        }

    @staticmethod
    async def _import_generic(
        session: AsyncSession,
        data: dict[str, Any],
        conflict_resolution: str,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Import generic JSON/CSV data as devices."""
        from app.models.devices import Device

        entities = data.get("entities", {})
        rows = entities.get("csv_rows", [])
        if not rows and isinstance(data, list):
            rows = data

        imported = 0
        failed = 0
        errors = []
        rollback_data: dict[str, list[str]] = {}

        for row in rows:
            try:
                name = row.get("name") or row.get("hostname") or row.get("device_name", "unknown")
                device = Device(
                    name=name,
                    device_type=normalize_device_type(row.get("type") or row.get("device_type")),
                    mac_address=row.get("mac") or row.get("mac_address"),
                    ip_address=row.get("ip") or row.get("ip_address"),
                    model=row.get("model"),
                )
                session.add(device)
                await session.flush()
                rollback_data.setdefault("devices", []).append(str(device.id))
                imported += 1
            except Exception as e:
                failed += 1
                errors.append({"entity": "device", "name": row.get("name"), "error": str(e)})

        return {
            "imported": imported,
            "skipped": 0,
            "failed": failed,
            "errors": errors,
            "rollback_data": rollback_data,
            "summary": {"generic_rows": len(rows)},
        }

    # =========================================================================
    # Rollback
    # =========================================================================

    @staticmethod
    async def rollback_import(
        session: AsyncSession,
        job_id: UUID,
    ) -> dict[str, Any]:
        """Rollback a completed import by deleting created entities."""
        from sqlalchemy import delete

        from app.models.core import Controller, Site
        from app.models.devices import Device
        from app.models.import_export import ImportJob, JobStatus

        job = (
            await session.execute(select(ImportJob).where(ImportJob.id == job_id))
        ).scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        if not job.can_rollback:
            return {"error": "Job cannot be rolled back"}

        if job.status not in (JobStatus.COMPLETED, JobStatus.FAILED):
            return {"error": "Job must be completed or failed to rollback"}

        job.status = JobStatus.ROLLING_BACK
        await session.flush()

        rollback = job.rollback_data or {}
        deleted = {}

        try:
            # Delete in reverse order (devices → controllers → sites)
            model_map = {
                "devices": Device,
                "controllers": Controller,
                "sites": Site,
            }
            for entity_type in ["devices", "controllers", "sites"]:
                ids = rollback.get(entity_type, [])
                if ids and entity_type in model_map:
                    model = model_map[entity_type]
                    from uuid import UUID as _UUID

                    uuids = [_UUID(i) for i in ids]
                    result = await session.execute(delete(model).where(model.id.in_(uuids)))
                    deleted[entity_type] = result.rowcount

            job.status = JobStatus.ROLLED_BACK
            job.rolled_back_at = datetime.now(UTC)
            job.can_rollback = False
            await session.flush()

            return {"status": "rolled_back", "deleted": deleted}

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = f"Rollback failed: {str(e)}"
            await session.flush()
            raise

    # =========================================================================
    # Job Summary
    # =========================================================================

    @staticmethod
    async def get_job_summary(
        session: AsyncSession,
        *,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get summary of import/export activity, scoped to ``organization_id``.

        SECURITY (tenant isolation): EVERY counter below is constrained to
        ``organization_id`` when one is supplied (the REST endpoint always
        supplies it via ``_org_id(user)``). Previously ``active_jobs`` and the
        recent/total rollups counted GLOBALLY across all tenants, so any
        org_admin saw the platform-wide figures (a cross-org count leak).
        ``organization_id is None`` (super_admin / background) keeps
        the unscoped behaviour by simply omitting the predicate — never build
        an unconditional ``== None`` filter.

        ``active_exports`` / ``active_imports`` are returned separately (in
        addition to their sum ``active_jobs``) so a site-limited caller can
        re-derive the export portion under its per-user site grant — the
        ``ExportJob.site_ids`` JSONB column is not a SQL-AND-able predicate.
        """
        from app.models.import_export import ExportJob, ImportJob, JobStatus

        scoped = organization_id is not None

        # Recent exports
        recent_exports_q = select(ExportJob)
        if scoped:
            recent_exports_q = recent_exports_q.where(ExportJob.organization_id == organization_id)
        exports_result = await session.execute(
            recent_exports_q.order_by(ExportJob.created_at.desc()).limit(10)
        )
        recent_exports = list(exports_result.scalars().all())

        # Recent imports
        recent_imports_q = select(ImportJob)
        if scoped:
            recent_imports_q = recent_imports_q.where(ImportJob.organization_id == organization_id)
        imports_result = await session.execute(
            recent_imports_q.order_by(ImportJob.created_at.desc()).limit(10)
        )
        recent_imports = list(imports_result.scalars().all())

        # Active jobs (org-scoped)
        active_exports_q = select(func.count(ExportJob.id)).where(
            ExportJob.status.in_([JobStatus.PENDING, JobStatus.IN_PROGRESS])
        )
        if scoped:
            active_exports_q = active_exports_q.where(ExportJob.organization_id == organization_id)
        active_exports = (await session.execute(active_exports_q)).scalar_one()

        active_imports_q = select(func.count(ImportJob.id)).where(
            ImportJob.status.in_([JobStatus.PENDING, JobStatus.VALIDATING, JobStatus.IN_PROGRESS])
        )
        if scoped:
            active_imports_q = active_imports_q.where(ImportJob.organization_id == organization_id)
        active_imports = (await session.execute(active_imports_q)).scalar_one()

        total_exports_q = select(func.count(ExportJob.id))
        total_imports_q = select(func.count(ImportJob.id))
        if scoped:
            total_exports_q = total_exports_q.where(ExportJob.organization_id == organization_id)
            total_imports_q = total_imports_q.where(ImportJob.organization_id == organization_id)
        total_exports = (await session.execute(total_exports_q)).scalar_one()
        total_imports = (await session.execute(total_imports_q)).scalar_one()

        return {
            "recent_exports": recent_exports,
            "recent_imports": recent_imports,
            "active_exports": active_exports,
            "active_imports": active_imports,
            "active_jobs": active_exports + active_imports,
            "total_exports": total_exports,
            "total_imports": total_imports,
        }
