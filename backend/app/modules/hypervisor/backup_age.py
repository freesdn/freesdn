# SPDX-License-Identifier: AGPL-3.0-only
"""Backup inventory observations; missing telemetry never proves a missing backup."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from functools import partial
from typing import Any, Literal

from app.adapters.base import AdapterResult
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.modules.hypervisor.schemas import BackupAgeReport, BackupAgeResponse, BackupReadFailure


async def collect_backup_age(adapter: ProxmoxAdapter, threshold_hours: int) -> BackupAgeResponse:
    inventory = await adapter.get_cluster_resources("vm")
    if not inventory.success or not isinstance(inventory.data, list):
        raise ConnectionError("Proxmox guest inventory is unavailable")

    guests: dict[int, dict[str, Any]] = {}
    for row in inventory.data:
        if not isinstance(row, dict):
            raise ConnectionError("Proxmox guest inventory is malformed")
        try:
            vmid = int(row["vmid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectionError("Proxmox guest inventory has no valid guest identity") from exc
        if vmid <= 0 or not isinstance(row.get("node"), str) or not row["node"]:
            raise ConnectionError("Proxmox guest inventory has no valid guest identity")
        guests[vmid] = row

    failures: list[BackupReadFailure] = []
    semaphore = asyncio.Semaphore(8)

    async def read(
        operation: Callable[[], Awaitable[AdapterResult]], node: str, storage: str | None = None
    ) -> list[Any] | None:
        try:
            async with semaphore:
                result = await asyncio.wait_for(operation(), timeout=20)
            if result.success and isinstance(result.data, list):
                return result.data
        except Exception:
            pass
        failures.append(
            BackupReadFailure(node=node, storage=storage, reason="Backup inventory read failed")
        )
        return None

    node_inventory = await read(adapter.get_nodes, "cluster")
    node_names = {row["node"] for row in guests.values()}
    for row in node_inventory or []:
        node = row.get("node") if isinstance(row, dict) else getattr(row, "node", None)
        if isinstance(node, str) and node:
            node_names.add(node)
        else:
            failures.append(BackupReadFailure(node="cluster", reason="Node inventory is malformed"))
    nodes = sorted(node_names)
    inventories = await asyncio.gather(
        *(read(partial(adapter.get_storage, node), node) for node in nodes)
    )
    storages: list[tuple[str, str]] = []
    for node, rows in zip(nodes, inventories, strict=True):
        for row in rows or []:
            content = (
                row.get("content", "") if isinstance(row, dict) else getattr(row, "content", "")
            )
            name = row.get("storage") if isinstance(row, dict) else getattr(row, "storage", None)
            if not isinstance(content, str) or not isinstance(name, str) or not name:
                failures.append(
                    BackupReadFailure(node=node, reason="Storage inventory is malformed")
                )
            elif "backup" in content.split(","):
                storages.append((node, name))

    archives = await asyncio.gather(
        *(
            read(
                partial(adapter.get_storage_content, node, name, content_type="backup"), node, name
            )
            for node, name in storages
        )
    )
    now = datetime.now(UTC)
    latest: dict[int, float] = {}
    for (node, storage), rows in zip(storages, archives, strict=True):
        for row in rows or []:
            try:
                if not isinstance(row, dict):
                    raise ValueError("not an archive record")
                vmid = int(row["vmid"])
                timestamp = float(row["ctime"])
                if (
                    not math.isfinite(timestamp)
                    or timestamp <= 0
                    or timestamp > now.timestamp() + 300
                ):
                    raise ValueError("invalid archive timestamp")
                latest[vmid] = max(latest.get(vmid, 0), timestamp)
            except (KeyError, TypeError, ValueError, OverflowError):
                failures.append(
                    BackupReadFailure(
                        node=node, storage=storage, reason="Archive metadata is malformed"
                    )
                )

    rows_out: list[BackupAgeReport] = []
    status: Literal["current", "stale", "missing", "unknown"]
    for vmid, guest in sorted(guests.items()):
        last_timestamp = latest.get(vmid)
        observed = (
            datetime.fromtimestamp(last_timestamp, UTC) if last_timestamp is not None else None
        )
        age = max(0, (now - observed).total_seconds() / 3600) if observed is not None else None
        # A recent observed archive proves freshness even when another store is
        # offline. Absence or apparent staleness cannot be proved in that case.
        if age is not None and age <= threshold_hours:
            status = "current"
        elif failures:
            status = "unknown"
        elif observed is None:
            status = "missing"
        else:
            status = "stale"
        rows_out.append(
            BackupAgeReport(
                vmid=vmid,
                name=guest.get("name"),
                node=guest["node"],
                last_backup_time=observed,
                age_hours=round(age, 1) if age is not None else None,
                is_stale=None if status == "unknown" else status != "current",
                status=status,
            )
        )
    return BackupAgeResponse(
        threshold_hours=threshold_hours,
        total_vms=len(guests),
        backed_up=sum(row.last_backup_time is not None for row in rows_out),
        fresh=sum(row.status == "current" for row in rows_out),
        stale=sum(row.status == "stale" for row in rows_out),
        never_backed_up=sum(row.status == "missing" for row in rows_out),
        unknown=sum(row.status == "unknown" for row in rows_out),
        complete=not failures,
        observed_at=now,
        read_failures=failures,
        vms=rows_out,
    )
