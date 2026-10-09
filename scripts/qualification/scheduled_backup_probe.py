"""HTTP-only backup operations on the install check's fresh synthetic tenant.

Run inside its API container so downloads can also be compared with the real
shared backup volume. Never dispatch a task manually or adjust stored deadlines:
the packaged Beat process and worker must produce both scheduled archives.
On failure the host harness retains evidence and removes its own Docker project;
this probe does not sweep a partially understood backup catalog.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

BASE = "/api/v1/backups"
POLL_SECONDS = 5
RUN_TIMEOUT = 240
QUIET_GRACE = 70  # past next due time and a complete one-minute Beat interval


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def instant(value):
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None, "Schedule timestamps must include a timezone")
    return result.astimezone(UTC)


def archive_path(row, root):
    """Refuse foreign/absolute/traversing/symlink paths before reading any bytes."""
    relative = Path(row["storage_path"])
    require(
        str(UUID(row["id"])) == row["id"]
        and not relative.is_absolute()
        and ".." not in relative.parts
        and relative.name.startswith(row["id"] + "_")
        and relative.suffix == ".fsdn",
        "Unexpected synthetic archive path",
    )
    base = root.resolve()
    path = base / relative
    require(
        path.resolve() == path and path.is_relative_to(base),
        "Archive path escapes shared volume",
    )
    return path


def verify_archive(row, body, root):
    require(
        row["status"] == "completed"
        and row["is_encrypted"] is True
        and row["include_secrets"] is False
        and row["storage_type"] == "local"
        and row["file_size"] == len(body),
        "Archive metadata is not a completed encrypted local configuration snapshot",
    )
    require(4 < len(body) <= 8 * 1024 * 1024, "Unexpected synthetic archive size")
    size = int.from_bytes(body[:4], "big")
    require(0 < size <= 65536 and 4 + size < len(body), "Invalid archive header length")
    header = json.loads(body[4 : 4 + size])
    require(
        header["backup_id"] == row["id"]
        and header["encrypted"] is True
        and header["secrets"] is False
        and header["compressed"] is True
        and bool(header["key_id"])
        and hashlib.sha256(body[4 + size :]).hexdigest() == header["checksum"],
        "Archive identity, encryption markers or payload checksum mismatch",
    )
    path = archive_path(row, root)
    require(
        path.is_file() and path.read_bytes() == body,
        "API download and shared volume disagree",
    )
    return path


def run_scheduled_backup_acceptance(
    request, state, headers, *, root=Path("/data/backups")
):
    def call(method, path, code=200, **kwargs):
        return request(method, path, code=code, headers=headers, **kwargs)

    def catalog():
        page = call("GET", BASE + "/", params={"per_page": 200}).json()
        require(
            page["total"] == len(page["items"]), "Unexpected paginated fixture catalog"
        )
        return page["items"]

    def schedule():
        value = call("GET", schedule_path).json()
        require(
            value["id"] == schedule_id and value["site_id"] == site_id,
            "Schedule identity changed",
        )
        return value

    def site_description():
        value = call("GET", site_path).json()
        require(
            value["id"] == site_id
            and value["organization_id"] == state["organization"],
            "Site identity changed",
        )
        return value["description"]

    # Reject an existing installation BEFORE the first write. The parent harness
    # independently requires fresh volumes, an internal network and no host ports.
    user = call("GET", "/api/v1/auth/me").json()
    require(
        user["id"] == state["user"]
        and user["organization_id"] == state["organization"]
        and user["username"] == "qualification-admin"
        and user["is_superuser"] is True,
        "Backup qualification requires the owned initial administrator",
    )
    sites = call("GET", "/api/v1/sites/", params={"per_page": 100}).json()
    require(
        sites["total"] == 1 and len(sites["items"]) == 1,
        "Backup probe requires only the fresh bootstrap site",
    )
    bootstrap = sites["items"][0]
    require(
        bootstrap["id"] == state["bootstrap_site"]
        and bootstrap["organization_id"] == state["organization"]
        and bootstrap["slug"] == "main"
        and bootstrap["description"] == "Default site created during setup"
        and bootstrap["device_count"] == bootstrap["controller_count"] == 0,
        "Bootstrap site is not the empty site returned by this fixture's setup",
    )
    require(catalog() == [], "Backup probe requires a fresh backup inventory")
    require(
        call("GET", BASE + "/schedules").json() == [],
        "Backup probe requires no existing schedules",
    )

    token = secrets.token_hex(8)
    sentinel = "Synthetic backup restore sentinel " + token
    site = call(
        "POST",
        "/api/v1/sites/",
        code=201,
        json={
            "name": "Scheduled backup qualification",
            "slug": "backup-check-" + token,
            "organization_id": state["organization"],
            "description": sentinel,
        },
    ).json()
    site_id = str(UUID(site["id"]))
    require(
        site["organization_id"] == state["organization"],
        "Created site is in another tenant",
    )
    site_path = "/api/v1/sites/" + site_id
    payload = {
        "name": "Owned scheduled backup " + token,
        "site_id": site_id,
        "cron_expression": "0 2 * * *",
        "timezone": "Asia/Kathmandu",
        "is_encrypted": True,
        "storage_type": "local",
        "retention_days": 1,
        "max_backups": 1,
        "include_devices": False,
        "include_vlans": False,
        "include_ssids": False,
        "include_users": False,
        "include_automation": False,
    }
    for invalid in ({"timezone": "No/Such_Zone"}, {"cron_expression": "0 2 31 2 *"}):
        call("POST", BASE + "/schedules", code=422, json={**payload, **invalid})
    value = call("POST", BASE + "/schedules", code=201, json=payload).json()
    schedule_id = str(UUID(value["id"]))
    schedule_path = BASE + "/schedules/" + schedule_id
    local = instant(value["next_run_at"]).astimezone(ZoneInfo("Asia/Kathmandu"))
    require(
        (local.hour, local.minute) == (2, 0),
        "API ignored the schedule's local calendar",
    )
    call("PUT", schedule_path, json={"cron_expression": "* * * * *", "timezone": "UTC"})
    deadline = time.monotonic() + RUN_TIMEOUT
    observed = []
    last_run = None
    while len(observed) < 2:
        require(
            time.monotonic() < deadline,
            "Packaged Beat/worker did not produce two retained scheduled archives",
        )
        rows = catalog()
        for row in rows:
            require(
                row["schedule_id"] == schedule_id and row["site_id"] == site_id,
                "Unexpected archive in owned fixture",
            )
            require(
                row["status"] in {"pending", "in_progress", "completed"},
                "Scheduled archive failed",
            )
        current = schedule()
        # Completion and retention commit before last_run_at. Avoid mistaking an
        # in-flight second row or a prior occurrence for a completed rotation.
        if (
            len(rows) == 1
            and rows[0]["status"] == "completed"
            and current["last_run_at"]
        ):
            row = rows[0]
            ran_at = instant(current["last_run_at"])
            if not observed or (
                row["id"] != observed[-1][0]["id"] and ran_at > last_run
            ):
                body = call("GET", BASE + "/" + row["id"] + "/download").content
                path = verify_archive(row, body, root)
                observed.append((row, path))
                last_run = ran_at
                if len(observed) == 2:
                    break
        time.sleep(POLL_SECONDS)

    old, retained = observed[0][0], observed[1][0]
    require(
        not observed[0][1].exists(),
        "Retention removed catalog metadata but left the archive file",
    )
    call("GET", BASE + "/" + old["id"], code=404)
    call("GET", BASE + "/" + old["id"] + "/download", code=404)
    call("POST", schedule_path + "/toggle", json={"is_enabled": False})
    disabled = schedule()
    require(disabled["is_enabled"] is False, "Disable did not persist")
    quiet_until = instant(disabled["next_run_at"]) + timedelta(seconds=QUIET_GRACE)
    require(
        0 < (quiet_until - datetime.now(UTC)).total_seconds() <= 150,
        "Unexpected disabled schedule deadline",
    )
    quiet_deadline = time.monotonic() + 160
    while True:
        require(
            time.monotonic() < quiet_deadline,
            "Clock moved during disabled schedule observation",
        )
        rows = catalog()
        current = schedule()
        require(
            [r["id"] for r in rows] == [retained["id"]],
            "Disabled schedule created or removed an archive",
        )
        require(
            current["is_enabled"] is False
            and current["last_run_at"] == disabled["last_run_at"],
            "Disabled schedule ran again",
        )
        if datetime.now(UTC) >= quiet_until:
            break
        time.sleep(POLL_SECONDS)

    changed = "Changed after backup " + token
    call("PATCH", site_path, json={"description": changed})
    require(site_description() == changed, "Restore sentinel mutation did not persist")
    restore = {
        "backup_id": retained["id"],
        "target_site_id": site_id,
        "contributors": ["core"],
        "overwrite_existing": True,
        "restore_users": False,
        "restore_devices": False,
        "restore_vlans": False,
        "restore_ssids": False,
        "restore_automation": False,
    }
    preview = call("POST", BASE + "/restore", json={**restore, "dry_run": True}).json()
    require(
        preview["status"] == "completed" and preview["dry_run"] is True,
        "Configuration preview failed",
    )
    require(site_description() == changed, "Dry-run restore changed configuration")
    require(
        [r["id"] for r in catalog()] == [retained["id"]],
        "Dry run created an unexpected archive",
    )
    job = call("POST", BASE + "/restore", json={**restore, "dry_run": False}).json()
    require(
        job["status"] == "completed"
        and job["dry_run"] is False
        and job["items_restored"] > 0
        and job["items_failed"] == 0
        and job["error_message"] is None,
        "Real configuration restore did not complete cleanly",
    )
    require(
        site_description() == sentinel,
        "Completed restore did not recover the archived sentinel",
    )
    summary = job["restore_log"]["summary"]
    core_results = [
        r for r in job["restore_log"]["contributors"] if r["contributor_id"] == "core"
    ]
    require(
        summary["total_errors"] == 0
        and len(core_results) == 1
        and core_results[0]["status"] == "ok",
        "Restore reported a contributor error",
    )
    rows = catalog()
    slots = [r for r in rows if r["rollback_for_restore_job_id"] == job["id"]]
    require(
        len(rows) == 2 and len(slots) == 1,
        "Restore did not capture exactly one owned rollback snapshot",
    )
    slot = slots[0]
    require(slot["backup_type"] == "rollback_slot", "Unexpected rollback archive type")
    slot_path = verify_archive(
        slot, call("GET", BASE + "/" + slot["id"] + "/download").content, root
    )

    # Delete only IDs observed for this schedule/restore, checking actual files.
    for row, path in ((slot, slot_path), observed[1]):
        call("DELETE", BASE + "/" + row["id"], code=204)
        call("GET", BASE + "/" + row["id"] + "/download", code=404)
        require(not path.exists(), "Deleted backup left an orphan on the shared volume")
    call("DELETE", schedule_path, code=204)
    call("GET", schedule_path, code=404)
    call("DELETE", site_path, code=204)
    call("GET", site_path, code=404)
    require(
        catalog() == [] and call("GET", BASE + "/schedules").json() == [],
        "Synthetic backup cleanup incomplete",
    )
    require(
        call("GET", "/api/v1/sites/", params={"per_page": 100}).json() == sites,
        "Backup probe changed the bootstrap site inventory",
    )
    return {
        "passed": True,
        "scheduled_archives_observed": 2,
        "retention_checked_in_catalog_and_shared_volume": True,
        "disabled_observed_past_next_due_and_beat_interval": True,
        "dry_run_preserved_sentinel": True,
        "real_restore_recovered_sentinel": True,
        "encrypted_rollback_snapshot_downloaded": True,
        "owned_archives_removed": True,
        "scope": "synthetic core configuration; no hardware restore or customer RTO/RPO",
    }
