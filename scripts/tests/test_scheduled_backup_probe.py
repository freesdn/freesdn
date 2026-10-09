"""Negative controls for the acceptance harness, not shipping backup evidence."""

import hashlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest


@pytest.fixture
def probe():
    path = Path(__file__).parents[1] / "qualification/scheduled_backup_probe.py"
    spec = importlib.util.spec_from_file_location("backup_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(root, *, row_id=None):
    row_id = row_id or str(uuid4())
    payload = b"synthetic encrypted-marker fixture, not a real encrypted backup"
    header = json.dumps(
        {
            "backup_id": row_id,
            "encrypted": True,
            "secrets": False,
            "compressed": True,
            "key_id": "synthetic-fixture",
            "checksum": hashlib.sha256(payload).hexdigest(),
        }
    ).encode()
    body = len(header).to_bytes(4, "big") + header + payload
    relative = "2026/09/26/" + row_id + "_synthetic.fsdn"
    row = {
        "id": row_id,
        "storage_path": relative,
        "status": "completed",
        "is_encrypted": True,
        "include_secrets": False,
        "storage_type": "local",
        "file_size": len(body),
        "rollback_for_restore_job_id": None,
    }
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return row, body, path


def test_matching_catalog_download_and_volume(probe, tmp_path):
    row, body, path = archive(tmp_path)
    assert probe.verify_archive(row, body, tmp_path) == path


@pytest.mark.parametrize(
    "field,value",
    [("encrypted", False), ("secrets", True), ("compressed", False), ("key_id", None)],
)
def test_catalog_markers_do_not_override_wrong_archive_header(
    probe, tmp_path, field, value
):
    row, body, path = archive(tmp_path)
    size = int.from_bytes(body[:4], "big")
    header = json.loads(body[4 : 4 + size])
    header[field] = value
    encoded = json.dumps(header).encode()
    body = len(encoded).to_bytes(4, "big") + encoded + body[4 + size :]
    row["file_size"] = len(body)
    path.write_bytes(body)
    with pytest.raises(RuntimeError):
        probe.verify_archive(row, body, tmp_path)


@pytest.mark.parametrize(
    "fault",
    [
        "truncated",
        "corrupt-payload",
        "oversized-header",
        "wrong-identity",
        "plaintext",
        "contains-secrets",
        "pending",
        "foreign-storage",
        "missing-file",
        "different-file",
        "absolute-path",
        "traversal",
        "foreign-filename",
        "symlink",
    ],
)
def test_archive_false_green_controls(probe, tmp_path, fault):
    row, body, path = archive(tmp_path)
    if fault == "truncated":
        body = body[:3]
        row["file_size"] = len(body)
    elif fault == "corrupt-payload":
        body = body[:-1] + b"!"
        path.write_bytes(body)
    elif fault == "oversized-header":
        body = (9999999).to_bytes(4, "big") + body[4:]
    elif fault == "wrong-identity":
        row["id"] = str(uuid4())
    elif fault == "plaintext":
        row["is_encrypted"] = False
    elif fault == "contains-secrets":
        row["include_secrets"] = True
    elif fault == "pending":
        row["status"] = "pending"
    elif fault == "foreign-storage":
        row["storage_type"] = "sftp"
    elif fault == "missing-file":
        path.unlink()
    elif fault == "different-file":
        path.write_bytes(b"other")
    elif fault == "absolute-path":
        row["storage_path"] = str(path)
    elif fault == "traversal":
        row["storage_path"] = "../" + path.name
    elif fault == "foreign-filename":
        row["storage_path"] = "other.fsdn"
    elif fault == "symlink":
        other = tmp_path / "foreign"
        path.rename(other)
        path.symlink_to(other)
    with pytest.raises(RuntimeError):
        probe.verify_archive(row, body, tmp_path)


@pytest.mark.parametrize(
    "fault",
    [
        "user",
        "organization",
        "username",
        "role",
        "site",
        "backup",
        "schedule",
        "pagination",
    ],
)
def test_existing_or_foreign_installation_refused_before_any_write(probe, fault):
    state = {
        "user": str(uuid4()),
        "organization": str(uuid4()),
        "bootstrap_site": str(uuid4()),
    }
    user = {
        "id": state["user"],
        "organization_id": state["organization"],
        "username": "qualification-admin",
        "is_superuser": True,
    }
    bootstrap = {
        "id": state["bootstrap_site"],
        "organization_id": state["organization"],
        "slug": "main",
        "description": "Default site created during setup",
        "device_count": 0,
        "controller_count": 0,
    }
    sites = {"total": 1, "items": [bootstrap]}
    backups = {"total": 0, "items": []}
    schedules = []
    if fault in {"user", "organization", "username", "role"}:
        user[
            {
                "user": "id",
                "organization": "organization_id",
                "username": "username",
                "role": "is_superuser",
            }[fault]
        ] = "foreign"
    elif fault == "site":
        sites = {"total": 2, "items": [bootstrap, {"id": "existing"}]}
    elif fault == "backup":
        backups = {"total": 1, "items": [{"id": "existing"}]}
    elif fault == "pagination":
        backups["total"] = 201
    else:
        schedules.append({"id": "existing"})

    def request(method, path, **kwargs):
        assert method == "GET", "Probe attempted a write before refusing foreign data"
        value = {
            "/api/v1/auth/me": user,
            "/api/v1/sites/": sites,
            probe.BASE + "/": backups,
            probe.BASE + "/schedules": schedules,
        }[path]
        return SimpleNamespace(json=lambda: value)

    with pytest.raises(RuntimeError):
        probe.run_scheduled_backup_acceptance(request, state, {})


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "stalled-worker",
        "failed-backup",
        "retention-orphan",
        "disabled-ran",
        "dry-run-writes",
        "restore-noop",
        "contributor-error",
        "missing-rollback",
        "delete-orphan",
    ],
)
def test_full_probe_trace_and_false_success_controls(
    probe, tmp_path, monkeypatch, fault
):
    """Deterministic HTTP trace. Only the real post-soak run can prove transport."""
    state = {
        "user": str(uuid4()),
        "organization": str(uuid4()),
        "bootstrap_site": str(uuid4()),
    }
    start = datetime(2026, 9, 26, 22, 0, tzinfo=UTC)
    clock = [0]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return start + timedelta(seconds=clock[0])

    monkeypatch.setattr(probe, "datetime", Clock)
    monkeypatch.setattr(
        probe,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock[0],
            sleep=lambda n: clock.__setitem__(0, clock[0] + n),
        ),
    )
    site_id, schedule_id, job_id = (str(uuid4()) for _ in range(3))
    rows = [archive(tmp_path) for _ in range(3)]
    for row, _, _ in rows[:2]:
        row.update(site_id=site_id, schedule_id=schedule_id)
    rows[2][0].update(rollback_for_restore_job_id=job_id, backup_type="rollback_slot")
    bootstrap = {
        "id": state["bootstrap_site"],
        "organization_id": state["organization"],
        "slug": "main",
        "description": "Default site created during setup",
        "device_count": 0,
        "controller_count": 0,
    }
    sites, catalog, schedules = [bootstrap], [], []
    site = {"id": site_id, "organization_id": state["organization"]}
    schedule = {
        "id": schedule_id,
        "site_id": site_id,
        "next_run_at": "2026-09-27T02:00:00+05:45",
        "is_enabled": True,
        "last_run_at": None,
    }
    armed, runs, disabled, sentinel = False, 0, False, None

    def response(value=None, content=b""):
        # Real JSON decoding returns independent snapshots, not mutable aliases.
        return SimpleNamespace(
            json=lambda: json.loads(json.dumps(value)), content=content
        )

    def request(method, path, code=200, json=None, **kwargs):
        nonlocal armed, runs, disabled, sentinel, catalog
        if method == "GET" and path == "/api/v1/auth/me":
            return response(
                {
                    "id": state["user"],
                    "organization_id": state["organization"],
                    "username": "qualification-admin",
                    "is_superuser": True,
                }
            )
        if path == "/api/v1/sites/":
            if method == "POST":
                assert code == 201
                sentinel = json["description"]
                site.update(json)
                sites.append(site)
                return response(site)
            return response({"total": len(sites), "items": sites})
        if path == "/api/v1/sites/" + site_id:
            if method == "PATCH":
                site.update(json)
            elif method == "DELETE":
                sites.remove(site)
            return response(site)
        if path == probe.BASE + "/schedules":
            if method == "POST":
                if code == 422:
                    return response()
                schedules.append(schedule)
                return response(schedule)
            return response(schedules)
        if path == probe.BASE + "/schedules/" + schedule_id:
            if method == "PUT":
                armed = True
                schedule["next_run_at"] = (start + timedelta(minutes=1)).isoformat()
            elif method == "DELETE":
                schedules.clear()
            return response(schedule)
        if path.endswith("/toggle"):
            assert json == {"is_enabled": False}
            disabled = True
            schedule["is_enabled"] = False
            return response()
        if path == probe.BASE + "/":
            if armed and not disabled and runs < 2 and fault != "stalled-worker":
                catalog = [rows[runs][0]]
                schedule["last_run_at"] = (start + timedelta(seconds=runs)).isoformat()
                if fault == "failed-backup":
                    catalog[0]["status"] = "failed"
                if runs == 1 and fault != "retention-orphan":
                    rows[0][2].unlink()
                runs += 1
            if disabled and fault == "disabled-ran":
                catalog = []
            return response({"total": len(catalog), "items": catalog})
        if path == probe.BASE + "/restore":
            if json["dry_run"]:
                if fault == "dry-run-writes":
                    site["description"] = sentinel
                return response({"status": "completed", "dry_run": True})
            if fault != "restore-noop":
                site["description"] = sentinel
            if fault != "missing-rollback":
                catalog.append(rows[2][0])
            return response(
                {
                    "id": job_id,
                    "status": "completed",
                    "dry_run": False,
                    "items_restored": 1,
                    "items_failed": 0,
                    "error_message": None,
                    "restore_log": {
                        "summary": {"total_errors": int(fault == "contributor-error")},
                        "contributors": [{"contributor_id": "core", "status": "ok"}],
                    },
                }
            )
        for row, body, path_on_disk in rows:
            if path in {
                probe.BASE + "/" + row["id"],
                probe.BASE + "/" + row["id"] + "/download",
            }:
                present = any(r["id"] == row["id"] for r in catalog)
                if method == "DELETE":
                    assert present and code == 204
                    catalog = [r for r in catalog if r["id"] != row["id"]]
                    if fault != "delete-orphan":
                        path_on_disk.unlink()
                else:
                    assert code == (200 if present else 404)
                return response(row, body)
        raise AssertionError("Unexpected request in synthetic trace")

    if fault is None:
        result = probe.run_scheduled_backup_acceptance(
            request, state, {}, root=tmp_path
        )
        assert (
            result["passed"] and not catalog and not schedules and sites == [bootstrap]
        )
        assert clock[0] >= 130
        assert not any(p.exists() for _, _, p in rows)
    else:
        with pytest.raises(RuntimeError):
            probe.run_scheduled_backup_acceptance(request, state, {}, root=tmp_path)
