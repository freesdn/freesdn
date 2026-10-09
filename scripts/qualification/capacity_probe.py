"""Bounded synthetic load and real ENOSPC inside the isolated Lite fixture.

Never point this probe at a deployment. Its private state is created by
check_install_acceptance.py; it deliberately writes disposable database rows.
"""

from __future__ import annotations

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import asyncio
import errno
import hashlib
import json
import math
import os
import socket
import ssl
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import httpx

STATE = Path("/tmp/install-probe-state.json")
PRESSURE_ROOT = Path("/qualification-reports")


def percentiles(values):
    ordered = sorted(values)
    return (
        {
            f"p{p}": round(ordered[math.ceil(len(ordered) * p / 100) - 1], 2)
            for p in (50, 95, 99)
        }
        if ordered
        else {}
    )


def main():
    if os.environ.get("FREESDN_CAPACITY_FIXTURE") != "isolated-disposable":
        raise RuntimeError(
            "Only the isolated qualification driver may invoke this probe"
        )
    mode, seconds = sys.argv[1], int(sys.argv[2])
    if mode not in {"pressure", "soak"} or (
        mode == "soak" and not 60 <= seconds <= 1800
    ):
        raise ValueError("Invalid bounded fixture mode or duration")
    state = json.loads(STATE.read_text())
    original_resolve = socket.getaddrinfo

    def resolve(host, *args, **kwargs):
        return original_resolve(
            "edge" if host in ("localhost", b"localhost") else host, *args, **kwargs
        )

    socket.getaddrinfo = resolve
    context = ssl.create_default_context(cafile="/tmp/qualification-ca.crt")
    report = {"passed": False, "mode": mode, "synthetic": True}
    with httpx.Client(
        base_url="https://localhost", verify=context, timeout=30, trust_env=False
    ) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={
                "login": "qualification-admin",
                "password": state["password"],
            },
        )
        assert login.status_code == 200
        from app.core.cookies import CSRF_COOKIE

        headers = {
            "Origin": "https://localhost",
            "X-CSRF-Token": login.cookies[CSRF_COOKIE],
        }

        def generate(fmt, title):
            return client.post(
                "/api/v1/sla/reports/generate",
                headers=headers,
                json={
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-01-02T00:00:00Z",
                    "format": fmt,
                    "title": title,
                },
            )

        def catalogue():
            response = client.get("/api/v1/sla/reports", headers=headers)
            assert response.status_code == 200
            return response.json()["total"]

        if mode == "pressure":
            # Refuse to fill a regular directory, even if the driver was misused.
            assert os.environ.get("SLA_REPORTS_DIR") == str(PRESSURE_ROOT)
            mounts = [
                line.split() for line in Path("/proc/mounts").read_text().splitlines()
            ]
            mount = next(row for row in mounts if row[1] == str(PRESSURE_ROOT))
            assert mount[2] == "tmpfs" and "rw" in mount[3].split(",")
            disk = os.statvfs(PRESSURE_ROOT)
            assert 0 < disk.f_blocks * disk.f_frsize <= 16 * 1024 * 1024
            org_dir = PRESSURE_ROOT / state["organization"]
            org_dir.mkdir(mode=0o700)
            filler = PRESSURE_ROOT / "owned-pressure-fixture"
            before = catalogue()
            filled = 0
            try:
                with filler.open("xb", buffering=0) as stream:
                    try:
                        while True:
                            filled += stream.write(b"x" * 4096)
                    except OSError as exc:
                        assert exc.errno == errno.ENOSPC
                assert os.statvfs(PRESSURE_ROOT).f_bavail == 0
                statuses = {}
                for fmt in ("csv", "pdf"):
                    response = generate(fmt, "Owned ENOSPC qualification " + fmt)
                    statuses[fmt] = response.status_code
                    assert response.status_code in {500, 503, 507}
                    # A failed write must not produce a successful-looking catalogue row.
                    assert catalogue() == before
                    assert not list(org_dir.iterdir()), "Partial render was retained"
                    assert client.get("/api/v1/health/ready").status_code == 200
            finally:
                filler.unlink(missing_ok=True)
            recovered = []
            for fmt in ("csv", "pdf"):
                response = generate(fmt, "Owned post-pressure qualification " + fmt)
                assert response.status_code == 201
                row = response.json()
                response = client.get("/api/v1/sla/reports/" + row["id"] + "/download")
                assert (
                    response.status_code == 200
                    and len(response.content) == row["file_size"]
                )
                assert (
                    response.content.startswith(b"%PDF-")
                    if fmt == "pdf"
                    else b"," in response.content
                )
                recovered.append(row["id"])
            assert catalogue() == before + 2

            # These two files belong to the temporary sink. Remove their owned
            # fixture rows before the sink disappears, not any persistent report.
            async def remove_pressure_rows():
                from app.db.session import async_session_factory, engine
                from app.models.sla import SLAReport
                from sqlalchemy import delete

                async with async_session_factory() as session:
                    result = await session.execute(
                        delete(SLAReport).where(
                            SLAReport.organization_id == UUID(state["organization"]),
                            SLAReport.id.in_([UUID(value) for value in recovered]),
                        )
                    )
                    assert result.rowcount == 2
                    await session.commit()
                await engine.dispose()

            asyncio.run(remove_pressure_rows())
            assert catalogue() == before
            report.update(
                passed=True,
                filesystem_bytes=disk.f_blocks * disk.f_frsize,
                bytes_written_before_enospc=filled,
                failure_statuses=statuses,
                phantom_rows=0,
                partial_files=0,
                recovered_formats=["csv", "pdf"],
            )
        else:
            from app.core.celery_app import celery_app

            async def seed_history():
                from app.db.session import async_session_factory, engine
                from app.models.sla import SLAPolicy
                from sqlalchemy import text

                async with async_session_factory() as session:
                    policies = [
                        SLAPolicy(
                            organization_id=UUID(state["organization"]),
                            name="Owned capacity history " + str(index),
                            scope="organization",
                            status="paused",
                        )
                        for index in range(8)
                    ]
                    session.add_all(policies)
                    await session.flush()
                    for policy in policies:
                        await session.execute(
                            text("""
                            INSERT INTO core.sla_breaches
                            (id,policy_id,organization_id,severity,status,violated_metric,
                             threshold_value,actual_value,deviation_percent,started_at,context,notes)
                            SELECT gen_random_uuid(),CAST(:policy AS uuid),CAST(:org AS uuid),
                                CASE WHEN n%2=0 THEN 'critical' ELSE 'warning' END,
                                CASE WHEN n%3=0 THEN 'acknowledged' ELSE 'active' END,
                                'uptime',99,42,57,'2026-01-01T00:00:00Z',
                                jsonb_build_object('payload',repeat('y',1024)),repeat('x',1024)
                            FROM generate_series(1,2500) n
                        """),
                            {"policy": str(policy.id), "org": state["organization"]},
                        )
                        await session.execute(
                            text("""
                            INSERT INTO core.sla_snapshots
                            (id,policy_id,recorded_at,compliance_percent,metrics,in_breach)
                            SELECT gen_random_uuid(),CAST(:policy AS uuid),
                                '2026-01-01T00:00:00Z'::timestamptz+n*INTERVAL '1 second',
                                n%101,'{}',false FROM generate_series(1,10000) n
                        """),
                            {"policy": str(policy.id)},
                        )
                    await session.commit()
                await engine.dispose()

            asyncio.run(seed_history())

            counts = Counter()
            latencies = defaultdict(list)
            samples = []
            lock = threading.Lock()
            stop = threading.Event()
            start = time.monotonic()
            deadline = start + seconds
            baseline_count = catalogue()
            expected_reports = []

            def record(kind, started, success):
                with lock:
                    counts[kind + ("_ok" if success else "_failed")] += 1
                    latencies[kind].append((time.monotonic() - started) * 1000)

            def reads(path):
                while time.monotonic() < deadline and not stop.is_set():
                    began = time.monotonic()
                    try:
                        response = client.get(path, headers=headers)
                        ok = response.status_code == 200
                    except httpx.HTTPError:
                        ok = False
                    record("read", began, ok)
                    stop.wait(max(0, 1.5 - (time.monotonic() - began)))

            def reports():
                index = 0
                while time.monotonic() < deadline and not stop.is_set():
                    began = time.monotonic()
                    fmt = "csv" if index % 2 == 0 else "pdf"
                    ok = False
                    try:
                        response = generate(fmt, "Owned soak " + str(index))
                        if response.status_code == 201:
                            row = response.json()
                            assert row["report_data"]["breaches"]["total"] == 20000
                            assert (
                                row["report_data"]["compliance"]["snapshot_count"]
                                == 80000
                            )
                            download = client.get(
                                "/api/v1/sla/reports/" + row["id"] + "/download"
                            )
                            ok = (
                                download.status_code == 200
                                and len(download.content) == row["file_size"]
                                and (
                                    download.content.startswith(b"%PDF-")
                                    if fmt == "pdf"
                                    else b"," in download.content
                                )
                            )
                            if ok:
                                expected_reports.append(
                                    {
                                        "id": row["id"],
                                        "format": fmt,
                                        "sha256": hashlib.sha256(
                                            download.content
                                        ).hexdigest(),
                                        "bytes": len(download.content),
                                    }
                                )
                    except httpx.HTTPError:
                        pass
                    record("report", began, ok)
                    index += 1
                    stop.wait(max(0, 10 - (time.monotonic() - began)))

            def queues():
                while time.monotonic() < deadline and not stop.is_set():
                    began = time.monotonic()
                    tasks = [
                        celery_app.send_task(
                            "app.tasks.maintenance.cleanup_token_revocations", queue=q
                        )
                        for q in ("default", "discovery", "sync", "priority", "metrics")
                    ]
                    for task in tasks:
                        result = task.get(timeout=45)
                        record("queue", began, result.get("success") is True)
                        task.forget()
                    stop.wait(max(0, 10 - (time.monotonic() - began)))

            async def ingest():
                from app.db.session import logdb_engine, logdb_session_factory
                from sqlalchemy import text

                inserted = 0
                try:
                    while time.monotonic() < deadline and not stop.is_set():
                        began = time.monotonic()
                        async with logdb_session_factory() as session:
                            await session.execute(
                                text("""
                                INSERT INTO events.event_records
                                (id,event_type,category,priority,payload,metadata,source,organization_id,timestamp)
                                SELECT gen_random_uuid(),'release.soak','system','normal',
                                jsonb_build_object('index',:offset+n,'message',repeat('x',512)), '{}',
                                'capacity-qualification', CAST(:org AS uuid), now()
                                FROM generate_series(1,250) n
                            """),
                                {"org": state["organization"], "offset": inserted},
                            )
                            await session.commit()
                        inserted += 250
                        record("event_batch", began, True)
                        samples.append(
                            {
                                "elapsed_seconds": round(time.monotonic() - start, 2),
                                "api_cgroup_bytes": int(
                                    Path("/sys/fs/cgroup/memory.current").read_text()
                                ),
                            }
                        )
                        await asyncio.sleep(max(0, 5 - (time.monotonic() - began)))
                    async with logdb_session_factory() as session:
                        actual = (
                            await session.execute(
                                text("""
                            SELECT count(*) FROM events.event_records
                            WHERE source='capacity-qualification' AND organization_id=CAST(:org AS uuid)
                        """),
                                {"org": state["organization"]},
                            )
                        ).scalar_one()
                    assert actual == inserted
                    return inserted
                finally:
                    await logdb_engine.dispose()

            def event_ingestion():
                return asyncio.run(ingest())

            with ThreadPoolExecutor(max_workers=7) as pool:
                jobs = [
                    pool.submit(reads, path)
                    for path in (
                        "/api/v1/dashboard/stats",
                        "/api/v1/sites",
                        "/api/v1/sla/reports",
                        "/api/v1/health/ready",
                    )
                ]
                jobs += [pool.submit(reports), pool.submit(queues)]
                event_job = pool.submit(event_ingestion)
                try:
                    for job in jobs:
                        job.result()
                    inserted = event_job.result()
                finally:
                    stop.set()
            # Preserve counters and latency evidence when a throughput gate
            # fails. Raising here previously discarded the measurements that
            # were needed to diagnose an unsuccessful run.
            acceptance = {
                "catalogue_matches_generated_archives": (
                    catalogue() == baseline_count + len(expected_reports)
                ),
                "minimum_successful_reports": seconds // 10 - 1,
                "minimum_successful_queue_jobs": (seconds // 10 - 1) * 5,
                "minimum_successful_reads": seconds,
            }
            throughput_passed = (
                acceptance["catalogue_matches_generated_archives"]
                and counts["report_ok"] >= acceptance["minimum_successful_reports"]
                and counts["queue_ok"] >= acceptance["minimum_successful_queue_jobs"]
                and counts["read_ok"] >= acceptance["minimum_successful_reads"]
            )
            # Subsequent recreation AND encrypted recovery verify every generated
            # archive byte against hashes, plus the ingestion count/fingerprint.
            state["reports"].extend(expected_reports)
            state["soak_events"] = inserted
            STATE.write_text(json.dumps(state))
            STATE.chmod(0o600)
            report.update(
                passed=throughput_passed
                and not any(v for k, v in counts.items() if k.endswith("_failed")),
                acceptance=acceptance,
                requested_seconds=seconds,
                elapsed_seconds=round(time.monotonic() - start, 2),
                counts=dict(counts),
                event_rows=inserted,
                reports=len(expected_reports),
                history={"policies": 8, "breaches": 20000, "snapshots": 80000},
                latency_ms={
                    kind: percentiles(values) for kind, values in latencies.items()
                },
                api_memory_samples=samples,
                workload="4 paced GET clients; PDF/CSV each 10s; 250 direct DB events each 5s; 5 queue tasks each 10s",
                limits="Synthetic empty fleet; direct DB event insertion is not collector throughput; load driver shares API cgroup; not a multi-day soak or fleet guarantee",
            )
    print("CAPACITY_RESULT=" + json.dumps(report))


if __name__ == "__main__":
    main()
