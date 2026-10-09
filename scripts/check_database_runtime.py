#!/usr/bin/env python3
"""Real-container qualification for the database runtime migration.

Creates only labelled disposable containers/volumes. No existing resources are
modified. Requires the old Debian images and newly built candidate images.
Runs PostgreSQL and Timescale logical restore, refusal, restart and rollback
checks. Customer data, credentials, live hardware and production are not used.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import re
import secrets
import signal
import subprocess
import time
from functools import partial
from pathlib import Path

from migrate_database_runtime import (
    Database,
    MigrationError,
    database_metadata,
    fingerprint,
    migrate,
    preflight,
)
from qualification.bounded_command import (
    CommandBoundaryError,
    capture_command,
    command_cancellation,
)
from qualification.fixture_evidence import FixtureAttempt
from qualification.owned_resources import (
    cleanup_resources,
    inspect_owned,
    plan_resource,
    remember_identity,
)


def _main(interruption):
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--source-postgres", required=True)
    parser.add_argument("--source-logdb", required=True)
    parser.add_argument("--target-postgres", required=True)
    parser.add_argument("--target-logdb", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=900,
                        help="Work budget, at most 900 seconds; separate evidence/cleanup budgets are 60/120 seconds")
    args = parser.parse_args()
    # Admission is exclusive and precedes even read-only engine contact.
    attempt = FixtureAttempt(args.report, work_seconds=args.timeout_seconds)
    prefix = attempt.owner
    resources, failures = [], []
    report = {"cases": [], "production_access": False}
    password = secrets.token_hex(24)
    comment_contexts = {}
    report["database_comment_observations"] = {}

    def docker(*command, check=True, timeout=120, deadline=None):
        # This wrapper captures small engine metadata/probe responses. Database
        # SQL/dump/restore streaming uses a separate path and needs its own bounds.
        if not command:
            raise ValueError("A metadata command is required")
        for value in (timeout,) if deadline is None else (timeout, deadline):
            if type(value) not in (int, float):
                raise ValueError("Finite command timeout and deadline required")
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError("Finite command timeout and deadline required")
        if timeout <= 0 or timeout > 120:
            raise ValueError("Finite positive command timeout within 120 seconds required")
        command_deadline = attempt.deadline(timeout)
        if deadline is not None:
            command_deadline = min(command_deadline, deadline)
        argv = [args.docker, *command]
        captured = capture_command(
            argv, deadline=command_deadline,
            max_output_bytes=4 * 1024 * 1024, max_input_bytes=1,
        )
        result = subprocess.CompletedProcess(
            argv, captured.returncode, captured.stdout, captured.stderr
        )
        if check and result.returncode:
            raise AssertionError(
                result.stderr.decode(errors="replace").replace(password, "[REDACTED]")[-3000:]
            )
        return result

    def case(name):
        report["cases"].append(name)
        attempt.record("case", name=name)
        print("PASS", name, flush=True)

    def planned(kind, name):
        limit = 7 if kind == "container" else 5
        if sum(row["kind"] == kind for row in resources) >= limit:
            raise RuntimeError("Disposable fixture resource limit exceeded")
        resource = plan_resource(resources, kind, name, prefix)
        # A lost acknowledgement must leave enough durable intent to inspect.
        attempt.record("plan", resource=resource)
        return resource

    def container_limits():
        return ["--pull", "never", "--restart", "no", "--memory", "768m",
                "--memory-swap", "768m", "--cpus", "2", "--pids-limit", "128",
                "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2"]

    def bind(db):
        stack.enter_context(db.operation(deadline=attempt.work_deadline))
        return db

    def resolve_images():
        rows = {}
        for role in ("source_postgres", "source_logdb", "target_postgres", "target_logdb"):
            reference = getattr(args, role)
            if not reference or len(reference) > 512 or reference.startswith("-"):
                raise ValueError("Invalid local image reference")
            raw = docker("image", "inspect", reference).stdout
            if len(raw) > 65536:
                raise ValueError("Image inspection exceeds its parse budget")
            inspected = json.loads(raw)
            if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
                raise ValueError("Ambiguous local image inspection")
            image = inspected[0]
            identity = image.get("Id")
            if (not isinstance(identity, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is None
                    or image.get("Os") != "linux" or image.get("Architecture") not in {"amd64", "arm64"}):
                raise ValueError("Unsupported local image identity or platform")
            rows[role] = {"reference": reference, "id": identity, "os": image["Os"], "architecture": image["Architecture"]}
            setattr(args, role, identity)
        if len({row["architecture"] for row in rows.values()}) != 1:
            raise ValueError("Fixture images must use one platform")
        if any(rows["source_"+kind]["id"] == rows["target_"+kind]["id"] for kind in ("postgres", "logdb")):
            raise ValueError("Source and target images must be distinct")
        attempt.record("images", images=rows)
        report["images"] = rows

    def start(
        label, image, user="freesdn", database="postgres", volume=None, command=None
    ):
        name = prefix + "-" + label
        if volume is None:
            volume = name
            volume_resource = planned("volume", volume)
            docker(
                "volume", "create", "--label", "freesdn.qualification=" + prefix, volume
            )
            inspect_owned(volume_resource, docker)
            attempt.record("observed", resource=volume_resource)
        resource = planned("container", name)
        created = docker(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "freesdn.qualification=" + prefix,
            "--network",
            "none",
            *container_limits(),
            "--mount",
            "type=volume,src=" + volume + ",dst=/var/lib/postgresql",
            "-e",
            "POSTGRES_USER=" + user,
            "-e",
            "POSTGRES_DB=" + database,
            "-e",
            "POSTGRES_PASSWORD=" + password,
            image,
            *(command or []),
        )
        remember_identity(resource, created.stdout)
        attempt.record("observed", resource=resource)
        db = bind(Database(args.docker, name, user, 600, io_policy=attempt.io_policy))
        for _ in range(100):
            try:
                if (
                    docker(
                        "exec", name, "cat", "/proc/1/comm", check=False
                    ).stdout.strip()
                    != b"postgres"
                ):
                    time.sleep(0.2)
                    continue
                db.sql("SELECT 1")
                return db
            except MigrationError:
                time.sleep(0.2)
        logs = docker("logs", name, check=False)
        raise AssertionError(
            (logs.stdout + logs.stderr).decode(errors="replace").replace(password, "[REDACTED]")[-3000:]
        )

    def refused(call, fragment):
        try:
            call()
        except MigrationError as exc:
            assert fragment in str(exc), str(exc)
        else:
            raise AssertionError("Unsafe operation was accepted: " + fragment)

    try:
        with contextlib.ExitStack() as stack:
            work = attempt.work
            resolve_images()
            for kind in ("postgres", "logdb"):
                source_image = getattr(args, "source_" + kind)
                target_image = getattr(args, "target_" + kind)
                name = "freesdn_test"
                command = ["postgres"]
                if kind == "logdb":
                    command += [
                        "-c",
                        "shared_preload_libraries=timescaledb",
                        "-c",
                        "timescaledb.max_background_workers=0",
                    ]
                source = start(
                    kind + "-source", source_image, database=name, command=command
                )
                target = start(
                    kind + "-target", target_image, user="freesdn", command=command
                )
                source.sql(
                    """
CREATE ROLE read_only NOLOGIN;
CREATE ROLE "odd\"role" NOLOGIN;
GRANT read_only TO freesdn WITH ADMIN OPTION;
CREATE EXTENSION "uuid-ossp";
CREATE EXTENSION pg_trgm;
CREATE SCHEMA "odd schema";
CREATE TABLE public.accounts(id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  label text UNIQUE, amount numeric(18,4), payload jsonb, bytes bytea);
INSERT INTO public.accounts(label,amount,payload,bytes)
SELECT 'record-'||i||'-é-אבג', i/13.0, jsonb_build_object('n',i,'enabled',i%2=0), decode(md5(i::text),'hex')
FROM generate_series(1,500) i;
CREATE TABLE "odd schema"."quoted table"(id integer PRIMARY KEY, parent bigint REFERENCES public.accounts(id));
INSERT INTO "odd schema"."quoted table" VALUES (7,123);
CREATE VIEW public.account_labels AS SELECT id,label FROM public.accounts;
GRANT USAGE ON SCHEMA public TO read_only;
GRANT SELECT ON public.accounts TO read_only;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO read_only;
SELECT lo_from_bytea(17001,decode(repeat('deadbeef',4000),'hex'));
COMMENT ON DATABASE freesdn_test IS 'Runtime migration qualification';
REVOKE TEMPORARY ON DATABASE freesdn_test FROM PUBLIC;
GRANT CONNECT ON DATABASE freesdn_test TO read_only WITH GRANT OPTION;
ALTER DATABASE freesdn_test SET search_path TO "odd schema",public;
ALTER ROLE read_only IN DATABASE freesdn_test SET statement_timeout TO '30s';
""".replace('"odd"role"', '"odd""role"'),
                    name,
                )
                if kind == "logdb":
                    source.sql(
                        """
CREATE EXTENSION timescaledb WITH SCHEMA public;
CREATE TABLE public.measurements(ts timestamptz NOT NULL, device text NOT NULL, value float8);
SELECT create_hypertable('public.measurements',by_range('ts',INTERVAL '1 day'));
INSERT INTO public.measurements SELECT '2026-01-01'::timestamptz + i*INTERVAL '1 minute', 'device-'||(i%4), i/7.0 FROM generate_series(1,6000) i;
CREATE MATERIALIZED VIEW public.hourly WITH (timescaledb.continuous) AS
 SELECT time_bucket('1 hour',ts) AS bucket,device,avg(value) AS value FROM public.measurements GROUP BY 1,2 WITH NO DATA;
CALL refresh_continuous_aggregate('public.hourly',NULL,NULL);
ALTER TABLE public.measurements SET (timescaledb.compress,timescaledb.compress_segmentby='device');
SELECT compress_chunk(i) FROM show_chunks('public.measurements') i;
SELECT add_retention_policy('public.measurements',INTERVAL '365 days');
""",
                        name,
                    )
                refused(partial(preflight, source, target, name), "read_only=on")
                case(kind + ": refuses writable source")
                source.sql("ALTER SYSTEM SET default_transaction_read_only=on")
                docker("restart", source.container)
                for _ in range(100):
                    try:
                        if source.sql("SHOW default_transaction_read_only") == "on":
                            break
                    except MigrationError:
                        pass
                    time.sleep(0.2)
                else:
                    raise AssertionError("Source did not restart read-only")
                preflight(source, target, name)
                case(kind + ": read-only preflight")
                refused(
                    partial(preflight, source, source, name), "different containers"
                )
                case(kind + ": refuses source/target aliasing")
                refused(
                    partial(
                        migrate, source, target, name, work / (kind + "-refused"), False
                    ),
                    "--accept-locale-change",
                )
                assert not (work / (kind + "-refused")).exists()
                case(kind + ": locale change needs explicit acknowledgement")
                receipt = migrate(source, target, name, work / kind, True)
                assert receipt["verified"] and not receipt["cutover_performed"]
                # Independent shared-catalog oracle; never use the migration's
                # own metadata collector or fingerprint as the baseline.
                comment_sql = (
                    "SELECT s.description AS comment FROM pg_catalog.pg_database d "
                    "LEFT JOIN pg_catalog.pg_shdescription s ON s.objoid=d.oid "
                    "AND s.classoid='pg_catalog.pg_database'::regclass "
                    "WHERE d.datname='freesdn_test'"
                )
                report["database_comment_observations"][kind] = {
                    "source": source.rows(comment_sql)[0]["comment"],
                    "target": target.rows(comment_sql)[0]["comment"],
                    "receipt": receipt["metadata"]["comment"],
                }
                comment_contexts[kind] = (target, receipt["roles"])
                assert os.stat(work / kind).st_mode & 0o777 == 0o700
                assert all(
                    os.stat(p).st_mode & 0o077 == 0 for p in (work / kind).iterdir()
                )
                case(
                    kind
                    + ": logical migration, roles, permissions, sequences, content, checksums and indexes"
                )
                if kind == "logdb":
                    assert (
                        int(
                            target.sql("SELECT count(*) FROM public.measurements", name)
                        )
                        == 6000
                    )
                    assert (
                        target.sql(
                            "SELECT count(*) FROM timescaledb_information.continuous_aggregates",
                            name,
                        )
                        == "1"
                    )
                    assert (
                        int(
                            target.sql(
                                "SELECT count(*) FROM timescaledb_information.chunks WHERE is_compressed",
                                name,
                            )
                        )
                        > 0
                    )
                    case(
                        kind
                        + ": compressed hypertables, continuous aggregates and jobs preserved"
                    )
                refused(
                    partial(preflight, source, target, name), "Target must be fresh"
                )
                case(kind + ": refuses overwriting a migrated target")
                before = receipt["content_digests"]
                docker("restart", target.container)
                for _ in range(100):
                    try:
                        target.sql("SELECT 1", name)
                        break
                    except MigrationError:
                        time.sleep(0.2)
                assert (
                    fingerprint(target, name, receipt["roles"], work / kind) == before
                )
                case(kind + ": restart preserves restored state")
                if kind == "postgres":
                    fault_target = start(kind + "-corrupt-target", target_image)

                    class CorruptingTarget(Database):
                        def run(self, *arguments, **kwargs):
                            result = super().run(*arguments, **kwargs)
                            if arguments[0] == "pg_restore":
                                self.sql(
                                    "UPDATE public.accounts SET amount=999 WHERE id=1",
                                    "freesdn_test",
                                )
                            return result

                    corrupt = bind(CorruptingTarget(
                        args.docker, fault_target.container, "freesdn", 600,
                        io_policy=attempt.io_policy,
                    ))
                    refused(
                        partial(migrate, source, corrupt, name, work / "corrupt", True),
                        "digest differs",
                    )
                    assert not (work / "corrupt" / "receipt.json").exists()
                    case(
                        "postgres: injected restored-row corruption prevents a verified receipt"
                    )
                # Prove the image will not physically reuse a REAL old data
                # directory when the operator forbids it, before any chown.
                # Source is stopped first; never run two servers on the same
                # volume.
                #
                # This asserted a plain refusal until 2026-10-09, which was
                # correct only while the target was Alpine: a musl image must
                # never reuse a glibc cluster. The shipped runtime is Debian, so
                # an unmarked same-major cluster is ADOPTED -- that IS the
                # 26.09.0 upgrade path. The old assertion therefore contradicted
                # shipped behaviour, and because the guard runs in the
                # foreground, an image that correctly started and served never
                # returned: the step consumed its whole deadline and failed with
                # "Command deadline exceeded" rather than naming the problem.
                #
                # FREESDN_REFUSE_UNMARKED=1 is the documented escape hatch for
                # an operator who knows the volume must not be reused. It keeps
                # this step's intent, matches the shipped entrypoint, and exits
                # 78 at once.
                #
                # Adoption is deliberately NOT asserted here: it lets a server
                # fully start on the SOURCE volume and mutate it, and the next
                # case requires that the old image restart unchanged for
                # pre-cutover rollback. Adoption and every refusal are covered
                # on disposable volumes by
                # scripts/tests/test_database_runtime_upgrade.sh.
                docker("stop", source.container)
                guard_name = prefix + "-" + kind + "-guard"
                guard_resource = planned("container", guard_name)
                docker(
                    "run",
                    "--name",
                    guard_name,
                    "--label",
                    "freesdn.qualification=" + prefix,
                    "--network",
                    "none",
                    *container_limits(),
                    "--user",
                    "0",
                    "--env",
                    "FREESDN_REFUSE_UNMARKED=1",
                    "--mount",
                    "type=volume,src="
                    + receipt["source"]["volume"]
                    + ",dst=/var/lib/postgresql",
                    target_image,
                    check=False,
                )
                guard = inspect_owned(guard_resource, docker)
                attempt.record("observed", resource=guard_resource)
                assert guard["State"]["ExitCode"] == 78
                case(
                    kind
                    + ": refuses physical reuse of the old volume when forbidden"
                )
                docker("start", source.container)
                for _ in range(100):
                    try:
                        source.sql("SELECT 1", name)
                        break
                    except MigrationError:
                        time.sleep(0.2)
                assert (
                    fingerprint(source, name, receipt["roles"], work / kind) == before
                )
                case(kind + ": old image restarts unchanged for pre-cutover rollback")
                report[kind] = {
                    "source_image": receipt["source"]["image"],
                    "target_image": receipt["target"]["image"],
                    "extensions": receipt["extensions"],
                    "digest_groups": len(before),
                }
            # Run every original case before the new acceptance checks so
            # both actual source/target observations survive a baseline failure.
            for comment_kind in ("postgres", "logdb"):
                observed = report["database_comment_observations"][comment_kind]
                expected_comment = "Runtime migration qualification"
                assert observed["source"] == expected_comment
                assert observed["target"] == expected_comment, "Shared database comment was not preserved"
                assert observed["receipt"] == expected_comment
                comment_target, comment_roles = comment_contexts[comment_kind]
                comment_before = fingerprint(comment_target, name, comment_roles, work / comment_kind)
                previous_comment_fingerprint = comment_before
                variants = []
                report.setdefault("database_comment_variant_observations", {})[comment_kind] = variants
                for label, sql_comment, expected_value, same_as_previous in (
                    ("NULL", "NULL", None, False),
                    ("empty", "''", None, True),
                    ("quotedUnicode", "'Operator''s β comment'", "Operator's β comment", False),
                ):
                    comment_target.sql("COMMENT ON DATABASE freesdn_test IS " + sql_comment)
                    actual_metadata = database_metadata(comment_target, name)["comment"]
                    actual_catalog = comment_target.rows(comment_sql)[0]["comment"]
                    altered = fingerprint(comment_target, name, comment_roles, work / comment_kind)
                    variants.append({
                        "variant": label, "metadata": actual_metadata, "catalog": actual_catalog,
                        "same_as_original": altered == comment_before,
                        "same_as_previous": altered == previous_comment_fingerprint,
                    })
                    assert actual_metadata == actual_catalog == expected_value
                    assert altered != comment_before
                    assert (altered == previous_comment_fingerprint) == same_as_previous
                    previous_comment_fingerprint = altered
                comment_target.sql("COMMENT ON DATABASE freesdn_test IS 'Runtime migration qualification'")
                restored_fingerprint = fingerprint(comment_target, name, comment_roles, work / comment_kind)
                restored_metadata = database_metadata(comment_target, name)["comment"]
                restored_catalog = comment_target.rows(comment_sql)[0]["comment"]
                variants.append({
                    "variant": "restored", "metadata": restored_metadata, "catalog": restored_catalog,
                    "same_as_original": restored_fingerprint == comment_before,
                    "same_as_previous": restored_fingerprint == previous_comment_fingerprint,
                })
                assert restored_metadata == restored_catalog == expected_comment
                assert restored_fingerprint == comment_before
                case(comment_kind + ": shared database comments preserved and drift detected")
    except BaseException as error:
        report["error_type"] = type(error).__name__
        failures.append(error)
    finally:
        # Signals only record intent. Stop accepting work, then allow bounded
        # evidence/cleanup commands even when another signal arrives there.
        interruption["cleanup"] = True
        report["checks_completed"] = not failures and not interruption["signals"]
        attempt.begin_evidence()
        logs = []
        for resource in resources:
            if resource["kind"] != "container":
                continue
            try:
                state = inspect_owned(resource, docker)
                attempt.record("container-state", identity=resource["identity"],
                               state={k: state.get("State", {}).get(k) for k in ("Status", "Running", "OOMKilled", "ExitCode")},
                               restart_count=state.get("RestartCount"))
                captured = docker("logs", "--tail", "1000", resource["identity"])
                logs.append(attempt.save_log(resource["planned_name"]+".log", captured.stdout+captured.stderr, password))
            except BaseException as evidence_error:
                failures.append(evidence_error)
        report["private_logs"] = logs
        try:
            report["retained_work"] = attempt.work_manifest()
            attempt.record("evidence", private_logs=logs, retained_work=report["retained_work"])
        except BaseException as evidence_error:
            failures.append(evidence_error)
        attempt.begin_cleanup()
        cleanup = cleanup_resources(resources, docker, failures)
        report["cleanup"] = cleanup
        report["owned_resources_removed"] = all(row["removed"] for row in cleanup)
        try:
            attempt.record("cleanup", outcomes=cleanup)
        except BaseException as evidence_error:
            failures.append(evidence_error)
        if time.monotonic() >= attempt.total_deadline:
            failures.append(TimeoutError("Complete fixture budget exceeded"))
        report["interrupted_signals"] = [signal.Signals(value).name for value in interruption["signals"]]
        if interruption["signals"]:
            failures.append(CommandBoundaryError("Qualification interrupted; original evidence retained"))
        report["passed"] = not failures
        report["qualification_complete"] = not failures
        try:
            attempt.finish(report)
        except BaseException as report_error:
            failures.append(report_error)
        finally:
            attempt.close()
    if failures:
        raise BaseExceptionGroup(
            "Database qualification, cleanup or reporting failed; original errors retained",
            failures,
        )
    return {"passed": len(report["cases"]), "report": str(args.report)}


def main() -> None:
    interruption = {"signals": [], "cleanup": False}
    previous = {}

    def remember(signum, _frame):
        # At most the two supported signal numbers; no I/O or asynchronous
        # exception can interrupt descriptor ownership or first-result writes.
        if signum not in interruption["signals"]:
            interruption["signals"].append(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, remember)
        with command_cancellation(lambda: bool(interruption["signals"]) and not interruption["cleanup"]):
            result = _main(interruption)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    # Publication is not proof of process success. A late interruption must
    # still produce a nonzero exit, even if the first report was already saved.
    if interruption["signals"]:
        raise CommandBoundaryError("Qualification interrupted during final publication")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
