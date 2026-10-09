#!/usr/bin/env python3
"""Offline PostgreSQL 18 logical runtime migration; never switches a deployment.

Both containers must use --network none, separate named volumes, and local
socket authentication. Start the old source with default_transaction_read_only
=on. For Timescale, start BOTH with timescaledb.max_background_workers=0.
The target must be a fresh qualified FreeSDN image with POSTGRES_DB=postgres
and the SAME initdb bootstrap superuser name as the source.

Default: read-only preflight. --execute --accept-locale-change writes ONLY to
the fresh target and a new private work directory. Restore is single-threaded
for Timescale. No --clean, DROP DATABASE, volume removal or automatic cutover.
Do not reconnect either container until both databases and the application have
been qualified. Original volumes and images are the pre-cutover rollback path.
See the database runtime upgrade guide before using this on customer data.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import math
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath

from qualification.bounded_command import CommandBoundaryError, capture_command
from qualification.migration_io import IOPolicy, operate, seconds

# The runtime marker the shipped database images write. MUST match the literal
# in docker/Dockerfile.postgres and docker/Dockerfile.logdb;
# scripts/tests/test_runtime_marker_parity.py gates that. It was hardcoded as
# the Alpine value in two scripts, and the Debian revert left them demanding a
# marker no shipped image writes -- which failed this script outright.
EXPECTED_DATABASE_RUNTIME = "postgresql-18-debian-trixie-v1"


class MigrationError(Exception):
    """An actionable, credential-free refusal."""


def ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MigrationError(message)


class Database:
    def __init__(self, docker: str, container: str, user: str, timeout: int, *, io_policy: IOPolicy | None = None):
        self.docker, self.container, self.user, self.timeout = (
            docker,
            container,
            user,
            timeout,
        )
        try:
            seconds(timeout)
            self.io_policy = io_policy if io_policy is not None else IOPolicy()
            require(isinstance(self.io_policy, IOPolicy), "Invalid migration I/O policy.")
        except ValueError:
            raise MigrationError("Invalid migration timeout or I/O policy.") from None
        self._operation_deadline = None
        self._workspace = None

    def deadline(self):
        end = time.monotonic() + self.timeout
        return min(end, self._operation_deadline) if self._operation_deadline is not None else end

    @contextlib.contextmanager
    def operation(self, *, deadline=None, workspace=None):
        previous = self._operation_deadline, self._workspace
        end = time.monotonic() + self.io_policy.operation_seconds if deadline is None else deadline
        self._operation_deadline = min(end, previous[0]) if previous[0] is not None else end
        if workspace is not None:
            self._workspace = workspace
        try:
            require(time.monotonic() < self._operation_deadline, "Migration operation deadline exceeded.")
            yield
            require(time.monotonic() < self._operation_deadline, "Migration operation deadline exceeded.")
        finally:
            self._operation_deadline, self._workspace = previous

    def file_operation(self, kind, *, data=None, stdin=None):
        try:
            return operate(kind, deadline=self.deadline(), policy=self.io_policy,
                           data=data, stdin=stdin, workspace=self._workspace)
        except (OSError, ValueError, TypeError, CommandBoundaryError):
            raise MigrationError("Migration file I/O failed; target is NOT qualified.") from None

    def command(self, *args: str) -> list[str]:
        # Override inherited libpq destinations/options. Always use this
        # container's local socket; never an inherited PGHOST/PGSERVICE.
        return [
            self.docker,
            "exec",
            "-i",
            self.container,
            "env",
            "-u",
            "PGSERVICE",
            "-u",
            "PGSERVICEFILE",
            "-u",
            "PGHOSTADDR",
            "PGOPTIONS=-c timezone=UTC -c extra_float_digits=3 -c standard_conforming_strings=on",
            *args,
        ]

    def run(
        self, *args: str, data: bytes | None = None, stdin=None, stdout=None,
        file_limit: int | None = None,
    ) -> bytes:
        try:
            if not args or any(type(arg) is not str or not arg or "\x00" in arg for arg in args):
                raise ValueError("A database command is required")
            policy = self.io_policy if file_limit is None else dataclasses.replace(self.io_policy, file_bytes=file_limit)
            return operate("command", deadline=self.deadline(), policy=policy,
                           argv=self.command(*args), data=data, stdin=stdin,
                           stdout=stdout, workspace=self._workspace)
        except (OSError, ValueError, TypeError, CommandBoundaryError):
            # No captured diagnostics, SQL, argument values or exception repr.
            # A daemon may already have committed: failure never qualifies it.
            raise MigrationError("Database command failed or exceeded its I/O budget; target is NOT qualified.") from None

    def client(self, binary: str, database: str = "postgres") -> list[str]:
        return [
            binary,
            "--no-password",
            "--host=/var/run/postgresql",
            "--port=5432",
            f"--username={self.user}",
            f"--dbname={database}",
        ]

    def sql(self, sql: str, database: str = "postgres") -> str:
        try:
            return self.run(
                *self.client("psql", database), "-X", "-qAt", "-v",
                "ON_ERROR_STOP=1", data=sql.encode("utf-8"),
            ).decode("utf-8").strip()
        except UnicodeError:
            raise MigrationError("Invalid database response encoding.") from None

    def rows(self, query: str, database: str = "postgres") -> list:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def reject(_value):
            raise ValueError

        def finite(value):
            number = float(value)
            if not math.isfinite(number):
                raise ValueError
            return number

        raw = self.sql(f"SELECT coalesce(json_agg(q),'[]'::json) FROM ({query}) q", database)
        # Bound nesting BEFORE allocating a recursive JSON object graph. Braces
        # inside quoted/escaped strings do not contribute to structure depth.
        depth = 0
        quoted = escaped = False
        for char in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                require(depth <= 64, "Database metadata nesting exceeds its bound.")
            elif char in "]}":
                depth -= 1
                require(depth >= 0, "Invalid database metadata structure.")
        require(not quoted and depth == 0, "Invalid database metadata structure.")
        try:
            result = json.loads(raw, object_pairs_hook=unique, parse_constant=reject, parse_float=finite)
        except (ValueError, RecursionError):
            raise MigrationError("Invalid or ambiguous database metadata.") from None
        require(type(result) is list and all(type(row) is dict for row in result),
                "Expected database metadata rows.")
        return result

    def inspect(self) -> dict:
        # Engine metadata has a small capture budget. SQL and dump/restore
        # streams use run(), and must not inherit this metadata output limit.
        deadline = time.monotonic() + 30
        if self._operation_deadline is not None:
            deadline = min(deadline, self._operation_deadline)

        def capture(*arguments: str) -> bytes:
            try:
                result = capture_command(
                    [self.docker, *arguments],
                    deadline=deadline,
                    max_output_bytes=4 * 1024 * 1024,
                    max_input_bytes=1,
                )
            except (OSError, ValueError, CommandBoundaryError) as exc:
                raise MigrationError("Cannot inspect migration container.") from exc
            require(result.returncode == 0, "Cannot inspect migration container.")
            return result.stdout

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Ambiguous inspection metadata")
                result[key] = value
            return result

        def reject_constant(_value):
            raise ValueError("Non-finite inspection metadata")

        def path(value) -> PurePosixPath:
            require(
                isinstance(value, str)
                and 0 < len(value) <= 4096
                and value.startswith("/")
                and "\x00" not in value
                and ".." not in value.split("/"),
                "Invalid migration data or mount path.",
            )
            return PurePosixPath(value)

        try:
            inspected = json.loads(
                capture("inspect", self.container),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (ValueError, RecursionError) as exc:
            raise MigrationError("Cannot inspect migration container.") from exc
        require(
            isinstance(inspected, list)
            and len(inspected) == 1
            and isinstance(inspected[0], dict),
            "Expected one migration container inspection.",
        )
        info = inspected[0]
        state, host, config = (info.get(key) for key in ("State", "HostConfig", "Config"))
        require(
            isinstance(state, dict) and isinstance(host, dict) and isinstance(config, dict),
            "Incomplete migration container inspection.",
        )
        require(state.get("Running") is True, "Both migration containers must be running.")
        require(
            host.get("NetworkMode") == "none"
            and "PortBindings" in host
            and (host["PortBindings"] is None or type(host["PortBindings"]) is dict and not host["PortBindings"]),
            "Both migration containers must use --network none with no published ports.",
        )
        require(
            host.get("Privileged") is False,
            "Privileged migration containers are not supported.",
        )
        identifier, image, started = info.get("Id"), info.get("Image"), state.get("StartedAt")
        require(
            isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{64}", identifier) is not None
            and isinstance(image, str) and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image) is not None
            and isinstance(started, str) and 0 < len(started) <= 128 and started.isascii()
            and all(32 < ord(char) < 127 for char in started),
            "Invalid migration container identity.",
        )
        env, mounts = config.get("Env"), info.get("Mounts")
        require(
            isinstance(env, list) and all(isinstance(entry, str) for entry in env)
            and isinstance(mounts, list) and all(isinstance(mount, dict) for mount in mounts),
            "Invalid migration environment or mounts.",
        )
        data_values = [entry.split("=", 1)[1] for entry in env if entry.startswith("PGDATA=")]
        require(len(data_values) == 1, "Expected one explicit PGDATA value.")
        data = path(data_values[0])
        matching = [mount for mount in mounts if data.is_relative_to(path(mount.get("Destination")))]
        require(
            len(matching) == 1 and matching[0].get("Type") == "volume",
            "PGDATA must be on one named volume.",
        )
        volume = matching[0].get("Name")
        require(
            isinstance(volume, str) and 0 < len(volume) <= 255
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", volume) is not None,
            "Invalid named migration volume.",
        )
        try:
            users = capture("ps", "--filter", "volume=" + volume, "--format", "{{.ID}}").decode("ascii").splitlines()
        except UnicodeError as exc:
            raise MigrationError("Cannot inspect migration volume users.") from exc
        require(
            len(users) == 1 and re.fullmatch(r"[0-9a-f]{12,64}", users[0]) is not None
            and identifier.startswith(users[0]),
            "Another running container mounts this database volume.",
        )
        require(time.monotonic() < deadline, "Migration inspection deadline exceeded.")
        # Return only nonsecret identity fields, never the inspected environment.
        return {"id": identifier, "image": image, "started": started, "volume": volume}


def roles(db: Database) -> list[str]:
    return [
        r["rolname"]
        for r in db.rows(
            "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolname COLLATE \"C\""
        )
    ]


def database_metadata(db: Database, name: str) -> dict:
    rows = db.rows(
        "SELECT d.datname, pg_get_userbyid(d.datdba) AS owner, "
        "pg_encoding_to_char(d.encoding) AS encoding, d.datlocprovider, d.datlocale, "
        "d.datcollate, d.datctype, d.datconnlimit, d.datistemplate, "
        "shobj_description(d.oid,'pg_database') AS comment "
        f"FROM pg_database d WHERE d.datname={literal(name)}"
    )
    require(len(rows) == 1, "Source database does not exist.")
    return rows[0]


def extensions(db: Database, name: str) -> dict[str, str]:
    return {
        r["extname"]: r["extversion"]
        for r in db.rows(
            "SELECT extname,extversion FROM pg_extension ORDER BY extname", name
        )
    }


def preflight(source: Database, target: Database, name: str) -> dict:
    deadline = time.monotonic() + min(source.io_policy.operation_seconds, target.io_policy.operation_seconds)
    with source.operation(deadline=deadline), target.operation(deadline=deadline):
        return _preflight(source, target, name)


def _preflight(source: Database, target: Database, name: str) -> dict:
    require(
        name not in {"postgres", "template0", "template1"},
        "Migrate the named FreeSDN database, not a template/maintenance database.",
    )
    si, ti = source.inspect(), target.inspect()
    require(
        si["id"] != ti["id"] and si["volume"] != ti["volume"],
        "Source and target must have different containers and named volumes.",
    )
    sv = int(source.sql("SHOW server_version_num"))
    tv = int(target.sql("SHOW server_version_num"))
    require(
        sv // 10000 == tv // 10000 == 18 and tv >= sv,
        "Only PostgreSQL 18 to an equal/newer PostgreSQL 18 is qualified.",
    )
    require(
        source.sql("SHOW default_transaction_read_only") == "on",
        "Source must start with default_transaction_read_only=on.",
    )
    require(
        target.sql("SHOW default_transaction_read_only") == "off",
        "Target must allow the offline restore.",
    )
    require(
        target.sql("SHOW data_checksums") == "on",
        "Target must have data checksums enabled.",
    )
    for db in (source, target):
        require(
            db.sql("SELECT rolsuper FROM pg_roles WHERE rolname=current_user") == "t",
            "Migration requires local database superusers.",
        )
        require(
            db.sql(
                "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()"
            )
            == "0",
            "Another client is connected; stop all writers and administrative sessions.",
        )
        require(
            db.sql(
                "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')"
            )
            == "0",
            "Custom tablespaces require a separately reviewed migration.",
        )
        require(
            db.sql("SELECT count(*) FROM pg_prepared_xacts") == "0",
            "Resolve prepared transactions before migration.",
        )
        require(
            db.sql("SELECT count(*) FROM pg_replication_slots") == "0",
            "Replication slots must be reviewed/recreated; never copy HA state implicitly.",
        )
        require(
            db.sql(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','m','S')"
            )
            == "0",
            "The maintenance database contains user objects; use a separately reviewed cluster migration.",
        )
    source_names = {
        x["datname"]
        for x in source.rows("SELECT datname FROM pg_database WHERE NOT datistemplate")
    }
    target_names = {
        x["datname"]
        for x in target.rows("SELECT datname FROM pg_database WHERE NOT datistemplate")
    }
    require(
        source_names == {"postgres", name},
        "Source must contain exactly one application database plus postgres.",
    )
    require(
        target_names == {"postgres"},
        "Target must be fresh and contain only postgres; never overwrite an existing database.",
    )
    sr, tr = roles(source), roles(target)
    require(
        tr == [source.user] and target.user == source.user,
        "Target must have only the same bootstrap role as source.",
    )
    for db in (source, target):
        require(
            db.sql("SELECT oid FROM pg_authid WHERE rolname=current_user") == "10",
            "Use the original initdb bootstrap identity on both clusters.",
        )
    marker = (
        target.run("cat", "/usr/local/share/freesdn-database-runtime").decode().strip()
    )
    require(
        marker == EXPECTED_DATABASE_RUNTIME,
        "Target is not the qualified FreeSDN database runtime.",
    )
    meta = database_metadata(source, name)
    require(
        meta["encoding"] == "UTF8" and not meta["datistemplate"],
        "Only non-template UTF8 application databases are qualified.",
    )
    require(
        source.sql("SELECT count(*) FROM pg_subscription", name) == "0",
        "Subscriptions require a separately reviewed migration.",
    )
    require(
        source.sql("SELECT count(*) FROM pg_class WHERE relkind='f'", name) == "0",
        "Foreign tables are not covered by a local data digest.",
    )
    require(
        source.sql(
            "SELECT count(*) FROM pg_collation c WHERE c.collprovider='c' AND c.collname NOT IN ('C','POSIX') "
            "AND (c.collnamespace NOT IN ('pg_catalog'::regnamespace,'information_schema'::regnamespace) OR EXISTS "
            "(SELECT FROM pg_depend d WHERE d.refclassid='pg_collation'::regclass AND d.refobjid=c.oid))",
            name,
        )
        == "0",
        "Explicit libc collations require manual review; only the database default can change automatically.",
    )
    ext = extensions(source, name)
    available = {
        (x["name"], x["version"])
        for x in target.rows("SELECT name,version FROM pg_available_extension_versions")
    }
    require(
        all(pair in available for pair in ext.items()),
        "Target lacks an exact source extension version; qualify extension upgrades separately.",
    )
    if "timescaledb" in ext:
        require(
            source.sql(
                "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='timescaledb'",
                name,
            )
            == "public",
            "Timescale installed outside public requires a separately reviewed schema restore.",
        )
        for db in (source, target):
            require(
                db.sql("SHOW timescaledb.max_background_workers") == "0",
                "Disable Timescale background workers on BOTH offline containers.",
            )
    return {
        "source": si,
        "target": ti,
        "database": name,
        "source_version": sv,
        "target_version": tv,
        "metadata": meta,
        "extensions": ext,
        "roles": sr,
        "target_locale": "builtin/C.UTF-8",
        "cutover_performed": False,
    }


def digest_query(db: Database, query: str, database: str, directory: Path) -> str:
    with db.operation(deadline=db.deadline(), workspace=directory):
        return _digest_query(db, query, database, directory)


def _digest_query(db: Database, query: str, database: str, directory: Path) -> str:
    # Stream to disk instead of holding customer tables or large objects in RAM.
    temporary = directory / "digest.tmp"
    try:
        with temporary.open("xb") as output:
            # fingerprint() is also used after migrate() restores the caller's
            # umask. Keep its transient file private in that supported path.
            os.fchmod(output.fileno(), 0o600)
            db.run(
                *db.client("psql", database),
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                data=f"COPY ({query}) TO STDOUT;".encode(),
                stdout=output,
            )
        with temporary.open("rb") as data:
            digest = db.file_operation("hash", stdin=data).decode("ascii")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "Invalid migration digest response.")
        return digest
    finally:
        temporary.unlink(missing_ok=True)


def fingerprint(
    db: Database, name: str, source_roles: list[str], directory: Path
) -> dict:
    with db.operation(workspace=directory):
        return _fingerprint(db, name, source_roles, directory)


def _fingerprint(
    db: Database, name: str, source_roles: list[str], directory: Path
) -> dict:
    tables = db.rows(
        "SELECT n.nspname,c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND n.nspname !~ '^_timescaledb_' "
        "AND c.relkind IN ('r','p','m','S') ORDER BY n.nspname COLLATE \"C\",c.relname COLLATE \"C\"",
        name,
    )
    hashes = {}
    for table in tables:
        qualified = ident(table["nspname"]) + "." + ident(table["relname"])
        query = (
            f"SELECT last_value,is_called FROM {qualified}"
            if table["relkind"] == "S"
            else f'SELECT row_to_json(t)::text FROM {qualified} t ORDER BY row_to_json(t)::text COLLATE "C"'
        )
        hashes[qualified] = digest_query(db, query, name, directory)
    role_list = ",".join(literal(x) for x in source_roles)
    hashes["roles"] = digest_query(
        db,
        f"SELECT (to_jsonb(r)-'oid')::text FROM pg_authid r WHERE rolname IN ({role_list}) ORDER BY rolname COLLATE \"C\"",
        name,
        directory,
    )
    hashes["memberships"] = digest_query(
        db,
        "SELECT pg_get_userbyid(roleid),pg_get_userbyid(member),pg_get_userbyid(grantor),admin_option,inherit_option,set_option "
        'FROM pg_auth_members ORDER BY pg_get_userbyid(roleid) COLLATE "C",pg_get_userbyid(member) COLLATE "C",pg_get_userbyid(grantor) COLLATE "C"',
        name,
        directory,
    )
    hashes["large_objects"] = digest_query(
        db,
        "SELECT loid,pageno,encode(data,'hex') FROM pg_largeobject ORDER BY loid,pageno",
        name,
        directory,
    )
    hashes["object_permissions"] = digest_query(
        db,
        "SELECT n.nspname,c.relname,pg_get_userbyid(c.relowner),"
        'ARRAY(SELECT x::text FROM unnest(c.relacl) x ORDER BY x::text COLLATE "C") '
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' "
        "AND n.nspname<>'information_schema' AND n.nspname !~ '^_timescaledb_' "
        'ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C"',
        name,
        directory,
    )
    hashes["database_permissions"] = digest_query(
        db,
        "SELECT pg_get_userbyid(d.datdba),d.datconnlimit,"
        "shobj_description(d.oid,'pg_database'),ARRAY(SELECT x::text FROM unnest(coalesce(d.datacl,acldefault('d',d.datdba))) x "
        'ORDER BY x::text COLLATE "C") FROM pg_database d WHERE d.datname=current_database()',
        name,
        directory,
    )
    hashes["database_settings"] = digest_query(
        db,
        "SELECT CASE WHEN s.setrole=0 THEN '' ELSE pg_get_userbyid(s.setrole) END AS role,"
        'ARRAY(SELECT x FROM unnest(s.setconfig) x ORDER BY x COLLATE "C") FROM pg_db_role_setting s '
        "WHERE s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) "
        "ORDER BY (CASE WHEN s.setrole=0 THEN '' ELSE pg_get_userbyid(s.setrole) END) COLLATE \"C\"",
        name,
        directory,
    )
    hashes["schema_permissions"] = digest_query(
        db,
        "SELECT nspname,pg_get_userbyid(nspowner),"
        'ARRAY(SELECT x::text FROM unnest(nspacl) x ORDER BY x::text COLLATE "C") FROM pg_namespace '
        "WHERE nspname !~ '^pg_' AND nspname<>'information_schema' AND nspname !~ '^_timescaledb_' "
        'ORDER BY nspname COLLATE "C"',
        name,
        directory,
    )
    hashes["default_permissions"] = digest_query(
        db,
        "SELECT pg_get_userbyid(d.defaclrole),coalesce(n.nspname,''),d.defaclobjtype,"
        'ARRAY(SELECT x::text FROM unnest(d.defaclacl) x ORDER BY x::text COLLATE "C") FROM pg_default_acl d '
        'LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace ORDER BY pg_get_userbyid(d.defaclrole) COLLATE "C",'
        "coalesce(n.nspname,'') COLLATE \"C\",d.defaclobjtype",
        name,
        directory,
    )
    hashes["large_object_permissions"] = digest_query(
        db,
        "SELECT oid,pg_get_userbyid(lomowner),"
        'ARRAY(SELECT x::text FROM unnest(lomacl) x ORDER BY x::text COLLATE "C") FROM pg_largeobject_metadata ORDER BY oid',
        name,
        directory,
    )
    if "timescaledb" in extensions(db, name):
        for view, fields in [
            (
                "hypertables",
                "hypertable_schema,hypertable_name,owner,num_dimensions,num_chunks,compression_enabled",
            ),
            (
                "continuous_aggregates",
                "hypertable_schema,hypertable_name,view_schema,view_name,view_owner,materialized_only,compression_enabled",
            ),
            (
                "jobs",
                "job_id,proc_schema,proc_name,owner,scheduled,config,schedule_interval,max_runtime,max_retries,retry_period",
            ),
        ]:
            hashes["timescale_" + view] = digest_query(
                db,
                f'SELECT row_to_json(t)::text AS row FROM (SELECT {fields} FROM timescaledb_information.{view}) t ORDER BY row_to_json(t)::text COLLATE "C"',
                name,
                directory,
            )
        for aggregate in db.rows(
            "SELECT view_schema,view_name,materialization_hypertable_schema,materialization_hypertable_name "
            "FROM timescaledb_information.continuous_aggregates ORDER BY view_schema,view_name",
            name,
        ):
            for prefix in ("view", "materialization_hypertable"):
                qualified = (
                    ident(aggregate[prefix + "_schema"])
                    + "."
                    + ident(aggregate[prefix + "_name"])
                )
                hashes["aggregate_" + qualified] = digest_query(
                    db,
                    f'SELECT row_to_json(t)::text FROM {qualified} t ORDER BY row_to_json(t)::text COLLATE "C"',
                    name,
                    directory,
                )
    return hashes


def restore_database_metadata(
    source: Database, target: Database, name: str, meta: dict
) -> None:
    qname = ident(name)
    target.sql(
        f"ALTER DATABASE {qname} CONNECTION LIMIT {int(meta['datconnlimit'])}; "
        f"COMMENT ON DATABASE {qname} IS "
        + (literal(meta["comment"]) if meta["comment"] is not None else "NULL")
    )
    acl = source.rows(
        "SELECT pg_get_userbyid(a.grantor) AS grantor, CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END AS grantee, "
        "a.privilege_type,a.is_grantable FROM pg_database d, LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a "
        f"WHERE d.datname={literal(name)}"
    )
    target.sql(
        f"REVOKE ALL ON DATABASE {qname} FROM PUBLIC; REVOKE ALL ON DATABASE {qname} FROM {ident(meta['owner'])}"
    )
    for grant in acl:
        require(
            grant["privilege_type"] in {"CREATE", "CONNECT", "TEMPORARY"},
            "Unexpected database privilege.",
        )
        target.sql(
            f"SET ROLE {ident(grant['grantor'])}; GRANT {grant['privilege_type']} ON DATABASE {qname} TO "
            + (ident(grant["grantee"]) if grant["grantee"] is not None else "PUBLIC")
            + (" WITH GRANT OPTION" if grant["is_grantable"] else "")
            + "; RESET ROLE"
        )
    settings = source.rows(
        "SELECT CASE WHEN s.setrole=0 THEN NULL ELSE pg_get_userbyid(s.setrole) END AS role, unnest(s.setconfig) AS setting "
        "FROM pg_db_role_setting s JOIN pg_database d ON d.oid=s.setdatabase "
        f"WHERE d.datname={literal(name)}"
    )
    for setting in settings:
        key, value = setting["setting"].split("=", 1)
        clause = (
            f"DATABASE {qname}"
            if setting["role"] is None
            else f"ROLE {ident(setting['role'])} IN DATABASE {qname}"
        )
        # FROM CURRENT preserves list-valued settings such as search_path; a
        # quoted comma-separated value in ALTER DATABASE is not equivalent.
        target.sql(
            f"SELECT set_config({literal(key)},{literal(value)},false); ALTER {clause} SET {ident(key)} FROM CURRENT; RESET {ident(key)}"
        )


def migrate(
    source: Database, target: Database, name: str, work: Path, accept_locale: bool
) -> dict:
    require(source.io_policy == target.io_policy, "Source and target must share one migration I/O policy.")
    deadline = time.monotonic() + min(source.io_policy.operation_seconds, target.io_policy.operation_seconds)
    try:
        with source.operation(deadline=deadline), target.operation(deadline=deadline):
            return _migrate(source, target, name, work, accept_locale)
    except (OSError, ValueError, UnicodeError, CommandBoundaryError):
        raise MigrationError("Migration I/O failed; preserve the source and incomplete target. NO cutover.") from None


def _migrate(
    source: Database, target: Database, name: str, work: Path, accept_locale: bool
) -> dict:
    plan = preflight(source, target, name)
    require(
        accept_locale,
        "Explicit --accept-locale-change is required: sorting/case behavior can change.",
    )
    require(
        os.name == "posix",
        "Use a POSIX host for private migration workspace permissions.",
    )
    require(
        work.is_absolute() and not work.exists(),
        "Work directory must be a NEW absolute path on trusted private storage.",
    )
    require(
        work.parent.is_dir()
        and work.parent.stat().st_uid == os.geteuid()
        and work.parent.stat().st_mode & 0o022 == 0,
        "Work directory parent must be owned by this user and not group/world writable.",
    )
    old_mask = os.umask(0o077)
    try:
        work.mkdir(mode=0o700)
        source._workspace = target._workspace = work
        before = fingerprint(source, name, plan["roles"], work)
        with (work / "roles.sql").open("xb") as out:
            source.run(
                "pg_dumpall",
                "--roles-only",
                "--no-password",
                "--host=/var/run/postgresql",
                "--port=5432",
                f"--username={source.user}",
                stdout=out, file_limit=source.io_policy.input_bytes,
            )
        with (work / "database.dump").open("xb") as out:
            source.run(*source.client("pg_dump", name), "--format=custom", stdout=out)
        # Recheck identities and all safety predicates immediately before the
        # first target mutation. A failed restore is never resumed in-place.
        require(
            preflight(source, target, name) == plan,
            "Migration state changed during export.",
        )
        # PG16+ validates GRANTED BY against the actual grantor. Restore roles
        # using the same initdb bootstrap identity on the target. Remove ONLY
        # its exact generated CREATE ROLE statement (initdb created it already).
        # Its original attributes/password are still restored by
        # pg_dumpall's ALTER ROLE. Any unexpected dump shape fails closed.
        create_role = source.sql("SELECT format('CREATE ROLE %I;',current_user)")
        with (work / "roles.sql").open("rb") as role_file:
            role_dump = source.file_operation("read", stdin=role_file).decode("utf-8")
        needle = "\n" + create_role + "\n"
        require(
            role_dump.count(needle) == 1,
            "Unexpected pg_dumpall role format; manual review required.",
        )
        role_dump = role_dump.replace(needle, "\n", 1)
        restorer = Database(
            target.docker, target.container, source.user, target.timeout,
            io_policy=target.io_policy,
        )
        restorer._operation_deadline = target._operation_deadline
        restorer._workspace = work
        restorer.run(
            *restorer.client("psql"),
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            data=role_dump.encode(),
        )
        target.sql(
            f"CREATE DATABASE {ident(name)} OWNER {ident(plan['metadata']['owner'])} TEMPLATE template0 "
            "ENCODING 'UTF8' LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'"
        )
        timescale = "timescaledb" in plan["extensions"]
        if timescale:
            target.sql(
                "CREATE EXTENSION timescaledb VERSION "
                + literal(plan["extensions"]["timescaledb"])
                + "; SELECT timescaledb_pre_restore()",
                name,
            )
        with (work / "database.dump").open("rb") as data:
            target.run(
                *target.client("pg_restore", name), "--exit-on-error", stdin=data
            )
        if timescale:
            target.sql("SELECT timescaledb_post_restore()", name)
        restore_database_metadata(source, target, name, plan["metadata"])
        require(
            extensions(target, name) == plan["extensions"],
            "Restored extensions differ from source.",
        )
        target.sql("ANALYZE", name)
        require(
            target.sql(
                "SELECT count(*) FROM pg_index WHERE NOT indisvalid OR NOT indisready",
                name,
            )
            == "0",
            "Restored indexes are invalid.",
        )
        had_amcheck = "amcheck" in plan["extensions"]
        if not had_amcheck:
            target.sql("CREATE EXTENSION amcheck", name)
        target.run(
            "pg_amcheck",
            "--no-password",
            "--host=/var/run/postgresql",
            "--port=5432",
            f"--username={target.user}",
            f"--database={name}",
            "--heapallindexed",
            "--parent-check",
            "--rootdescend",
        )
        if not had_amcheck:
            target.sql("DROP EXTENSION amcheck", name)
        after = fingerprint(target, name, plan["roles"], work)
        require(
            after == before,
            "Restored content, sequence, role or Timescale metadata digest differs; NO cutover.",
        )
        require(
            fingerprint(source, name, plan["roles"], work) == before,
            "Source changed during migration; NO cutover.",
        )
        require(
            source.inspect() == plan["source"] and target.inspect() == plan["target"],
            "Container identity changed during migration.",
        )
        receipt = {
            **plan,
            "verified": True,
            "cutover_performed": False,
            "content_digests": after,
            "data_checksums": target.sql("SHOW data_checksums"),
            "indexes_checked": True,
            "bootstrap_identity_preserved": True,
            "rollback": "Original source retained. Do not resume writes until application acceptance. After new writes, rollback needs data reconciliation.",
        }
        receipt["io_policy"] = dataclasses.asdict(source.io_policy)
        source.file_operation("receipt", data=(json.dumps(receipt, indent=2, allow_nan=False) + "\n").encode("utf-8"))
        return receipt
    finally:
        os.umask(old_mask)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--docker",
        default="docker",
        help="Docker executable (including an absolute path)",
    )
    parser.add_argument(
        "--source", required=True, help="Isolated read-only old-runtime container"
    )
    parser.add_argument(
        "--target", required=True, help="Fresh isolated new-runtime container"
    )
    parser.add_argument("--source-user", default="freesdn")
    parser.add_argument(
        "--target-user",
        help="Must match source initdb bootstrap user; defaults to --source-user",
    )
    parser.add_argument("--database", required=True)
    parser.add_argument(
        "--timeout", type=int, default=3600, help="Maximum seconds per database command"
    )
    parser.add_argument("--file-limit-bytes", type=int, default=64 * 1024**3,
                        help="Maximum bytes per dump, restore input or fingerprint file (default64GiB)")
    parser.add_argument("--workspace-limit-bytes", type=int, default=128 * 1024**3,
                        help="Maximum combined migration workspace file bytes (default128GiB)")
    parser.add_argument("--min-free-bytes", type=int,
                        help="Free-space reserve; default min(4GiB, one quarter of filesystem capacity)")
    parser.add_argument("--operation-timeout", type=int, default=6 * 3600,
                        help="Total migration/preflight seconds (default6hours, maximum7days)")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--accept-locale-change", action="store_true")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    try:
        policy = IOPolicy(file_bytes=args.file_limit_bytes, workspace_bytes=args.workspace_limit_bytes,
                          min_free_bytes=args.min_free_bytes, operation_seconds=args.operation_timeout)
        source = Database(args.docker, args.source, args.source_user, args.timeout, io_policy=policy)
        target = Database(
            args.docker, args.target, args.target_user or args.source_user, args.timeout, io_policy=policy
        )
        if args.execute:
            require(
                args.work_dir is not None,
                "--execute requires a new private --work-dir.",
            )
            migrate(
                source, target, args.database, args.work_dir, args.accept_locale_change
            )
            print(
                "Logical migration verified. No cutover performed. Keep source volume/image and protect the private work directory."
            )
        else:
            deadline = time.monotonic() + policy.operation_seconds
            with source.operation(deadline=deadline), target.operation(deadline=deadline):
                plan = preflight(source, target, args.database)
            print(
                json.dumps(
                    {
                        "preflight": "passed",
                        "mutations": False,
                        "source_version": plan["source_version"],
                        "target_version": plan["target_version"],
                        "target_locale": plan["target_locale"],
                    },
                    indent=2,
                )
            )
        return 0
    except ValueError:
        print("REFUSED: Invalid migration resource policy.", file=sys.stderr)
        return 1
    except MigrationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
