#!/usr/bin/env bash
# The database entrypoint's adoption/refusal decisions, against real clusters.
#
# docker/postgres/runtime-entrypoint.sh decides whether an operator's existing
# PostgreSQL volume is started, adopted or refused. It runs before upstream's
# initialization and before any ownership change, so a wrong answer either
# blocks a legitimate upgrade or lets an incompatible cluster be chowned and
# started. Nothing tested it: scripts/tests/database_runtime/ covers the
# check_database_runtime.py tooling against a synthetic engine client, not the
# entrypoint against an actual PGDATA.
#
# Requires a Docker daemon and roughly four minutes.
#
#   OLD_IMAGE   the previous release's database image. Defaults to
#               postgres:18.6-trixie, which is what 26.09.0 builds FROM and
#               which produces the same unmarked PG18 glibc cluster. Point it
#               at a real published image for a faithful artifact test.
#   NEW_IMAGE   the candidate image under test.
#
# ---------------------------------------------------------------------------
# Two traps cost hours when this was first written, and both are guarded here
# rather than described in a comment someone has to find:
#
# 1. postgres:17-trixie declares VOLUME /var/lib/postgresql/data -- a path
#    NESTED inside the mount this project uses, /var/lib/postgresql. Docker
#    creates an ANONYMOUS volume there which shadows the named one, so the PG17
#    cluster lands somewhere else entirely and the named volume gets an empty
#    data/ directory. A major-version negative control written the obvious way
#    therefore hands the candidate an EMPTY volume and calls a correct fresh
#    initdb a failure. make_pg17_cluster() overrides PGDATA and then PROVES the
#    cluster is in the named volume. (The PG18 images declare
#    VOLUME /var/lib/postgresql, matching their PGDATA, so they are unaffected.)
#
# 2. `docker logs` returns the WHOLE log. Asserting "the second start did not
#    re-adopt" against it re-reads the first start's adoption line and always
#    fails. The idempotency check scopes logs with --since.
#
# Harness failures abort with exit 99 and the words HARNESS ERROR. A product
# failure is a FAIL line and exit 1. Keeping those apart is the whole point:
# an earlier version of this file reported 7/4, 10/1 and 1/10 across three runs
# of unchanged code, and every difference was the harness.
# ---------------------------------------------------------------------------
set -uo pipefail

OLD=${OLD_IMAGE:-postgres:18.6-trixie}
NEW=${NEW_IMAGE:-freesdn-postgres:local}
V=${TEST_VOLUME:-freesdn-runtime-upgrade-test}
MOUNT=/var/lib/postgresql
EXPECT_MARK=${EXPECT_MARKER:-postgresql-18-debian-trixie-v1}
PG17=${PG17_IMAGE:-postgres:17-trixie}
NAMES="ru-old ru-new ru-pg17 ru-neg3 ru-neg4 ru-neg4b ru-neg5"

pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }
die() { echo "  HARNESS ERROR  $*" >&2; exit 99; }

# docker rm -f returns before the name is released; a following --name run then
# fails with "already in use" and the phase silently tests nothing.
rmc() {
    docker rm -f "$1" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        docker inspect "$1" >/dev/null 2>&1 || return 0
        sleep 0.5
    done
    die "container $1 would not go away"
}
fresh_vol() {
    docker volume rm -f "$V" >/dev/null 2>&1 || true
    docker volume create "$V" >/dev/null || die "could not create volume $V"
}
wait_ready() {
    for _ in $(seq 1 60); do
        docker exec "$1" pg_isready -U postgres >/dev/null 2>&1 && return 0
        docker inspect "$1" --format '{{.State.Running}}' 2>/dev/null | grep -q true || break
        sleep 2
    done
    return 1
}
# psql that reports its OWN failure. Piping through tr makes the pipeline
# status tr's, so `psq ... && ok "writes work"` can never fail.
psq() {
    local out
    out=$(docker exec "$1" psql -U postgres -tAc "$2" 2>&1) || return 1
    printf '%s' "$out" | tr -d '\r'
}
# A container that fails to refuse KEEPS SERVING, so a foreground docker run
# blocks forever. Start detached, poll, and treat still-running as the product
# failure it is.
refusal() {   # refusal <name> <image> [extra docker args...]
    local name="$1" img="$2"; shift 2
    docker run -d --name "$name" -v "$V:$MOUNT" -e POSTGRES_PASSWORD=testpw \
        "$@" "$img" >/dev/null 2>&1 || die "could not start $name"
    REF_RC=""
    for _ in $(seq 1 60); do
        if [ "$(docker inspect "$name" --format '{{.State.Running}}' 2>/dev/null)" = "false" ]; then
            REF_RC=$(docker inspect "$name" --format '{{.State.ExitCode}}' 2>/dev/null)
            break
        fi
        sleep 1
    done
    REF_LOG=$(docker logs "$name" 2>&1) || die "could not read logs for $name"
    if [ -z "$REF_RC" ]; then
        REF_RC="STILL-RUNNING"
        REF_LOG="$REF_LOG (still serving after 60s -- it did not refuse)"
    fi
    rmc "$name"
}
# See trap 1 in the header.
make_pg17_cluster() {   # make_pg17_cluster <pgdata-path-inside-volume>
    rmc ru-pg17
    docker run -d --name ru-pg17 -v "$V:$MOUNT" -e PGDATA="$1" \
        -e POSTGRES_PASSWORD=testpw "$PG17" >/dev/null \
        || die "could not start $PG17"
    wait_ready ru-pg17 || { docker logs ru-pg17 2>&1 | tail -15; die "pg17 cluster never became ready"; }
    local v
    v=$(docker exec ru-pg17 sh -c 'cat "$PGDATA/PG_VERSION"' 2>/dev/null | tr -d '\r')
    [ "$v" = "17" ] || die "expected a PG17 cluster at $1, found PG_VERSION='$v'"
    rmc ru-pg17
    docker run --rm -v "$V:$MOUNT" --entrypoint sh "$NEW" \
        -c "test -s '$1/PG_VERSION'" >/dev/null 2>&1 \
        || die "the PG17 cluster is not in the named volume (anonymous-volume shadowing)"
}

trap 'for c in $NAMES; do docker rm -f $c >/dev/null 2>&1; done; docker volume rm -f "$V" >/dev/null 2>&1' EXIT
for c in $NAMES; do rmc "$c"; done

docker image inspect "$OLD" >/dev/null 2>&1 || die "OLD image missing: $OLD"
docker image inspect "$NEW" >/dev/null 2>&1 || die "NEW image missing: $NEW"
docker image inspect "$PG17" >/dev/null 2>&1 || die "PG17 image missing: $PG17"
echo "OLD: $OLD"
echo "NEW: $NEW"
echo

echo "=== 1. a previous-release cluster, with data in it ==="
fresh_vol
docker run -d --name ru-old -v "$V:$MOUNT" -e POSTGRES_PASSWORD=testpw "$OLD" >/dev/null \
    || die "could not start the previous-release image"
wait_ready ru-old || { docker logs ru-old 2>&1 | tail -20; die "old cluster never became ready"; }

psq ru-old "create table seam(id int primary key, name text);" >/dev/null || die "create table failed"
psq ru-old "insert into seam values (1,'Alpha'),(2,'beta'),(3,'Gamma'),(4,'alpha2'),(5,'Ahre');" >/dev/null \
    || die "insert failed"
psq ru-old "create unique index seam_name_lower on seam (lower(name));" >/dev/null \
    || die "index creation failed"
OLD_COLLATE=$(psq ru-old "select datcollate from pg_database where datname=current_database()") \
    || die "could not read datcollate"
OLD_SORT=$(psq ru-old "select string_agg(name,',' order by name) from seam") || die "could not read sort order"
OLD_UID=$(docker exec ru-old id -u postgres 2>/dev/null | tr -d '\r') || die "could not read postgres uid"
OLD_CKSUM=$(psq ru-old "show data_checksums") || die "could not read data_checksums"
OLD_IDX=$(psq ru-old "select count(*) from pg_index i join pg_class c on c.oid=i.indexrelid where c.relname='seam_name_lower'")

# An empty baseline makes every later comparison meaningless, and an earlier
# version did exactly that after a failed docker exec.
[ -n "$OLD_COLLATE" ] || die "empty datcollate baseline"
[ -n "$OLD_SORT" ]    || die "empty sort baseline"
[ -n "$OLD_UID" ]     || die "empty uid baseline"
echo "  baseline: datcollate=$OLD_COLLATE uid=$OLD_UID checksums=$OLD_CKSUM"
echo "  baseline: sort=[$OLD_SORT]"

if docker exec ru-old sh -c 'test -f "$PGDATA/FREESDN_RUNTIME"'; then
    bad "the previous-release cluster already carries a marker; adoption premise is wrong"
else
    ok "previous-release cluster has no FREESDN_RUNTIME marker"
fi
rmc ru-old

echo
echo "=== 2. the candidate image on that SAME volume ==="
docker run -d --name ru-new -v "$V:$MOUNT" -e POSTGRES_PASSWORD=testpw "$NEW" >/dev/null \
    || die "docker run of the candidate failed outright"
if wait_ready ru-new; then
    ok "candidate started on the existing volume"
else
    bad "candidate did NOT start on the existing volume"
    docker logs ru-new 2>&1 | tail -25
    echo; echo "================ RESULT: $pass passed, $fail failed ================"
    exit 1
fi

LOGS=$(docker logs ru-new 2>&1) || die "could not read candidate logs"
echo "$LOGS" | grep -q "adopting an unmarked PostgreSQL" \
    && ok "adoption path taken, and logged" \
    || bad "no adoption message; the guard took a different path"
echo "$LOGS" | grep -q "No data is read, rewritten or converted" \
    && ok "logged that no conversion occurred" \
    || bad "missing the no-conversion statement"

NEW_COUNT=$(psq ru-new "select count(*) from seam") || die "could not count rows after adoption"
NEW_SORT=$(psq ru-new "select string_agg(name,',' order by name) from seam") || die "could not read sort order"
NEW_COLLATE=$(psq ru-new "select datcollate from pg_database where datname=current_database()") || die "could not read datcollate"
NEW_UID=$(docker exec ru-new id -u postgres 2>/dev/null | tr -d '\r')
NEW_CKSUM=$(psq ru-new "show data_checksums")
NEW_IDX=$(psq ru-new "select count(*) from pg_index i join pg_class c on c.oid=i.indexrelid where c.relname='seam_name_lower'")

[ "$NEW_COUNT" = "5" ] && ok "data intact (5 rows)" || bad "row count '$NEW_COUNT', expected 5"
[ "$NEW_SORT" = "$OLD_SORT" ] && ok "collation-sensitive ORDER BY unchanged" \
    || bad "sort order changed: was [$OLD_SORT] now [$NEW_SORT]"
[ "$NEW_COLLATE" = "$OLD_COLLATE" ] && ok "datcollate unchanged ($NEW_COLLATE)" \
    || bad "datcollate changed: $OLD_COLLATE -> $NEW_COLLATE"
[ "$NEW_UID" = "$OLD_UID" ] && ok "postgres uid unchanged ($NEW_UID)" || bad "uid changed: $OLD_UID -> $NEW_UID"
[ "$NEW_CKSUM" = "$OLD_CKSUM" ] && ok "data_checksums unchanged ($NEW_CKSUM)" \
    || bad "data_checksums changed: $OLD_CKSUM -> $NEW_CKSUM"
[ "$NEW_IDX" = "$OLD_IDX" ] && ok "the lower(name) index survived" \
    || bad "index count changed: $OLD_IDX -> $NEW_IDX"

# lower(name) is collation-dependent: if the runtime's sort changed, an index
# scan disagrees with a sequential scan.
psq ru-new "set enable_seqscan=off; select count(*) from seam where lower(name)='alpha';" >/dev/null \
    && ok "index scan on the collation-dependent index works" \
    || bad "index scan failed after adoption"

if psq ru-new "insert into seam values (6,'delta');" >/dev/null; then
    BACK=$(psq ru-new "select name from seam where id=6")
    [ "$BACK" = "delta" ] && ok "writes work after adoption (read back)" \
        || bad "write reported success but read back '$BACK'"
else
    bad "write after adoption failed"
fi

MARK=$(docker exec ru-new sh -c 'cat "$PGDATA/FREESDN_RUNTIME"' 2>/dev/null | tr -d '\r')
[ "$MARK" = "$EXPECT_MARK" ] && ok "marker recorded: $MARK" || bad "marker is '$MARK', expected '$EXPECT_MARK'"

# Scope the logs to the restart. See trap 2 in the header.
STAMP=$(date -u +%Y-%m-%dT%H:%M:%S)
sleep 1
docker restart ru-new >/dev/null 2>&1 || die "restart failed"
if wait_ready ru-new; then
    SINCE=$(docker logs --since "$STAMP" ru-new 2>&1)
    echo "$SINCE" | grep -q "adopting an unmarked" \
        && bad "re-adopted an already-marked cluster" \
        || ok "second start is idempotent (no re-adoption)"
else
    docker logs ru-new 2>&1 | tail -15
    bad "marked cluster did not restart"
fi
rmc ru-new

echo
echo "=== 3. NEGATIVE CONTROL: a cluster marked with a different runtime ==="
docker run --rm -v "$V:$MOUNT" --entrypoint sh "$NEW" \
    -c 'printf "%s\n" postgresql-18-alpine-3.24-v1 > "$PGDATA/FREESDN_RUNTIME"' >/dev/null 2>&1 \
    || die "could not plant a foreign marker"
refusal ru-neg3 "$NEW"
{ [ "$REF_RC" = "78" ] && echo "$REF_LOG" | grep -q "database runtime mismatch"; } \
    && ok "refused a foreign-marked cluster (exit 78)" \
    || { bad "did NOT refuse a foreign-marked cluster (exit=$REF_RC)"; echo "$REF_LOG" | tail -8; }

echo
echo "=== 4a. NEGATIVE CONTROL: a real PG17 cluster beside PGDATA ==="
fresh_vol
make_pg17_cluster /var/lib/postgresql/17/docker
refusal ru-neg4 "$NEW"
{ [ "$REF_RC" = "78" ] && echo "$REF_LOG" | grep -qE "another database data layout|cluster is PostgreSQL 17"; } \
    && ok "refused a sibling PG17 cluster (exit 78)" \
    || { bad "did NOT refuse a sibling PG17 cluster (exit=$REF_RC)"; echo "$REF_LOG" | tail -8; }

echo
echo "=== 4b. NEGATIVE CONTROL: real PG17 files AT PGDATA ==="
fresh_vol
make_pg17_cluster /var/lib/postgresql/17/docker
# The same genuine cluster, relocated to the path THIS image calls PGDATA: the
# "image replaced under an older cluster" case the major-version branch exists
# for.
docker run --rm -v "$V:$MOUNT" --entrypoint sh "$NEW" -c \
    'mkdir -p /var/lib/postgresql/18 && mv /var/lib/postgresql/17/docker /var/lib/postgresql/18/docker && rmdir /var/lib/postgresql/17' \
    >/dev/null 2>&1 || die "could not relocate the PG17 cluster to PGDATA"
refusal ru-neg4b "$NEW"
{ [ "$REF_RC" = "78" ] && echo "$REF_LOG" | grep -q "cluster is PostgreSQL 17"; } \
    && ok "refused PG17 files at PGDATA (exit 78)" \
    || { bad "did NOT refuse PG17 files at PGDATA (exit=$REF_RC)"; echo "$REF_LOG" | tail -8; }

echo
echo "=== 5. FREESDN_REFUSE_UNMARKED=1 turns adoption back into a refusal ==="
fresh_vol
docker run -d --name ru-old -v "$V:$MOUNT" -e POSTGRES_PASSWORD=testpw "$OLD" >/dev/null \
    || die "could not start the previous-release image for case 5"
wait_ready ru-old || die "case-5 old cluster never became ready"
rmc ru-old
refusal ru-neg5 "$NEW" -e FREESDN_REFUSE_UNMARKED=1
{ [ "$REF_RC" = "78" ] && echo "$REF_LOG" | grep -q "FREESDN_REFUSE_UNMARKED=1"; } \
    && ok "escape hatch refuses an unmarked cluster (exit 78)" \
    || { bad "escape hatch did NOT refuse (exit=$REF_RC)"; echo "$REF_LOG" | tail -8; }
STILL=$(docker run --rm -v "$V:$MOUNT" --entrypoint sh "$NEW" \
    -c 'test -f "$PGDATA/FREESDN_RUNTIME" && echo yes || echo no' 2>/dev/null | tr -d '\r')
[ "$STILL" = "no" ] && ok "refusal left no marker behind" || bad "refusal still wrote a marker"

echo
echo "================ RESULT: $pass passed, $fail failed ================"
[ "$fail" -eq 0 ] || exit 1
