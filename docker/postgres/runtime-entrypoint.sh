#!/usr/bin/env bash
# Prevent an accidental physical cross-libc upgrade BEFORE upstream chown/init.
# This is an operator safety guard, not an access-control boundary for root.
#
# It ADOPTS a compatible unmarked cluster rather than refusing it. The marker
# file is a FreeSDN invention, so every cluster initialised by a release that
# predates it -- including every 26.09.0 deployment -- has no marker at all. A
# plain missing-marker refusal therefore blocks the ordinary upgrade path for
# everyone while catching nothing, because an incompatible cluster created by a
# musl image DOES carry a marker and is still caught by the mismatch branch.
#
# Adoption is decided on the marker, NOT on the cluster's collation. An earlier
# draft of this header claimed pg_controldata could distinguish a glibc cluster
# from a musl/builtin C.UTF-8 one; it cannot. PostgreSQL 16 removed LC_COLLATE
# and LC_CTYPE from both the server GUC and pg_controldata's output, so that
# check read an empty string and refused every valid cluster. See the long
# comment on the adoption branch below for what is actually relied on.
set -euo pipefail

if [[ "${1:-}" == -* ]]; then set -- postgres "$@"; fi
if [[ "${1:-}" == postgres ]]; then
    # Match upstream's informational commands; these never start a database.
    for arg in "$@"; do
        case "$arg" in -\?|--help|--describe-config|-V|--version)
            exec /usr/local/bin/docker-entrypoint-upstream.sh "$@";;
        esac
    done
    : "${PGDATA:?PGDATA must be set}"
    # Upstream checks old layouts only after preparing/chowning directories.
    # Refuse them first, including the former standby mount at .../data.
    for old in /var/lib/postgresql/PG_VERSION /var/lib/postgresql/data/PG_VERSION /var/lib/postgresql/*/docker/PG_VERSION; do
        if [[ -s "$old" && "$old" != "$PGDATA/PG_VERSION" ]]; then
            echo >&2 'FreeSDN: another database data layout is present. Refusing initialization or ownership changes.'
            exit 78
        fi
    done
    expected=$(cat /usr/local/share/freesdn-database-runtime)
    marker="$PGDATA/FREESDN_RUNTIME"

    if [[ -s "$PGDATA/PG_VERSION" ]]; then
        existing_major=$(tr -dc '0-9' < "$PGDATA/PG_VERSION")
        if [[ "$existing_major" != "$PG_MAJOR" ]]; then
            echo >&2 "FreeSDN: cluster is PostgreSQL ${existing_major}, this image is ${PG_MAJOR}."
            echo >&2 'A major-version change is a separate reviewed operation. Refusing to start.'
            exit 78
        fi

        if [[ -L "$marker" ]]; then
            echo >&2 'FreeSDN: runtime marker is a symlink. Refusing to start.'
            exit 78
        fi

        if [[ -f "$marker" ]]; then
            if [[ "$(cat "$marker")" != "$expected" ]]; then
                echo >&2 'FreeSDN: database runtime mismatch. Refusing to start or change ownership.'
                echo >&2 "  cluster: $(cat "$marker")"
                echo >&2 "  image:   ${expected}"
                echo >&2 'Keep the old image and volume. Use the documented offline logical migration into a NEW volume.'
                echo >&2 'Do not create a marker manually or use pg_upgrade across libc implementations.'
                exit 78
            fi
        else
            # No marker: a cluster initialised by a release older than the
            # marker itself. Adopt it, because the absence is itself the
            # evidence:
            #
            #   * FREESDN_RUNTIME is a FreeSDN invention written by
            #     zz-freesdn-runtime.sh during initdb. Any cluster an Alpine
            #     image initialised therefore HAS a marker, and is caught by the
            #     mismatch branch above.
            #   * Every release that predates the marker shipped
            #     postgres:*-trixie, so an unmarked cluster is a Debian/glibc
            #     cluster. Published 26.09.0 is the obvious case.
            #
            # Collation is deliberately NOT consulted, because it cannot be:
            # PostgreSQL 16 removed LC_COLLATE and LC_CTYPE from BOTH the
            # server-level GUC and pg_controldata's output. On 18 the control
            # file reports no locale, collation or encoding field at all, so any
            # attempt to read one back yields an empty string -- which is how an
            # earlier version of this guard managed to refuse every real
            # 26.09.0 cluster while believing it was being careful. Per-database
            # collation now lives in pg_database.datcollate, which needs a
            # running server and so cannot gate startup.
            #
            # Operators who know their unmarked cluster is NOT glibc can set
            # FREESDN_REFUSE_UNMARKED=1 to restore a hard refusal.
            if [[ "${FREESDN_REFUSE_UNMARKED:-0}" == "1" ]]; then
                echo >&2 'FreeSDN: unmarked cluster and FREESDN_REFUSE_UNMARKED=1. Refusing to start.'
                echo >&2 'Use the documented offline logical migration into a NEW volume.'
                exit 78
            fi
            echo >&2 "FreeSDN: adopting an unmarked PostgreSQL ${existing_major} cluster."
            echo >&2 'FreeSDN: no marker means it predates the marker, so it is a Debian/glibc cluster.'
            echo >&2 "FreeSDN: recording runtime marker ${expected}. No data is read, rewritten or converted."
            printf '%s\n' "$expected" > "$marker"
        fi
    fi
fi
exec /usr/local/bin/docker-entrypoint-upstream.sh "$@"
