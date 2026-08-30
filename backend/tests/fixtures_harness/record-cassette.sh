#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Record a real-device cassette for one adapter.
#
#   ./record-cassette.sh pfsense   10.0.0.1     admin 's3cret'
#   ./record-cassette.sh mikrotik  10.0.0.2     admin 'x' 443
#   FREESDN_RECORD_MAC=00:0b:82:.. ./record-cassette.sh grandstream 192.168.0.21 admin 'x'
#
# Recordings land in $FREESDN_CASSETTE_DIR (default ~/freesdn-cassettes), OFF-REPO.
# Run from the backend dir with the project venv active.
set -euo pipefail

adapter="${1:?usage: record-cassette.sh <adapter> <host> <user> <pass> [port]}"
host="${2:?host required}"
user="${3:?user required}"
pass="${4:?pass required}"
port="${5:-}"

export FREESDN_RECORD_FIXTURES=1
export FREESDN_CASSETTE_DIR="${FREESDN_CASSETTE_DIR:-$HOME/freesdn-cassettes}"
export FREESDN_RECORD_HOST="$host"
export FREESDN_RECORD_USERNAME="$user"
export FREESDN_RECORD_PASSWORD="$pass"
[ -n "$port" ] && export FREESDN_RECORD_PORT="$port"
# grandstream also needs the phone MAC: export FREESDN_RECORD_MAC=.. before calling.

echo "Recording '$adapter' from $host -> $FREESDN_CASSETTE_DIR (off-repo)"
exec python -m pytest "tests/adapters/test_${adapter}_cassette.py" -v
