#!/usr/bin/env bash
# Compatibility entrypoint for the isolated, destructive-fault qualification.
# No longer pauses containers in an existing deployment. Required arguments:
# --valkey <built-image> --backend <production-image> --report <new-report.json>
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/check_valkey_ha.py" "$@"
