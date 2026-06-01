#!/usr/bin/env bash
# FreeSDN Self-Healing Start (Linux/macOS)
# Convenience wrapper for the self-healing orchestrator.
#
# Usage:
#   ./scripts/start.sh              # Start with self-healing
#   ./scripts/start.sh --check      # Health check only
#   ./scripts/start.sh --stop       # Stop stack
#   ./scripts/start.sh --restart    # Full restart
#   ./scripts/start.sh --status     # Show status
#   ./scripts/start.sh --monitor    # Continuous monitoring

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Find Python
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python not found. Install Python 3.10+ and try again."
    exit 1
fi

exec "$PYTHON" scripts/selfheal.py "$@"
