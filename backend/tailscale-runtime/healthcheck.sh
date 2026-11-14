#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
# Healthcheck of the Tailscale runtime container (see entrypoint.sh).
#
# Standing by is healthy: an install that never uses Tailscale must not show an
# unhealthy container. Once tailscaled runs, it is healthy only if it ANSWERS
# on its LocalAPI socket: a hung or crashed daemon leaves the socket file on
# disk, so `test -S` would pass while the overlay is dead. `status --json`
# carries BackendState in every login state, NeedsLogin included.
#
# NeedsLogin is healthy on purpose: it is where every enrollment starts and
# where a node whose key expired waits, and restarting tailscaled fixes neither.
# Docker only reports this status; it never restarts an unhealthy container.
# Recovering a daemon that runs but no longer answers is the entrypoint's
# watchdog, which asks the same question and stops tailscaled after about two
# minutes of silence so the restart policy brings it back.
PHASE_FILE="${TS_PHASE_FILE:-/tmp/freesdn-tailscale.phase}"
SOCKET="${TS_RUN_DIR:-/var/run/tailscale}/tailscaled.sock"

case "$(cat "$PHASE_FILE" 2>/dev/null)" in
    standby | sidecar)
        exit 0
        ;;
    running)
        out=$(timeout 5 "${TAILSCALE_BIN:-tailscale}" --socket="$SOCKET" status --json 2>/dev/null)
        case "$out" in
            *'"BackendState"'*) exit 0 ;;
        esac
        echo "tailscaled does not answer on $SOCKET"
        exit 1
        ;;
    *)
        echo "not running: $(cat "$PHASE_FILE" 2>/dev/null || echo starting); see the container log"
        exit 1
        ;;
esac
