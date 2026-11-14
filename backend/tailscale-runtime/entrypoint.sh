#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
# =============================================================================
# FreeSDN Tailscale runtime container (the `tailscale` service, every tier)
# =============================================================================
# Runs tailscaled with userspace networking: no TUN device, no capability,
# uid 1001, read-only root filesystem. The api and the Celery workers drive it
# with the `tailscale` CLI over the shared tailscale_run volume (the LocalAPI
# socket) and reach tailnet addresses through its SOCKS5 server, which listens
# on this container's compose-network address (tailscale:1055).
#
# tailscaled starts only once Tailscale is in use here: a node's state is on
# the tailscale_state volume, or an operator clicked Connect (the api cannot
# see the state volume, so it leaves a request file in the run volume). Until
# then this script waits, and nothing talks to Tailscale's servers.
#
# Once started, tailscaled runs as this script's child, watched over its
# LocalAPI. When it exits, the container exits and Docker's restart policy
# starts it again; the state volume then brings the node straight back.
#
# A tailscaled that is still running but no longer answers on its LocalAPI
# (hung) does not exit, and Docker does not restart an unhealthy container. So
# the watchdog asks it, the way the healthcheck does, every
# TS_WATCHDOG_INTERVAL seconds; after TS_WATCHDOG_FAILS answers in a row went
# missing it stops tailscaled (TERM, then KILL) and the container exits for
# the restart policy. It only asks whether the daemon answers, never which
# state it reports, so a node waiting for a login, a slow enrollment or an
# unreachable control server never trips it. TS_WATCHDOG_FAILS=0 turns it off.
#
# Upgrading. Up to 26.12 tailscaled ran inside the api container, on these
# same two volumes, with the same --state path and the same uid 1001. The node
# identity is therefore already in place and nothing is copied: a state file
# with no autostart marker (written by 26.11 and earlier) counts as "in use",
# and is recorded as such. While the api container of the older release still
# runs its own tailscaled, the socket answers, so this waits for it to go away
# instead of failing to bind the socket and restart-looping.
#
# Phase, read by the healthcheck (freesdn-tailscale-health):
#   standby  Tailscale is not in use here yet                  healthy
#   sidecar  VPN sidecar mode: the vpn container runs it       healthy
#   waiting  another tailscaled already answers on the socket  unhealthy
#   blocked  in use, but the volumes cannot be used as is      unhealthy
#   running  tailscaled runs; probed over the LocalAPI
# =============================================================================
set -u

STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
RUN_DIR="${TS_RUN_DIR:-/var/run/tailscale}"
STATE_FILE="$STATE_DIR/tailscaled.state"
SOCKET="$RUN_DIR/tailscaled.sock"
# Present once Tailscale has been started here; survives restarts. Same name
# and place as app/tailscaled_supervisor.py uses inside the api container.
AUTOSTART_MARKER="$STATE_DIR/freesdn-autostart"
# Left by the api's start_daemon() (vpn_integration.TAILSCALE_START_REQUEST).
START_REQUEST="$RUN_DIR/freesdn-start-requested"
PHASE_FILE="${TS_PHASE_FILE:-/tmp/freesdn-tailscale.phase}"
TAILSCALED="${TAILSCALED_BIN:-tailscaled}"
TAILSCALE="${TAILSCALE_BIN:-tailscale}"
# All interfaces of THIS container's network namespace, i.e. loopback and its
# address on the compose network. Nothing publishes it to the host.
SOCKS5_ADDR="${TS_SOCKS5_ADDR:-:1055}"
POLL="${TS_POLL_SECONDS:-1}"
# The watchdog (see the header). Defaults: a missing answer for four checks in
# a row, 30 s apart, i.e. about two minutes; the healthcheck already reports
# unhealthy after 90 s. Each check may take up to TS_WATCHDOG_TIMEOUT seconds.
WATCH_INTERVAL="${TS_WATCHDOG_INTERVAL:-30}"
WATCH_FAILS="${TS_WATCHDOG_FAILS:-4}"
WATCH_TIMEOUT="${TS_WATCHDOG_TIMEOUT:-10}"
# How long a stopped tailscaled gets to exit on TERM before it is killed.
WATCH_STOP_GRACE="${TS_WATCHDOG_STOP_GRACE:-10}"
WATCH_FIRED="${TS_WATCHDOG_FIRED_FILE:-/tmp/freesdn-tailscale.watchdog}"

say() { echo "[tailscale-runtime] $*" >&2; }

lower() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

truthy() {
    case "$(lower "${1:-}")" in
        1 | true | yes | on) return 0 ;;
    esac
    return 1
}

# Record the phase; log only when it changes, so a wait does not flood the log.
phase() {
    if [ "$(cat "$PHASE_FILE" 2>/dev/null)" != "$1" ]; then
        echo "$1" >"$PHASE_FILE"
        if [ -n "${2:-}" ]; then say "$2"; fi
    fi
}

nap() {
    sleep "$1" &
    wait $!
}

sidecar_mode() {
    [ "$(lower "${VPN_MODE:-off}")" = sidecar ] ||
        truthy "${FREESDN_OPENVPN_SIDECAR:-}" ||
        truthy "${FREESDN_WIREGUARD_SIDECAR:-}"
}

in_use() {
    [ -s "$STATE_FILE" ] || [ -e "$AUTOSTART_MARKER" ] || [ -e "$START_REQUEST" ]
}

# Print why tailscaled cannot run on these volumes; print nothing if it can.
unusable() {
    for dir in "$STATE_DIR" "$RUN_DIR"; do
        if ! [ -d "$dir" ] || ! [ -w "$dir" ] || ! [ -x "$dir" ]; then
            echo "$dir is not writable by uid $(id -u)"
            return
        fi
    done
    # What tailscaled reads and rewrites in its state directory. A file written
    # as root (by the privileged vpn sidecar, or by the development image) is
    # mode 0600 and unreadable here. The two log files the api container's
    # supervisor kept are not tailscaled's and do not matter.
    for path in "$STATE_DIR"/*; do
        [ -e "$path" ] || continue
        case "${path##*/}" in
            tailscaled.log | tailscaled.log.1 | freesdn-*) continue ;;
        esac
        if ! [ -r "$path" ] || ! [ -w "$path" ]; then
            echo "$path is not readable and writable by uid $(id -u)"
            return
        fi
    done
}

# Does a tailscaled (not this one) already answer on the socket?
socket_answers() {
    [ -S "$SOCKET" ] || return 1
    if out=$(timeout 5 "$TAILSCALE" --socket="$SOCKET" status --json 2>&1); then
        return 0
    fi
    case "$out" in
        *"connection refused"* | *"no such file"* | *"doesn't appear to be running"*) return 1 ;;
    esac
    # It neither answered nor refused: something holds the socket.
    return 0
}

# Does the tailscaled we started answer on its LocalAPI? Same question as the
# healthcheck. A hung daemon still has its socket, and the kernel still
# accepts the connection, so only an answer counts.
daemon_answers() {
    out=$(timeout "$WATCH_TIMEOUT" "$TAILSCALE" --socket="$SOCKET" status --json --peers=false 2>/dev/null)
    case "$out" in
        *'"BackendState"'*) return 0 ;;
    esac
    return 1
}

# Runs in the background next to tailscaled ($1). Stops it once it has missed
# WATCH_FAILS answers in a row, so that this script, and the container, exit.
watchdog() {
    fails=0
    while :; do
        nap "$WATCH_INTERVAL"
        # This script ($$) is gone, or tailscaled is: nothing left to watch,
        # and the pid may not be ours any more.
        kill -0 "$$" 2>/dev/null && kill -0 "$1" 2>/dev/null || return 0
        if daemon_answers; then
            if [ "$fails" -gt 0 ]; then say "tailscaled answers on its LocalAPI again"; fi
            fails=0
            continue
        fi
        fails=$((fails + 1))
        say "tailscaled did not answer on its LocalAPI socket ($fails of $WATCH_FAILS in a row)"
        [ "$fails" -ge "$WATCH_FAILS" ] || continue
        say "tailscaled runs but has stopped answering; stopping it so Docker restarts this container"
        : >"$WATCH_FIRED"
        kill -TERM "$1" 2>/dev/null
        kill -CONT "$1" 2>/dev/null
        waited=0
        while kill -0 "$1" 2>/dev/null && [ "$waited" -lt "$WATCH_STOP_GRACE" ]; do
            nap 1
            waited=$((waited + 1))
        done
        if kill -0 "$1" 2>/dev/null; then
            say "tailscaled did not exit on TERM within ${WATCH_STOP_GRACE}s; killing it"
            kill -KILL "$1" 2>/dev/null
        fi
        return 0
    done
}

trap 'exit 0' TERM INT
rm -f "$PHASE_FILE" "$WATCH_FIRED"

if sidecar_mode; then
    phase sidecar "VPN sidecar mode: the vpn container runs tailscaled on these volumes; standing by"
    while :; do nap 60; done
fi

while :; do
    if ! in_use; then
        phase standby "Tailscale is not in use here yet; waiting for Connect in the UI (no daemon, no traffic to Tailscale)"
    else
        why=$(unusable)
        if [ -n "$why" ]; then
            phase blocked "cannot start tailscaled: $why. If an older privileged vpn container or the development image wrote it as root, hand it back to uid 1001 once: docker compose run --rm --no-deps --user 0 --cap-add CHOWN --entrypoint chown tailscale -R 1001:1001 /var/lib/tailscale /var/run/tailscale"
        elif socket_answers; then
            phase waiting "another tailscaled already answers on $SOCKET (the api container of an older release, during an upgrade); waiting for it to stop"
        else
            break
        fi
    fi
    nap "$POLL"
done

if ! [ -e "$AUTOSTART_MARKER" ]; then
    if [ -s "$STATE_FILE" ] && ! [ -e "$START_REQUEST" ]; then
        say "adopted the Tailscale node state already on the tailscale_state volume"
    fi
    : >"$AUTOSTART_MARKER"
fi
# The request is answered, and the api container's old supervisor lock means
# nothing here (it may be root-owned; the directory is ours, so rm works).
rm -f "$START_REQUEST" "$RUN_DIR/freesdn-supervisor.lock"

set -- "$TAILSCALED" \
    --state="$STATE_FILE" \
    --socket="$SOCKET" \
    --tun=userspace-networking \
    --socks5-server="$SOCKS5_ADDR"
uploads=on
# Off only when the operator says so (TAILSCALE_NO_LOGS_NO_SUPPORT=true):
# tailscaled then sends no logs to Tailscale Inc., and Tailscale support can no
# longer see this node's logs.
if truthy "${TAILSCALE_NO_LOGS_NO_SUPPORT:-}"; then
    set -- "$@" --no-logs-no-support
    uploads=off
fi
echo running >"$PHASE_FILE"
say "starting tailscaled: userspace networking, SOCKS5 on $SOCKS5_ADDR, log upload to Tailscale $uploads"
case "$WATCH_FAILS" in
    '' | *[!0-9]* | 0) exec "$@" ;; # watchdog off: tailscaled replaces this script
esac

"$@" &
daemon=$!
# docker stop: hand the TERM to tailscaled and wait for it, as when it was
# the container's main process.
trap 'kill -TERM "$daemon" 2>/dev/null' TERM INT
watchdog "$daemon" &
watcher=$!
while :; do
    wait "$daemon"
    rc=$?
    # wait returns early when a trapped signal arrives; tailscaled is then
    # still shutting down, so wait again.
    kill -0 "$daemon" 2>/dev/null || break
done
kill "$watcher" 2>/dev/null
if [ -e "$WATCH_FIRED" ]; then
    say "tailscaled was stopped by the watchdog (exit $rc); exiting for the restart policy"
    exit 1
fi
exit "$rc"
