#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
# =============================================================================
# FreeSDN Tailscale private-access addon (docker-compose.tailscale.yml)
# =============================================================================
# Tailscale's containerboot, plus the one FreeSDN setting it does not know.
#
# TAILSCALE_NO_LOGS_NO_SUPPORT=true stops tailscaled sending its diagnostic
# logs to Tailscale Inc., as it already does for the runtime container and the
# vpn sidecar. It becomes tailscaled's --no-logs-no-support flag through
# containerboot's TS_TAILSCALED_EXTRA_ARGS. It is deliberately not handed on as
# tailscaled's own TS_NO_LOGS_NO_SUPPORT variable: tailscaled accepts only Go
# booleans there and exits on anything else ("yes", "on"), which FreeSDN accepts
# for this setting everywhere. Unset or false: uploads stay on, as before.
# =============================================================================
set -eu

case "$(printf '%s' "${TAILSCALE_NO_LOGS_NO_SUPPORT:-}" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | on)
        TS_TAILSCALED_EXTRA_ARGS="${TS_TAILSCALED_EXTRA_ARGS:+$TS_TAILSCALED_EXTRA_ARGS }--no-logs-no-support"
        export TS_TAILSCALED_EXTRA_ARGS
        uploads=off
        ;;
    *) uploads=on ;;
esac
echo "[tailscale-access] log upload to Tailscale $uploads" >&2

exec "${CONTAINERBOOT_BIN:-/usr/local/bin/containerboot}" "$@"
