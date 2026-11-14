#!/bin/sh
# ============================================================================
# FreeSDN VPN sidecar — the single PRIVILEGED overlay node.
#
# Runs the VPN daemons so the (unprivileged, read-only, non-root) api/worker
# containers don't have to: they join THIS container's network namespace
# (docker-compose `network_mode: "service:vpn"`) to route to remote sites
# through these tunnels, and reach the daemon control sockets over shared
# volumes. This keeps the app containers fully hardened.
#
#   * tailscaled       — kernel TUN (so routes land in the shared netns)
#   * netbird daemon   — WireGuard-based mesh
#   * openvpn supervisor — reconciles per-connection desired-state markers the
#                          api writes, and publishes status back for the api to
#                          read (the api is in a different pid namespace, so it
#                          cannot signal these processes directly).
#
# Requires: cap_add NET_ADMIN, devices /dev/net/tun, ip_forward=1 (compose).
# ============================================================================
set -e

TS_SOCK="${TS_SOCKET:-/var/run/tailscale/tailscaled.sock}"
TS_STATE="${TS_STATE_FILE:-/var/lib/tailscale/tailscaled.state}"
OVPN_CFG_DIR="${OPENVPN_CONFIG_DIR:-/etc/openvpn}/client"
OVPN_RUN_DIR="${OPENVPN_RUN_DIR:-/run/openvpn-client}"
OVPN_LOG_DIR="${OPENVPN_LOG_DIR:-/var/log/openvpn}"
OVPN_DESIRED_DIR="$OVPN_RUN_DIR/desired"
WG_CFG_DIR="${WIREGUARD_CONFIG_DIR:-/etc/wireguard}"
WG_RUN_DIR="${WIREGUARD_RUN_DIR:-/run/wireguard}"
WG_DESIRED_DIR="$WG_RUN_DIR/desired"

mkdir -p /var/run/tailscale /var/lib/tailscale \
         "$OVPN_CFG_DIR" "$OVPN_RUN_DIR" "$OVPN_DESIRED_DIR" "$OVPN_LOG_DIR" \
         "$WG_CFG_DIR" "$WG_RUN_DIR" "$WG_DESIRED_DIR" \
         /etc/netbird /var/lib/netbird

# The api/worker run as the non-root appuser (uid 1001) and must be able to WRITE
# openvpn/wireguard configs + desired-state markers, and read the status this
# sidecar publishes. THIS container runs as root and would otherwise own those
# shared-volume dirs root-only, so the api's connect() fails with EACCES
# ("Permission denied"). Hand write access to the app uid; root (this supervisor)
# can still write regardless of ownership.
APP_UID="${FREESDN_APP_UID:-1001}"
APP_GID="${FREESDN_APP_GID:-1001}"
chown -R "$APP_UID:$APP_GID" "$OVPN_CFG_DIR" "$OVPN_RUN_DIR" "$WG_CFG_DIR" "$WG_RUN_DIR" 2>/dev/null || true

# TAILSCALE_NO_LOGS_NO_SUPPORT=true (x-backend-env, default true) stops
# tailscaled uploading its logs to Tailscale Inc., the same as in the capless
# tailscale runtime container. Unquoted on purpose: empty adds no argument.
TS_EXTRA=""
case "$(printf '%s' "${TAILSCALE_NO_LOGS_NO_SUPPORT:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) TS_EXTRA="--no-logs-no-support" ;;
esac

echo "[vpn] starting tailscaled (kernel TUN)…"
# shellcheck disable=SC2086
tailscaled --state="$TS_STATE" --socket="$TS_SOCK" $TS_EXTRA \
    >/var/lib/tailscale/tailscaled.log 2>&1 &
TS_PID=$!

# Let the non-root appuser (the api/worker, uid 1001) drive `tailscale up/down/
# set` over the shared socket. tailscaled restricts write ops (login etc.) to
# root or the configured operator, so without this the api's Tailscale "Connect"
# fails with "Access denied: checkprefs access denied". appuser exists in this
# image (uid 1001, same as the api) so the operator uid check passes.
TS_OPERATOR="${FREESDN_APP_USER:-appuser}"
( for _ in $(seq 1 20); do [ -S "$TS_SOCK" ] && break; sleep 0.5; done
  tailscale --socket="$TS_SOCK" set --operator="$TS_OPERATOR" 2>/dev/null || true ) &

NB_PID=""
NB_ADDR="${NETBIRD_DAEMON_ADDR:-unix:///var/run/netbird.sock}"
if command -v netbird >/dev/null 2>&1; then
    # Listen on NETBIRD_DAEMON_ADDR so the api/worker `netbird` CLI (sharing this
    # netns but not the fs) can reach the daemon. A tcp address is carried by the
    # shared netns; the default unix socket would be invisible to those containers.
    echo "[vpn] starting netbird daemon (daemon-addr=$NB_ADDR)…"
    netbird service run --daemon-addr "$NB_ADDR" \
        >/var/lib/netbird/netbird.log 2>&1 &
    NB_PID=$!
fi

# ── OpenVPN supervisor ──────────────────────────────────────────────────────
# Desired-state protocol with the api (over the shared /run/openvpn-client vol):
#   api connect(name)    -> touch  $OVPN_DESIRED_DIR/<name>
#   api disconnect(name) -> rm     $OVPN_DESIRED_DIR/<name>
#   api status(name)     -> read   $OVPN_RUN_DIR/<name>.status  (written here)
_ovpn_pid()   { cat "$OVPN_RUN_DIR/$1.pid" 2>/dev/null; }
_ovpn_alive() { p="$(_ovpn_pid "$1")"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
_ovpn_state() {
    if _ovpn_alive "$1"; then
        # bound the grep to the log TAIL so a stale "Initialization Sequence
        # Completed" from an earlier session can't report a reconnecting tunnel
        # as connected.
        if tail -c 4000 "$OVPN_LOG_DIR/$1.log" 2>/dev/null | grep -q "Initialization Sequence Completed"; then
            echo connected
        else
            echo connecting
        fi
    else
        echo down
    fi
}

# ── WireGuard reconciler ─────────────────────────────────────────────────────
# Same desired-state protocol over the shared /etc/wireguard + /run/wireguard
# vols. `wg-quick up <iface>` reads $WG_CFG_DIR/<iface>.conf and needs NET_ADMIN
# (this container has it; the api does not). Status = the interface is present in
# `wg show interfaces` AND (best-effort) has had a handshake.
_wg_active() { wg show "$1" >/dev/null 2>&1; }
_wg_state() {
    if _wg_active "$1"; then
        # a non-zero latest-handshake on any peer ⇒ traffic-capable ⇒ connected
        if wg show "$1" latest-handshakes 2>/dev/null | awk '{ if ($2 != 0) ok=1 } END { exit ok?0:1 }'; then
            echo connected
        else
            echo connecting
        fi
    else
        echo down
    fi
}

# ── Defense-in-depth config validation (exec chokepoint) ─────────────────────
# This sidecar runs openvpn/wg-quick as ROOT off configs on volumes the (non-root)
# api can write. The app-layer schema + materialize validators already refuse
# anything outside the OpenVPN client allowlist, but a COMPROMISED api could write
# a config file directly, bypassing the API. So re-check here, immediately before
# exec, with the SAME allowlist (since 26.12.0; it was a blocklist, which could be
# routed around via `setenv opt <directive>`, a quoted directive name, or lines
# inside a <connection> block). Mirrors _assert_openvpn_config_safe in
# app/schemas/vpn.py; tests/services/test_vpn_sidecar_scanner.py runs this exact
# program against the same cases and fails if the ALLOWED / FILEREF / MATERIAL
# lists below differ from the Python ones.
_ovpn_cfg_safe() {
    awk '
        function check(k,   d, a) {
            d = $k
            if (d !~ /^(--)?[a-z0-9][a-z0-9-]*$/) { bad = 1; return }
            sub(/^--/, "", d)
            if (!(d in allowed)) { bad = 1; return }
            if (d == "setenv") {
                if (NF < k + 1 || $(k + 1) !~ /^[A-Za-z0-9_]+$/) { bad = 1; return }
                if (tolower($(k + 1)) == "opt") {
                    if (NF < k + 2 || depth >= 2) { bad = 1; return }
                    depth++
                    check(k + 2)
                    depth--
                }
                return
            }
            if ((d in fileref) && NF > k) {
                a = $(k + 1)
                if (index(a, SQ)) { bad = 1; return }
                gsub(/"/, "", a)
                a = tolower(a)
                if (a != "none" && a != "[inline]") bad = 1
            }
            if ((d == "http-proxy" || d == "socks-proxy") && NF > k + 2) {
                a = $(k + 3)
                if (index(a, SQ)) { bad = 1; return }
                gsub(/"/, "", a)
                a = tolower(a)
                if (d == "socks-proxy" || (a != "auto" && a != "auto-nct")) bad = 1
            }
        }
        BEGIN {
            SQ = sprintf("%c", 39)
            ALLOWED = "client tls-client pull dev dev-type topology proto proto-force remote"
            ALLOWED = ALLOWED " remote-random remote-random-hostname resolv-retry port lport rport"
            ALLOWED = ALLOWED " local bind nobind float connect-retry connect-retry-max connect-timeout"
            ALLOWED = ALLOWED " server-poll-timeout explicit-exit-notify persist-key persist-tun"
            ALLOWED = ALLOWED " persist-local-ip persist-remote-ip inactive session-timeout ping"
            ALLOWED = ALLOWED " ping-exit ping-restart ping-timer-rem keepalive hand-window tran-window"
            ALLOWED = ALLOWED " single-session tls-exit tun-mtu tun-mtu-extra tun-mtu-max link-mtu"
            ALLOWED = ALLOWED " mtu-disc mssfix fragment sndbuf rcvbuf txqueuelen fast-io socket-flags"
            ALLOWED = ALLOWED " tcp-nodelay passtos disable-dco route route-ipv6 route-gateway"
            ALLOWED = ALLOWED " route-metric route-delay route-nopull route-noexec ifconfig"
            ALLOWED = ALLOWED " ifconfig-ipv6 ifconfig-noexec redirect-gateway redirect-private"
            ALLOWED = ALLOWED " block-outside-dns block-ipv6 dhcp-option tun-ipv6 pull-filter"
            ALLOWED = ALLOWED " allow-pull-fqdn max-routes cipher data-ciphers data-ciphers-fallback"
            ALLOWED = ALLOWED " ncp-ciphers ncp-disable auth tls-version-min tls-version-max tls-cipher"
            ALLOWED = ALLOWED " tls-ciphersuites tls-groups tls-cert-profile ecdh-curve key-direction"
            ALLOWED = ALLOWED " key-method tls-timeout reneg-sec reneg-bytes reneg-pkts replay-window"
            ALLOWED = ALLOWED " mute-replay-warnings no-replay remote-cert-tls remote-cert-ku"
            ALLOWED = ALLOWED " remote-cert-eku ns-cert-type verify-x509-name verify-hash"
            ALLOWED = ALLOWED " peer-fingerprint opt-verify ca cert key dh secret tls-auth tls-crypt"
            ALLOWED = ALLOWED " tls-crypt-v2 pkcs12 extra-certs crl-verify auth-user-pass auth-nocache"
            ALLOWED = ALLOWED " auth-retry static-challenge push-peer-info comp-lzo compress"
            ALLOWED = ALLOWED " allow-compression comp-noadapt http-proxy http-proxy-option"
            ALLOWED = ALLOWED " http-proxy-retry socks-proxy socks-proxy-retry verb mute"
            ALLOWED = ALLOWED " suppress-timestamps mlock nice user group remap-usr1"
            ALLOWED = ALLOWED " ignore-unknown-option setenv"
            FILEREF = "auth-user-pass ca capath cert key dh secret tls-auth tls-crypt tls-crypt-v2"
            FILEREF = FILEREF " pkcs12 crl-verify askpass extra-certs pkcs11-id pkcs11-providers"
            MATERIAL = "ca cert key dh secret tls-auth tls-crypt tls-crypt-v2 pkcs12 extra-certs"
            MATERIAL = MATERIAL " crl-verify auth-user-pass http-proxy-user-pass peer-fingerprint"
            n = split(ALLOWED, w, " "); for (i = 1; i <= n; i++) allowed[w[i]] = 1
            n = split(FILEREF, w, " "); for (i = 1; i <= n; i++) fileref[w[i]] = 1
            n = split(MATERIAL, w, " "); for (i = 1; i <= n; i++) material[w[i]] = 1
        }
        { sub(/\r$/, ""); line = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line) }
        block != "" { if (line == "</" block ">") block = ""; next }
        line == "" || line ~ /^[#;]/ { next }
        { t = line; gsub(/\t/, "", t); if (t ~ /[[:cntrl:]]/) { bad = 1; next } }
        line ~ /^</ {
            if (line !~ /^<\/?[a-z0-9-]+>$/) { bad = 1; next }
            closing = (line ~ /^<\//)
            name = line; gsub(/[<>\/]/, "", name)
            if (name == "connection") {
                if (closing == inconn) inconn = !closing
                else bad = 1
                next
            }
            if (closing || inconn || !(name in material)) { bad = 1; next }
            block = name
            next
        }
        { check(1) }
        END { if (block != "" || inconn) bad = 1; exit bad ? 1 : 0 }
    ' "$1"
}
_wg_cfg_safe() { ! grep -iqE '^[[:space:]]*(PostUp|PostDown|PreUp|PreDown)[[:space:]]*=' "$1"; }

# atomic status publish (temp + mv) so the api never reads a transient empty file
_publish() { printf '%s\n' "$2" > "$1.tmp" 2>/dev/null && mv -f "$1.tmp" "$1" 2>/dev/null || true; }

echo "[vpn] openvpn + wireguard supervisor running…"
while true; do
    # ── Mesh-daemon liveness (restart on crash) ──
    # tailscaled/netbird are started once; if one crashes its control socket file
    # lingers, so a socket-existence healthcheck would still report "healthy" while
    # the overlay is silently dead. Restart a dead daemon within one cycle.
    if ! kill -0 "$TS_PID" 2>/dev/null; then
        echo "[vpn] tailscaled exited — restarting" >&2
        # shellcheck disable=SC2086
        tailscaled --state="$TS_STATE" --socket="$TS_SOCK" $TS_EXTRA \
            >>/var/lib/tailscale/tailscaled.log 2>&1 &
        TS_PID=$!
    fi
    if [ -n "$NB_PID" ] && ! kill -0 "$NB_PID" 2>/dev/null; then
        echo "[vpn] netbird daemon exited — restarting" >&2
        netbird service run --daemon-addr "$NB_ADDR" \
            >>/var/lib/netbird/netbird.log 2>&1 &
        NB_PID=$!
    fi

    # ── Tailscale operator (re-assert) ──
    # `tailscale up --reset` (used by the app's login flow) WIPES the operator
    # grant, which would re-lock the non-root api out of tailscale write ops
    # ("Access denied: checkprefs access denied"). Re-assert it every cycle so the
    # grant is restored within one loop after any login. Idempotent + quiet.
    tailscale --socket="$TS_SOCK" set --operator="$TS_OPERATOR" >/dev/null 2>&1 || true

    # ── OpenVPN ──
    # bring up everything desired that has a SAFE config and isn't already running
    for marker in "$OVPN_DESIRED_DIR"/*; do
        [ -e "$marker" ] || continue
        name="$(basename "$marker")"
        cfg="$OVPN_CFG_DIR/$name.conf"
        if [ -f "$cfg" ] && ! _ovpn_alive "$name"; then
            if _ovpn_cfg_safe "$cfg"; then
                echo "[vpn] openvpn up: $name"
                openvpn --config "$cfg" --cd "$OVPN_CFG_DIR" --daemon "ovpn-$name" \
                    --writepid "$OVPN_RUN_DIR/$name.pid" \
                    --log "$OVPN_LOG_DIR/$name.log" || true
            else
                echo "[vpn] REFUSED openvpn $name: config carries a dangerous directive" >&2
            fi
        fi
    done
    # tear down anything running that is no longer desired (wait for exit before
    # removing the pidfile, else a rapid reconnect double-spawns openvpn)
    for pidf in "$OVPN_RUN_DIR"/*.pid; do
        [ -e "$pidf" ] || continue
        name="$(basename "$pidf" .pid)"
        if [ ! -e "$OVPN_DESIRED_DIR/$name" ] && _ovpn_alive "$name"; then
            echo "[vpn] openvpn down: $name"
            p="$(_ovpn_pid "$name")"
            kill "$p" 2>/dev/null || true
            i=0; while kill -0 "$p" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 0.3; i=$((i + 1)); done
            kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
            rm -f "$pidf"
        fi
    done
    # publish status for every known config so the api can read it (atomic)
    for cfg in "$OVPN_CFG_DIR"/*.conf; do
        [ -e "$cfg" ] || continue
        name="$(basename "$cfg" .conf)"
        _publish "$OVPN_RUN_DIR/$name.status" "$(_ovpn_state "$name")"
    done

    # ── WireGuard ──
    # bring up desired interfaces that have a SAFE config and aren't already up
    for marker in "$WG_DESIRED_DIR"/*; do
        [ -e "$marker" ] || continue
        iface="$(basename "$marker")"
        cfg="$WG_CFG_DIR/$iface.conf"
        if [ -f "$cfg" ] && ! _wg_active "$iface"; then
            if _wg_cfg_safe "$cfg"; then
                echo "[vpn] wg-quick up: $iface"
                wg-quick up "$iface" || true
            else
                echo "[vpn] REFUSED wireguard $iface: config carries Pre/Post Up/Down" >&2
            fi
        fi
    done
    # tear down any ACTIVE wg interface no longer desired. Sweep `wg show
    # interfaces` (NOT just *.conf) so a deleted connection whose .conf was already
    # removed by the api's cleanup() still gets torn down — otherwise the interface
    # is orphaned in the kernel (routes intact) until a container restart. wg-quick
    # down needs the .conf; if it's gone, delete the link directly.
    for iface in $(wg show interfaces 2>/dev/null); do
        if [ ! -e "$WG_DESIRED_DIR/$iface" ]; then
            echo "[vpn] wg down: $iface"
            if [ -f "$WG_CFG_DIR/$iface.conf" ]; then
                wg-quick down "$iface" 2>/dev/null || ip link del "$iface" 2>/dev/null || true
            else
                ip link del "$iface" 2>/dev/null || true
            fi
        fi
    done
    # sweep dangling desired-markers (no conf, not up) left by a partial cleanup
    for marker in "$WG_DESIRED_DIR"/*; do
        [ -e "$marker" ] || continue
        iface="$(basename "$marker")"
        if [ ! -f "$WG_CFG_DIR/$iface.conf" ] && ! _wg_active "$iface"; then
            rm -f "$marker" "$WG_RUN_DIR/$iface.status"
        fi
    done
    # publish status for every configured interface
    for cfg in "$WG_CFG_DIR"/*.conf; do
        [ -e "$cfg" ] || continue
        iface="$(basename "$cfg" .conf)"
        _publish "$WG_RUN_DIR/$iface.status" "$(_wg_state "$iface")"
    done

    sleep 5
done
