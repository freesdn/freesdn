# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Schemas
===========================

Pydantic schemas for VPN API endpoints.
Matches frontend types in api.ts (VPNConnection, TailscaleNode, etc.)
"""

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.vpn import VPNType

# OpenVPN config directives that let the config (a) run arbitrary commands as the
# daemon (script hooks, plugins) or (b) create/overwrite files as the daemon or
# open a control socket. The daemon runs as ROOT in the privileged vpn sidecar
# off a config the app materializes, so an authenticated vpn:write user — trusted
# to configure VPNs but NOT to run code on the appliance — must not be able to
# smuggle any of these in. Since 26.12.0 this is no longer the enforcement list
# (see _OPENVPN_ALLOWED_DIRECTIVES below); it is kept so a refusal can say
# "dangerous" rather than "unsupported", and so tests can prove none of these is
# ever allowlisted.
_DANGEROUS_OPENVPN_DIRECTIVES = frozenset(
    {
        # config INCLUSION: ``config <file>`` inlines another file's directives
        # at parse time, which no scanner of this file would ever see.
        "config",
        # script / plugin execution
        "up",
        "down",
        "ipchange",
        "route-up",
        "route-pre-down",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "tls-verify",
        "tls-crypt-v2-verify",
        "auth-user-pass-verify",
        "script-security",
        "plugin",
        # control channel
        "management",
        # file-write / path / process directives (don't need script-security)
        "iproute",
        "tls-export-cert",
        "tmp-dir",
        "cd",
        "chroot",
        "daemon",
        "log",
        "log-append",
        "status",
        "writepid",
        "http-proxy-user-pass",
        "ifconfig-pool-persist",
        # code loading through OpenSSL
        "engine",
        "providers",
    }
)

# Every directive FreeSDN accepts in an OpenVPN client config. An ALLOWLIST
# since 26.12.0: the previous blocklist named the dangerous directives and so
# could be routed around (``setenv opt <directive>`` runs the inner directive;
# OpenVPN unquotes a quoted directive name; ``<connection>`` block lines were
# skipped unread). Anything not listed is refused. The sidecar's pre-exec
# scanner (``vpn-sidecar-entrypoint.sh``, ``_ovpn_cfg_safe``) carries the same
# list, and tests/services/test_vpn_sidecar_scanner.py fails if the two drift.
_OPENVPN_ALLOWED_DIRECTIVES = frozenset(
    {
        # role, transport, reconnection
        "client",
        "tls-client",
        "pull",
        "dev",
        "dev-type",
        "topology",
        "proto",
        "proto-force",
        "remote",
        "remote-random",
        "remote-random-hostname",
        "resolv-retry",
        "port",
        "lport",
        "rport",
        "local",
        "bind",
        "nobind",
        "float",
        "connect-retry",
        "connect-retry-max",
        "connect-timeout",
        "server-poll-timeout",
        "explicit-exit-notify",
        "persist-key",
        "persist-tun",
        "persist-local-ip",
        "persist-remote-ip",
        "inactive",
        "session-timeout",
        "ping",
        "ping-exit",
        "ping-restart",
        "ping-timer-rem",
        "keepalive",
        "hand-window",
        "tran-window",
        "single-session",
        "tls-exit",
        # MTU and performance
        "tun-mtu",
        "tun-mtu-extra",
        "tun-mtu-max",
        "link-mtu",
        "mtu-disc",
        "mssfix",
        "fragment",
        "sndbuf",
        "rcvbuf",
        "txqueuelen",
        "fast-io",
        "socket-flags",
        "tcp-nodelay",
        "passtos",
        "disable-dco",
        # routes, addresses, DNS
        "route",
        "route-ipv6",
        "route-gateway",
        "route-metric",
        "route-delay",
        "route-nopull",
        "route-noexec",
        "ifconfig",
        "ifconfig-ipv6",
        "ifconfig-noexec",
        "redirect-gateway",
        "redirect-private",
        "block-outside-dns",
        "block-ipv6",
        "dhcp-option",
        "tun-ipv6",
        "pull-filter",
        "allow-pull-fqdn",
        "max-routes",
        # crypto and peer verification
        "cipher",
        "data-ciphers",
        "data-ciphers-fallback",
        "ncp-ciphers",
        "ncp-disable",
        "auth",
        "tls-version-min",
        "tls-version-max",
        "tls-cipher",
        "tls-ciphersuites",
        "tls-groups",
        "tls-cert-profile",
        "ecdh-curve",
        "key-direction",
        "key-method",
        "tls-timeout",
        "reneg-sec",
        "reneg-bytes",
        "reneg-pkts",
        "replay-window",
        "mute-replay-warnings",
        "no-replay",
        "remote-cert-tls",
        "remote-cert-ku",
        "remote-cert-eku",
        "ns-cert-type",
        "verify-x509-name",
        "verify-hash",
        "peer-fingerprint",
        "opt-verify",
        # key and cert material: inline only (see _OPENVPN_FILE_REF_DIRECTIVES)
        "ca",
        "cert",
        "key",
        "dh",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "pkcs12",
        "extra-certs",
        "crl-verify",
        "auth-user-pass",
        # authentication behaviour
        "auth-nocache",
        "auth-retry",
        "static-challenge",
        "push-peer-info",
        # compression
        "comp-lzo",
        "compress",
        "allow-compression",
        "comp-noadapt",
        # proxies (credentials inline only, see _OPENVPN_PROXY_SAFE_THIRD_ARGS)
        "http-proxy",
        "http-proxy-option",
        "http-proxy-retry",
        "socks-proxy",
        "socks-proxy-retry",
        # logging verbosity, process, provider-profile metadata
        "verb",
        "mute",
        "suppress-timestamps",
        "mlock",
        "nice",
        "user",
        "group",
        "remap-usr1",
        "ignore-unknown-option",
        # ``setenv NAME value`` only sets a variable for scripts (none can run);
        # ``setenv opt <directive …>`` is checked as that directive.
        "setenv",
    }
)

# OpenVPN directives that make the daemon READ a local file by PATH and can then
# transmit its contents to the (attacker-controlled) server/proxy — e.g.
# `auth-user-pass /etc/wireguard/wgXXX.conf` sends the file's first two lines as
# username/password; `cert /path` sends the file as the client cert. The daemon
# runs as ROOT in the sidecar (with DAC_OVERRIDE), so this is an arbitrary-file
# read/exfiltration primitive for a vpn:write user. All such material MUST be
# supplied INLINE (`<ca>…</ca>`), which FreeSDN materializes into the one .conf —
# so the path/file form of these is rejected. Safe non-path args are allowed.
_OPENVPN_FILE_REF_DIRECTIVES = frozenset(
    {
        "auth-user-pass",
        "ca",
        "capath",
        "cert",
        "key",
        "dh",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "pkcs12",
        "crl-verify",
        "askpass",
        "extra-certs",
        "pkcs11-id",
        "pkcs11-providers",
    }
)
_OPENVPN_SAFE_FILE_REF_ARGS = frozenset({"none", "[inline]"})

# Inline material blocks (``<ca>…</ca>``) whose contents are key/cert payloads,
# not directives, and are skipped. Any other block name is refused, except
# ``<connection>``, whose lines are directives and are checked like the rest.
_OPENVPN_MATERIAL_BLOCKS = frozenset(
    {
        "ca",
        "cert",
        "key",
        "dh",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "pkcs12",
        "extra-certs",
        "crl-verify",
        "auth-user-pass",
        "http-proxy-user-pass",
        "peer-fingerprint",
    }
)

# ``http-proxy host port [authfile|auto|auto-nct] [method]`` and ``socks-proxy
# host port [authfile]``: a third argument that is a path is the same
# read-and-send primitive as ``auth-user-pass /path``. Only keywords are allowed.
_OPENVPN_PROXY_SAFE_THIRD_ARGS = {
    "http-proxy": frozenset({"auto", "auto-nct"}),
    "socks-proxy": frozenset(),
}

# A directive name is a plain lowercase word. Refusing quotes and backslashes
# here matters: OpenVPN unquotes ``"up"`` to ``up``, so comparing raw text
# against a list is only sound when the raw text cannot be quoted.
_OPENVPN_DIRECTIVE_RE = re.compile(r"(?:--)?([a-z0-9][a-z0-9-]*)")
_OPENVPN_SETENV_NAME_RE = re.compile(r"[A-Za-z0-9_]+")
_OPENVPN_BLOCK_TAG_RE = re.compile(r"<(/?)([a-z0-9-]+)>")
# OpenVPN, like the sidecar's awk scanner, splits on spaces and tabs only.
_OPENVPN_TOKEN_SPLIT_RE = re.compile(r"[ \t]+")
_OPENVPN_LINE_STRIP = " \t\r\n\f\v"


def _check_openvpn_directive(tokens: list[str], depth: int = 0) -> None:
    """Refuse one directive line (already split on whitespace) unless allowed."""
    raw = tokens[0]
    match = _OPENVPN_DIRECTIVE_RE.fullmatch(raw)
    if match is None:
        raise ValueError(
            f"OpenVPN directive not allowed: {raw[:40]!r} "
            "(directive names must be plain lowercase words)"
        )
    directive = match.group(1)
    if directive not in _OPENVPN_ALLOWED_DIRECTIVES:
        kind = "Dangerous" if directive in _DANGEROUS_OPENVPN_DIRECTIVES else "Unsupported"
        raise ValueError(f"{kind} OpenVPN directive not allowed: {directive}")
    args = tokens[1:]
    if directive == "setenv":
        if not args or _OPENVPN_SETENV_NAME_RE.fullmatch(args[0]) is None:
            raise ValueError("OpenVPN 'setenv' needs a plain variable name")
        if args[0].lower() == "opt":
            # ``setenv opt <directive …>`` makes OpenVPN process the rest of the
            # line as a directive (ignored if unknown), so check it as one.
            if len(args) < 2 or depth >= 2:
                raise ValueError("OpenVPN 'setenv opt' must name one allowed directive")
            _check_openvpn_directive(args[1:], depth + 1)
        return
    if directive in _OPENVPN_FILE_REF_DIRECTIVES and args:
        if "'" in args[0] or args[0].replace('"', "").lower() not in _OPENVPN_SAFE_FILE_REF_ARGS:
            raise ValueError(
                f"OpenVPN '{directive}' must be supplied inline "
                f"(<{directive}>…</{directive}>), not as a file path"
            )
    safe_third = _OPENVPN_PROXY_SAFE_THIRD_ARGS.get(directive)
    if safe_third is not None and len(args) > 2:
        third = args[2]
        if "'" in third or third.replace('"', "").lower() not in safe_third:
            raise ValueError(
                f"OpenVPN '{directive}' credentials must be supplied inline "
                "(<http-proxy-user-pass>), not as a file path"
            )


def _assert_openvpn_config_safe(v: str | None) -> str | None:
    """Refuse OpenVPN config text unless every directive is on the allowlist.

    Inline material blocks (``<ca>``, ``<cert>``, ``<key>``, ``<tls-auth>``, …)
    are key/cert payloads and are skipped; ``<connection>`` blocks are checked
    line by line; any other, nested, stray or unterminated block is refused.
    Comment lines start with ``#`` or ``;``. A trailing comment on a directive
    line is NOT stripped, so a ``#`` can never hide an argument from the checks.
    """
    if not v:
        return v
    material: str | None = None
    in_connection = False
    for raw in v.split("\n"):
        line = raw.strip(_OPENVPN_LINE_STRIP)
        if material is not None:
            if line == f"</{material}>":
                material = None
            continue
        if not line or line[0] in "#;":
            continue
        if any(c == "\x7f" or (c < " " and c != "\t") for c in line):
            raise ValueError("OpenVPN config contains a control character")
        if line.startswith("<"):
            tag = _OPENVPN_BLOCK_TAG_RE.fullmatch(line)
            if tag is None:
                raise ValueError(f"Malformed OpenVPN block tag: {line[:40]!r}")
            closing, name = tag.group(1) == "/", tag.group(2)
            if name == "connection":
                if closing == in_connection:
                    in_connection = not closing
                    continue
                raise ValueError("Nested or stray OpenVPN <connection> block")
            if closing or in_connection or name not in _OPENVPN_MATERIAL_BLOCKS:
                raise ValueError(f"Unsupported OpenVPN block: {line[:40]}")
            material = name
            continue
        _check_openvpn_directive(_OPENVPN_TOKEN_SPLIT_RE.split(line))
    if material is not None or in_connection:
        raise ValueError("Unterminated OpenVPN block")
    return v


# wg-quick runs these INI keys as shell commands when bringing an interface up or
# down — an authed vpn:write user supplying a WireGuard config is not trusted to
# run code on the appliance, so they are rejected (host-RCE prevention).
_DANGEROUS_WIREGUARD_KEYS = frozenset({"postup", "postdown", "preup", "predown"})


def _assert_wireguard_config_safe(v: str | None) -> str | None:
    """Reject WireGuard wg-quick config text containing a command-executing key."""
    if not v:
        return v
    for line in v.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            # INI form is "Key = value"; compare the key case-insensitively.
            key = stripped.split("=", 1)[0].strip().lower()
            if key in _DANGEROUS_WIREGUARD_KEYS:
                raise ValueError(f"Dangerous WireGuard directive not allowed: {key}")
    return v


# Free-form extra_data must not become a back door for write-only secrets: a key
# ending in one of these has a dedicated, ENCRYPTED column (setup key / config
# text / private key) and storing it in extra_data would leak it to vpn:read users
# (the redactor also masks these now, but reject on write so they never land in
# the clear in the first place). publicKey is intentionally allowed.
_EXTRA_DATA_SECRET_SUFFIXES = ("setup_key", "config_content", "private_key")


def _assert_extra_data_no_secret_keys(v: dict | None) -> dict | None:
    if v:
        for k in v:
            norm = str(k).lower().replace("-", "_")
            if norm != "public_key" and norm.endswith(_EXTRA_DATA_SECRET_SUFFIXES):
                raise ValueError(
                    f"extra_data key '{k}' looks like a secret — use the dedicated "
                    "encrypted field, not free-form extra_data"
                )
    return v


# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampSchema(BaseSchema):
    created_at: datetime
    updated_at: datetime


# =============================================================================
# VPN Connection
# =============================================================================


class VPNConnectionResponse(BaseSchema):
    """Matches frontend VPNConnection interface."""

    id: str
    name: str
    vpn_type: str
    status: str
    endpoint: str | None = None
    port: int | None = None
    allowed_ips: list[str] | None = None
    connected_at: str | None = None
    connected_since: str | None = None
    last_handshake: str | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    latency_ms: float | None = None
    local_ip: str | None = None
    remote_ip: str | None = None
    dns_servers: list[str] | None = None
    extra_data: dict[str, Any] | None = None
    openvpn_config_path: str | None = None
    openvpn_protocol: str | None = None
    netbird_management_url: str | None = None
    organization_id: str | None = None


class VPNConnectionCreate(BaseSchema):
    """Create a new VPN connection."""

    name: str = Field(..., min_length=1, max_length=255)
    vpn_type: VPNType
    endpoint: str | None = None
    port: int | None = None
    local_ip: str | None = None
    remote_ip: str | None = None
    allowed_ips: list[str] | None = None
    dns_servers: list[str] | None = None
    # OpenVPN
    openvpn_config_path: str | None = None
    openvpn_protocol: str | None = None
    # Full .ovpn text; materialized to disk at connect time. Encrypted at rest by
    # the endpoint. Validated against host-RCE directives (see validator below).
    openvpn_config_content: str | None = Field(default=None, max_length=102400)
    # Full wg-quick INI; materialized to /etc/wireguard/<iface>.conf at connect
    # time. Encrypted at rest. Validated against PostUp/PostDown/PreUp/PreDown.
    wireguard_config_content: str | None = Field(default=None, max_length=102400)
    # Netbird
    netbird_setup_key: str | None = None
    netbird_management_url: str | None = None
    extra_data: dict[str, Any] | None = None

    @field_validator("openvpn_config_content", mode="before")
    @classmethod
    def validate_openvpn_config_safe(cls, v: str | None) -> str | None:
        return _assert_openvpn_config_safe(v)

    @field_validator("wireguard_config_content", mode="before")
    @classmethod
    def validate_wireguard_config_safe(cls, v: str | None) -> str | None:
        return _assert_wireguard_config_safe(v)

    @field_validator("extra_data", mode="before", check_fields=False)
    @classmethod
    def limit_extra_data_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None:
            import json

            if len(json.dumps(v)) > 65536:
                raise ValueError("extra_data exceeds 64KB limit")
        return _assert_extra_data_no_secret_keys(v)


class VPNConnectionUpdate(BaseSchema):
    """Update a VPN connection."""

    name: str | None = None
    vpn_type: VPNType | None = None
    endpoint: str | None = None
    port: int | None = None
    local_ip: str | None = None
    remote_ip: str | None = None
    allowed_ips: list[str] | None = None
    dns_servers: list[str] | None = None
    openvpn_config_path: str | None = None
    openvpn_protocol: str | None = None
    openvpn_config_content: str | None = Field(default=None, max_length=102400)
    wireguard_config_content: str | None = Field(default=None, max_length=102400)
    netbird_setup_key: str | None = None
    netbird_management_url: str | None = None
    extra_data: dict[str, Any] | None = None

    @field_validator("openvpn_config_content", mode="before")
    @classmethod
    def validate_openvpn_config_safe(cls, v: str | None) -> str | None:
        return _assert_openvpn_config_safe(v)

    @field_validator("wireguard_config_content", mode="before")
    @classmethod
    def validate_wireguard_config_safe(cls, v: str | None) -> str | None:
        return _assert_wireguard_config_safe(v)

    @field_validator("extra_data", mode="before", check_fields=False)
    @classmethod
    def limit_extra_data_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None:
            import json

            if len(json.dumps(v)) > 65536:
                raise ValueError("extra_data exceeds 64KB limit")
        return _assert_extra_data_no_secret_keys(v)


# =============================================================================
# Tailscale
# =============================================================================


class TailscaleNodeResponse(BaseSchema):
    """Matches frontend TailscaleNode interface."""

    id: str
    name: str
    hostname: str
    dns_name: str
    tailscale_ip: str | None = None
    tailscale_ips: list[str] = Field(default_factory=list)
    public_ip: str | None = None
    advertised_routes: list[str] | None = None
    status: str = "offline"
    online: bool = False
    is_exit_node: bool = False
    relay: str | None = None
    direct: bool = False
    os: str = ""
    user: str | None = None
    tags: list[str] | None = None


class TailscaleStatusResponse(BaseSchema):
    """Matches frontend TailscaleStatus interface."""

    connected: bool = False
    backend_state: str = "Unknown"
    tailnet_name: str | None = None
    magic_dns_suffix: str | None = None
    magic_dns_enabled: bool = False
    has_exit_node: bool = False
    self_node: TailscaleNodeResponse | None = None
    peers: list[TailscaleNodeResponse] = Field(default_factory=list)
    peer_count: int = 0


# =============================================================================
# Tailscale Setup / Enrollment
# =============================================================================


class TailscaleSetupStatusResponse(BaseSchema):
    """Full Tailscale agent setup status."""

    state: str = "not_installed"  # not_installed | daemon_stopped | needs_login | awaiting_auth | disconnected | connected | error
    installed: bool = False
    daemon_running: bool = False
    authenticated: bool = False
    connected: bool = False
    version: str | None = None
    hostname: str | None = None
    tailscale_ip: str | None = None
    tailscale_ips: list[str] = Field(default_factory=list)
    tailnet: str | None = None
    magic_dns_suffix: str | None = None
    magic_dns_enabled: bool = False
    online: bool = False
    os: str | None = None
    login_url: str | None = None
    peer_count: int = 0
    message: str = ""


class _TailscaleInputMixin:
    """Shared validators for Tailscale hostname and routes."""

    @field_validator("hostname", mode="before", check_fields=False)
    @classmethod
    def validate_hostname(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import re

        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$", v):
            raise ValueError(
                "hostname must be RFC 1123 compliant (alphanumeric + hyphens, max 63 chars)"
            )
        return v

    @field_validator("advertise_routes", mode="before", check_fields=False)
    @classmethod
    def validate_routes(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        import ipaddress

        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR in advertise_routes: {cidr!r}")
        return v


class TailscaleAuthKeyLoginRequest(BaseSchema, _TailscaleInputMixin):
    """Login with a pre-authenticated Tailscale auth key."""

    auth_key: str = Field(..., min_length=1, description="Tailscale auth key (tskey-auth-...)")
    hostname: str | None = Field(None, description="Override the machine hostname on the tailnet")
    accept_routes: bool = Field(True, description="Accept subnet routes advertised by other nodes")
    advertise_routes: list[str] | None = Field(
        None, description="CIDR subnets to advertise (e.g., ['192.168.1.0/24'])"
    )
    advertise_exit_node: bool = Field(False, description="Advertise this node as an exit node")
    shields_up: bool = Field(
        False, description="Block incoming connections from other tailnet nodes"
    )


class TailscaleInteractiveLoginRequest(BaseSchema, _TailscaleInputMixin):
    """Start browser-based interactive login."""

    hostname: str | None = Field(None, description="Override the machine hostname on the tailnet")
    accept_routes: bool = Field(True, description="Accept subnet routes from other nodes")


class TailscaleLoginResponse(BaseSchema):
    """Result of a login attempt."""

    success: bool = False
    message: str = ""
    state: str = ""
    login_url: str | None = None
    hostname: str | None = None
    tailscale_ip: str | None = None
    tailnet: str | None = None


class TailscaleConfigureRequest(BaseSchema, _TailscaleInputMixin):
    """Reconfigure a running Tailscale agent."""

    hostname: str | None = None
    accept_routes: bool | None = None
    advertise_routes: list[str] | None = None
    accept_dns: bool | None = None
    advertise_exit_node: bool | None = None
    shields_up: bool | None = None


class TailscaleActionResponse(BaseSchema):
    """Generic result for setup actions (start, logout, disconnect, reconnect)."""

    success: bool = False
    message: str = ""
    state: str | None = None


# =============================================================================
# VPN Subnet
# =============================================================================


class VPNSubnetResponse(BaseSchema):
    """Matches frontend VPNSubnet interface."""

    subnet: str
    via: str
    node: str | None = None
    interface: str | None = None
    direct: bool = False


# =============================================================================
# Site VPN Config
# =============================================================================


class SiteVPNConfigResponse(TimestampSchema):
    """Matches frontend SiteVPNConfig interface."""

    id: UUID
    site_id: UUID
    vpn_type: str
    enabled: bool = True
    auto_connect: bool = True
    is_primary: bool = False
    priority: int = 0
    # Brain-VPN
    controller_id: UUID | None = None
    vpn_source: str = "manual"
    brain_vpn_server_id: str | None = None
    last_config_sync: datetime | None = None
    # Tailscale
    tailscale_node: str | None = None
    tailscale_hostname: str | None = None
    tailscale_tags: list[str] | None = None
    # WireGuard
    wireguard_interface: str | None = None
    wireguard_endpoint: str | None = None
    wireguard_peer_public_key: str | None = None
    wireguard_allowed_ips: list[str] | None = None
    # Generic
    vpn_endpoint: str | None = None
    vpn_port: int | None = None
    # Health
    health_check_ip: str | None = None
    health_check_interval: int = 60
    remote_subnets: list[str] | None = None
    local_subnets: list[str] | None = None
    # OpenVPN
    openvpn_config_path: str | None = None
    openvpn_protocol: str | None = None
    openvpn_mode: str | None = None
    # ZeroTier
    zerotier_network_id: str | None = None
    zerotier_node_id: str | None = None
    # Netbird
    netbird_peer_id: str | None = None
    netbird_group: str | None = None
    # Status
    status: str = "not_configured"
    last_health_check: datetime | None = None
    # Certificate metadata
    cert_metadata: dict[str, Any] | None = None
    cert_expires_at: datetime | None = None
    # Organization scope
    organization_id: UUID | None = None


class SiteVPNConfigCreate(BaseSchema):
    vpn_type: VPNType = VPNType.TAILSCALE
    enabled: bool = True
    auto_connect: bool = True
    is_primary: bool = False
    priority: int = Field(default=0, ge=0, le=100)
    # Brain-VPN
    controller_id: UUID | None = None
    vpn_source: str = Field(default="manual", max_length=20)
    # Tailscale
    tailscale_node: str | None = Field(default=None, max_length=255)
    tailscale_hostname: str | None = Field(default=None, max_length=255)
    # WireGuard
    wireguard_interface: str | None = Field(default=None, max_length=50)
    wireguard_endpoint: str | None = Field(default=None, max_length=255)
    wireguard_peer_public_key: str | None = Field(default=None, max_length=255)
    # Generic
    vpn_endpoint: str | None = Field(default=None, max_length=255)
    vpn_port: int | None = None
    # Health
    health_check_ip: str | None = Field(default=None, max_length=45)
    remote_subnets: list[str] | None = None
    local_subnets: list[str] | None = None
    # OpenVPN
    openvpn_config_path: str | None = Field(default=None, max_length=500)
    openvpn_protocol: str | None = Field(default=None, max_length=10)
    openvpn_config_content: str | None = Field(default=None, max_length=102400)
    openvpn_mode: str | None = Field(default=None, max_length=10)
    # ZeroTier
    zerotier_network_id: str | None = Field(default=None, max_length=16)
    zerotier_node_id: str | None = Field(default=None, max_length=10)
    # Netbird
    netbird_peer_id: str | None = Field(default=None, max_length=255)
    netbird_group: str | None = Field(default=None, max_length=255)

    @field_validator("openvpn_config_content", mode="before")
    @classmethod
    def validate_openvpn_config_safe(cls, v: str | None) -> str | None:
        return _assert_openvpn_config_safe(v)


class SiteVPNConfigUpdate(BaseSchema):
    vpn_type: VPNType | None = None
    enabled: bool | None = None
    auto_connect: bool | None = None
    is_primary: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=100)
    # Brain-VPN
    controller_id: UUID | None = None
    vpn_source: str | None = Field(default=None, max_length=20)
    # Tailscale
    tailscale_node: str | None = Field(default=None, max_length=255)
    tailscale_hostname: str | None = Field(default=None, max_length=255)
    # WireGuard
    wireguard_interface: str | None = Field(default=None, max_length=50)
    wireguard_endpoint: str | None = Field(default=None, max_length=255)
    wireguard_peer_public_key: str | None = Field(default=None, max_length=255)
    # Generic
    vpn_endpoint: str | None = Field(default=None, max_length=255)
    vpn_port: int | None = None
    # Health
    health_check_ip: str | None = Field(default=None, max_length=45)
    remote_subnets: list[str] | None = None
    local_subnets: list[str] | None = None
    # OpenVPN
    openvpn_config_path: str | None = Field(default=None, max_length=500)
    openvpn_protocol: str | None = Field(default=None, max_length=10)
    openvpn_config_content: str | None = Field(default=None, max_length=102400)
    openvpn_mode: str | None = Field(default=None, max_length=10)
    # ZeroTier
    zerotier_network_id: str | None = Field(default=None, max_length=16)
    zerotier_node_id: str | None = Field(default=None, max_length=10)
    # Netbird
    netbird_peer_id: str | None = Field(default=None, max_length=255)
    netbird_group: str | None = Field(default=None, max_length=255)

    @field_validator("openvpn_config_content", mode="before")
    @classmethod
    def validate_openvpn_config_safe(cls, v: str | None) -> str | None:
        return _assert_openvpn_config_safe(v)


# =============================================================================
# Connectivity
# =============================================================================


class ConnectivityCheckRequest(BaseSchema):
    target: str = Field(..., min_length=1, max_length=253, pattern=r"^[a-zA-Z0-9.\-:]+$")


class ConnectivityCheckResponse(BaseSchema):
    target: str
    reachable: bool = False
    latency_ms: float | None = None
    connection_type: str | None = None


# =============================================================================
# Health Check
# =============================================================================


class VPNHealthCheckResponse(BaseSchema):
    time: str
    connection_id: str
    site_id: str | None = None
    is_healthy: bool = False
    latency_ms: float | None = None
    status: str
    error_message: str | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    peer_count: int = 0


class VPNStatusSummaryResponse(BaseSchema):
    """Overall VPN status summary."""

    total_connections: int = 0
    connected: int = 0
    disconnected: int = 0
    error: int = 0
    tailscale_connected: bool = False
    wireguard_tunnels: int = 0
    total_peers: int = 0
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0


# =============================================================================
# Netbird
# =============================================================================


class NetbirdPeerResponse(BaseSchema):
    """Netbird peer info."""

    id: str
    name: str
    hostname: str
    ip: str
    status: str = "disconnected"
    direct: bool = False
    relay: str | None = None
    last_handshake: str | None = None
    routes: list[str] = Field(default_factory=list)


class NetbirdStatusResponse(BaseSchema):
    """Netbird daemon status."""

    connected: bool = False
    management_state: str = "Unknown"
    signal_state: str = "Unknown"
    management_url: str | None = None
    self_ip: str | None = None
    fqdn: str | None = None
    interface: str | None = None
    peers: list[NetbirdPeerResponse] = Field(default_factory=list)
    peer_count: int = 0
    connected_peers: int = 0


# =============================================================================
# OpenVPN
# =============================================================================


class OpenVPNStatusResponse(BaseSchema):
    """OpenVPN connection status."""

    name: str
    status: str
    connected: bool = False
    local_ip: str | None = None
    remote_ip: str | None = None
    bytes_received: int = 0
    bytes_sent: int = 0


# =============================================================================
# Provider Info
# =============================================================================


class VPNProviderInfo(BaseSchema):
    """Info about a supported VPN provider."""

    id: str
    name: str
    description: str
    icon: str
    supported: bool = True
    installed: bool = False
    features: list[str] = Field(default_factory=list)


class VPNProvidersResponse(BaseSchema):
    """List of all supported VPN providers."""

    providers: list[VPNProviderInfo]


# =============================================================================
# Connection Action
# =============================================================================


class VPNConnectionActionRequest(BaseSchema):
    """Request to connect/disconnect a VPN."""

    action: str = Field(..., pattern="^(connect|disconnect)$")


class VPNConnectionActionResponse(BaseSchema):
    """Result of a connect/disconnect action."""

    success: bool
    message: str
    connection_id: str | None = None


# =============================================================================
# Reconnect State
# =============================================================================


class VPNReconnectStatusResponse(BaseSchema):
    """Auto-reconnect state for a VPN connection."""

    connection_id: str
    attempt_count: int = 0
    max_attempts: int = 10
    next_retry_at: str | None = None
    backoff_seconds: int = 30
    state: str = "idle"  # idle | retrying | exhausted | success
    last_error: str | None = None


# =============================================================================
# VPN Event
# =============================================================================


class VPNEventResponse(BaseSchema):
    """VPN audit trail event."""

    id: str
    organization_id: str
    site_id: str | None = None
    connection_id: str | None = None
    tunnel_id: str | None = None
    event_type: str
    severity: str = "info"
    title: str
    details: dict[str, Any] = {}
    source: str | None = None
    actor_id: str | None = None
    created_at: str


class VPNEventListResponse(BaseSchema):
    """Paginated VPN events list."""

    events: list[VPNEventResponse]
    total: int


class VPNEventSummaryResponse(BaseSchema):
    """VPN event counts by type and severity."""

    total: int = 0
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    period_hours: int = 24


# =============================================================================
# Preflight
# =============================================================================


class PreflightResultResponse(BaseSchema):
    """VPN pre-flight check result."""

    reachable: bool = False
    vpn_type: str | None = None
    latency_ms: float | None = None
    vpn_status: str | None = None
    error: str | None = None
    skipped: bool = False


class DeviceReachabilityResponse(BaseSchema):
    """Per-device reachability result."""

    device_id: str
    device_name: str
    device_type: str
    ip: str | None = None
    reachable: bool = False
    latency_ms: float | None = None
    error: str | None = None


class SiteReachabilityResponse(BaseSchema):
    """Site-wide device reachability results."""

    site_id: str
    vpn_status: str | None = None
    devices: list[DeviceReachabilityResponse] = []


# =============================================================================
# Metrics
# =============================================================================


class VPNMetricsBucketResponse(BaseSchema):
    """Time-bucketed VPN bandwidth/latency metrics."""

    time: str
    avg_latency_ms: float | None = None
    max_latency_ms: float | None = None
    rx_bytes_delta: int = 0
    tx_bytes_delta: int = 0
    health_pct: float = 100.0  # percentage of checks that were healthy


class VPNAggregateMetricsResponse(BaseSchema):
    """Org-wide aggregate VPN metrics."""

    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    avg_latency_ms: float | None = None
    connection_count: int = 0
    by_provider: dict[str, dict[str, Any]] = {}


# =============================================================================
# Health Config
# =============================================================================


class VPNHealthConfigUpdate(BaseSchema):
    """Update health check settings for a connection/site config."""

    health_check_interval: int | None = Field(default=None, ge=30, le=3600)
    health_check_ip: str | None = Field(default=None, max_length=45)
    latency_threshold_ms: int | None = Field(default=None, ge=50, le=5000)


# =============================================================================
# Dashboard Widget
# =============================================================================


class VPNDashboardResponse(BaseSchema):
    """Pre-aggregated dashboard widget data."""

    active_connections: int = 0
    healthy_pct: float = 100.0
    avg_latency_ms: float | None = None
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    active_tunnels: int = 0
    error_tunnels: int = 0
    vpn_alerts: int = 0
    sites_with_vpn: int = 0
    sites_healthy: int = 0


# =============================================================================
# Route Conflict Detection
# =============================================================================


class VPNRouteConflict(BaseSchema):
    """A single route conflict between two VPN sources."""

    subnet: str
    source_a: str  # e.g. "wireguard:wg0"
    source_b: str  # e.g. "tailscale:100.64.0.0/10"
    source_a_type: str  # connection | tunnel | site_config
    source_b_type: str
    severity: str = "warning"  # warning | error (exact overlap = error)
    overlap_type: str = "subset"  # exact | subset | superset


class VPNRouteConflictsResponse(BaseSchema):
    """All detected route conflicts."""

    conflicts: list[VPNRouteConflict] = []
    total: int = 0
    scanned_sources: int = 0


# =============================================================================
# Certificate Lifecycle
# =============================================================================


class VPNCertMetadata(BaseSchema):
    """Certificate metadata for OpenVPN/IPsec configs."""

    issuer: str | None = None
    subject: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    fingerprint: str | None = None
    days_until_expiry: int | None = None


class VPNCertExpiryAlert(BaseSchema):
    """Certificate approaching expiry."""

    config_id: str
    site_id: str
    site_name: str | None = None
    vpn_type: str
    cert_subject: str | None = None
    expires_at: str
    days_remaining: int
    severity: str = "info"  # info (>30d), warning (7-30d), error (1-7d), critical (<1d)


class VPNCertExpiryResponse(BaseSchema):
    """All certificates with upcoming expirations."""

    certs: list[VPNCertExpiryAlert] = []
    total: int = 0


# =============================================================================
# MTU/MSS Tuning
# =============================================================================


class VPNTunnelTuningUpdate(BaseSchema):
    """Update MTU/MSS settings for a tunnel template."""

    mtu: int | None = Field(default=None, ge=576, le=9000)
    mss_clamp: int | None = Field(default=None, ge=536, le=8960)
