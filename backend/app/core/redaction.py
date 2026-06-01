# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Adapter secret redaction
==================================

Shared helper that strips sensitive fields from controller responses
before they reach API consumers. Every adapter (Omada, OPNsense,
pfSense, Proxmox, MikroTik, ...) leaks vendor-specific secret material
in different field names; centralising the strip-list keeps each
service free of vendor minutiae and makes it cheap to add new fields
when a new vendor lands.

Lives under ``app.core`` (not ``app.services``) because adapter
modules import it at module load time, and the ``app.services``
package init eagerly imports ``discovery`` which transitively
imports adapters — that creates a circular-import deadlock at
startup. ``app.core`` has no such transitive load chain.

Read-path responses MUST pass through :func:`redact_secrets` before
being returned. The function is recursion-bounded (depth cap) so a
hostile / malformed controller response cannot blow the stack.
"""

from __future__ import annotations

import re
from typing import Any

# Master strip-list. Lower-cased; matched against the *normalised*
# key (``key.lower().replace("-", "_")``) so RouterOS-style
# hyphenated keys (``private-key``, ``pre-shared-key``,
# ``radius-secret``, ``auth-key``) collapse to the same underscored
# entries as Proxmox/OPNsense JSON. Each grouping documents which
# adapter contributes the field name so it's clear why the entry
# exists.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        # Generic auth credentials — apply across every adapter.
        "password",
        "hashed_password",
        "secret",
        "api_key",
        "apikey",  # no-underscore spelling (won't normalize to api_key)
        "api_secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "credential",  # singular (the divergent VPN redactor caught this)
        "credentials",
        "setup_key",  # Tailscale/VPN provider auth key
        "cookie",
        "session_token",
        "encryption_key",
        "passphrase",
        "passwd",
        # Cryptographic material — VPN / certificates / SSH.
        "private_key",
        "privkey",
        "priv_key",
        # NOTE: ``public_key`` is intentionally NOT redacted — the
        # whole point of a public key is that it's public, and the
        # UI uses it as the stable identifier on WireGuard peer rows
        # (the row .id rotates; the public key doesn't). Masking it
        # broke per-peer update/delete dialog matching.
        "ssh_key",
        "sshkeys",  # Proxmox cloud-init
        "psk",  # OPNsense / pfSense WireGuard / IPsec
        "pre_shared_key",
        "preshared_key",  # WireGuard
        "tls_key",  # OpenVPN
        "tls_auth",
        "tls_crypt",
        "shared_key",
        "ca_key",
        "auth_key",  # RouterOS OSPF/BGP authentication-key
        "key_passphrase",  # RouterOS certificate sign
        "private_key_passphrase",  # RouterOS cert import passphrase
        # Certificate / chain material — redacted because
        # certificate bodies frequently include the issuer's full
        # PEM (and OPNsense / pfSense ship them inline on read);
        # masking the public certs keeps response shape consistent
        # with the masked private keys in the same row.
        "cert",
        "certificate",
        "ca",
        "ca_chain",
        "crl",
        "dh",  # Diffie-Hellman params (large, slow, secret-adjacent)
        "tls_certificate",  # RouterOS / CAPsMAN
        # Cloud-init / VM provisioning that ships secrets in the body.
        "cipassword",  # Proxmox cloud-init password
        "args",  # Proxmox VM args (often contains creds)
        "hookscript",  # Proxmox hook script path (may leak intent)
        # Hotspot / PPP / RADIUS / SNMP — RouterOS surfaces these as
        # plain top-level keys on read.
        "auth_user_pass",
        "radius_secret",  # underscore form
        "snmp_community",
        "community",  # RouterOS /snmp/community 'name' field is
        # the actual community string — redact via this alias rather
        # than walking 'name' globally
        # SNMPv3 — RouterOS surfaces SNMPv3 user secrets in plaintext on
        # the /snmp/users row. The hyphen-to-underscore normalisation
        # collapses RouterOS' ``auth-password`` / ``encryption-password``
        # to the underscored form below. Both the short (``auth-password``)
        # and the long (``authentication-password``, ``encryption-password``)
        # SNMPv3 keys are listed because the FE submits the long forms via
        # ``MikroTikSnmpTab.tsx`` while reads surface the short forms — the
        # drawer renders staged payloads verbatim, so both shapes must be
        # masked.
        "auth_password",
        "authentication_password",
        "encryption_password",
        "mschapv2_password",  # RADIUS / PEAP-MSCHAPv2 echoes
        # RouterOS-specific keys formerly redacted by per-service
        # ``_mask_routeros`` helpers. Centralising here closes the
        # double-walk perf hit and prevents per-service drift.
        "shared_secret",  # IPsec / RADIUS shared secret
        "ipsec_secret",  # RouterOS /ip/ipsec preshared
        "private_key_file",  # RouterOS cert file reference
        "auth_secret",  # RouterOS routing auth
        # Two-factor / OTP material.
        "mfa_secret",
        "mfa_backup_codes",
        "otp_secret",
        # UniFi-specific. UniFi WLAN objects
        # expose ``x_passphrase`` as the live PSK and ``x_iapp_key`` as
        # the Inter-AP protocol shared key — both flow through every
        # ``GET /rest/wlanconf`` response and would otherwise reach
        # the FE in plain text.
        "x_passphrase",
        "x_iapp_key",
        "x_xstauthkey",  # 802.1X EAP key occasionally surfaced
        "x_xstcrypt",  # legacy cipher material
        # x_password is the RADIUS account secret returned verbatim by UniFi's
        # GET /rest/account (surfaced via adapter.list_radius_users); x_authkey is
        # a sibling x_* secret. Neither normalizes to a base key (no camelCase
        # boundary, x_authkey != auth_key), so they need explicit entries.
        "x_password",
        "x_authkey",
        # x_ssh_password is the plaintext device SSH login password UniFi pushes to
        # adopted APs/switches/gateways (grants an interactive shell), and x_vwirekey
        # is the wireless-uplink/mesh pre-shared key — both ship inline on
        # GET /stat/device // /rest/device (adapter.list_devices) and neither
        # normalizes to a base key (x_ssh_password != password, no camelCase
        # boundary, x_vwirekey has no matching suffix), so they need explicit
        # entries. ``ssh_password`` (generic) covers the non-x_ form on other
        # adapters.
        "x_ssh_password",
        "ssh_password",
        "x_vwirekey",
        # OPNsense / pfSense WireGuard / IPsec inline fields that the
        # vendor API ships with the rule body.
        "wpa_psk",  # UniFi/OpenWrt wireless PSK alias
        "wireguard_private_key",
        "wireguard_psk",
        # Proxmox-specific. Cloud-init user-data and
        # boot commands embed passwords / secrets verbatim; the proxy
        # tickets are short-lived but should never reach the FE; and
        # backup/replication targets ship credentials with the job.
        "ciuserdata",  # cloud-init user-data (raw YAML with creds)
        "cinetuserdata",  # cloud-init network user-data
        "cibootcmd",  # cloud-init boot commands
        "ciupgrade",  # cloud-init upgrade payload
        "vncticket",  # QEMU VNC proxy ticket
        "ticket",  # generic Proxmox proxy ticket
        "csrf_prevention_token",  # Proxmox CSRF token
        "target_password",  # replication / migration target creds
        "acme_account_key",  # ACME / Let's Encrypt account keypair
        "registration_password",  # SDN controller registration auth
        "bindpw",  # LDAP realm bind password
        # LDAP bind password — Omada ships it as camelCase ``bindPassword``,
        # which the camelCase-aware _norm_key collapses to ``bind_password``;
        # the underscore-less ``bindpassword`` covers an already-lowercased
        # source.
        "bind_password",
        "bindpassword",
        # WLAN PSK — Omada SSID payloads ship the live key as camelCase
        # ``pskSetting.securityKey`` -> ``security_key``.
        "security_key",
        "securitykey",
        # WireGuard/IPsec PSK already-lowercased collapsed form:
        # ``presharedKey``.lower() == ``presharedkey`` with no underscore.
        "presharedkey",
        # FreePBX trunk secret (HTML-scraped ``sipSecret`` -> ``sip_secret``).
        "sip_secret",
        "client_key",  # TLS client key
        "owner_password",  # generic owner credential pattern
        # Proxmox backup pre/post scripts leak operator filesystem
        # layout — not a credential, but reconnaissance-grade info.
        "prescript",
        "postscript",
    }
)

# Prefix-match patterns for keys that vary by index/suffix. Proxmox
# emits ``ipconfig0``..``ipconfig31`` for cloud-init NICs and these
# strings often carry inline passwords (``ip=...,gw=...,user=root,
# password=hunter2`` for some image flavours). Exact-key matching
# misses the index suffix; the prefix walk below catches them.
_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "ipconfig",  # Proxmox cloud-init per-NIC config strings
)

# Suffix patterns: a key ENDING in one of these is sensitive regardless of its
# provider prefix. Catches the VPN write-only fields a user could smuggle into
# free-form extra_data (e.g. ``netbird_setup_key``, ``openvpn_config_content``,
# ``wireguard_config_content``, ``config_content``) which the exact strip-list
# missed — so a vpn:read user couldn't read them back out of extra_data.
_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    "setup_key",
    "config_content",
    "private_key",
    # UniFi VPN networkconf ships PSK/secret material on read under x_-prefixed
    # compound names that don't collapse to an exact strip-list entry
    # (x_ipsec_pre_shared_key, x_wireguard_preshared_key, x_radius_secret,
    # x_*_shared_secret). Suffix-match them generically, exactly like
    # ``private_key`` already saves x_wireguard_private_key (audit #3 F1).
    "pre_shared_key",
    "preshared_key",
    "radius_secret",
    "shared_secret",
)


# Insert an underscore at camelCase / PascalCase boundaries so vendor keys
# like ``preSharedKey`` / ``securityKey`` / ``apiSecret`` / ``APIKey`` collapse
# onto the underscored strip-list entries. Two alternatives:
#   lower|digit -> Upper      (preShared -> pre_Shared)
#   Upper -> Upper+lower      (APIKey   -> API_Key, handles acronym runs)
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _norm_key(key: str) -> str:
    """Normalise a JSON key for sensitive-key matching.

    Splits camelCase/PascalCase boundaries, then lower-cases and converts
    hyphens to underscores — so RouterOS ``private-key``, Proxmox
    ``private_key``, and Omada ``privateKey`` all collapse to the same
    strip-list entry. Without the camelCase split, camelCase
    vendor secret keys like ``preSharedKey`` / ``securityKey`` / ``apiSecret``
    silently passed the redactor unmasked.

    NOTE: ``publicKey`` -> ``public_key`` which is intentionally absent from
    the strip-list, so the WireGuard public-key carve-out is preserved.
    """
    return _CAMEL_BOUNDARY_RE.sub("_", key).lower().replace("-", "_")


# Maximum depth the recursive walk will descend. Bounded so a
# self-referential or pathologically nested controller response
# can't blow the Python stack (default recursion limit ~1000).
_MAX_DEPTH = 16

_REDACTED = "***"


def _key_is_sensitive(key: str) -> bool:
    """Match a key against the strip-list AND the prefix-match patterns.

    Exact match wins fast; otherwise we test prefix patterns where the
    sensitive key is followed by digits (covers Proxmox cloud-init's
    ``ipconfig0``..``ipconfig31``). New cases get added to
    ``_SENSITIVE_KEYS`` or ``_SENSITIVE_PREFIXES`` — this helper is
    the single chokepoint.
    """
    norm = _norm_key(key)
    if norm in _SENSITIVE_KEYS:
        return True
    for prefix in _SENSITIVE_PREFIXES:
        if norm.startswith(prefix) and len(norm) > len(prefix) and norm[len(prefix) :].isdigit():
            return True
    # ``publicKey`` -> ``public_key`` must stay UNmasked (WireGuard pubkey carve-
    # out), so only suffix-match keys that aren't the public-key case.
    if norm != "public_key":
        for suffix in _SENSITIVE_SUFFIXES:
            if norm.endswith(suffix):
                return True
    return False


def redact_secrets(payload: Any, *, depth: int = 0) -> Any:
    """Return ``payload`` with sensitive keys masked as ``"***"``.

    Walks dicts and lists recursively, replacing the *value* of any
    key that matches the strip-list with the string ``"***"`` (rather
    than dropping it — keeping the key shape lets the UI render
    redacted-field markers without conditional logic).

    Stops descending at :data:`_MAX_DEPTH`; deeper structures are
    returned unchanged. Non-container leaves are returned as-is.

    Args:
        payload: Any value — typically a dict or list of dicts that
            came back from a controller.
        depth: Internal recursion counter. Callers pass nothing.

    Returns:
        A new structure with redactions applied. Original payload is
        not mutated.
    """
    if depth >= _MAX_DEPTH:
        # do NOT return a nested container unchanged at the
        # depth cap — a secret-keyed subtree beyond the limit would leak
        # un-redacted. Mask any remaining container wholesale; scalar leaves
        # carry no nested secret and are safe to pass through.
        return _REDACTED if isinstance(payload, (dict, list, tuple)) else payload
    if isinstance(payload, dict):
        return {
            k: (
                _REDACTED
                if isinstance(k, str) and _key_is_sensitive(k)
                else redact_secrets(v, depth=depth + 1)
            )
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [redact_secrets(item, depth=depth + 1) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact_secrets(item, depth=depth + 1) for item in payload)
    return payload


def redact_list(items: list[Any]) -> list[Any]:
    """Convenience wrapper for the common list-of-dicts response shape."""
    return [redact_secrets(item) for item in items]


__all__ = ["redact_secrets", "redact_list"]
