# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OpenVPN client configs are checked against ONE allowlist, in two places.

FreeSDN runs ``openvpn`` as root in the privileged vpn sidecar off a config an
authenticated ``vpn:write`` user supplies. Until 26.12.0 the config was checked
against a BLOCKLIST of dangerous directives, which could be routed around:
``setenv opt <directive>`` makes OpenVPN process the rest of the line as a
directive, OpenVPN unquotes a quoted directive name, and lines inside a
``<connection>`` block were skipped unread.

Now every directive must be on ``_OPENVPN_ALLOWED_DIRECTIVES``. The same rules
run in Python (``app.schemas.vpn._assert_openvpn_config_safe``: the API schema,
the materializer and the ``.ovpn`` import) and in the sidecar's pre-exec awk
scanner (``vpn-sidecar-entrypoint.sh``). Every case below goes through both, and
the awk lists must equal the Python sets.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.schemas.vpn import (
    _DANGEROUS_OPENVPN_DIRECTIVES,
    _OPENVPN_ALLOWED_DIRECTIVES,
    _OPENVPN_FILE_REF_DIRECTIVES,
    _OPENVPN_MATERIAL_BLOCKS,
    _assert_openvpn_config_safe,
)

_SCRIPT = Path(__file__).parents[2] / "vpn-sidecar-entrypoint.sh"
_HAS_AWK = shutil.which("awk") is not None

CA = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n</ca>\n"
TLS_AUTH = (
    "key-direction 1\n<tls-auth>\n#\n# 2048 bit OpenVPN static key\n#\n"
    "-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n"
    "</tls-auth>\n"
)

# Shapes taken from real exporters: the pfSense/OPNsense client export, an
# OpenVPN Access Server profile, a commercial provider profile, and a
# multi-remote <connection> failover profile.
ACCEPT = {
    "pfsense-opnsense-export": (
        "dev tun\npersist-tun\npersist-key\n"
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n"
        "data-ciphers-fallback AES-256-CBC\nauth SHA256\ntls-client\nclient\n"
        "resolv-retry infinite\nremote vpn.example.com 1194 udp4\nnobind\n"
        'verify-x509-name "C=US, ST=CA, L=Town, O=Example, CN=vpn-server" subject\n'
        "auth-user-pass\nremote-cert-tls server\nexplicit-exit-notify\n"
        "setenv opt block-outside-dns # Prevent Windows 10 DNS leak\n" + CA + TLS_AUTH
    ),
    "access-server-profile": (
        "setenv FORWARD_COMPATIBLE 1\nclient\nserver-poll-timeout 4\nnobind\n"
        "remote vpn.example.com 1194 udp\nremote vpn.example.com 443 tcp\n"
        "dev tun\ndev-type tun\nremote-cert-tls server\ntls-version-min 1.2\n"
        "reneg-sec 604800\ntun-mtu 1420\nverb 3\npush-peer-info\n"
        'static-challenge "Enter Authenticator Code" 1\nsetenv PUSH_PEER_INFO\n'
        "auth-user-pass\n" + CA + "<tls-crypt>\nzz\n</tls-crypt>\n"
    ),
    "provider-profile": (
        "client\ndev tun\nproto udp\nremote 192.0.2.10 1194\nresolv-retry infinite\n"
        "remote-random\nnobind\ntun-mtu 1500\ntun-mtu-extra 32\nmssfix 1450\n"
        "persist-key\npersist-tun\nping 15\nping-restart 0\nping-timer-rem\n"
        "reneg-sec 0\ncomp-lzo no\nverify-x509-name CN=us1.example.com\n"
        "remote-cert-tls server\nauth-user-pass\nverb 3\npull\nfast-io\n"
        "cipher AES-256-CBC\nauth SHA512\n" + CA + TLS_AUTH
    ),
    "connection-blocks": (
        "client\ndev tun\n<connection>\nremote a.example 1194 udp\n</connection>\n"
        "<connection>\nremote b.example 443 tcp\nhttp-proxy proxy.example 8080 auto\n"
        "</connection>\n" + CA
    ),
    "crlf-and-double-dash": "client\r\n--nobind\r\ndev tun\r\nremote x 1194\r\n",
    "inline-and-none-args": 'client\ndh none\nca [inline]\ncert "[inline]"\n' + CA,
    "setenv-opt-nested-once": "client\nsetenv opt setenv opt block-ipv6\n",
    "blank-and-comment-lines": "\n# comment\n; also a comment\n   \nclient\n",
}

REJECT = {
    # the directives the old blocklist named (still refused)
    "up": "client\nup /bin/true\n",
    "down": "client\ndown /bin/true\n",
    "script-security": "client\nscript-security 2\n",
    "plugin": "client\nplugin /tmp/x.so\n",
    "management": "client\nmanagement 127.0.0.1 7505\n",
    "config-include": "dev tun\nconfig other.conf\n",
    "config-double-dash": "client\n--config /etc/openvpn/client/x.inc\n",
    "log-file": "client\nlog /tmp/x\n",
    "status-file": "client\nstatus /tmp/s\n",
    "writepid": "client\nwritepid /tmp/p\n",
    "chroot": "client\nchroot /\n",
    "daemon": "client\ndaemon\n",
    "engine": "client\nengine dynamic\n",
    "providers": "client\nproviders legacy default\n",
    # ways around a blocklist
    "setenv-opt-up": "client\nsetenv opt up /bin/true\n",
    "setenv-opt-script-security": "client\nsetenv opt script-security 2\n",
    "setenv-OPT-uppercase": "client\nsetenv OPT up /bin/true\n",
    "setenv-quoted-opt": 'client\nsetenv "opt" up /bin/true\n',
    "setenv-opt-nested-too-deep": "client\nsetenv opt setenv opt setenv opt block-ipv6\n",
    "setenv-without-name": "client\nsetenv\n",
    "setenv-opt-without-directive": "client\nsetenv opt\n",
    "double-quoted-directive": 'client\n"up" /bin/true\n',
    "single-quoted-directive": "client\n'up' /bin/true\n",
    "backslash-in-directive": "client\nu\\p /bin/true\n",
    "uppercase-directive": "client\nUP /bin/true\n",
    "tab-separated": "client\nup\t/bin/true\n",
    "control-character": "client\nnobind\x1cup /bin/true\n",
    "delete-character": "client\nno\x7fbind\n",
    # blocks
    "inside-connection-block": "client\n<connection>\nup /bin/true\n</connection>\n",
    "nested-connection": "client\n<connection>\n<connection>\n</connection>\n</connection>\n",
    "material-inside-connection": "client\n<connection>\n<ca>\nx\n</ca>\n</connection>\n",
    "stray-connection-close": "client\n</connection>\n",
    "unknown-block": "client\n<foo>\nx\n</foo>\n",
    "unterminated-material": "client\n<ca>\nMIIB\n",
    "unterminated-connection": "client\n<connection>\nremote x 1194\n",
    "stray-material-close": "client\n</ca>\n",
    "malformed-tag": "client\n<ca> extra\nx\n</ca>\n",
    # file references (read-and-send primitive)
    "ca-path": "client\nca /etc/shadow\n",
    "ca-quoted-path": 'client\nca "/etc/shadow"\n',
    "ca-single-quoted-inline": "client\nca '[inline]'\n",
    "auth-user-pass-path": "client\nauth-user-pass /etc/passwd\n",
    "tls-auth-path": "client\ntls-auth ta.key 1\n",
    "pkcs12-path": "client\npkcs12 /x.p12\n",
    "capath": "client\ncapath /etc/ssl/certs\n",
    "http-proxy-authfile": "client\nhttp-proxy proxy.example 8080 /etc/creds\n",
    "http-proxy-other-keyword": "client\nhttp-proxy proxy.example 8080 basic\n",
    "socks-proxy-authfile": "client\nsocks-proxy proxy.example 1080 /etc/creds\n",
    "unknown-directive": "client\nfoo-bar 1\n",
}


def _python_accepts(text: str) -> bool:
    try:
        _assert_openvpn_config_safe(text)
    except ValueError:
        return False
    return True


def _awk_program() -> str:
    src = _SCRIPT.read_text(encoding="utf-8")
    fn = src.index("_ovpn_cfg_safe()")
    start = src.index("awk '", fn) + len("awk '")
    return src[start : src.index("'", start)]


def _awk_accepts(text: str, tmp_path: Path) -> bool:
    cfg = tmp_path / "case.conf"
    cfg.write_bytes(text.encode("utf-8"))
    return subprocess.run(["awk", _awk_program(), str(cfg)], capture_output=True).returncode == 0


@pytest.mark.parametrize("case", sorted(ACCEPT))
def test_python_accepts_real_client_configs(case: str) -> None:
    _assert_openvpn_config_safe(ACCEPT[case])


@pytest.mark.parametrize("case", sorted(REJECT))
def test_python_refuses(case: str) -> None:
    assert not _python_accepts(REJECT[case])


@pytest.mark.skipif(not _HAS_AWK, reason="awk not available")
@pytest.mark.parametrize("case", sorted(ACCEPT))
def test_sidecar_scanner_accepts_real_client_configs(case: str, tmp_path: Path) -> None:
    assert _awk_accepts(ACCEPT[case], tmp_path)


@pytest.mark.skipif(not _HAS_AWK, reason="awk not available")
@pytest.mark.parametrize("case", sorted(REJECT))
def test_sidecar_scanner_refuses(case: str, tmp_path: Path) -> None:
    assert not _awk_accepts(REJECT[case], tmp_path)


def _awk_list(prog: str, name: str) -> set[str]:
    parts = re.findall(name + r" = (?:" + name + r' )?"([^"]*)"', prog)
    assert parts, f"{name} not found in the sidecar scanner"
    return set(" ".join(parts).split())


def test_sidecar_lists_equal_the_python_sets() -> None:
    prog = _awk_program()
    assert _awk_list(prog, "ALLOWED") == set(_OPENVPN_ALLOWED_DIRECTIVES)
    assert _awk_list(prog, "FILEREF") == set(_OPENVPN_FILE_REF_DIRECTIVES)
    assert _awk_list(prog, "MATERIAL") == set(_OPENVPN_MATERIAL_BLOCKS)


def test_no_dangerous_directive_is_allowlisted() -> None:
    assert not (_DANGEROUS_OPENVPN_DIRECTIVES & _OPENVPN_ALLOWED_DIRECTIVES)


def test_refusal_names_the_directive_and_says_why() -> None:
    with pytest.raises(ValueError, match="Dangerous OpenVPN directive not allowed: up"):
        _assert_openvpn_config_safe("client\nsetenv opt up /bin/true\n")
    with pytest.raises(ValueError, match="Unsupported OpenVPN directive not allowed: foo-bar"):
        _assert_openvpn_config_safe("client\nfoo-bar 1\n")
    with pytest.raises(ValueError, match="must be supplied inline"):
        _assert_openvpn_config_safe("client\nca /etc/shadow\n")


def test_import_path_uses_the_same_check_and_still_reads_metadata() -> None:
    from app.services.brain_vpn import BrainVPNService

    meta = BrainVPNService.validate_openvpn_config(ACCEPT["provider-profile"])
    assert meta["remote"] == "192.0.2.10"
    assert meta["port"] == 1194
    assert meta["protocol"] == "udp"
    assert meta["has_ca"] and meta["has_tls_auth"]
    with pytest.raises(ValueError, match="OpenVPN config refused"):
        BrainVPNService.validate_openvpn_config(REJECT["setenv-opt-up"])
