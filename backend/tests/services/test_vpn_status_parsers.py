# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""VPN status parsing + sidecar control wiring (Tailscale / NetBird).

These pin two classes of fix exposed by end-to-end testing of the privileged
``vpn`` sidecar topology:

1. **NeedsLogin robustness.** On a fresh install the daemons are up but not yet
   authenticated, and ``tailscale status --json`` / ``netbird status --json``
   emit their nested objects as explicit JSON ``null``. The parsers used
   ``data.get(key, {})`` which returns ``None`` for a present-but-null key, so
   ``None.get(...)`` / iterating ``None`` crashed — a correctly-wired daemon
   reported ``backend_state="Error"`` / ``management_state="Error"``. The parsers
   now ``or {}`` / ``or []`` those holes.

2. **NetBird daemon-addr threading.** In the sidecar topology the NetBird daemon
   runs in the privileged container and the api/worker drive it via the
   ``netbird`` CLI over the SHARED network namespace, so the CLI must be pointed
   at a tcp ``--daemon-addr`` (the default unix socket isn't visible across the
   filesystem boundary). ``_nb_cmd`` injects that flag when configured.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from app.services.vpn_integration import NetbirdService, TailscaleService

# ── NetBird: --daemon-addr threading (sidecar control path) ──────────────────


def test_nb_cmd_omits_daemon_addr_when_unset():
    nb = NetbirdService()
    nb.daemon_addr = None  # single-container deploy ⇒ default unix socket
    assert nb._nb_cmd("status", "--json") == ("netbird", "status", "--json")
    assert nb._nb_cmd("up") == ("netbird", "up")


def test_nb_cmd_injects_daemon_addr_after_subcommand():
    nb = NetbirdService()
    nb.daemon_addr = "tcp://127.0.0.1:41731"
    assert nb._nb_cmd("status", "--json") == (
        "netbird",
        "status",
        "--daemon-addr",
        "tcp://127.0.0.1:41731",
        "--json",
    )
    assert nb._nb_cmd("down") == ("netbird", "down", "--daemon-addr", "tcp://127.0.0.1:41731")


def test_netbird_service_reads_daemon_addr_from_env(monkeypatch):
    monkeypatch.setenv("NETBIRD_DAEMON_ADDR", "tcp://127.0.0.1:41731")
    assert NetbirdService().daemon_addr == "tcp://127.0.0.1:41731"
    monkeypatch.delenv("NETBIRD_DAEMON_ADDR", raising=False)
    assert NetbirdService().daemon_addr is None  # default ⇒ unix socket


# ── NetBird: connect() threads the setup key (the join-the-mesh fix) ─────────


class _FakeProc:
    def __init__(self, rc=0):
        self.returncode = rc

    async def communicate(self):
        return (b"", b"")


@pytest.mark.asyncio
async def test_netbird_connect_threads_setup_key_file_and_mgmt_url(monkeypatch):
    """The blocker fix: connect(setup_key=...) must pass --setup-key-file (NOT the
    key on argv) + --management-url, and delete the temp keyfile afterward."""
    captured = {}

    async def fake_exec(*args, **kwargs):
        # connect() runs `down` first (clear stale state) then `up`; capture each.
        if "up" in args:
            captured["argv"] = list(args)
            i = args.index("--setup-key-file")
            kf = args[i + 1]
            captured["key_path"] = kf
            with open(kf, encoding="utf-8") as f:
                captured["key_contents"] = f.read()
        elif "down" in args:
            captured["down_first"] = True
        return _FakeProc(rc=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    nb = NetbirdService()
    nb.daemon_addr = "tcp://127.0.0.1:41731"
    r = await nb.connect(setup_key="SECRET-KEY-123", management_url="https://nb.example:443")

    assert r["success"] is True
    assert captured.get("down_first") is True  # stale-state clear before up
    argv = captured["argv"]
    assert argv[0] == "netbird" and "up" in argv
    assert "--daemon-addr" in argv and "tcp://127.0.0.1:41731" in argv
    assert "--management-url" in argv and "https://nb.example:443" in argv
    # the SECRET must NOT appear as a bare argv token (kept off /proc)
    assert "SECRET-KEY-123" not in argv
    assert captured["key_contents"] == "SECRET-KEY-123"
    # temp keyfile cleaned up after connect returns
    assert not os.path.exists(captured["key_path"])


@pytest.mark.asyncio
async def test_netbird_connect_without_key_runs_bare_up(monkeypatch):
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["argv"] = list(args)
        return _FakeProc(rc=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    nb = NetbirdService()
    nb.daemon_addr = None
    r = await nb.connect()
    assert r["success"] is True
    assert captured["argv"] == ["netbird", "up"]
    assert "--setup-key-file" not in captured["argv"]


# ── Schema: OpenVPN config content RCE-directive rejection ────────────────────


def test_connection_create_rejects_host_rce_openvpn_directive():
    from app.schemas.vpn import VPNConnectionCreate

    for bad in ("up /bin/sh", "down /x", "script-security 2", "plugin /e.so"):
        with pytest.raises(ValueError):
            VPNConnectionCreate(
                name="c1", vpn_type="openvpn", openvpn_config_content=f"client\n{bad}\n"
            )


def test_connection_create_accepts_safe_openvpn_config():
    from app.schemas.vpn import VPNConnectionCreate

    c = VPNConnectionCreate(
        name="c1",
        vpn_type="openvpn",
        openvpn_config_content="client\nremote vpn.example 1194\ncipher AES-256-CBC\n",
    )
    assert c.openvpn_config_content and "remote vpn.example" in c.openvpn_config_content


def test_openvpn_blocklist_covers_file_write_and_management_directives():
    # audit fix: the connection-path validator must match brain_vpn's full set,
    # not just the script hooks (management/status/log/writepid don't need
    # script-security and let the ROOT sidecar open a control socket / write files)
    from app.schemas.vpn import _assert_openvpn_config_safe

    for bad in (
        "management 127.0.0.1 7505",
        "status /etc/openvpn/x",
        "log /x",
        "writepid /x",
        "tls-crypt-v2-verify /x",
        "iproute /x",
        "--up /x",
    ):
        with pytest.raises(ValueError):
            _assert_openvpn_config_safe(f"client\n{bad}\n")


def test_openvpn_rejects_config_include_directive():
    # HIGH: `config <file>` (alias `--config`) inlines another file's
    # directives at parse time. Unblocked, a clean-looking top-level config can
    # `config pwn.inc` and have the INCLUDED file run `up /bin/sh …` as ROOT in the
    # privileged sidecar — directives the scanner never sees. Both ingest paths must
    # reject the include directive itself (case- and `--`-insensitive).
    from app.schemas.vpn import _assert_openvpn_config_safe
    from app.services.brain_vpn import BrainVPNService

    for bad in (
        "client\nconfig pwn.inc\n",
        "client\n--config /etc/openvpn/client/pwn.inc\n",
        "dev tun\nCONFIG extra.conf\n",
    ):
        with pytest.raises(ValueError):
            _assert_openvpn_config_safe(bad)
        with pytest.raises(ValueError):
            BrainVPNService.validate_openvpn_config(bad)
    # `config` is in the canonical single-source-of-truth set
    from app.schemas.vpn import _DANGEROUS_OPENVPN_DIRECTIVES

    assert "config" in _DANGEROUS_OPENVPN_DIRECTIVES


def test_openvpn_validator_is_inline_block_aware():
    # cert/key payload lines must NOT false-positive (a base64 line could start
    # with a directive word), and a directive after the block close is still caught
    from app.schemas.vpn import _assert_openvpn_config_safe

    _assert_openvpn_config_safe("client\n<ca>\nstatus is just base64 here\n</ca>\nremote x 1194\n")
    with pytest.raises(ValueError):
        _assert_openvpn_config_safe("client\n<ca>\nzzz\n</ca>\nmanagement 127.0.0.1 7\n")


def test_brain_vpn_shares_the_single_blocklist():
    # the two ingest paths must not drift — brain_vpn imports the canonical set
    from app.schemas.vpn import _DANGEROUS_OPENVPN_DIRECTIVES
    from app.services.brain_vpn import _DANGEROUS_OPENVPN_DIRECTIVES as brain_set

    assert brain_set is _DANGEROUS_OPENVPN_DIRECTIVES


def test_site_vpn_config_create_rejects_dangerous_directive():
    # F1: SiteVPNConfigCreate must validate openvpn_config_content like the others
    from app.schemas.vpn import SiteVPNConfigCreate

    with pytest.raises(ValueError):
        SiteVPNConfigCreate(
            vpn_type="openvpn", openvpn_config_content="client\nmanagement 127.0.0.1 7505\n"
        )
    ok = SiteVPNConfigCreate(
        vpn_type="openvpn", openvpn_config_content="client\nremote x 1194\ncipher AES-256-CBC\n"
    )
    assert ok.openvpn_config_content


def test_brain_vpn_validator_strips_double_dash():
    # F2: `--up` must be rejected on the brain import path too (leading -- stripped)
    from app.services.brain_vpn import BrainVPNService

    with pytest.raises(ValueError):
        BrainVPNService.validate_openvpn_config("client\n--up /tmp/evil.sh\n")
    # a normal config still validates
    BrainVPNService.validate_openvpn_config("client\nremote x 1194\n")


def test_openvpn_rejects_file_read_path_directives():
    # CAND-001 (High): `auth-user-pass <path>` / `cert <path>` etc. make root
    # OpenVPN read+exfil an arbitrary local file. Path forms must be rejected;
    # inline blocks + safe args (none/[inline]) accepted.
    from app.schemas.vpn import _assert_openvpn_config_safe
    from app.services.brain_vpn import BrainVPNService

    for bad in (
        "client\nauth-user-pass /etc/wireguard/wg0.conf\n",
        "client\ncert /etc/shadow\n",
        "client\nca /proc/self/environ\n",
        "client\nsecret /etc/x.key\n",
        "client\ntls-auth ta.key 1\n",
        "client\nkey /etc/openvpn/client/other.conf\n",
    ):
        with pytest.raises(ValueError):
            _assert_openvpn_config_safe(bad)
        with pytest.raises(ValueError):
            BrainVPNService.validate_openvpn_config(bad)
    # inline blocks + dh none + [inline] args are fine
    _assert_openvpn_config_safe("client\nremote x 1194\ndh none\nca [inline]\n<ca>\nMIIB\n</ca>\n")


def test_vpn_connection_create_rejects_secret_extra_data_keys():
    # CAND-002 (Med): a write-only secret must not be smuggled into free-form
    # extra_data (it would be returned to vpn:read users).
    from app.schemas.vpn import VPNConnectionCreate

    for bad_key in ("netbird_setup_key", "openvpn_config_content", "wg_private_key"):
        with pytest.raises(ValueError):
            VPNConnectionCreate(name="c", vpn_type="netbird", extra_data={bad_key: "SECRET"})
    # a normal extra_data key is fine, and public_key is allowed
    VPNConnectionCreate(name="c", vpn_type="wireguard", extra_data={"note": "x", "public_key": "P"})


# ── Tailscale/NetBird coexistence: --netfilter-mode=off ──────────────────────


@pytest.mark.asyncio
async def test_tailscale_login_passes_netfilter_mode(monkeypatch):
    # coexistence fix: `tailscale up --netfilter-mode=off` lets Tailscale share
    # the 100.64.0.0/10 range with NetBird instead of grabbing all the packets
    from app.services.vpn_integration import TailscaleSetupService

    svc = TailscaleSetupService()
    captured = {}

    async def fake_run(*cmd, **kw):
        captured["cmd"] = cmd
        return (1, "", "stop")  # rc!=0 short-circuits before get_setup_status

    monkeypatch.setattr(svc, "_run_cmd", fake_run)
    await svc.login_with_authkey(auth_key="k", netfilter_mode="off")
    assert "--netfilter-mode=off" in captured["cmd"]

    captured.clear()
    await svc.login_with_authkey(auth_key="k", netfilter_mode=None)
    assert not any("netfilter-mode" in str(c) for c in captured["cmd"])


@pytest.mark.asyncio
async def test_netfilter_resolver_env_override(monkeypatch):
    # operator env override wins and short-circuits before any DB query
    # (session/org are unused on this path)
    from app.api.v1.endpoints.vpn import _resolve_tailscale_netfilter_mode

    for mode in ("off", "nodivert", "on"):
        monkeypatch.setenv("FREESDN_TAILSCALE_NETFILTER_MODE", mode)
        assert await _resolve_tailscale_netfilter_mode(None, None) == mode


# ── NetBird: NeedsLogin parser robustness ────────────────────────────────────


def test_netbird_parse_needslogin_null_fields_does_not_crash():
    nb = NetbirdService()
    # Shape emitted by `netbird status --json` when up-but-NeedsLogin.
    out = nb._parse_status({"peers": {"details": None}, "management": None, "signal": None})
    assert out["connected"] is False
    assert out["management_state"] == "Disconnected"
    assert out["signal_state"] == "Disconnected"
    assert out["peers"] == []
    assert out["peer_count"] == 0


def test_netbird_parse_peers_object_itself_null():
    nb = NetbirdService()
    out = nb._parse_status({"peers": None, "management": None, "signal": None})
    assert out["peers"] == []
    assert out["connected"] is False


def test_netbird_parse_connected_happy_path_unchanged():
    nb = NetbirdService()
    out = nb._parse_status(
        {
            "management": {"connected": True, "url": "https://api.netbird.io"},
            "signal": {"connected": True},
            "ip": "100.64.0.5",
            "peers": {
                "details": [
                    {"fqdn": "peer1.netbird.cloud", "ip": "100.64.0.6", "connStatus": "connected"}
                ]
            },
        }
    )
    assert out["connected"] is True
    assert out["management_state"] == "Running"
    assert out["management_url"] == "https://api.netbird.io"
    assert out["peer_count"] == 1
    assert out["connected_peers"] == 1


# ── Tailscale: NeedsLogin parser robustness ──────────────────────────────────


def test_tailscale_parse_needslogin_null_fields_does_not_crash():
    ts = TailscaleService()
    # `tailscale status --json` on a fresh, unauthenticated daemon.
    status = ts._parse_status(
        {"BackendState": "NeedsLogin", "CurrentTailnet": None, "Peer": None, "Self": None}
    )
    assert status.backend_state == "NeedsLogin"
    assert status.tailnet_name == ""
    assert status.peers == []
    assert status.self_node is None


def test_tailscale_parse_running_happy_path_unchanged():
    ts = TailscaleService()
    status = ts._parse_status(
        {
            "BackendState": "Running",
            "CurrentTailnet": {"Name": "example.ts.net", "MagicDNSEnabled": True},
            "Self": {"HostName": "controller", "TailscaleIPs": ["100.64.0.1"], "Online": True},
            "Peer": {
                "nodekey:abc": {
                    "HostName": "site-a",
                    "TailscaleIPs": ["100.64.0.2"],
                    "Online": True,
                }
            },
        }
    )
    assert status.backend_state == "Running"
    assert status.tailnet_name == "example.ts.net"
    assert status.magic_dns_enabled is True
    assert status.self_node is not None and status.self_node.hostname == "controller"
    assert len(status.peers) == 1 and status.peers[0].hostname == "site-a"


def test_classify_overlay_peer_tags_beat_hostname_beat_os():
    from app.services.overlay_discovery import classify_overlay_peer

    # ACL tag -> high confidence (strongest signal)
    assert classify_overlay_peer("random-host", "linux", ["tag:proxmox"]) == (
        "proxmox",
        "high",
    )
    assert classify_overlay_peer("x", "", ["tag:nvr"]) == ("camera", "high")
    # hostname substring -> medium
    assert classify_overlay_peer("pve1.example", "linux", []) == ("proxmox", "medium")
    assert classify_overlay_peer("office-truenas", "", []) == ("truenas", "medium")
    assert classify_overlay_peer("fw-opnsense-1", "", []) == ("opnsense", "medium")
    # OS only -> low (still adoptable, unclassified)
    assert classify_overlay_peer("box42", "Linux 6.1", []) == ("linux", "low")
    # nothing -> unknown/low
    assert classify_overlay_peer("box42", "", []) == ("unknown", "low")
    # tag wins even when hostname suggests something else
    assert classify_overlay_peer("looks-like-nas", "", ["tag:proxmox"]) == (
        "proxmox",
        "high",
    )


def test_annotate_already_adopted_matches_ip_or_hostname():
    from app.services.overlay_discovery import annotate_already_adopted

    devices = [
        {"address": "100.64.0.5", "hostname": "pve1"},
        {"address": "100.64.0.6", "hostname": "nas"},
        {"address": "100.64.0.7", "hostname": "unknown-host"},
    ]
    adopted = [
        ("dev-1", "100.64.0.5", "something"),  # matches device 0 by overlay IP
        ("dev-2", "192.168.1.9", "NAS"),  # matches device 1 by hostname (case-insensitive)
    ]
    annotate_already_adopted(devices, adopted)
    assert devices[0]["already_adopted"] and devices[0]["adopted_device_id"] == "dev-1"
    assert devices[1]["already_adopted"] and devices[1]["adopted_device_id"] == "dev-2"
    assert devices[2]["already_adopted"] is False
    assert devices[2]["adopted_device_id"] is None


def test_resolved_vpn_mode_reconciles_legacy_flags(monkeypatch):
    # FREESDN is capless by default; VPN_MODE is the canonical switch, but legacy
    # env flags must keep working for existing deployments.
    from app.core.config import Settings

    for k in (
        "VPN_MODE",
        "FREESDN_OPENVPN_SIDECAR",
        "FREESDN_WIREGUARD_SIDECAR",
        "FREESDN_VPN_AUTOSTART",
    ):
        monkeypatch.delenv(k, raising=False)
    assert Settings().resolved_vpn_mode == "off"  # default
    monkeypatch.setenv("VPN_MODE", "sidecar")
    assert Settings().resolved_vpn_mode == "sidecar"
    monkeypatch.setenv("VPN_MODE", "userspace")
    assert Settings().resolved_vpn_mode == "userspace"
    monkeypatch.setenv("VPN_MODE", "garbage")
    assert Settings().resolved_vpn_mode == "off"  # unknown -> fail safe
    monkeypatch.delenv("VPN_MODE")
    monkeypatch.setenv("FREESDN_WIREGUARD_SIDECAR", "true")
    assert Settings().resolved_vpn_mode == "sidecar"  # legacy -> sidecar
    monkeypatch.delenv("FREESDN_WIREGUARD_SIDECAR")
    monkeypatch.setenv("FREESDN_VPN_AUTOSTART", "1")
    assert Settings().resolved_vpn_mode == "userspace"  # legacy -> userspace


def test_tailscale_parse_node_null_list_fields_coerced_to_empty():
    # Regression: a live `tailscale status --json` can emit a Self/Peer node that
    # IS present but has TailscaleIPs/AllowedIPs/Tags == null (e.g. logged-out-but-
    # registered). `.get(key, [])` returns None for an explicit JSON null, which
    # then violated the `list[str]` TailscaleNodeResponse schema -> 500 on
    # GET /vpn/tailscale/status for every fresh install. The parser must coerce
    # null -> [].
    ts = TailscaleService()
    node = ts._parse_node(
        {
            "ID": "n1",
            "HostName": "h",
            "DNSName": "h.ts.net",
            "TailscaleIPs": None,
            "AllowedIPs": None,
            "Tags": None,
            "Online": False,
        }
    )
    assert node.tailscale_ips == []
    assert node.advertised_routes == []
    assert node.tags == []
