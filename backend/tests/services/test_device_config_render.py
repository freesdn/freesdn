# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Device config exports: what is stored, what decides "changed", what is shown.

Every value below whose name contains SECRET must never appear in a rendering or
a diff; the fixtures are shaped like real OPNsense config.xml / OpenWrt
sysupgrade archives.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import time

import pytest

from app.services.device_config_render import (
    OPENWRT_SYSUPGRADE,
    OPNSENSE_XML,
    ConfigFormatError,
    content_digest,
    diff_summary,
    name_is_secret,
    normalize_export,
    redacted_diff,
    render_redacted,
)

KEY = "unit-test-instance-key"
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvSECRETPEMBODYxxxxxxxxxxxxxxxx\n-----END PRIVATE KEY-----"
BASE64_PRV = "LS0tLS1CRUdJTi" + "SECRETBASE64" * 20


def opnsense(password: str = "SECRET-root-password", descr: str = "Main firewall") -> bytes:
    return f"""<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw1</hostname>
    <user>
      <name>root</name>
      <descr>System Administrator</descr>
      <password>{password}</password>
      <bcrypt-hash>$2y$10$SECRETbcrypthashvalue</bcrypt-hash>
      <apikeys><item><key>SECRET-api-key</key><secret>SECRET-api-secret</secret></item></apikeys>
      <authorizedkeys>c3NoLWVkMjU1MTkgU0VDUkVUc3No</authorizedkeys>
      <otp_seed>SECRETOTPSEED</otp_seed>
    </user>
    <ssh><enabled>enabled</enabled></ssh>
  </system>
  <interfaces><lan><if>igb1</if><ipaddr>192.168.1.1</ipaddr><descr>{descr}</descr></lan></interfaces>
  <snmpd><rocommunity>SECRET-community</rocommunity></snmpd>
  <ipsec><phase1><pre-shared-key>SECRET-psk</pre-shared-key></phase1></ipsec>
  <openvpn><openvpn-server><tls>SECRET-static-tls-key</tls>
    <description>long note without secrets but with spaces in it, many words</description>
  </openvpn-server></openvpn>
  <cert><descr>web</descr><crt>{BASE64_PRV}</crt><prv>{BASE64_PRV}</prv></cert>
  <notes>{PEM}</notes>
  <wireguard><server><pubkey>PUBLICwgKEY=</pubkey><privkey>SECRET-wg-private</privkey></server></wireguard>
</opnsense>
""".encode()


def sysupgrade(files: dict[str, bytes], *, mtime: float | None = None, extra=None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime if mtime is not None else time.time()
            tar.addfile(info, io.BytesIO(data))
        for member in extra or []:
            tar.addfile(member)
    return gzip.compress(raw.getvalue(), mtime=mtime)


OPENWRT_FILES = {
    "etc/config/network": b"config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '192.168.1.1'\n",
    "etc/config/wireless": (
        b"config wifi-iface 'default_radio0'\n\toption ssid 'Office'\n"
        b"\toption encryption 'psk2'\n\toption key 'SECRET-wifi-passphrase'\n"
        b"\tlist sae_password 'SECRET-sae'\n"
    ),
    "etc/config/wireguard": b"config interface 'wg0'\n\toption private_key 'SECRET-wg'\n",
    "etc/shadow": b"root:$1$SECRETshadowhash:19000:0:99999:7:::\n",
    "etc/dropbear/dropbear_ed25519_host_key": b"\x00\x00SECRET-host-key",
    "etc/uhttpd.key": PEM.encode(),
    "etc/firmware.bin": b"\x7fELF\x00\x01binary",
}


def _assert_no_secret(text: str) -> None:
    assert "SECRET" not in text, [line for line in text.splitlines() if "SECRET" in line]


def test_opnsense_rendering_hides_every_secret_and_keeps_the_structure():
    text = render_redacted(OPNSENSE_XML, opnsense(), KEY)
    _assert_no_secret(text)
    for visible in (
        "<hostname>fw1</hostname>",
        "192.168.1.1",
        "Main firewall",
        "igb1",
        "<name>root</name>",
    ):
        assert visible in text
    assert "PUBLICwgKEY=" in text  # public keys are public
    assert "long note without secrets" in text  # prose is not mistaken for a blob
    assert "[redacted:" in text and "[blob:" in text


def test_a_changed_password_shows_as_a_changed_fingerprint_not_its_value():
    older = render_redacted(OPNSENSE_XML, opnsense("SECRET-old"), KEY)
    newer = render_redacted(OPNSENSE_XML, opnsense("SECRET-new"), KEY)
    lines, truncated = redacted_diff(older, newer, older_label="v1", newer_label="v2")
    _assert_no_secret("\n".join(lines))
    changed = [line for line in lines if line.startswith(("+", "-")) and "password" in line]
    assert len(changed) == 2 and not truncated
    assert diff_summary(lines) == {"added": 1, "removed": 1}
    # Same value, same fingerprint: an unchanged secret is not diff noise.
    assert render_redacted(OPNSENSE_XML, opnsense("SECRET-old"), KEY) == older
    # The fingerprint depends on the instance key (no offline guessing).
    assert render_redacted(OPNSENSE_XML, opnsense("SECRET-old"), "other-key") != older


def test_opnsense_identity_is_the_document_and_the_digest_is_keyed():
    first = normalize_export(OPNSENSE_XML, opnsense())
    assert first.identity == first.content == opnsense()
    assert content_digest(first.identity, KEY) == content_digest(opnsense(), KEY)
    assert content_digest(first.identity, KEY) != content_digest(first.identity, "other-key")
    assert content_digest(opnsense(descr="x"), KEY) != content_digest(first.identity, KEY)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"<pfsense><system/></pfsense>",
        b"not xml at all",
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><opnsense>&e;</opnsense>',
        b"<opnsense>" + b"a" * (16 * 1024 * 1024) + b"</opnsense>",
    ],
)
def test_opnsense_rejects_anything_but_a_safe_opnsense_document(payload):
    with pytest.raises(ConfigFormatError):
        normalize_export(OPNSENSE_XML, payload)


def test_openwrt_rendering_hides_secrets_and_secret_files():
    text = render_redacted(OPENWRT_SYSUPGRADE, sysupgrade(OPENWRT_FILES), KEY)
    _assert_no_secret(text)
    assert "### /etc/config/network" in text and "option ipaddr '192.168.1.1'" in text
    assert "option ssid 'Office'" in text
    assert "option key [redacted:" in text and "list sae_password [redacted:" in text
    assert "option private_key [redacted:" in text
    for secret_file in (
        "/etc/shadow",
        "/etc/dropbear/dropbear_ed25519_host_key",
        "/etc/uhttpd.key",
    ):
        index = text.index("### " + secret_file)
        assert text[index:].splitlines()[1].startswith("[secret file:")
    assert "[binary file:" in text


def test_openwrt_rebuilt_archive_of_the_same_files_is_not_a_change():
    first = normalize_export(OPENWRT_SYSUPGRADE, sysupgrade(OPENWRT_FILES, mtime=1_700_000_000))
    again = normalize_export(OPENWRT_SYSUPGRADE, sysupgrade(OPENWRT_FILES, mtime=1_800_000_000))
    assert first.content != again.content
    assert first.identity == again.identity
    changed = dict(OPENWRT_FILES, **{"etc/config/network": b"config interface 'wan'\n"})
    assert normalize_export(OPENWRT_SYSUPGRADE, sysupgrade(changed)).identity != first.identity


def _member(name: str, kind: bytes, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size
    info.linkname = "/etc/shadow" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    return info


def test_openwrt_links_and_devices_are_ignored_not_followed():
    archive = sysupgrade(
        {"etc/config/system": b"config system\n"},
        extra=[_member("etc/link", tarfile.SYMTYPE), _member("etc/hard", tarfile.LNKTYPE)],
    )
    text = render_redacted(OPENWRT_SYSUPGRADE, archive, KEY)
    assert "/etc/link" not in text and "/etc/hard" not in text


@pytest.mark.parametrize(
    "files",
    [
        {"../../etc/passwd": b"x"},
        {"etc/../../escape": b"x"},
        {"etc/big": b"x" * (8 * 1024 * 1024 + 1)},
    ],
)
def test_openwrt_traversal_and_oversized_members_are_refused(files):
    with pytest.raises(ConfigFormatError):
        normalize_export(OPENWRT_SYSUPGRADE, sysupgrade(files))


def test_openwrt_rejects_non_archives_and_empty_archives():
    for payload in (b"plain text", gzip.compress(b"not a tar"), sysupgrade({})):
        with pytest.raises(ConfigFormatError):
            normalize_export(OPENWRT_SYSUPGRADE, payload)


def test_absolute_member_names_are_rooted_not_escaping():
    normalized = normalize_export(OPENWRT_SYSUPGRADE, sysupgrade({"/etc/config/x": b"config x\n"}))
    text = render_redacted(OPENWRT_SYSUPGRADE, normalized.content, KEY)
    assert "### /etc/config/x" in text


# Text files a sysupgrade archive carries that are NOT UCI, so the UCI redactor
# cannot know where their secrets are.
NON_UCI_SECRET_FILES = {
    "etc/openvpn/client.auth": b"vpnuser\nSECRET-openvpn-password\n",
    "etc/ppp/chap-secrets": b'"dsluser" * "SECRET-chap-password" *\n',
    "etc/sysupgrade.conf": b"/etc/openvpn/\n# SECRET-comment\n",
    "etc/rc.local": b"curl -u admin:SECRET-script https://example.invalid\nexit 0\n",
}


def test_openwrt_non_uci_text_files_show_only_name_size_and_fingerprint():
    files = dict(OPENWRT_FILES, **NON_UCI_SECRET_FILES)
    text = render_redacted(OPENWRT_SYSUPGRADE, sysupgrade(files), KEY)
    _assert_no_secret(text)
    for name, data in NON_UCI_SECRET_FILES.items():
        index = text.index(f"### /{name}")
        line = text[index:].splitlines()[1]
        assert line.startswith("[file:") and line.endswith(f"({len(data)} bytes)"), line
    # A changed auth file is still visible as a change, via the fingerprint.
    rotated = dict(files, **{"etc/openvpn/client.auth": b"vpnuser\nSECRET-rotated\n"})
    again = render_redacted(OPENWRT_SYSUPGRADE, sysupgrade(rotated), KEY)
    _assert_no_secret(again)
    assert again != text


def test_openwrt_uci_urls_never_show_their_credentials():
    ddns = (
        b"config service 'home'\n"
        b"\toption update_url 'http://admin:SECRET-ddns@members.example.invalid/nic/update'\n"
        b"\tlist mirror 'https://SECRET-token@mirror.example.invalid/feed'\n"
        b"\toption odd 'ftp://us@r:SECRET-at@sign@ftp.example.invalid/'\n"
        b"\toption plain 'https://downloads.example.invalid/x'\n"
    )
    text = render_redacted(OPENWRT_SYSUPGRADE, sysupgrade({"etc/config/ddns": ddns}), KEY)
    _assert_no_secret(text)
    assert "option update_url 'http://[redacted:" in text
    assert "@members.example.invalid/nic/update'" in text
    assert "list mirror 'https://[redacted:" in text
    assert "option plain 'https://downloads.example.invalid/x'" in text


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("password", True),
        ("bcrypt-hash", True),
        ("prv", True),
        ("pre-shared-key", True),
        ("rocommunity", True),
        ("ldap_bindpw", True),
        ("key", True),
        ("pubkey", False),
        ("hostname", False),
        ("descr", False),
        ("ipaddr", False),
        ("authserver", False),
    ],
)
def test_secret_name_classifier(name, secret):
    assert name_is_secret(name) is secret


def test_diff_is_capped():
    older = "\n".join(f"line {i}" for i in range(6000))
    newer = "\n".join(f"changed {i}" for i in range(6000))
    lines, truncated = redacted_diff(older, newer, older_label="a", newer_label="b")
    assert truncated and len(lines) == 5000


# ── UCI parsed the way libuci parses it, not line by line ───────────────────


def _openwrt_text(files: dict[str, bytes]) -> str:
    return render_redacted(OPENWRT_SYSUPGRADE, sysupgrade(files), KEY)


def test_openwrt_url_query_credentials_are_masked():
    ddns = (
        b"config service 'home'\n"
        b"\toption update_url 'https://example.test/update?password=SECRET-q1&host=gw'\n"
        b"\toption check 'http://example.test/x?Token=SECRET-q2'\n"
        b"\tlist hook 'https://example.test/h?a=1&apikey=SECRET-q3;pwd=SECRET-q4'\n"
        b"\toption cb 'https://example.test/cb#auth=SECRET-q5'\n"
        b"\toption other 'https://example.test/y?passwd=SECRET-q6&KEY=SECRET-q7&access_token=SECRET-q8'\n"
    )
    text = _openwrt_text({"etc/config/ddns": ddns})
    _assert_no_secret(text)
    assert "update?password=[redacted:" in text and "&host=gw'" in text
    assert "x?Token=[redacted:" in text


def test_opnsense_url_query_credentials_are_masked():
    doc = b"<opnsense><system><url>https://x.invalid/?token=SECRET-q&amp;a=1</url></system></opnsense>"
    text = render_redacted(OPNSENSE_XML, doc, KEY)
    _assert_no_secret(text)
    assert "?token=[redacted:" in text and "a=1" in text


@pytest.mark.parametrize(
    "uci",
    [
        # A quoted value spanning lines: the old matcher masked only the first.
        b"config service 'x'\n\toption password 'first-line\nSECRET-second-line'\n",
        b'config service \'x\'\n\toption password "first\\\nSECRET-continued"\n',
        b"config service 'x'\n\toption password first\\\nSECRET-continued-unquoted\n",
        # Several statements on one line.
        b"config service 'x'; option password 'SECRET-semi'\n",
        b"config service 'x'\n\toption ssid 'Office'; option key 'SECRET-semi2'\n",
        # Abbreviated keywords, quoted names, concatenated pieces.
        b"config service 'x'\n\to password 'SECRET-abbrev'\n",
        b"config service 'x'\n\tl 'sae_password' SECRET-'joined'\"pieces\"\n",
        # A comment is not shown.
        b"config service 'x'\n\t# old password SECRET-comment\n\toption ssid 'Office'\n",
    ],
)
def test_openwrt_uci_forms_libuci_accepts_never_show_a_secret(uci):
    text = _openwrt_text({"etc/config/wireless": uci})
    _assert_no_secret(text)
    assert "[redacted:" in text or "option ssid 'Office'" in text


@pytest.mark.parametrize(
    "uci",
    [
        b"config service 'x'\n\tbogus SECRET-unknown-command\n",
        b"config service 'x'\n\toption key 'SECRET-unterminated\n",
        b"\toption description SECRET-before-any-section\n",
        b"config service 'x'\n\toption description SECRET-too many arguments\n",
        b"config service 'x'\n\toption 'odd name' SECRET-odd-name\n",
    ],
)
def test_openwrt_uci_that_cannot_be_parsed_is_only_fingerprinted(uci):
    text = _openwrt_text({"etc/config/wireless": uci})
    _assert_no_secret(text)
    index = text.index("### /etc/config/wireless")
    line = text[index:].splitlines()[1]
    assert line.startswith("[unparsed file:") and line.endswith(f"({len(uci)} bytes)"), line


def test_openwrt_uci_values_keep_their_quotes_and_structure():
    uci = b"package 'wireless'\nconfig wifi-iface 'w0'\n\toption ssid 'it'\\''s'\n\tlist dns '1.1.1.1'\n"
    text = _openwrt_text({"etc/config/wireless": uci})
    assert "package 'wireless'" in text
    assert "config wifi-iface 'w0'" in text
    assert "\toption ssid 'it'\\''s'" in text
    assert "\tlist dns '1.1.1.1'" in text
