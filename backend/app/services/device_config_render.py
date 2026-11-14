# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device configuration export: normalize, fingerprint, redact, diff
==========================================================================

Pure functions (no I/O, no database) shared by the config-backup service and its
API. Two export formats today:

* ``opnsense-config-xml`` -- OPNsense ``config.xml`` from
  ``/api/core/backup/download/this`` (read-only).
* ``openwrt-sysupgrade`` -- the LuCI ``cgi-backup`` sysupgrade ``.tar.gz``
  (read-only: rpcd builds the archive on the fly).

Redaction is DELIBERATELY over-eager. Anything whose element / option name looks
secret (``pass``, ``secret``, ``key``, ``psk``, ``hash``, ``token``, ``prv`` ...),
any PEM private key and any long base64 blob is replaced by
``[redacted:<fingerprint>]``. The fingerprint is a keyed HMAC prefix (the key is
derived from SECRET_KEY), so a diff still shows THAT a password changed without
revealing it, and nothing short of the instance key can test guesses against it.
Hiding a harmless value is acceptable; showing a secret is not. In an OpenWrt
archive only UCI files (``etc/config/*``) are shown; every other text file is an
unknown format and appears as its name, size and fingerprint only.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import io
import re
import tarfile
import xml.etree.ElementTree as ET  # nosec B405 - only serialises a tree parse_untrusted_xml built
from collections.abc import Iterable
from dataclasses import dataclass

from app.core.redaction import _key_is_sensitive
from app.core.xml_utils import UnsafeXML, parse_untrusted_xml

OPNSENSE_XML = "opnsense-config-xml"
OPENWRT_SYSUPGRADE = "openwrt-sysupgrade"
FORMATS = (OPNSENSE_XML, OPENWRT_SYSUPGRADE)

MAX_EXPORT_BYTES = 16 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 4096
_MAX_ARCHIVE_UNPACKED = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_DIFF_LINES = 5000

# Substrings that make an element / option name secret-looking.
_SECRET_FRAGMENTS = (
    "pass",
    "secret",
    "key",
    "psk",
    "hash",
    "token",
    "cred",
    "prv",
    "priv",
    "seed",
    "otp",
    "tls",
    "community",
    "bindpw",
    "crypt",
    "cookie",
    "auth",
)
# Names containing a fragment above that are public by definition.
_PUBLIC_NAMES = frozenset({"pubkey", "publickey", "public_key", "public-key", "authserver"})
_PEM_PRIVATE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    r"|-----BEGIN OpenVPN Static key V1-----.*?-----END OpenVPN Static key V1-----",
    re.DOTALL,
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_UCI_LINE = re.compile(r"^(\s*(?:option|list)\s+)(\S+)(\s+)(.*)$")
# Whole files never shown, only fingerprinted (path relative to the archive root).
_SECRET_FILES = (
    re.compile(r"^etc/shadow-?$"),
    re.compile(r"^etc/dropbear/.*"),
    re.compile(r"^etc/ssl/private/.*"),
    re.compile(r"^etc/wireguard/.*"),
    re.compile(r".*\.(key|pem|p12|pfx|crt|der)$"),
    re.compile(r"^etc/uhttpd\..*"),
)
# Only UCI files are parsed and shown. Every other member (openvpn auth files,
# ppp chap-secrets, scripts, arbitrary sysupgrade.conf includes) is an unknown
# format whose secrets the UCI redactor cannot recognise, so it is fingerprinted
# whole: name, size and a keyed hash, never its contents.
_UCI_FILE = re.compile(r"^etc/config/[^/]+$")
# Credentials embedded in a URL (scheme://user:pass@host or scheme://token@host).
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^\s/?#'\"]+)@")


class ConfigFormatError(ValueError):
    """The export is not a valid document of the declared format (no detail kept)."""


def _digest_key(secret_key: str) -> bytes:
    return hashlib.sha256(b"freesdn.device-config-backup.v1\0" + secret_key.encode()).digest()


def _instance_secret() -> str:
    from app.core.config import settings

    return settings.SECRET_KEY


@dataclass(frozen=True)
class Normalized:
    """``content`` is what gets stored; ``identity`` is what decides "changed"."""

    format: str
    content: bytes
    identity: bytes


def name_is_secret(name: str) -> bool:
    lowered = name.lower()
    if lowered in _PUBLIC_NAMES:
        return False
    if _key_is_sensitive(name):
        return True
    return any(fragment in lowered for fragment in _SECRET_FRAGMENTS)


def _fingerprint(value: str | bytes, secret_key: str) -> str:
    data = value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value
    return hmac.new(_digest_key(secret_key), data, hashlib.sha256).hexdigest()[:10]


def _marker(value: str | bytes, secret_key: str, label: str = "redacted") -> str:
    return f"[{label}:{_fingerprint(value, secret_key)}]"


def content_digest(identity: bytes, secret_key: str | None = None) -> str:
    """Keyed digest used to decide whether a new export differs from the last."""
    key = _digest_key(secret_key if secret_key is not None else _instance_secret())
    return hmac.new(key, identity, hashlib.sha256).hexdigest()


# ── normalization ────────────────────────────────────────────────────────────


def _safe_member_name(name: str) -> str | None:
    cleaned = name.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _archive_files(archive: bytes) -> list[tuple[str, bytes]]:
    """Regular files of a sysupgrade archive, bounded, sorted, never written to disk."""
    files: dict[str, bytes] = {}
    unpacked = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for count, member in enumerate(tar, start=1):
                if count > _MAX_ARCHIVE_MEMBERS:
                    raise ConfigFormatError("archive has too many members")
                if not member.isreg():
                    continue
                name = _safe_member_name(member.name)
                if name is None or member.size > _MAX_MEMBER_BYTES:
                    raise ConfigFormatError("archive member rejected")
                unpacked += member.size
                if unpacked > _MAX_ARCHIVE_UNPACKED:
                    raise ConfigFormatError("archive expands beyond the limit")
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                data = stream.read(_MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    raise ConfigFormatError("archive member size mismatch")
                files[name] = data
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        if isinstance(exc, ConfigFormatError):
            raise
        raise ConfigFormatError("not a readable sysupgrade archive") from None
    if not files:
        raise ConfigFormatError("archive holds no configuration files")
    return sorted(files.items())


def normalize_export(fmt: str, payload: bytes) -> Normalized:
    """Validate an export and compute what identifies its configuration."""
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EXPORT_BYTES:
        raise ConfigFormatError("export is empty or too large")
    if fmt == OPNSENSE_XML:
        try:
            root = parse_untrusted_xml(payload, max_bytes=MAX_EXPORT_BYTES)
        except UnsafeXML:
            raise ConfigFormatError("not a safe XML document") from None
        if root.tag != "opnsense":
            raise ConfigFormatError("not an OPNsense configuration")
        # config.xml is stored verbatim; any byte change is a new version.
        return Normalized(fmt, payload, payload)
    if fmt == OPENWRT_SYSUPGRADE:
        files = _archive_files(payload)
        # The archive is rebuilt (new mtimes, new gzip header) on every request,
        # so identity is the file list and contents, not the archive bytes.
        identity = b"".join(
            name.encode("utf-8", "surrogateescape") + b"\0" + hashlib.sha256(data).digest()
            for name, data in files
        )
        return Normalized(fmt, payload, identity)
    raise ConfigFormatError("unknown export format")


# ── redacted rendering ──────────────────────────────────────────────────────


def _redact_text_value(value: str, secret_key: str) -> str:
    value = _PEM_PRIVATE.sub(lambda match: _marker(match.group(0), secret_key), value)
    stripped = value.strip()
    # Certificates, keys and opaque tokens are stored as long base64 runs; prose
    # (descriptions) has spaces, so it is never mistaken for one.
    compact = "".join(stripped.split())
    if len(compact) >= 128 and " " not in stripped and _BASE64.fullmatch(compact):
        return _marker(stripped, secret_key, "blob")
    return value


def _render_opnsense(payload: bytes, secret_key: str) -> str:
    try:
        root = parse_untrusted_xml(payload, max_bytes=MAX_EXPORT_BYTES)
    except UnsafeXML:
        raise ConfigFormatError("not a safe XML document") from None
    for element in root.iter():
        for attribute, value in list(element.attrib.items()):
            if name_is_secret(attribute):
                element.attrib[attribute] = _marker(value, secret_key)
        text = element.text
        if text is not None and text.strip():
            if name_is_secret(str(element.tag)):
                element.text = _marker(text, secret_key)
            else:
                element.text = _redact_text_value(text, secret_key)
        if element.tail is not None and element.tail.strip():
            element.tail = _redact_text_value(element.tail, secret_key)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def _redact_uci(text: str, secret_key: str) -> str:
    text = _PEM_PRIVATE.sub(lambda match: _marker(match.group(0), secret_key), text)
    text = _URL_USERINFO.sub(
        lambda match: match.group(1) + _marker(match.group(2), secret_key) + "@", text
    )
    lines = []
    for line in text.splitlines():
        match = _UCI_LINE.match(line)
        if match and name_is_secret(match.group(2)):
            line = (
                match.group(1)
                + match.group(2)
                + match.group(3)
                + _marker(match.group(4), secret_key)
            )
        lines.append(line)
    return "\n".join(lines)


def _render_openwrt(payload: bytes, secret_key: str) -> str:
    out: list[str] = []
    for name, data in _archive_files(payload):
        out.append(f"### /{name}")
        if any(pattern.match(name) for pattern in _SECRET_FILES):
            out.append(f"{_marker(data, secret_key, 'secret file')} ({len(data)} bytes)")
            continue
        if not data:
            out.append("(empty)")
            continue
        try:
            text: str | None = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is None or "\0" in text:
            out.append(f"{_marker(data, secret_key, 'binary file')} ({len(data)} bytes)")
            continue
        if not _UCI_FILE.match(name):
            out.append(f"{_marker(data, secret_key, 'file')} ({len(data)} bytes)")
            continue
        out.append(_redact_uci(text, secret_key))
    return "\n".join(out) + "\n"


def render_redacted(fmt: str, payload: bytes, secret_key: str | None = None) -> str:
    """Human-readable configuration with every secret-looking value replaced."""
    key = secret_key if secret_key is not None else _instance_secret()
    if fmt == OPNSENSE_XML:
        return _render_opnsense(payload, key)
    if fmt == OPENWRT_SYSUPGRADE:
        return _render_openwrt(payload, key)
    raise ConfigFormatError("unknown export format")


def redacted_diff(
    older: str, newer: str, *, older_label: str, newer_label: str
) -> tuple[list[str], bool]:
    """Unified diff of two REDACTED renderings, capped at MAX_DIFF_LINES."""
    lines: Iterable[str] = difflib.unified_diff(
        older.splitlines(),
        newer.splitlines(),
        fromfile=older_label,
        tofile=newer_label,
        lineterm="",
    )
    result: list[str] = []
    for line in lines:
        if len(result) >= MAX_DIFF_LINES:
            return result, True
        result.append(line)
    return result, False


def diff_summary(diff_lines: list[str]) -> dict[str, int]:
    added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    return {"added": added, "removed": removed}
