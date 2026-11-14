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
# UCI keywords and the abbreviations libuci accepts for them, and the number
# of arguments each statement takes.
_UCI_KEYWORDS = {
    "package": "package",
    "p": "package",
    "config": "config",
    "c": "config",
    "option": "option",
    "o": "option",
    "list": "list",
    "l": "list",
}
_UCI_ARGS = {"package": (1,), "config": (1, 2), "option": (2,), "list": (2,)}
_UCI_NAME = re.compile(r"[A-Za-z0-9_-]+")
_UCI_SPACE = " \t\r\f\v"
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
# A URL query (or fragment) parameter: separator, name, value.
_URL_PARAM = re.compile(r"([?&;#])([^=&;#?\s'\"]+)=([^&;#\s'\"]*)")
_CREDENTIAL_PARAMS = frozenset(
    {"password", "pass", "pwd", "passwd", "token", "secret", "key", "apikey", "auth"}
)


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


def _redact_url_credentials(text: str, secret_key: str) -> str:
    """Mask ``user:pass@`` in URLs and credential-bearing query parameters."""
    text = _URL_USERINFO.sub(
        lambda match: match.group(1) + _marker(match.group(2), secret_key) + "@", text
    )

    def _param(match: re.Match[str]) -> str:
        separator, name, value = match.groups()
        if value and (name.lower() in _CREDENTIAL_PARAMS or name_is_secret(name)):
            return f"{separator}{name}={_marker(value, secret_key)}"
        return match.group(0)

    return _URL_PARAM.sub(_param, text)


def _redact_text_value(value: str, secret_key: str) -> str:
    value = _PEM_PRIVATE.sub(lambda match: _marker(match.group(0), secret_key), value)
    value = _redact_url_credentials(value, secret_key)
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


class _UciUnsure(ValueError):
    """The file is not UCI this reader can split into statements with confidence."""


def _uci_backslash(text: str, i: int, out: list[str]) -> int:
    """``text[i]`` is a backslash: keep the next character, or continue the line."""
    if i + 1 >= len(text):
        raise _UciUnsure("dangling backslash")
    if text[i + 1] != "\n":
        out.append(text[i + 1])
    return i + 2


def _uci_word(text: str, i: int) -> tuple[str, int]:
    """One argument starting at ``text[i]``, unquoted, as libuci's ``parse_str`` reads it.

    Adjacent unquoted, ``'...'`` and ``"..."`` pieces form one word; quotes may
    span lines; a backslash escapes the next character or continues the line.
    """
    out: list[str] = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise _UciUnsure("unterminated quote")
            out.append(text[i + 1 : end])
            i = end + 1
        elif c == '"':
            i += 1
            while True:
                if i >= n:
                    raise _UciUnsure("unterminated quote")
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\\":
                    i = _uci_backslash(text, i, out)
                else:
                    out.append(text[i])
                    i += 1
        elif c == "\\":
            i = _uci_backslash(text, i, out)
        elif c in _UCI_SPACE or c in "\n;#":
            break
        else:
            out.append(c)
            i += 1
    return "".join(out), i


def _uci_statements(text: str) -> list[tuple[str, list[str]]]:
    """Split a UCI file into (keyword, arguments) statements.

    Statements end at a newline or ``;``; ``#`` starts a comment (comments are
    dropped, so a password noted in one is never shown). Raises
    :class:`_UciUnsure` on anything libuci would reject or this reader cannot
    be sure of: an unknown keyword, a wrong argument count, an odd name, an
    option before the first section, an unterminated quote.
    """
    statements: list[tuple[str, list[str]]] = []
    words: list[str] = []
    in_section = False

    def finish() -> None:
        nonlocal in_section
        if not words:
            return
        keyword = _UCI_KEYWORDS.get(words[0])
        args = words[1:]
        if keyword is None or len(args) not in _UCI_ARGS[keyword]:
            raise _UciUnsure("unexpected statement")
        if keyword == "config":
            if not all(_UCI_NAME.fullmatch(arg) for arg in args):
                raise _UciUnsure("odd section")
            in_section = True
        elif keyword in ("option", "list") and (not in_section or not _UCI_NAME.fullmatch(args[0])):
            raise _UciUnsure("odd option")
        statements.append((keyword, args))
        words.clear()

    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\n;":
            finish()
            i += 1
        elif c in _UCI_SPACE:
            i += 1
        elif c == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("\\\n", i):
            i += 2  # a continued line between two words
        else:
            word, i = _uci_word(text, i)
            words.append(word)
    finish()
    return statements


def _uci_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _redact_uci(text: str, secret_key: str) -> str:
    """Re-emit a UCI file from its parsed statements, with every secret masked.

    Raises :class:`_UciUnsure` when the file cannot be parsed with confidence.
    """
    lines: list[str] = []
    for keyword, args in _uci_statements(text):
        if keyword == "package":
            lines.append(f"package {_uci_quote(args[0])}")
        elif keyword == "config":
            if lines:
                lines.append("")
            lines.append(" ".join(["config", args[0], *map(_uci_quote, args[1:])]))
        else:
            name, value = args
            if name_is_secret(name):
                shown = _marker(value, secret_key)
            else:
                shown = _uci_quote(_redact_text_value(value, secret_key))
            lines.append(f"\t{keyword} {name} {shown}")
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
        try:
            out.append(_redact_uci(text, secret_key))
        except _UciUnsure:
            # Shown only when every statement in it is understood.
            out.append(f"{_marker(data, secret_key, 'unparsed file')} ({len(data)} bytes)")
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
