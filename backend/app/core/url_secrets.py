# SPDX-License-Identifier: AGPL-3.0-only
"""Hide free text that may carry a credential in a URL or a parameter list.

A value in a device configuration, a remembered device answer or a log line
can carry a login (``scheme://user:pass@host``) or a credential parameter
(``?password=...``). An earlier version masked just those parts with a
URL-aware parser. Two independent reviews kept finding inputs it misread:
repeated or partial percent-encoding, quotes, tabs and spaces inside values,
``=`` inside a login, logins without ``//``, ``+`` read two ways. A parser that
decides exactly where a credential ends cannot be made complete.

The rule is now simple enough to check by reading it. A text that, read any
way a URL or form parser might read it, holds a credential-like name before an
``=`` or ``:``, or holds a URL login, is masked WHOLE. Nothing is masked
partly, so there is no value boundary to get wrong. Masking too much is
acceptable; showing a credential is not.

Readings: the text as written, and percent-decoded repeatedly both keeping
``+`` (as ``unquote`` and URL userinfo do) and reading it as a space (as form
decoding does), each with tabs, line breaks and other control characters
removed, as URL parsers remove them. A text still changing when the decoding
bound is reached is masked whole.

A credential-like name: the text between the previous separator and an
``=`` or ``:``, judged whole and word by word (``password'=``, ``password[0]=``,
``pass word=`` all count), that the caller's classifier calls a credential,
or that has a part in ``CREDENTIAL_PARAMS``. A login: an ``@`` with ``:`` or
``//`` before it in the same run of non-space text (``user:pass@host``,
``//token@host``, a backslash read as "/"), or after "//" across spaces; an
email address (``admin@example.com``) or ``git@host:path`` is not one.

A secret with no credential-like name (``?p=hunter2``) is not recognised.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote, unquote_plus

#: Names that carry a credential whatever the classifier says.
CREDENTIAL_PARAMS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "pass",
        "pwd",
        "pw",
        "token",
        "secret",
        "key",
        "apikey",
        "auth",
        "psk",
        "community",
        "credential",
        "credentials",
        "signature",
        "sig",
    }
)

#: Decoding rounds read. A text still changing after this many is masked whole.
_MAX_DECODE_ROUNDS = 8

#: Runs of name characters inside a name, each judged on its own
#: ("mfa_backup_codes" inside "//h/?mfa_backup_codes").
_NAME_RUNS = re.compile(r"[A-Za-z0-9_.\-]+")
#: A public key: base64 of at least 40 characters (a WireGuard key has 44),
#: which holds no ":" or "@" (so no URL login) and "=" only as padding.
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
#: Web URL schemes, whose parser accepts a login with no "//" after them.
_WEB_SCHEME = re.compile(r"(?i)(?:https?|ftp|wss?):")
#: Words inside a name, each checked on its own.
_NAME_WORDS = re.compile(r"[A-Za-z0-9]+")
#: Where a name splits into the parts checked against ``CREDENTIAL_PARAMS``.
_NAME_PARTS = re.compile(r"[^A-Za-z0-9]+")
#: Runs of non-space text, where a login is looked for.
_RUNS = re.compile(r"\S+")


def _without_controls(text: str) -> str:
    return "".join(char for char in text if char.isprintable() or char == " ")


def _readings(text: str) -> list[str] | None:
    """Every reading of ``text``, or None when decoding does not settle.

    Decoding starts both from the text as written and from it with control
    characters removed, because a URL parser removes tabs and line breaks
    before it decodes (``pass%\t77ord`` is ``password`` to it).
    """
    cleaned = _without_controls(text)
    readings = [cleaned]
    for start in (text, cleaned):
        for decode in (unquote, unquote_plus):
            current = start
            for _ in range(_MAX_DECODE_ROUNDS):
                decoded = (
                    _without_controls(decode(current)) if start is cleaned else decode(current)
                )
                if decoded == current:
                    break
                current = decoded
                readings.append(_without_controls(current))
            else:
                if decode(current) != current:
                    return None
    return readings


def _names_a_credential(name: str, is_secret_name: Callable[[str], bool]) -> bool:
    if is_secret_name(name):
        return True
    return any(part.lower() in CREDENTIAL_PARAMS for part in _NAME_PARTS.split(name) if part)


def _holds_credential_name(reading: str, is_secret_name: Callable[[str], bool]) -> bool:
    """Whether a credential-like name stands before an "=" or ":" in ``reading``.

    The name is everything since the previous "=" or ":" (a decoded "&" may
    belong to it: ``%70assword%26x=`` names ``password&x``). It is judged
    whole (``password[0]``), run by run (``mfa_backup_codes``) and word by
    word (``pass word``). Every character belongs to one name, so this is
    linear.
    """
    floor = 0
    for index, char in enumerate(reading):
        if char not in "=:":
            continue
        name = reading[floor:index].strip()
        floor = index + 1
        if not name:
            continue
        if _names_a_credential(name, is_secret_name):
            return True
        for pattern in (_NAME_RUNS, _NAME_WORDS):
            if any(
                _names_a_credential(part.group(0), is_secret_name)
                for part in pattern.finditer(name)
            ):
                return True
    return False


def _login_in_runs(reading: str, *, compact: bool) -> bool:
    """A login in a run of non-space text: ":" or "//" before its last "@".

    ``compact`` is the reading with its spaces removed, where a single ":"
    could come from prose ("Contact: admin@example.com"), so there "//", ":/",
    two ":" or a web scheme ("https:") before the "@" count
    (``https:u: pre secret@h``, ``https: token@h``).
    """
    for match in _RUNS.finditer(reading):
        run = match.group(0)
        at = run.rfind("@")
        if at <= 0:
            continue
        before = run[:at]
        if compact:
            if (
                "//" in before
                or ":/" in before
                or before.count(":") >= 2
                or _WEB_SCHEME.search(before) is not None
            ):
                return True
        elif ":" in before or "//" in before:
            return True
    return False


def _holds_login(reading: str) -> bool:
    """Whether ``reading`` holds a URL login.

    A backslash is read as "/" (browsers do, for web URLs: ``\\token@h``). A
    login can hold spaces (``https://u:pre secret@h``), so after "//" the
    text is also read with its spaces removed (see ``_login_in_runs``), so
    "Contact: admin@example.com" stays readable.
    """
    if "@" not in reading:
        return False
    slashed = reading.replace("\\", "/")
    if _login_in_runs(slashed, compact=False):
        return True
    return _login_in_runs("".join(slashed.split()), compact=True)


def looks_like_public_key(value: str) -> bool:
    """Whether ``value`` is shaped like a base64 public key (so it can hold no
    URL login). Values under public-key names are kept only when they are."""
    return _PUBLIC_KEY.fullmatch(value.strip()) is not None


def may_hold_credential(text: str, is_secret_name: Callable[[str], bool]) -> bool:
    """Whether ``text``, read any way a URL or form parser might, could show a
    credential: a credential-like name before ``=`` or ``:``, or a URL login.
    True also when its percent-decoding does not settle."""
    if not any(char in text for char in "=:@%"):
        return False
    readings = _readings(text)
    if readings is None:
        return True
    return any(
        _holds_credential_name(reading, is_secret_name) or _holds_login(reading)
        for reading in readings
    )


def mask_url_credentials(
    text: str, mask: Callable[[str], str], is_secret_name: Callable[[str], bool]
) -> str:
    """Return ``text``, or ``mask(text)`` when it may hold a credential.

    ``mask`` turns the whole text into what is shown instead; ``is_secret_name``
    classifies a name (``CREDENTIAL_PARAMS`` always count).
    """
    return mask(text) if may_hold_credential(text, is_secret_name) else text


def mask_url_credentials_in(
    payload: Any,
    mask: Callable[[str], str],
    is_secret_name: Callable[[str], bool],
    *,
    keep: frozenset[str] = frozenset(),
    depth: int = 0,
) -> Any:
    """Apply :func:`mask_url_credentials` to every string inside ``payload``,
    dictionary keys included. A string value under a key named in ``keep``
    (lower case: public-key names) is kept when it is shaped like a base64
    public key.
    Anything nested deeper than the bound is masked whole rather than kept
    unread."""
    if isinstance(payload, str):
        return mask_url_credentials(payload, mask, is_secret_name)
    if depth >= 32:
        return mask("")
    if isinstance(payload, dict):
        out: dict[Any, Any] = {}
        # Every masked key gets the next number of one counter, skipping any
        # name an original key already has, so no entry overwrites another
        # (nor an unmasked "***" key a masked one). The counter only moves
        # forward, and each original key can block it at most once: linear.
        number = 0
        for key, value in payload.items():
            shown_key = (
                mask_url_credentials(key, mask, is_secret_name) if isinstance(key, str) else key
            )
            if shown_key != key:
                while True:
                    number += 1
                    candidate = f"{shown_key} ({number})"
                    if candidate not in payload and candidate not in out:
                        break
                shown_key = candidate
            if (
                isinstance(key, str)
                and isinstance(value, str)
                and key.lower() in keep
                and looks_like_public_key(value)
            ):
                out[shown_key] = value
            else:
                out[shown_key] = mask_url_credentials_in(
                    value, mask, is_secret_name, keep=keep, depth=depth + 1
                )
        return out
    if isinstance(payload, (list, tuple)):
        return type(payload)(
            mask_url_credentials_in(item, mask, is_secret_name, keep=keep, depth=depth + 1)
            for item in payload
        )
    return payload
