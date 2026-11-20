# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 FreeSDN
"""Keep phone credentials out of what the VoIP read APIs return.

Configuration templates hold the phone admin password (``feature_settings``)
and any Grandstream P-value (``raw_overrides``), a phone's own
``settings.p_values`` override any P-value, and the rendered config holds the
SIP password. All of it was readable with ``voip.view``, which the Viewer role
has, so any viewer could read the very secrets the provisioning window keeps
from the site network (found in review of the 26.11.3 candidates).

Grandstream has more password P-values than any list here will name (config
server, firmware server, per-account and per-model numbering), so a Viewer
gets NO P-value's value at all: every key that is a P-value number is hidden,
along with every key named like a password. Someone who may manage phones,
and could write those values anyway, sees the known credentials hidden. An
update or create that sends the placeholder back keeps the stored value, or
stores nothing.
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree.ElementTree import tostring

from app.core.url_secrets import may_hold_credential

SECRET_PLACEHOLDER = "********"
# What the shared redactor (app/core/redaction.py) shows; a phone read passes
# through both, so a client can send either back.
_PLACEHOLDERS = frozenset({SECRET_PLACEHOLDER, "***"})

# Grandstream P-values known to hold a credential: admin (P2) and end-user
# (P196) passwords, each account's SIP password (P34, P134, ... P1634,
# P406/P506/P606 on GXP21xx), the XML config passwords (P145, P1359), the
# config-server and firmware-server HTTP passwords (P1361, P6769) and P1.
_CREDENTIAL_PVALUES: frozenset[str] = frozenset(
    {
        "1",
        "2",
        "196",
        "34",
        "134",
        "234",
        *(f"{n}34" for n in range(4, 17)),
        "406",
        "506",
        "606",
        "145",
        "1359",
        "1361",
        "6769",
    }
)
_PVALUE_KEY = re.compile(r"^[Pp]?\d+$")


def _pvalue_number(key: object) -> str | None:
    text = str(key or "").strip()
    return text.upper().removeprefix("P") if _PVALUE_KEY.match(text) else None


def is_secret_setting(key: object) -> bool:
    """True for a setting or config element known to hold a credential."""
    lowered = str(key or "").strip().lower().replace("-", "_")
    if any(
        word in lowered
        for word in ("password", "passwd", "secret", "passphrase", "token", "apikey", "api_key")
    ):
        return True
    if lowered in {"pin", "psk"} or lowered.endswith(("_pass", "pwd", "_pin", "_psk")):
        return True
    return _pvalue_number(key) in _CREDENTIAL_PVALUES


# A field that holds a secret by its name's ending (extPassword, vmPin, apiKey).
_SECRET_FIELD_END = re.compile(r"(pass|password|passwd|pin|secret|token|key)$", re.IGNORECASE)


def secret_values(payload: Any, *, minimum: int = 3) -> list[str]:
    """The values in ``payload`` sent under a credential's name (any depth).

    For checking what a device or PBX answers: a message that repeats one of
    them is not shown (found in review of 26.11.3).
    """
    found: list[str] = []

    def walk(value: Any, key: str) -> None:
        if isinstance(value, dict):
            for name, item in value.items():
                walk(item, str(name))
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, key)
        elif isinstance(value, (str, int)) and not isinstance(value, bool):
            text = str(value)
            if len(text) >= minimum and (is_secret_setting(key) or _SECRET_FIELD_END.search(key)):
                found.append(text)

    walk(payload, "")
    return found


def shown_provider_text(text: object, *, secrets: Any = (), limit: int = 300) -> str:
    """A device's or PBX's message for an error or a log line, or a note that
    it was hidden because it repeats a credential FreeSDN sent or looks like
    it holds one. ``secrets`` are the values sent (see :func:`secret_values`)."""
    value = str(text)
    if any(secret and str(secret) in value for secret in secrets) or may_hold_credential(
        value, is_secret_setting
    ):
        return "(message hidden: it may contain a credential)"
    return value[:limit]


def _has_value(item: object) -> bool:
    return item not in (None, "") and not isinstance(item, bool)


def redact_settings(value: Any, *, every_pvalue: bool = False) -> Any:
    """A copy of ``value`` with credentials replaced by the placeholder.

    Walks nested dicts and lists. ``every_pvalue`` also hides the value of every
    key that is a P-value number, whatever it is: that is what a Viewer gets.
    """
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            hide = (
                is_secret_setting(key)
                or (every_pvalue and _pvalue_number(key) is not None)
                # A server URL with a login in it (http://user:pass@host/...).
                or (isinstance(item, str) and may_hold_credential(item, is_secret_setting))
            )
            out[key] = (
                SECRET_PLACEHOLDER
                if hide and _has_value(item)
                else redact_settings(item, every_pvalue=every_pvalue)
            )
        return out
    if isinstance(value, list):
        return [
            SECRET_PLACEHOLDER
            if isinstance(item, str) and may_hold_credential(item, is_secret_setting)
            else redact_settings(item, every_pvalue=every_pvalue)
            for item in value
        ]
    return value


def _is_placeholder(item: object) -> bool:
    return isinstance(item, str) and item in _PLACEHOLDERS


def restore_redacted(new: Any, stored: Any) -> Any:
    """Keep the stored value wherever a client sent the placeholder back.

    A placeholder with nothing stored behind it (a template created from a
    read response) is dropped rather than saved as the password.
    """
    if isinstance(new, dict):
        old = stored if isinstance(stored, dict) else {}
        out: dict[Any, Any] = {}
        for key, item in new.items():
            if _is_placeholder(item):
                if key in old:
                    out[key] = old[key]
                continue
            out[key] = restore_redacted(item, old.get(key))
        return out
    if isinstance(new, list):
        old_items = stored if isinstance(stored, list) else []
        kept = []
        for index, item in enumerate(new):
            previous = old_items[index] if index < len(old_items) else None
            if _is_placeholder(item):
                if previous is not None:
                    kept.append(previous)
                continue
            kept.append(restore_redacted(item, previous))
        return kept
    return new


def redact_config_xml(xml: str) -> str:
    """The rendered config with every known credential element's text replaced."""
    from defusedxml.ElementTree import fromstring

    root = fromstring(xml)
    for element in root.iter():
        if element.text and (
            is_secret_setting(element.tag)
            # A config or firmware server URL with a login in it (P237, P192).
            or may_hold_credential(element.text, is_secret_setting)
        ):
            element.text = SECRET_PLACEHOLDER
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")
