# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Alert-rule Email / SMS / In-App channels have never delivered anything.

Background
----------
``_extract_recipients`` read ``config["to"]`` for both email and SMS. The Alert
Rules dialog writes different keys entirely::

    AlertRulesPage.tsx:1293   updateChannelConfig('email', 'recipients', ...)
    AlertRulesPage.tsx:1353   updateChannelConfig('sms',   'phone_numbers', ...)

The key never matched, so the function returned ``[]``. An empty recipient list
produces no send task, no ``DeliveryResult`` and no error -- the rule reports
success and nothing is sent. Slack, Teams and webhook happened to agree on
their key (``channel`` / ``webhook_url`` / ``url``) and worked, which is exactly
why the feature looked healthy.

Two follow-on traps this file also pins:

1. Re-keying alone is not enough. ``recipients`` is free text, so it arrives as
   ``"ops@example.com, devops@example.com"`` -- ONE string.
   ``email.utils.parseaddr`` returns ``("", "")`` for that, so
   ``_validate_email_address`` rejects it and the send FAILS. Without splitting,
   the fix would trade a silent no-op for a hard error.

2. Single-valued channels must NOT be split. A webhook URL containing a comma
   would be shredded into two bogus recipients.

In-App was broken differently: the dialog offers a bare enable toggle and
collects no user IDs, so its recipient list was always empty too. Enabling it
means "raise this in the bell for this org", so it now resolves the
organization's active users.
"""

from __future__ import annotations

import pytest

from app.services.notification_helpers import _extract_recipients, _split_recipients

# ── The regression ───────────────────────────────────────────────


def test_email_reads_the_key_the_alert_rule_dialog_writes() -> None:
    """The bug: the dialog writes `recipients`, the reader wanted `to`."""
    got = _extract_recipients("email", {"enabled": True, "recipients": "ops@example.com"})
    assert got == ["ops@example.com"]


def test_sms_reads_the_key_the_alert_rule_dialog_writes() -> None:
    got = _extract_recipients("sms", {"enabled": True, "phone_numbers": "+15551234567"})
    assert got == ["+15551234567"]


def test_comma_joined_recipients_are_split() -> None:
    """
    The second half of the bug. One string containing two addresses fails
    parseaddr, so re-keying without splitting would still not deliver.
    """
    got = _extract_recipients("email", {"recipients": "ops@example.com, devops@example.com"})
    assert got == ["ops@example.com", "devops@example.com"]


@pytest.mark.parametrize(
    "raw",
    [
        "a@x.com,b@x.com",
        "a@x.com, b@x.com",
        "a@x.com; b@x.com",
        "a@x.com\nb@x.com",
        ["a@x.com", "b@x.com"],
        [" a@x.com ", "b@x.com"],
    ],
)
def test_every_realistic_multi_recipient_shape(raw: object) -> None:
    assert _extract_recipients("email", {"recipients": raw}) == ["a@x.com", "b@x.com"]


def test_in_app_reads_user_ids() -> None:
    assert _extract_recipients("in_app", {"user_ids": ["u1", "u2"]}) == ["u1", "u2"]


# ── The canonical keys must keep working ─────────────────────────


def test_the_documented_to_key_still_works() -> None:
    """
    Rows already in the database carry whichever key was written when they were
    saved, and the module docstring documents `to`. Both must resolve.
    """
    assert _extract_recipients("email", {"to": ["ops@example.com"]}) == ["ops@example.com"]
    assert _extract_recipients("sms", {"to": ["+1555"]}) == ["+1555"]


@pytest.mark.parametrize(
    ("channel", "config", "expected"),
    [
        ("slack", {"channel": "#alerts"}, ["#alerts"]),
        (
            "teams",
            {"webhook_url": "https://outlook.office.com/webhook/x"},
            ["https://outlook.office.com/webhook/x"],
        ),
        ("webhook", {"url": "https://api.example.com/hook"}, ["https://api.example.com/hook"]),
    ],
)
def test_channels_that_already_worked_are_unchanged(
    channel: str, config: dict, expected: list[str]
) -> None:
    assert _extract_recipients(channel, config) == expected


def test_single_valued_channels_are_never_split() -> None:
    """
    A comma inside a webhook URL is legal. Splitting it would turn one working
    endpoint into two broken ones -- a regression introduced BY the fix.
    """
    url = "https://api.example.com/hook?tags=a,b"
    assert _extract_recipients("webhook", {"url": url}) == [url]


# ── Shapes that must not raise ───────────────────────────────────


@pytest.mark.parametrize(
    "config",
    [{}, {"enabled": True}, {"recipients": ""}, {"recipients": None}, {"recipients": []}],
)
def test_empty_configs_yield_no_recipients_without_raising(config: dict) -> None:
    assert _extract_recipients("email", config) == []


def test_non_dict_config_is_tolerated() -> None:
    assert _extract_recipients("email", None) == []  # type: ignore[arg-type]
    assert _extract_recipients("email", "nonsense") == []  # type: ignore[arg-type]


def test_unknown_channel_yields_nothing() -> None:
    assert _extract_recipients("carrier_pigeon", {"to": "x"}) == []


def test_duplicates_are_collapsed() -> None:
    assert _split_recipients("a@x.com, a@x.com, b@x.com") == ["a@x.com", "b@x.com"]


def test_in_app_falls_back_to_org_users_when_none_are_named() -> None:
    """
    The dialog collects no user IDs, so without a fallback the In-App toggle is
    decorative. Pin that the dispatcher has the fallback wired.
    """
    import inspect

    from app.services import notification_helpers

    src = inspect.getsource(notification_helpers.dispatch_notifications)
    assert "_org_user_ids" in src, "the in_app fallback is gone; the toggle does nothing again"
