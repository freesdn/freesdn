# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The three ticketing plugins, and the sandbox trap that nearly shipped in them.

FreeSDN raised alerts and nothing turned them into work. The Integrations page
listed Jira, ServiceNow and PagerDuty and described exactly that behaviour, but
an integration is a webhook -- a URL, event types and an HMAC secret -- with
nowhere to put a vendor credential and no way to shape a vendor payload. None of
the three could authenticate, so none of them could ever have worked.

THE TRAP, caught by running them rather than reading them. All three formatted
transport failures with ``type(exc).__name__``, and ``type`` is NOT in the
plugin sandbox's builtin allowlist. So the except block raised NameError, the
supervisor recorded a lifecycle failure, and the settings check returned an
EMPTY warning -- an unreachable host reported nothing at all:

    PUT /plugins/jira-tickets/settings {...unreachable host...}
    -> {"settings": {...}}          # no warning
    log: Plugin jira-tickets validator raised: name 'type' is not defined

and after switching to ``exc.__class__.__name__``:

    -> "Jira did not accept the request: ValueError: Cannot resolve hostname:
        nope.invalid.example"

The ratchet at the bottom covers every plugin, not just these three, because
this is a mistake that reads as completely normal Python and only fails inside
the sandbox.
"""

from __future__ import annotations

import pathlib
import re

import pytest

PLUGINS = ["jira-tickets", "servicenow-incidents", "pagerduty-incidents"]


def _registry() -> pathlib.Path:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins"
        if candidate.is_dir():
            return candidate
    pytest.skip("registry plugins are not present in this checkout")


def _source(plugin_id: str) -> str:
    return (_registry() / plugin_id / "plugin.py").read_text(encoding="utf-8")


def _manifest(plugin_id: str) -> str:
    return (_registry() / plugin_id / "plugin.yaml").read_text(encoding="utf-8")


def _code_only(src: str) -> str:
    """Source with comments and docstrings stripped.

    Every one of these files EXPLAINS the trap in prose, naming ``type(exc)``.
    An assertion that matched the explanation would fail on correct code and
    pass on the bug if the comment were ever deleted.
    """
    src = re.sub(r'"""[\s\S]*?"""', "", src)
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))


# ── the sandbox trap ────────────────────────────────────────────


def _withheld_builtins() -> set[str]:
    """Names the plugin sandbox does NOT provide."""
    import builtins

    from app.plugins.sandbox import _SAFE_BUILTINS

    return {n for n in dir(builtins) if not n.startswith("_")} - set(_SAFE_BUILTINS)


def test_the_allowlist_really_withholds_type():
    """Premise. If ``type`` becomes available the ratchet below stops meaning anything."""
    assert "type" in _withheld_builtins()


@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_no_ticketing_plugin_calls_a_withheld_builtin(plugin_id: str):
    code = _code_only(_source(plugin_id))
    # Only the ones a plugin plausibly reaches for. Checking all 60-odd would
    # trip over ordinary identifiers and teach nobody anything.
    for name in ("type", "eval", "exec", "setattr", "globals", "vars", "open"):
        if name not in _withheld_builtins():
            continue
        assert not re.search(rf"(?<![\w.]){name}\s*\(", code), (
            f"{plugin_id} calls {name}(), which the sandbox withholds: it raises "
            f"NameError at runtime, and inside an except block it replaces the real "
            f"error with a confusing one"
        )


def test_every_shipped_plugin_avoids_them_too():
    """
    The ratchet, across the whole catalogue. This mistake reads as completely
    normal Python and only fails inside the sandbox, so it will be made again.
    """
    offenders = []
    for path in sorted(_registry().glob("*/plugin.py")):
        code = _code_only(path.read_text(encoding="utf-8"))
        for name in ("type", "eval", "exec", "setattr", "globals", "vars", "open"):
            if name in _withheld_builtins() and re.search(rf"(?<![\w.]){name}\s*\(", code):
                offenders.append(f"{path.parent.name}: {name}()")
    assert not offenders, f"plugins calling withheld builtins: {offenders}"


# ── they subscribe to an event that exists ──────────────────────


@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_they_subscribe_to_alert_fired_not_alert_created(plugin_id: str):
    """
    ``alert.created`` is never published -- events.py records that explicitly.
    Subscribing to it is how an integration ends up looking enabled while
    receiving nothing, which is the exact failure these plugins replace.
    """
    manifest = _manifest(plugin_id)
    body = "\n".join(ln for ln in manifest.splitlines() if not ln.strip().startswith("#"))
    assert "alert.fired" in body
    assert "alert.created" not in body
    assert "alert.resolved" in body, "nothing would ever close the ticket"


# ── the decisions worth protecting ──────────────────────────────


@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_dry_run_is_on_by_default(plugin_id: str):
    """
    The first thing a ticketing integration should do is show you the tickets it
    WOULD have opened. It matters most for PagerDuty, where getting it wrong
    pages a human at 3am.
    """
    manifest = _manifest(plugin_id)
    block = manifest.split("dry_run:", 1)[1][:200]
    assert "default: true" in block, f"{plugin_id} would file for real on first install"


@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_credentials_are_declared_secret(plugin_id: str):
    """
    ``secret: true`` is what makes a field a credential rather than a string:
    the platform encrypts it on write and never returns it on read.
    """
    assert "secret: true" in _manifest(plugin_id), f"{plugin_id} stores a credential in plaintext"


@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_each_checks_its_settings_at_save_time(plugin_id: str):
    code = _code_only(_source(plugin_id))
    assert "async def async_validate_config" in code
    assert "PluginNotReady" in code, (
        f"{plugin_id} does not distinguish a remote being down from being broken, "
        "so an outage would quarantine it"
    )


def test_pagerduty_says_it_cannot_verify_the_routing_key():
    """
    The honest limitation. A routing key is only proved by sending an event, and
    sending one pages somebody -- which is not what saving settings should do. A
    green tick that meant nothing would be worse than saying so.
    """
    code = _code_only(_source("pagerduty-incidents"))
    assert "NOT been verified" in code
    assert "ROUTING_KEY_LENGTH" in code, "the key's shape is not checked at all"


def test_pagerduty_does_not_guess_severity_upward():
    """An unrecognised severity must not page someone as critical."""
    path = _registry() / "pagerduty-incidents" / "plugin.py"
    src = path.read_text(encoding="utf-8")
    mapping = re.search(r"PD_SEVERITY = \{(.*?)\}", src, re.S).group(1)
    assert '"critical": "critical"' in mapping
    # The fallback lives at the call site; make sure it is not "critical".
    fallback = re.search(r'PD_SEVERITY\.get\([^,]+,\s*"([a-z]+)"\)', src)
    assert fallback and fallback.group(1) != "critical", (
        "an unknown severity would page on-call as critical"
    )


def test_jira_and_servicenow_deduplicate_by_alert_id():
    """
    A flapping rule publishes ``alert.fired`` every time it trips. One ticket
    per firing gives an operator forty identical tickets by morning, and the
    reliable outcome of that is the integration being switched off.
    """
    assert "__jira_issue__" in _source("jira-tickets")
    assert "__snow_incident__" in _source("servicenow-incidents")


def test_pagerduty_uses_the_remote_dedup_instead_of_its_own():
    """
    PagerDuty deduplicates server-side on ``dedup_key``, so this plugin holds no
    state at all. Keeping a local map as well would be a second source of truth
    that can disagree with theirs.
    """
    code = _code_only(_source("pagerduty-incidents"))
    assert '"dedup_key": alert_id' in code
    assert "__pd_" not in code, "pagerduty is keeping local state it does not need"


def test_servicenow_does_not_invent_a_priority():
    """
    ServiceNow has no severity: it derives priority from urgency and impact via
    a matrix every instance tunes. A plugin that guessed would file everything
    at a priority somebody has to correct by hand.
    """
    manifest = _manifest("servicenow-incidents")
    assert "urgency_map" in manifest
    assert "impact" in manifest


def test_jira_sends_atlassian_document_format():
    """
    Jira Cloud v3 refuses a plain string for ``description``. The failure is a
    400 that does not obviously say so, which makes it the most likely reason a
    first issue never files.
    """
    code = _code_only(_source("jira-tickets"))
    assert '"type": "doc"' in code and '"version": 1' in code


@pytest.mark.parametrize("plugin_id", ["jira-tickets", "servicenow-incidents"])
def test_an_unclosable_ticket_is_left_open_with_a_reason(plugin_id: str):
    """
    A workflow with no matching transition, or a close code the instance does
    not know, must not end in silence. An incident that quietly stayed open is
    worse than one that says what stopped it closing.
    """
    code = _code_only(_source(plugin_id))
    assert "left to you" in code, f"{plugin_id} abandons a ticket it cannot close"
