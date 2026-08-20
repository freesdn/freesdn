# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The SIP secret must never appear in the push-sip-config HTTP response.

Background
----------
``push_sip_config_to_phone`` built its P-value plan with::

    "P34": "********" if dry_run else str(sip_password)

so the DRY RUN -- which carries nothing worth protecting -- was redacted, and
the LIVE push, the one an operator actually clicks, put the extension's SIP
secret in cleartext into ``plan``. ``plan`` is returned verbatim in the response
body, so the secret landed in the browser's react-query cache, in any HAR or
devtools capture, and in any reverse proxy or APM that records response
payloads.

The module goes out of its way never to persist this secret -- its own docstring
says "FreeSDN deliberately does NOT cache SIP secrets ... we want the secret to
travel server-side-only" -- and then handed it back over HTTP.

Both surrounding comments described the intended behaviour rather than the
actual: "build a new dict that's NEVER returned to the caller" (of a dict that
was a no-op copy, since ``plan`` already held the secret) and "Plan with the
password redacted before returning" (it was not).

Secret exposure is one of the blocker classes in this project's threat model,
not a medium.
"""

from __future__ import annotations

import inspect
import re

from app.modules.voip import service as voip_service


def _code() -> str:
    """The method's source with comments stripped.

    The fix deliberately quotes the old broken line in a comment explaining
    what it did, so a naive substring check trips on the explanation rather
    than the code. Strip comments and assert against real statements only.
    """
    src = inspect.getsource(voip_service.VoIPService.push_sip_config_to_phone)
    kept = [
        line.split("  #", 1)[0] for line in src.splitlines() if not line.strip().startswith("#")
    ]
    return chr(10).join(kept)


# ── The regression ───────────────────────────────────────────────


def test_the_live_path_no_longer_puts_the_secret_in_the_returned_plan() -> None:
    """
    The defect in one line: the ternary keyed redaction off ``dry_run``, so the
    live push was the UNREDACTED one. Fail the build if that shape returns.
    """
    src = _code()

    assert '"********" if dry_run else' not in src, (
        "the dry_run-keyed redaction ternary is back: the LIVE push would again "
        "return the SIP secret in the response body"
    )
    assert "if dry_run else str(sip_password)" not in src


def test_the_returned_plan_is_built_already_redacted() -> None:
    """``plan`` is what goes back to the caller, so it must never hold the secret."""
    src = _code()

    plan_block = src[src.index("plan = {") : src.index("write_plan")]
    assert '"P34": "********"' in plan_block, "the returned plan no longer redacts P34"
    assert "sip_password" not in plan_block, (
        "sip_password appears in the dict that is returned to the caller"
    )


def test_only_write_plan_carries_the_real_secret() -> None:
    """
    The separation the comments always claimed: exactly one dict holds the
    secret, and it is the one handed to the phone client, not the one returned.
    """
    src = _code()

    assert 'write_plan = {**plan, "P34": str(sip_password)}' in src

    # every use of the raw secret must be on the write_plan side
    for match in re.finditer(r"^.*str\(sip_password\).*$", src, re.M):
        line = match.group(0)
        assert "write_plan" in line, f"raw secret used outside write_plan: {line.strip()!r}"


def test_the_response_returns_plan_not_write_plan() -> None:
    """If the return were switched to write_plan the redaction would be undone."""
    src = _code()

    assert '"plan": plan,' in src
    assert '"plan": write_plan' not in src


# ── The behaviour that must be preserved ─────────────────────────


def test_the_phone_still_receives_the_real_secret() -> None:
    """
    The fix must not have redacted the write itself -- a phone provisioned with
    the literal string "********" would fail to register, which is the exact
    class of bug (P34 carrying the wrong value) already fixed once in c34e6c7b.
    """
    src = _code()

    write_idx = src.index("write_plan = ")
    set_config_idx = src.index("set_config(")
    assert write_idx < set_config_idx
    assert "set_config(write_plan)" in src, "the phone is no longer sent the real plan"


def test_dry_run_is_still_redacted() -> None:
    """It always was; make sure making the live path safe did not flip this."""
    src = _code()
    dry_block = src[src.index("if dry_run:") : src.index("write_plan")]
    assert "sip_password" not in dry_block
