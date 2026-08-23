# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Reading a plugin's settings and saving them back destroyed its credentials.

``GET /plugins/{id}/settings`` never returns a stored secret. It reports ``***``
to mean "configured", which is right. But ``PUT`` treated that mask like any
other submitted value: it encrypted the literal three asterisks and stored them
AS the credential.

So the most natural thing any client does -- read the settings, change one
field, write them back -- silently replaced every untouched credential with
``***``. Nothing reported a problem. The plugin then authenticated with ``***``
and failed, while the settings page went on showing the field as configured, so
the one place an operator would look to diagnose it actively said it was fine.

Reproduced against the running stack before fixing:

    PUT {"zabbix_token": "REAL-SECRET-TOKEN-123"}   -> stored, encrypted
    GET                                             -> {"zabbix_token": "***"}
    PUT (same body back, one unrelated field edited) -> 200
    decrypt(stored)                                 -> '***'      <-- gone

and after:

    decrypt(stored)                                 -> 'REAL-SECRET-TOKEN-123'

Fixed in the ENDPOINT rather than only in the new settings form, because the
form is not the only client: anything holding an API key can round-trip these,
and a fix that lives in the UI protects only the caller that did not need
protecting.
"""

from __future__ import annotations

import inspect


def _put_source() -> str:
    from app.api.v1.endpoints.plugins import update_plugin_settings

    src = inspect.getsource(update_plugin_settings)
    # Strip comments: the explanation below names the mask and the failure, and
    # an assertion that matched MY OWN COMMENT would pass against the bug.
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))


# ── one sentinel, shared ────────────────────────────────────────


def test_the_mask_is_defined_once():
    """
    GET and PUT have to agree on the exact string. If GET masked with one value
    and PUT recognised another, the round-trip would store the mask again and
    this whole class of bug would come back through the gap between them.
    """
    from app.api.v1.endpoints import plugins as ep

    assert hasattr(ep, "SECRET_MASK"), "the mask is a bare literal again"
    assert ep.SECRET_MASK == "***"


def test_get_masks_with_the_shared_constant():
    from app.api.v1.endpoints.plugins import get_plugin_settings

    src = inspect.getsource(get_plugin_settings)
    assert "SECRET_MASK" in src
    assert '"***"' not in src, "GET masks with a literal that PUT cannot be sure of"


def test_put_recognises_the_shared_constant():
    body = _put_source()
    assert "SECRET_MASK" in body


# ── the fix ─────────────────────────────────────────────────────


def test_a_secret_submitted_as_the_mask_is_left_alone():
    """
    The whole bug. ``value == SECRET_MASK`` for a declared-secret key has to
    skip the write entirely -- not encrypt it, not blank it.
    """
    body = _put_source()
    assert "value == SECRET_MASK" in body, "the mask is still stored as a credential"
    assert "continue" in body.split("value == SECRET_MASK", 1)[1][:200], (
        "the masked secret is recognised but still falls through to the write"
    )


def test_the_skip_happens_before_the_encrypt():
    """
    Order is the fix. Encrypting first and checking afterwards would still have
    replaced the stored ciphertext.
    """
    body = _put_source()
    assert body.index("value == SECRET_MASK") < body.index("encrypt_webhook_secret")


def test_it_only_applies_to_declared_secrets():
    """
    A plain string setting whose value really is ``***`` must still be stored.
    The skip is keyed on the field being a declared secret, not on the value
    alone.
    """
    body = _put_source()
    guard = body.split("value == SECRET_MASK", 1)[0]
    assert "key in secret_keys" in guard.rsplit("if ", 1)[-1], (
        "the mask is being skipped for non-secret fields too"
    )


def test_a_masked_secret_is_still_reported_as_configured():
    """
    Skipping the write must not make the field look unset in the response, or
    the UI would redraw it as empty and invite someone to retype the credential
    that is already there and fine.
    """
    body = _put_source()
    after = body.split("value == SECRET_MASK", 1)[1][:200]
    assert "stored[key] = SECRET_MASK" in after


# ── what must not regress ───────────────────────────────────────


def test_a_real_secret_is_still_encrypted():
    body = _put_source()
    assert "encrypt_webhook_secret(" in body
    assert ':encrypted"' in body or ":encrypted" in body


def test_a_secret_is_never_echoed_back():
    """
    Not even the one just sent. It would land in request logs and browser
    history for no benefit.
    """
    body = _put_source()
    assert 'result: dict[str, Any] = {"settings": stored}' in body
    # `stored` carries the mask for secrets, never the value.
    assert "stored[key] = SECRET_MASK" in body


def test_the_reserved_prefix_is_still_refused():
    """
    Platform state shares this table with operator configuration; a settings
    form that could write ``__``-prefixed keys would let someone "fix" a value
    the plugin depends on.
    """
    body = _put_source()
    assert 'startswith("__")' in body
