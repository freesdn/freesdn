# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A credential typed into the plugin settings UI was stored as plaintext.

The SDK had ``set_secret``/``get_secret``, which keep a value encrypted under a
separate ``<key>:encrypted`` entry. Nothing connected them to the form an
operator actually fills in. So the flow was:

    operator types an API token into the field the plugin declared
      -> PUT /plugins/{id}/settings stores it verbatim in plugin_settings
      -> the plugin reads it with get_secret(), finds NOTHING, because that
         looks under a different key
      -> the plugin appears unconfigured, and the token sits in the clear

Every credential-bearing plugin therefore had to migrate the value itself on
first read. netbox-sync shipped exactly that. It worked, and it is precisely the
kind of thing that belongs in the platform: a convention every plugin must
remember is a footgun for the first author who does not.

Now a property marked ``secret: true`` (or the JSON Schema idiom
``format: password``) is encrypted by the platform on write and never returned
on read. ``settings.get()`` falls back to the encrypted twin so the declaration
is purely ADDITIVE -- marking an existing field secret cannot break the plugin
that reads it, which it otherwise would have, silently, by turning the value
into empty string.
"""

from __future__ import annotations

import inspect

import pytest


def _secret_keys_source() -> str:
    from app.api.v1.endpoints.plugins import _secret_setting_keys

    return inspect.getsource(_secret_setting_keys)


def _property_block(manifest_body: str, field: str) -> str | None:
    """The lines belonging to one settings_schema property.

    Splitting on a newline plus four spaces looks right and is not: a property's
    own child lines are indented SIX spaces, so that separator matches the very
    next line and returns an empty string. My first version of this did exactly
    that, and every assertion below passed vacuously against an empty block.
    Match the next key at the SAME indent instead.
    """
    import re

    match = re.search(rf"^    {re.escape(field)}:\s*$", manifest_body, re.M)
    if match is None:
        return None
    rest = manifest_body[match.end() :]
    nxt = re.search(r"^    \S", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


# ── declaring a secret ──────────────────────────────────────────


def test_both_spellings_are_recognised():
    """
    ``secret: true`` is ours; ``format: password`` is the JSON Schema idiom an
    author is likely to reach for first. Accepting only one would mean a field
    that LOOKS declared and is not.
    """
    src = _secret_keys_source()
    assert 'spec.get("secret") is True' in src
    assert '"password"' in src


def test_an_undeclared_field_is_not_treated_as_secret():
    """Encrypting a field nobody marked would make it unreadable in the UI for
    no reason, and the operator would have no way to see what they had set."""
    src = _secret_keys_source()
    # The predicate must require an explicit marker, never default to secret.
    assert "return set()" in src, "the resolver has no safe fallback"


def test_the_resolver_reads_the_cached_manifest_not_the_disk():
    """
    The manifest cached at install time is the trusted copy. Reading plugin.yaml
    from PLUGIN_DIR at request time would let anything that can write there
    change which fields are protected.
    """
    src = _secret_keys_source()
    assert "manifest_cache" in src
    assert "open(" not in src and "read_text" not in src


# ── writing ─────────────────────────────────────────────────────


def test_a_secret_is_encrypted_and_the_plaintext_blanked():
    from app.api.v1.endpoints.plugins import update_plugin_settings

    src = inspect.getsource(update_plugin_settings)
    assert "encrypt_webhook_secret" in src, "secrets are stored in the clear again"
    assert ":encrypted" in src, "the encrypted twin is gone"
    # Blanking matters: a value written before the field was marked secret, or
    # by an older client, would otherwise sit next to the encrypted one.
    assert 'value=""' in src or '"value": ""' in src, (
        "the plaintext twin is no longer blanked; a stale credential can linger"
    )


def test_the_write_response_never_echoes_a_secret():
    """It would land in request logs and browser history for no benefit.

    Checks the shared ``SECRET_MASK`` rather than the literal. The literal used
    to appear in three places, and GET and PUT having their own copies is what
    let a round-trip store the mask AS the credential -- see
    test_plugin_settings_secrets.py. Pinning the literal here would push it back
    towards that.
    """
    from app.api.v1.endpoints.plugins import update_plugin_settings

    src = inspect.getsource(update_plugin_settings)
    assert "stored[key] = SECRET_MASK" in src
    assert 'return {"settings": body.settings}' not in src, (
        "the endpoint echoes the submitted settings, secrets included"
    )


# ── reading ─────────────────────────────────────────────────────


def test_the_api_never_returns_a_secret_or_its_ciphertext():
    from app.api.v1.endpoints.plugins import get_plugin_settings

    src = inspect.getsource(get_plugin_settings)
    assert "SECRET_MASK" in src, "secrets are returned to the client again"
    assert 'key.endswith(":encrypted")' in src, (
        "the ciphertext twin is returned; handing back fernet:gAAAA... is no better "
        "than handing back the token"
    )


def test_settings_get_falls_back_to_the_encrypted_twin():
    """
    The property that makes ``secret: true`` safe to add to an existing plugin.
    Without it, marking a field secret turns the value the plugin reads into
    empty string -- and an empty credential looks exactly like an unconfigured
    one, so the plugin reports itself unconfigured and nobody knows why.
    """
    from app.plugins.sdk import PluginSettingsSDK

    src = inspect.getsource(PluginSettingsSDK.get)
    assert ":encrypted" in src, "settings.get no longer reads the encrypted twin"
    assert "decrypt_webhook_secret" in src


def test_the_fallback_cannot_recurse():
    """
    ``get_secret`` is implemented on top of ``get``. If ``get`` reached for the
    twin unconditionally, reading ``k:encrypted`` would look for
    ``k:encrypted:encrypted`` and so on.
    """
    from app.plugins.sdk import PluginSettingsSDK

    src = inspect.getsource(PluginSettingsSDK.get)
    assert 'if not key.endswith(":encrypted")' in src, "the fallback can recurse"


def test_an_undecryptable_value_is_treated_as_unset_not_raised():
    """
    A rotated encryption key must not make every plugin route 500. Unset is
    wrong but recoverable; a crash on read is neither.
    """
    from app.plugins.sdk import PluginSettingsSDK

    src = inspect.getsource(PluginSettingsSDK.get)
    assert "return default" in src.split("decrypt_webhook_secret", 1)[1]


# ── the plugins that use it ─────────────────────────────────────


@pytest.mark.parametrize(
    ("plugin", "field"),
    [
        ("netbox-sync", "netbox_token"),
    ],
)
def test_shipped_plugins_declare_their_credentials(plugin: str, field: str):
    """
    A Discord or Slack webhook URL embeds its credential in the path: anyone
    holding it can post as you. Storing one in the clear because it is spelled
    like a URL is the same mistake as storing a token in the clear.
    """
    import pathlib

    manifest = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / plugin / "plugin.yaml"
        if candidate.is_file():
            manifest = candidate
            break
    if manifest is None:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")

    following = _property_block(manifest.read_text(encoding="utf-8"), field)
    assert following is not None, f"{plugin} no longer declares {field}"
    assert "secret: true" in following, f"{plugin}.{field} is not marked secret"


def test_a_plain_url_is_not_marked_secret():
    """
    Over-marking has a cost: an operator can never see what they configured, so
    a base URL they typo'd shows as ``***`` forever.

    This used to check notify-hub's gotify_url against its gotify_token. That
    plugin is retired -- Gotify is a native notification provider now -- so the
    property is checked where it still lives: netbox-sync declares both a URL
    and a token, and only one of them is a credential.
    """
    import pathlib

    manifest = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins" / "netbox-sync" / "plugin.yaml"
        if candidate.is_file():
            manifest = candidate
            break
    if manifest is None:  # pragma: no cover - backend-only checkout
        pytest.skip("registry plugins are not present in this checkout")

    text = manifest.read_text(encoding="utf-8")
    url_block = _property_block(text, "netbox_url")
    assert url_block is not None, "netbox-sync no longer declares netbox_url"
    assert "secret: true" not in url_block, "netbox_url is a base URL, not a credential"

    # And the credential next to it still is one, or this test would pass on a
    # manifest that marks nothing at all.
    token_block = _property_block(text, "netbox_token")
    assert token_block is not None and "secret: true" in token_block
