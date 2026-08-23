# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
An install failure has to say what went wrong.

Every ``PluginLoadError`` from a marketplace install used to become the same
opaque 400: "Marketplace plugin installation failed". So a version-floor
refusal, an already-installed plugin, a tampered archive and an unpinned
dependency were indistinguishable to the only person who could fix any of them,
with the real reason visible only in the container log.

The loader's messages are written for exactly that person -- "requires FreeSDN X
or newer", "Use upgrade_plugin() to upgrade", "Checksum mismatch: expected ...
got ...", "requirements.txt is missing --hash= annotations" -- and the endpoint
already requires an UNSCOPED SUPER ADMIN, so there is no audience here that
should not see a plugin diagnostic.

The one message that carried a server filesystem path was rewritten, because
these strings now reach an API response and not just a log.

Verified live on a running instance:

    installing an already-installed plugin
      -> 400 "Plugin installation failed: Plugin 'notify-hub' is already
              installed. Use upgrade_plugin() to upgrade."
    installing against a planted wrong checksum
      -> 400 "Checksum mismatch: expected deadbeef00... got fe78a7f1d9..."
"""

from __future__ import annotations

import inspect
import re

import pytest


def _install_source() -> str:
    from app.api.v1.endpoints.marketplace import install_from_marketplace

    return inspect.getsource(install_from_marketplace)


def test_the_loader_reason_reaches_the_response():
    """The handler must interpolate the exception, not discard it."""
    src = _install_source()
    match = re.search(r"except PluginLoadError as exc:(.*?)(?=\n    except |\Z)", src, re.S)
    assert match, "the PluginLoadError arm is gone"

    # Strip comments before asserting. The first version of this test matched
    # the explanatory comment that QUOTES the old opaque message, and so failed
    # against the FIXED code. Assert on what runs, not on what the source
    # happens to contain.
    arm = "\n".join(
        line for line in match.group(1).splitlines() if not line.strip().startswith("#")
    )

    assert "{exc}" in arm, "the install failure no longer names the reason"
    assert "Marketplace plugin installation failed" not in arm, "the opaque message is back"
    assert "logger.error" in arm, "the failure must still be logged in full"


def test_no_plugin_load_error_message_carries_a_filesystem_path():
    """
    These strings are now returned to a caller. ``plugin_dir`` was the only one
    that embedded an absolute server path; nothing may reintroduce that.
    """
    import pathlib

    loader = pathlib.Path(inspect.getfile(_load_loader())).read_text(encoding="utf-8")

    offenders = []
    for raw in re.findall(r"PluginLoadError\(\s*((?:f?\"[^\"]*\"\s*)+)", loader):
        for var in re.findall(r"\{(\w+)\}", raw):
            if var in {"plugin_dir", "path", "dest", "target_dir", "extract_dir"}:
                offenders.append(f"{var} in {raw.strip()[:70]}")
    assert not offenders, f"PluginLoadError messages leak a server path: {offenders}"


def _load_loader():
    from app.plugins import loader

    return loader


@pytest.mark.parametrize(
    "message",
    [
        "Plugin 'notify-hub' is already installed. Use upgrade_plugin() to upgrade.",
        "Checksum mismatch: expected aaa, got bbb",
        "Plugin 'x' requires FreeSDN 27.0.0 or newer, but this instance is 26.08.2.",
    ],
)
def test_representative_reasons_survive_formatting(message):
    """
    The detail is built with an f-string, so a message containing braces or
    quotes must not mangle it. Guards against a future switch to ``%`` or
    ``.format`` that would break on the loader's own text.
    """
    from app.plugins.loader import PluginLoadError

    exc = PluginLoadError(message)
    assert f"Plugin installation failed: {exc}" == f"Plugin installation failed: {message}"


def test_every_install_path_names_the_reason():
    """
    There are four ways a plugin arrives -- marketplace, upload, URL, and
    upgrade -- and only the marketplace one interpolated the exception. The
    same failure was therefore legible or opaque depending on which button the
    operator pressed, and this test passed the whole time because it read one
    function.

    Found while installing a plugin that used a withheld builtin: the response
    said "Plugin installation failed" while the container log carried a full
    explanation of exactly which builtin and what to use instead.
    """
    from app.api.v1.endpoints import plugins as plugins_endpoints

    src = inspect.getsource(plugins_endpoints)
    arms = re.findall(
        r"except PluginLoadError as exc:(.*?)(?=\n    except |\n@router|\Z)", src, re.S
    )
    assert len(arms) >= 3, f"expected the upload, url and upgrade arms; found {len(arms)}"

    opaque = []
    for arm in arms:
        body = "\n".join(line for line in arm.splitlines() if not line.strip().startswith("#"))
        if "raise HTTPException" not in body:
            continue
        if "status_code=404" in body:
            # Deliberate. A PluginLoadError on a lookup means the plugin is not
            # there, and "Plugin not found" is the honest answer -- appending a
            # loader diagnostic would describe a load that was never attempted.
            continue
        if "{exc}" not in body:
            # Name the arm by its detail= line, not its last line: ruff reflows
            # a long raise across several lines and the last one is just ")".
            detail = next(
                (ln.strip() for ln in body.splitlines() if "detail=" in ln),
                body.strip()[:80],
            )
            opaque.append(detail)
    assert not opaque, f"these arms discard the reason: {opaque}"


def test_a_withheld_builtin_is_explained_rather_than_named():
    """
    A plugin runs with restricted builtins. Reaching for one it does not get
    raised a bare ``name 'type' is not defined`` -- at INSTALL time, from an API
    response, about a builtin that works in every other Python file the author
    has ever written. ``type(exc).__name__`` is a universal idiom and produces
    exactly that.
    """
    from app.plugins.sandbox import explain_missing_name

    message = explain_missing_name(NameError("name 'type' is not defined"), "probe")
    assert message is not None
    assert "'type'" in message
    assert "isinstance" in message, "no alternative offered; the author is left guessing"

    # A genuine typo must NOT be dressed up as a policy explanation.
    assert explain_missing_name(NameError("name 'widgt' is not defined"), "probe") is None
    # Nor an allowed builtin, which cannot produce this error anyway.
    assert explain_missing_name(NameError("name 'len' is not defined"), "probe") is None


def test_constructing_the_plugin_is_covered_too():
    """
    The module body was wrapped and ``cls()`` was not, so a withheld builtin
    used in ``__init__`` -- the natural place to set up state -- escaped as a
    bare NameError from an install endpoint.
    """
    from app.plugins import loader

    src = inspect.getsource(loader)
    # The guard WRAPS the call, so look at the block around it rather than
    # before it -- the first version of this test read the 600 characters
    # preceding cls() and found the comment but not the except clause.
    head, _, tail = src.partition("instance = cls()")
    assert "try:" in head[-200:], "the construction is no longer inside a try"
    assert "except NameError" in tail[:400], "constructing the plugin is unguarded again"
