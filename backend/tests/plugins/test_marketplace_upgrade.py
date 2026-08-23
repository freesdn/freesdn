# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
You could install a plugin from the UI and then never update it from the UI.

The only upgrade path took an uploaded ZIP, so keeping a marketplace plugin
current meant going and finding the archive by hand. Pressing Install again did
not help either -- the loader answers "already installed, use upgrade" -- and the
card never compared the installed version against the catalogue's, so a plugin
with a newer version available simply read "Installed" for ever.

That was the last gap in the install story, and the one all the hot-reload work
was built for: an update that takes effect without restarting the API is only
worth having if there is a way to ask for it.

``POST /marketplace/plugins/{slug}/upgrade`` closes it. Verified live against
the real registry:

    already on the catalogue version -> 409 "already on 1.2.0"
    installed newer than catalogue   -> 409 "refusing to roll back"
    published but not installed      -> 404 "install it first"
    withdrawn                        -> 410
    a real update 1.1.0 -> 1.2.0     -> 200, restart_required false,
                                        and GET /api/v1/hello-world/ answers 200
                                        immediately, with no restart

The refusals matter as much as the success. Every one of them arrives by
pressing a button labelled "update", so silently reinstalling the same version
or silently rolling back would be the wrong answer to what was asked.
"""

from __future__ import annotations

import inspect

import pytest


def _src():
    from app.api.v1.endpoints.marketplace import upgrade_from_marketplace

    return inspect.getsource(upgrade_from_marketplace)


def _body():
    """Source with comment lines stripped.

    Assertions here have matched my own explanatory comments before now, which
    passes against code that does not do the thing the comment describes.
    """
    return "\n".join(ln for ln in _src().splitlines() if not ln.strip().startswith("#"))


# ── it exists and is reachable ──────────────────────────────────


def test_the_endpoint_exists():
    from app.api.v1.endpoints import marketplace as mp

    assert hasattr(mp, "upgrade_from_marketplace"), "there is still no way to update from the UI"


def test_it_is_mounted_as_a_post_route():
    from app.api.v1.endpoints.marketplace import router

    routes = {(r.path, m) for r in router.routes for m in getattr(r, "methods", set())}
    assert ("/{slug}/upgrade", "POST") in routes


def test_it_requires_an_unscoped_super_admin():
    """
    It downloads and executes third-party code, exactly like install. A scoped
    key must not inherit that.
    """
    assert "is_unscoped_superuser(" in _body()


def test_it_takes_the_request_it_needs_to_remount_routes():
    from app.api.v1.endpoints.marketplace import upgrade_from_marketplace

    assert "request" in inspect.signature(upgrade_from_marketplace).parameters


# ── the refusals ────────────────────────────────────────────────


def test_a_plugin_that_is_not_installed_is_refused():
    body = _body()
    assert "not installed" in body
    assert "404" in body


@pytest.mark.parametrize("case", ["already on", "newer than"])
def test_it_refuses_anything_that_is_not_forward_motion(case: str):
    """
    Same version and older version are separate messages on purpose. "Nothing
    happened" and "I am not going to roll you back" send an operator to
    different next steps -- one syncs the registry, the other decides whether
    they really want a downgrade.
    """
    body = _body()
    assert case in body, f"the {case!r} case is not distinguished"
    assert "409" in body


def test_the_version_comparison_is_numeric_not_textual():
    """
    Reusing the loader's parser rather than comparing strings. As text
    "1.10.0" < "1.9.0", which would refuse every tenth release as a downgrade.
    """
    assert "_version_tuple" in _body(), "versions are being compared as strings"


def test_an_unparseable_version_does_not_block_the_upgrade():
    """
    ``_version_tuple`` returns None for anything it cannot judge, and the guard
    only fires when BOTH sides parsed. A plugin versioned "nightly" should still
    be updatable, not permanently stuck behind a comparison that cannot be made.
    """
    body = _body()
    assert "if current_t and target_t:" in body, (
        "the version guard fires even when a version cannot be parsed"
    )


def test_a_withdrawn_plugin_cannot_be_updated_either():
    """
    Withdrawal has to stop updates as well as installs, or a plugin pulled for
    being harmful would keep being delivered to everyone who already had it.
    """
    assert "_resolve_published(" in _body()


# ── the upgrade itself ──────────────────────────────────────────


def test_it_verifies_the_download_before_running_it():
    """
    The signature proves the catalogue is authentic; the checksum proves the
    bytes are the ones it vouched for. Sharing one helper with install is what
    keeps the two from drifting.
    """
    assert "_download_and_verify(" in _body()


def test_it_stops_the_plugin_before_replacing_its_files():
    """
    The per-organisation runtimes hold connections, event subscriptions and
    scheduler claims belonging to the old code. Swapping files underneath them
    leaves those pointing at a version that no longer exists.
    """
    body = _body()
    assert "stop_plugin_everywhere(" in body
    assert body.index("stop_plugin_everywhere(") < body.index("upgrade_plugin(")


def test_it_starts_the_plugin_again_afterwards():
    """
    The bug this endpoint's sibling shipped with: installing without starting
    leaves a plugin that reports success and does nothing.
    """
    body = _body()
    assert "_start_plugin_everywhere(" in body
    assert "replace_routes=True" in body, "an upgrade must remount, not skip as already-registered"


def test_it_reports_reload_state_the_same_way_as_every_other_path():
    """
    They disagreed once, and the same situation read as legible or alarming
    depending on which button was pressed.
    """
    assert "_reload_note(" in _body()


def test_it_tells_the_operator_where_they_came_from():
    """
    "Upgraded" alone does not say what changed. The previous version is what
    makes the result checkable, and what an audit row needs to be worth having.
    """
    body = _body()
    assert '"previous_version"' in body
    assert "AuditAction.UPGRADE" in body


def test_a_failed_audit_write_does_not_fail_the_upgrade():
    """
    The plugin is already upgraded and running by then. Raising here would
    report failure for something that succeeded.
    """
    src = _src()
    after = src.split("AuditService(session)", 1)[1]
    assert "except Exception" in after.split("await session.commit()", 1)[0]
