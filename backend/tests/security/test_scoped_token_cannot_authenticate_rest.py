# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A narrowed token must not authenticate the general API.

``POST /cameras/{id}/stream-token`` mints a 60-second access token carrying
``scope="stream"`` and ``camera_id``. Its whole purpose is to be safe in a URL
query string: the frontend puts it in ``<img src=".../snapshot?token=JWT">``
(src/lib/api/cameras.ts:88) and on ``/playback-frame`` and ``/stream/mjpeg``. A
URL reaches reverse-proxy access logs, browser history and Referer headers -- that
is precisely why the token is scoped and short-lived.

The narrowing was enforced by only two consumers:

  * the camera media handler, which checks scope AND camera_id AND org
    (app/modules/cameras/api.py:224-240);
  * the WebSocket, whose comment says it refuses ANY scope because "a future
    scope would otherwise inherit the same hole by default"
    (app/api/v1/endpoints/websocket.py:585).

It was never added to ``get_current_user_optional``, the chokepoint the other
~1,800 REST routes share. Verified against a running stack before the fix: a
``scope="stream"`` bearer token returned HTTP 200 on /devices/, /sites/,
/organizations/ and /credentials/ with its owner's full role. Anyone who read one
line of an access log within 60 seconds had the whole appliance.
"""

from __future__ import annotations

from datetime import timedelta

from app.core.security import create_access_token


def _token(**extra) -> str:
    return create_access_token(
        subject="11111111-1111-1111-1111-111111111111",
        expires_delta=timedelta(seconds=60),
        extra_claims=extra or None,
    )


def test_a_stream_token_is_a_structurally_valid_access_token() -> None:
    """The premise: it is a normal access token. The narrowing is what stops it.

    Decoded locally on purpose. ``verify_token`` also consults the Redis jti
    blacklist, and the CI backend leg has no Redis -- calling it here made this
    test fail in the gate while passing locally, which is exactly the kind of
    environment-fragile assertion this suite keeps getting bitten by. The claim
    under test is about the token's SHAPE, so decode it directly.
    """
    import jwt

    from app.core.config import settings

    raw = _token(scope="stream", camera_id="c0ffee00-0000-0000-0000-000000000001")
    payload = jwt.decode(
        raw,
        settings.SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert payload.get("type") == "access", (
        "a stream token is minted by create_access_token, so it is type=access -- "
        "which is why nothing downstream treated it as special"
    )
    assert payload.get("scope") == "stream"
    assert payload.get("camera_id")


def test_the_shared_rest_dependency_refuses_any_scope() -> None:
    """The core regression, asserted on the real source.

    A behavioural test needs a DB session and a live user row; this pins the
    guard itself, and the live 401/200 split was verified by hand against the
    running stack. Both matter: the guard must exist AND must not be
    scope-specific, because the WebSocket's comment is right that a future scope
    would otherwise inherit the hole.
    """
    import inspect

    from app.core import dependencies

    src = inspect.getsource(dependencies.get_current_user_optional)
    assert 'payload.get("scope")' in src, (
        "get_current_user_optional no longer refuses scoped tokens -- a "
        "stream-scoped camera token, which is designed to travel in a URL query "
        "string, would authenticate the entire REST API with its owner's role"
    )
    assert '== "stream"' not in src, (
        "the REST guard must refuse ANY scope, not just 'stream'. A future "
        "narrowed scope would otherwise inherit the same hole by default -- "
        "which is exactly the reasoning in the WebSocket guard's own comment."
    )


def test_the_auth_router_refuses_scoped_tokens_too() -> None:
    """/auth/* has its own token path and needed the same guard."""
    import inspect

    from app.api.v1.endpoints import auth

    src = inspect.getsource(auth._get_authenticated_user)
    assert 'payload.get("scope")' in src, (
        "the auth router accepts a scoped token, so a leaked stream token could "
        "still read /auth/me and enumerate the account it belongs to"
    )


def test_the_websocket_guard_that_got_this_right_is_still_there() -> None:
    """The one place that always refused a scope. Pin it so it cannot regress."""
    import inspect

    from app.api.v1.endpoints import websocket

    src = inspect.getsource(websocket)
    assert 'token_scope = payload.get("scope")' in src


def test_the_camera_media_path_still_accepts_its_own_token() -> None:
    """The fix must not break the legitimate consumer.

    The camera handler verifies the token itself rather than going through the
    shared dependency, so refusing scopes there costs it nothing. Confirmed live:
    a snapshot request with a stream token returns 403 (auth passed, camera check
    failed) rather than 401.
    """
    import inspect

    from app.modules.cameras import api as cameras_api

    src = inspect.getsource(cameras_api)
    assert 'payload.get("scope") != "stream"' in src, (
        "the camera media handler no longer enforces the stream scope on a query-string token"
    )
    assert 'payload.get("camera_id")' in src, (
        "the camera media handler no longer binds the token to one camera"
    )
