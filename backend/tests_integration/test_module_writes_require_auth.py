# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""No module write endpoint answers an unauthenticated caller.

The ten module routers were unreachable from this harness until the
``_module_routes`` fixture existed, so nothing had ever checked this over HTTP.
A module write endpoint that resolves without authentication would be a serious
hole, and it is exactly the kind of defect that survives on a surface with no
integration coverage: every endpoint declares its own auth dependency, so one
that forgets looks identical to one that does not until a real request arrives.

The first meaningful sweep found all 63 refused with 401, by the endpoints
themselves. This keeps it that way.

It has to get PAST the CSRF middleware to mean anything. CSRFMiddleware refuses
any state-changing request that carries neither a bearer-without-cookie nor a
matching double-submit pair, so a naive version of this sweep saw 63 identical
403s from the middleware and concluded the endpoints were protected without a
single one of them having been reached. Sending a matching cookie and header
gets past CSRF without authenticating, and the sweep then observes what the
endpoints themselves do: all 63 answer 401.

Safe by construction: the requests carry no credentials, so a healthy stack
refuses every one before it touches anything. If one is NOT refused that is the
finding, and an empty JSON body makes an actual mutation unlikely even then.

POST/PUT/PATCH on parameterless paths only, so no ids are invented. DELETE is
excluded deliberately: on the off chance something is open, a DELETE is the one
verb whose accidental success could not be shrugged off.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

import pytest

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

MODULE_IDS = frozenset(
    {
        "network",
        "firewall",
        "cameras",
        "voip",
        "hypervisor",
        "storage",
        "backup",
        "collector",
        "ai",
        "access_control",
    }
)
WRITE_VERBS = ("post", "put", "patch")

# A refusal, or the route simply not being there. Anything else means the
# request got PAST authentication, which is the thing this test exists to catch.
# 422 is NOT in this set on purpose: a body-validation error means the endpoint
# was willing to consider the request.
ACCEPTABLE = frozenset({401, 403, 404, 405})


def _module_write_targets() -> list[tuple[str, str]]:
    """Parameterless module writes, read from the generated schema.

    From ``app.openapi()`` rather than ``app.routes``: since FastAPI 0.137
    ``include_router`` appends an opaque ``_IncludedRouter`` with no path, so a
    sweep over app.routes would find nothing and pass while covering nothing.
    """
    from app.main import app

    paths = app.openapi().get("paths", {})
    targets: list[tuple[str, str]] = []
    for path, operations in paths.items():
        if "{" in path or not path.startswith("/api/v1/"):
            continue
        if path.split("/")[3] not in MODULE_IDS:
            continue
        targets.extend(
            (verb, path) for verb in WRITE_VERBS if verb in operations
        )
    return sorted(targets)


async def test_no_module_write_accepts_an_unauthenticated_request(
    integration_client: Any,
) -> None:
    targets = _module_write_targets()

    # If the routers ever stop being mounted this sweep would cover nothing and
    # report success. Fail instead.
    assert len(targets) > 30, (
        f"only {len(targets)} module write endpoints found; the module routers "
        "are probably not mounted, so this test would prove nothing"
    )

    seen: Counter[int] = Counter()
    unprotected: list[str] = []
    for verb, path in targets:
        try:
            # Double-submit CSRF. The middleware only compares the cookie
            # against the header, so a matching pair passes it WITHOUT
            # authenticating. Omit this and every request is refused by the
            # middleware and nothing about endpoint auth is observed.
            response = await integration_client.request(
                verb.upper(),
                path,
                json={},
                headers={"X-CSRF-Token": "test-csrf"},
                cookies={"freesdn_csrf": "test-csrf"},
            )
        except Exception as exc:  # noqa: BLE001 - any raise is a failure here
            unprotected.append(f"{verb.upper()} {path} RAISED {type(exc).__name__}: {exc}")
            continue
        seen[response.status_code] += 1
        if response.status_code not in ACCEPTABLE:
            body = re.sub(r"\s+", " ", response.text)[:160]
            unprotected.append(f"{verb.upper()} {path} -> {response.status_code} {body}")

    assert not unprotected, (
        f"{len(unprotected)} module write endpoint(s) got past authentication "
        f"(status distribution {dict(sorted(seen.items()))}):\n  "
        + "\n  ".join(unprotected)
    )
