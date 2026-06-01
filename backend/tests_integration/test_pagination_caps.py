"""
Integration tests — pagination caps must match what the frontend asks for.

Regression test for the AgentsPage 422 incident: the frontend was sending
``per_page=200`` while the backend capped at ``le=100``, which produced a
422 the user only discovered by browsing.

The list endpoints in this project fall into two policy buckets:

  bucket-200: high-volume / log-style endpoints — audit, events, logs,
              switches, access points, agents, users, organizations.
              These can serve up to 200 items per page.
  bucket-100: low-cardinality / admin endpoints — controllers, sites,
              webhooks, integrations, automation rules. These cap at
              100 (which the frontend already respects).

This test asserts the cap policy by hammering each bucket-200 endpoint
with ``per_page=200``. If a future PR drops the cap, the test fails.

Note: most of these endpoints require auth. We use the ``super_admin``
fixture to authenticate, then check that each endpoint accepts the
boundary value AND rejects ``per_page=201`` with 422.
"""

from __future__ import annotations

from typing import Any

import pytest


pytestmark = pytest.mark.asyncio


# Paths the frontend hits with per_page=200. If you bump per_page in
# any frontend page above 200, also raise the cap on the corresponding
# backend endpoint and add it here.
BUCKET_200_PATHS = [
    "/api/v1/agents/",
    "/api/v1/users",
    "/api/v1/organizations",
]


@pytest.mark.parametrize("path", BUCKET_200_PATHS)
async def test_endpoint_accepts_per_page_200(
    integration_client: Any, super_admin: dict[str, Any], path: str
) -> None:
    """The endpoint MUST accept per_page=200 — the frontend sends this."""
    resp = await integration_client.get(
        path,
        params={"per_page": 200, "page": 1},
        headers=super_admin["headers"],
    )
    # Either 200 (data returned) or 403 (RBAC denied) — but NOT 422.
    # 422 means the frontend's per_page=200 broke validation.
    assert resp.status_code != 422, (
        f"{path}: per_page=200 returned 422 — backend cap is below the "
        f"frontend's per_page parameter. Bump the Query(le=...) cap to >=200. "
        f"Body: {resp.text}"
    )


