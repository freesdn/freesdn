# SPDX-License-Identifier: AGPL-3.0-only
"""Malformed JSON recipients are validation errors, never server failures."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints.sla_reports import (
    SLAReportScheduleCreate,
    SLAReportScheduleUpdate,
)


@pytest.mark.parametrize("endpoint", ["create", "update"])
@pytest.mark.parametrize(
    "recipients",
    [
        [1],
        [None],
        [True],
        [{}],
        [["user@example.test"]],
        1,
        {},
        "user@example.test",
        ["user@example.test\n"],
        ["user@example.test\r\nBcc: other@example.test"],
    ],
)
async def test_bad_recipient_json_is_http_422(endpoint, recipients):
    # Exercise the real request schemas through FastAPI's validation machinery.
    # No business/auth overrides or database/network services are involved.
    app = FastAPI()

    @app.post("/create")
    async def create(body: SLAReportScheduleCreate):
        return body.model_dump()

    @app.post("/update")
    async def update(body: SLAReportScheduleUpdate):
        return body.model_dump()

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    ) as client:
        response = await client.post(
            "/" + endpoint, json={"name": "Report", "recipients": recipients}
        )
    assert response.status_code == 422


@pytest.mark.parametrize("schema", [SLAReportScheduleCreate, SLAReportScheduleUpdate])
def test_supported_addresses_and_empty_metadata_are_preserved(schema):
    addresses = ["First.Last+tag@example.test", "other@example.test"]
    assert schema(name="Report", recipients=addresses).recipients == addresses
    assert schema(name="Report", recipients=[]).recipients == []
