"""Explicit sysupgrade metadata crosses the privileged export boundary losslessly."""

import base64

import pytest

from app.adapters.base import AdapterResult
from tests.modules import test_gateway_config_delivery as helpers

delivery = helpers.delivery
request = helpers.request


@pytest.mark.parametrize("scope", ["/etc/config/", "sysupgrade"])
@pytest.mark.parametrize(
    "value", [b"\x1f\x8b\x00\xffowned\x00\x80", b"owned-ascii-bytes"]
)
async def test_explicit_export_scope_is_preserved_by_delivery(delivery, scope, value):
    f = delivery
    f.gateway.vendor = "openwrt"
    f.result = AdapterResult.ok(
        {"backup_data": value, "format": "tar.gz", "scope": scope}
    )
    response = await request(f)
    assert response.status_code == 200
    data = response.json()["config"]
    assert data == {
        "backup_data": base64.b64encode(value).decode("ascii"),
        "encoding": "base64",
        "format": "tar.gz",
        "scope": scope,
    }
    assert base64.b64decode(data["backup_data"], validate=True) == value
    assert f.created == f.closed == 1
