"""Malformed scalar fields must not escape direct inventory adapters."""

import copy

import pytest

from tests.adapters import test_opnsense_remaining_inventory_contracts as vendor

TEXT_FIELDS = [
    (family, field)
    for family, specific in [
        ("servers", "address"),
        ("backends", "mode"),
        ("frontends", "bind"),
        ("acls", "expression"),
        ("actions", "type"),
    ]
    for field in ["name", "Description", specific]
]


@pytest.mark.parametrize("family,field", TEXT_FIELDS)
@pytest.mark.parametrize(
    "malformed", [None, [], {"owned-private-field": "owned-private-marker"}, True]
)
async def test_haproxy_public_text_is_not_null_boolean_or_nested(family, field, malformed):
    wire = vendor.haproxy_wire()
    wire[f"/api/haproxy/settings/search{vendor.FAMILIES[family]}"]["rows"][0][field] = (
        copy.deepcopy(malformed)
    )
    result, _ = await vendor.read(f"get_haproxy_{family}", wire)
    assert not result.success
    assert result.data is None


@pytest.mark.parametrize("family", vendor.FAMILIES)
async def test_haproxy_whitespace_identity_is_unavailable(family):
    wire = vendor.haproxy_wire()
    wire[f"/api/haproxy/settings/search{vendor.FAMILIES[family]}"]["rows"][0]["uuid"] = "  "
    result, _ = await vendor.read(f"get_haproxy_{family}", wire)
    assert not result.success


@pytest.mark.parametrize("path", vendor.VPN_INVENTORIES)
async def test_vpn_whitespace_identity_is_unavailable(path):
    wire = vendor.vpn_wire()
    wire[path]["rows"][0]["uuid"] = "  "
    result, _ = await vendor.read("get_vpn_status", wire)
    assert not result.success
