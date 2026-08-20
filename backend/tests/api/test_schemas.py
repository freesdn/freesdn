# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Pure unit tests for Pydantic schema validation.

No network, no DB — just instantiate schemas and assert.

Covers:
- DeviceCreate / DeviceBase field validation
- MAC address format validation
- IP address format validation
- VLAN ID range validation (VlanConfig: 1-4094)
- DeviceUpdate partial-update semantics
"""

import uuid

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Device schemas
# ---------------------------------------------------------------------------
from app.schemas.devices import DeviceCreate, DeviceUpdate


class TestDeviceCreateValidData:
    """DeviceCreate should accept well-formed payloads."""

    def test_minimal_valid(self):
        d = DeviceCreate(
            name="sw-01",
            device_type="switch",
            site_id=uuid.uuid4(),
        )
        assert d.name == "sw-01"
        assert d.mac_address is None
        assert d.ip_address is None

    def test_full_valid(self):
        d = DeviceCreate(
            name="Core Switch",
            device_type="access_point",
            site_id=uuid.uuid4(),
            controller_id=uuid.uuid4(),
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="10.0.0.1",
            model="TL-SG3428",
            manufacturer="TP-Link",
            firmware_version="1.2.3",
            location="Server Room A",
            serial_number="SN123456",
        )
        assert d.manufacturer == "TP-Link"

    def test_accepts_ipv6(self):
        d = DeviceCreate(
            name="v6-host",
            device_type="server",
            site_id=uuid.uuid4(),
            ip_address="fe80::1",
        )
        assert d.ip_address == "fe80::1"

    def test_accepts_lowercase_mac(self):
        d = DeviceCreate(
            name="sw",
            device_type="switch",
            site_id=uuid.uuid4(),
            mac_address="aa:bb:cc:dd:ee:ff",
        )
        assert d.mac_address == "aa:bb:cc:dd:ee:ff"

    def test_accepts_hyphenated_mac(self):
        d = DeviceCreate(
            name="sw",
            device_type="switch",
            site_id=uuid.uuid4(),
            mac_address="AA-BB-CC-DD-EE-FF",
        )
        assert d.mac_address == "AA-BB-CC-DD-EE-FF"


class TestDeviceCreateInvalidData:
    """DeviceCreate should reject malformed inputs."""

    def test_missing_name(self):
        with pytest.raises(ValidationError):
            DeviceCreate(device_type="switch", site_id=uuid.uuid4())

    def test_empty_name(self):
        with pytest.raises(ValidationError):
            DeviceCreate(name="", device_type="switch", site_id=uuid.uuid4())

    def test_missing_device_type(self):
        with pytest.raises(ValidationError):
            DeviceCreate(name="sw", site_id=uuid.uuid4())

    def test_invalid_device_type(self):
        with pytest.raises(ValidationError):
            DeviceCreate(name="sw", device_type="toaster", site_id=uuid.uuid4())

    def test_missing_site_id(self):
        with pytest.raises(ValidationError):
            DeviceCreate(name="sw", device_type="switch")

    def test_invalid_mac_format_short(self):
        with pytest.raises(ValidationError):
            DeviceCreate(
                name="sw",
                device_type="switch",
                site_id=uuid.uuid4(),
                mac_address="AA:BB:CC",
            )

    def test_invalid_mac_format_no_separator(self):
        with pytest.raises(ValidationError):
            DeviceCreate(
                name="sw",
                device_type="switch",
                site_id=uuid.uuid4(),
                mac_address="AABBCCDDEEFF",
            )

    def test_invalid_ip_address(self):
        with pytest.raises(ValidationError):
            DeviceCreate(
                name="sw",
                device_type="switch",
                site_id=uuid.uuid4(),
                ip_address="999.0.0.1",
            )

    def test_name_too_long(self):
        with pytest.raises(ValidationError):
            DeviceCreate(
                name="x" * 256,
                device_type="switch",
                site_id=uuid.uuid4(),
            )


class TestDeviceUpdate:
    """DeviceUpdate allows partial updates — all fields optional."""

    def test_empty_update(self):
        u = DeviceUpdate()
        assert u.name is None
        assert u.location is None

    def test_partial_update(self):
        u = DeviceUpdate(location="Rack 5")
        assert u.location == "Rack 5"
        assert u.name is None

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            DeviceUpdate(name="")

    def test_accepts_is_active_flag(self):
        u = DeviceUpdate(is_active=False)
        assert u.is_active is False


# ---------------------------------------------------------------------------
# VLAN ID range validation (VlanConfig from switches endpoint)
# ---------------------------------------------------------------------------

from app.api.v1.endpoints.switches import VlanConfig


class TestVlanIdRange:
    """IEEE 802.1Q VLAN IDs must be in range 1-4094."""

    def test_valid_vlan_id_min(self):
        v = VlanConfig(native_vlan=1)
        assert v.native_vlan == 1

    def test_valid_vlan_id_max(self):
        v = VlanConfig(native_vlan=4094)
        assert v.native_vlan == 4094

    def test_valid_vlan_id_mid(self):
        v = VlanConfig(native_vlan=100)
        assert v.native_vlan == 100

    def test_rejects_vlan_id_zero(self):
        with pytest.raises(ValidationError):
            VlanConfig(native_vlan=0)

    def test_rejects_vlan_id_negative(self):
        with pytest.raises(ValidationError):
            VlanConfig(native_vlan=-1)

    def test_rejects_vlan_id_above_4094(self):
        with pytest.raises(ValidationError):
            VlanConfig(native_vlan=4095)

    # voice_vlan / guest_vlan range tests removed with the fields.
    #
    # They validated the SHAPE of input the port-save endpoint accepted,
    # echoed back, and never pushed to any controller -- so a green suite
    # was confirming that a dead control's numbers were in range. The
    # fields are gone from VlanConfig; the dialog no longer offers them.
    # Port PROFILES keep their own voice_vlan on a different path.

    def test_tagged_vlans_list(self):
        v = VlanConfig(tagged_vlans=[10, 20, 30])
        assert v.tagged_vlans == [10, 20, 30]

    def test_defaults(self):
        v = VlanConfig()
        assert v.mode == "access"
        assert v.native_vlan == 1
        assert v.tagged_vlans == []
        assert not hasattr(v, "voice_vlan"), "the dead voice_vlan field is back"
        assert not hasattr(v, "guest_vlan"), "the dead guest_vlan field is back"
