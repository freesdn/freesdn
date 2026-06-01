# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream XML Provisioner
===========================================

Generates XML configuration files for Grandstream phones.

Grandstream phones can be provisioned via XML files served over TFTP/HTTP(S).
File naming convention: ``cfg{MAC}.xml`` where MAC is lowercase, no colons.

XML format::

    <?xml version="1.0" encoding="UTF-8"?>
    <gs_provision version="1">
      <config version="1">
        <P35>1001</P35>
        <P34>password</P34>
        ...
      </config>
    </gs_provision>
"""

from __future__ import annotations

import logging
import re
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

from .constants import (
    CODEC_MAP,
    LINE_KEY_STRIDE,
    P_ACCOUNT_ACTIVE,
    P_ACCOUNT_NAME,
    P_ADMIN_PASSWORD,
    P_AUTH_ID,
    P_AUTH_PASSWORD,
    P_AUTO_PROVISION,
    P_DEFAULT_GATEWAY,
    P_DISPLAY_NAME,
    P_DNS_1,
    P_DNS_2,
    P_IP_MODE,
    P_LAN_VLAN_PRIORITY,
    P_LAN_VLAN_TAG,
    P_LCD_BRIGHTNESS,
    P_LINE_KEY_1_ACCOUNT,
    P_LINE_KEY_1_MODE,
    P_LINE_KEY_1_NAME,
    P_LINE_KEY_1_VALUE,
    P_NTP_SERVER,
    P_PREFERRED_CODEC_1,
    P_PROVISION_INTERVAL,
    P_PROVISION_PROTOCOL,
    P_PROVISION_SERVER,
    P_REGISTER_EXPIRY,
    P_RING_VOLUME,
    P_SIP_SERVER,
    P_SIP_SERVER_PORT,
    P_SIP_TRANSPORT,
    P_SIP_USER_ID,
    P_SPEAKER_VOLUME,
    P_STATIC_IP,
    P_SUBNET_MASK,
    P_TIME_ZONE,
    P_USER_PASSWORD,
    P_VLAN_PRIORITY,
    P_VLAN_TAG,
    P_XML_CONFIG_PASSWORD,
    XML_CONFIG_EXTENSION,
    XML_CONFIG_PREFIX,
)
from .models import (
    LineKeyConfig,
    LineKeyMode,
    PhoneConfig,
    SIPAccountConfig,
)

logger = logging.getLogger("freesdn.adapters.grandstream.provisioner")

# Line key mode → P-value
_LINE_KEY_MODE_MAP = {
    LineKeyMode.NONE: "0",
    LineKeyMode.SPEED_DIAL: "1",
    LineKeyMode.BLF: "2",
    LineKeyMode.PRESENCE: "3",
    LineKeyMode.SPEED_DIAL_BLF: "10",
    LineKeyMode.DIAL_DTMF: "16",
    LineKeyMode.LINE: "7",
}

# Transport → P-value
_TRANSPORT_MAP = {
    "UDP": "0",
    "TCP": "1",
    "TLS": "2",
}


class GrandstreamProvisioner:
    """
    Generates XML provisioning files for Grandstream phones.

    Usage::

        provisioner = GrandstreamProvisioner(
            freesdn_provision_url="http://192.168.1.105:8080/provision",
        )
        config = PhoneConfig(
            accounts=[SIPAccountConfig(sip_server="pbx.local", sip_user_id="1001", ...)],
            line_keys=[LineKeyConfig(key_index=1, mode=LineKeyMode.BLF, value="1002")],
        )
        xml = provisioner.generate_config_xml(config)
        filename = provisioner.get_config_filename("00:0B:82:12:34:56")
    """

    def __init__(
        self,
        freesdn_provision_url: str = "",
        provision_protocol: str = "HTTP",
    ):
        self.freesdn_provision_url = freesdn_provision_url
        self.provision_protocol = provision_protocol

    # ── main entry point ───────────────────────────────────────────────

    def generate_config_xml(
        self,
        config: PhoneConfig,
        *,
        include_provisioning: bool = True,
        pretty: bool = True,
    ) -> str:
        """
        Generate a complete XML provisioning file.

        Returns:
            XML string ready to serve to the phone.
        """
        p_values: dict[str, str] = {}

        # Accounts
        for account in config.accounts:
            p_values.update(self._account_to_p_values(account))

        # Line keys
        for key in config.line_keys:
            p_values.update(self._line_key_to_p_values(key))

        # Network
        if config.network:
            p_values.update(self._network_to_p_values(config))

        # General settings
        if config.admin_password:
            p_values[P_ADMIN_PASSWORD] = config.admin_password
        if config.user_password:
            p_values[P_USER_PASSWORD] = config.user_password
        if config.timezone:
            p_values[P_TIME_ZONE] = config.timezone
        if config.ntp_server:
            p_values[P_NTP_SERVER] = config.ntp_server
        if config.ring_volume is not None:
            p_values[P_RING_VOLUME] = str(config.ring_volume)
        if config.speaker_volume is not None:
            p_values[P_SPEAKER_VOLUME] = str(config.speaker_volume)
        if config.lcd_brightness is not None:
            p_values[P_LCD_BRIGHTNESS] = str(config.lcd_brightness)

        # Provisioning settings
        if include_provisioning and self.freesdn_provision_url:
            p_values.update(self._provisioning_p_values(config))

        # Raw overrides (last, so they win)
        if config.raw_p_values:
            p_values.update(config.raw_p_values)

        return self._build_xml(p_values, pretty=pretty)

    def generate_minimal_registration_xml(
        self,
        sip_server: str,
        extension: str,
        password: str,
        *,
        display_name: str = "",
        account_index: int = 0,
        pretty: bool = True,
    ) -> str:
        """
        Generate a minimal XML file that just registers an extension.

        Useful for quick provisioning without full PhoneConfig.
        """
        config = PhoneConfig(
            accounts=[
                SIPAccountConfig(
                    account_index=account_index,
                    active=True,
                    sip_server=sip_server,
                    sip_user_id=extension,
                    auth_id=extension,
                    auth_password=password,
                    display_name=display_name or extension,
                )
            ]
        )
        return self.generate_config_xml(config, include_provisioning=False, pretty=pretty)

    # ── filename helpers ───────────────────────────────────────────────

    @staticmethod
    def get_config_filename(mac_address: str) -> str:
        """
        Get the config filename for a MAC address.

        E.g. ``00:0B:82:12:34:56`` → ``cfg000b82123456.xml``
        """
        mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac_address).lower()
        return f"{XML_CONFIG_PREFIX}{mac_clean}{XML_CONFIG_EXTENSION}"

    @staticmethod
    def normalize_mac(mac_address: str) -> str:
        """Normalize MAC to lowercase no-separator format."""
        return re.sub(r"[^0-9a-fA-F]", "", mac_address).lower()

    # ── internal: P-value converters ───────────────────────────────────

    def _account_to_p_values(self, account: SIPAccountConfig) -> dict[str, str]:
        """Convert a SIPAccountConfig to P-values."""
        # Account 1 uses base P-values; additional accounts use offsets
        # For simplicity, account 0 = base values, account 1+ need model-specific offsets
        # This implementation covers Account 1 (index 0) directly
        idx = account.account_index

        p: dict[str, str] = {}

        if idx == 0:
            p[P_ACCOUNT_ACTIVE] = "1" if account.active else "0"
            p[P_ACCOUNT_NAME] = account.account_name or account.display_name
            p[P_SIP_SERVER] = account.sip_server
            if account.sip_server_port != 5060:
                p[P_SIP_SERVER_PORT] = str(account.sip_server_port)
            p[P_SIP_USER_ID] = account.sip_user_id
            p[P_AUTH_ID] = account.auth_id or account.sip_user_id
            p[P_AUTH_PASSWORD] = account.auth_password
            p[P_DISPLAY_NAME] = account.display_name or account.sip_user_id
            p[P_SIP_TRANSPORT] = _TRANSPORT_MAP.get(account.transport.upper(), "0")
            p[P_REGISTER_EXPIRY] = str(account.register_expiry)

            # Codecs
            codec_p_values = [P_PREFERRED_CODEC_1, "P58", "P59", "P60", "P61"]
            for i, codec_name in enumerate(account.preferred_codecs[:5]):
                codec_val = CODEC_MAP.get(codec_name)
                if codec_val is not None and i < len(codec_p_values):
                    p[codec_p_values[i]] = str(codec_val)
        else:
            # For accounts beyond index 0, we'd need model-specific P-value
            # offsets.  Store them with a comment prefix for now.
            logger.debug(
                "Account %d requires model-specific P-value offsets (not yet mapped)",
                idx,
            )

        return p

    def _line_key_to_p_values(self, key: LineKeyConfig) -> dict[str, str]:
        """Convert a LineKeyConfig to P-values."""
        p: dict[str, str] = {}
        idx = key.key_index - 1  # 0-based
        if idx < 0:
            return p

        stride = LINE_KEY_STRIDE
        mode_base = int(P_LINE_KEY_1_MODE.replace("P", ""))
        value_base = int(P_LINE_KEY_1_VALUE.replace("P", ""))
        name_base = int(P_LINE_KEY_1_NAME.replace("P", ""))
        account_base = int(P_LINE_KEY_1_ACCOUNT.replace("P", ""))

        p[f"P{mode_base + idx * stride}"] = _LINE_KEY_MODE_MAP.get(key.mode, "0")
        p[f"P{value_base + idx * stride}"] = key.value
        p[f"P{name_base + idx * stride}"] = key.label
        p[f"P{account_base + idx * stride}"] = str(key.account_index)

        return p

    def _network_to_p_values(self, config: PhoneConfig) -> dict[str, str]:
        """Convert network config to P-values."""
        p: dict[str, str] = {}
        net = config.network

        ip_mode_map = {"DHCP": "0", "Static": "1", "PPPoE": "2"}
        p[P_IP_MODE] = ip_mode_map.get(net.ip_mode, "0")

        if net.ip_mode == "Static":
            if net.static_ip:
                p[P_STATIC_IP] = net.static_ip
            if net.subnet_mask:
                p[P_SUBNET_MASK] = net.subnet_mask
            if net.gateway:
                p[P_DEFAULT_GATEWAY] = net.gateway
        if net.dns1:
            p[P_DNS_1] = net.dns1
        if net.dns2:
            p[P_DNS_2] = net.dns2

        if net.voice_vlan_id is not None:
            p[P_LAN_VLAN_TAG] = str(net.voice_vlan_id)
        if net.voice_vlan_priority is not None:
            p[P_LAN_VLAN_PRIORITY] = str(net.voice_vlan_priority)
        if net.data_vlan_id is not None:
            p[P_VLAN_TAG] = str(net.data_vlan_id)
        if net.data_vlan_priority is not None:
            p[P_VLAN_PRIORITY] = str(net.data_vlan_priority)

        return p

    def _provisioning_p_values(self, config: PhoneConfig) -> dict[str, str]:
        """Build P-values for auto-provisioning settings."""
        p: dict[str, str] = {}

        protocol_map = {"TFTP": "0", "HTTP": "1", "HTTPS": "2", "FTP": "4"}
        p[P_PROVISION_PROTOCOL] = protocol_map.get(self.provision_protocol.upper(), "1")
        p[P_PROVISION_SERVER] = self.freesdn_provision_url
        p[P_AUTO_PROVISION] = "1"
        p[P_PROVISION_INTERVAL] = str(config.provisioning.provision_interval)

        if config.provisioning.xml_password:
            p[P_XML_CONFIG_PASSWORD] = config.provisioning.xml_password

        return p

    # ── internal: XML builder ──────────────────────────────────────────

    @staticmethod
    def _build_xml(p_values: dict[str, str], *, pretty: bool = True) -> str:
        """
        Build the Grandstream provisioning XML from P-values.

        Output format::

            <?xml version="1.0" encoding="UTF-8"?>
            <gs_provision version="1">
              <config version="1">
                <P35>1001</P35>
                ...
              </config>
            </gs_provision>
        """
        root = Element("gs_provision", version="1")
        config_el = SubElement(root, "config", version="1")

        for key in sorted(p_values.keys(), key=_p_sort_key):
            el = SubElement(config_el, key)
            el.text = p_values[key]

        raw_xml = tostring(root, encoding="unicode", xml_declaration=True)

        if pretty:
            dom = minidom.parseString(raw_xml)
            return dom.toprettyxml(indent="  ", encoding=None)

        return raw_xml


def _p_sort_key(p_name: str) -> int:
    """Sort P-values numerically (P2 < P10 < P35)."""
    digits = re.sub(r"[^0-9]", "", p_name)
    return int(digits) if digits else 0
