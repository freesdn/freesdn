# SPDX-License-Identifier: AGPL-3.0-only
"""Device and identity XML cannot downgrade to an unsafe parser."""

import builtins
from unittest.mock import patch

import pytest
from defusedxml import ElementTree

from app.adapters.grandstream.provisioner import GrandstreamProvisioner
from app.adapters.hikvision.adapter import _parse_xml
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.core.xml_utils import UnsafeXML, parse_untrusted_xml
from app.services.sso import SSOCallbackError, SSONotSupportedError, SSOService

HOSTILE_DOCUMENTS = [
    "<!DOCTYPE root><root/>",
    '<!DOCTYPE root [<!ENTITY secret "expanded">]><root>&secret;</root>',
    '<!DOCTYPE root [<!ENTITY secret SYSTEM "file:///etc/passwd">]><root>&secret;</root>',
    '<!DOCTYPE root SYSTEM "http://192.0.2.1/private"><root/>',
    "<root><unclosed>",
]


@pytest.mark.parametrize("payload", HOSTILE_DOCUMENTS)
def test_external_input_rejects_dtd_entities_and_malformed_xml(payload):
    with pytest.raises(UnsafeXML):
        parse_untrusted_xml(payload, max_bytes=4096)
    assert _parse_xml(payload) is None
    assert OPNsenseAdapter._parse_legacy_rules(payload) == []
    with pytest.raises(SSOCallbackError):
        SSOService._parse_saml_attributes(payload)


def test_missing_protective_dependency_never_calls_stdlib_parser(monkeypatch):
    original_import = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "defusedxml" or name.startswith("defusedxml."):
            raise ImportError("simulated missing dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    with patch("xml.etree.ElementTree.fromstring") as unsafe_parser:
        assert _parse_xml("<root/>") is None
        assert OPNsenseAdapter._parse_legacy_rules("<opnsense/>") == []
        with pytest.raises(SSOCallbackError):
            SSOService._parse_saml_attributes("<root/>")
        unsafe_parser.assert_not_called()


@pytest.mark.parametrize("as_bytes", [False, True])
def test_limit_is_encoded_bytes_not_character_count(as_bytes):
    text = "<root>" + "界" * 20 + "</root>"
    payload = text.encode() if as_bytes else text
    with pytest.raises(UnsafeXML):
        parse_untrusted_xml(payload, max_bytes=60)
    root = parse_untrusted_xml(payload, max_bytes=len(text.encode()))
    assert root.text == "界" * 20


@pytest.mark.parametrize("as_bytes", [False, True])
def test_non_utf8_declaration_preserves_already_decoded_text(as_bytes):
    text = '<?xml version="1.0" encoding="ISO-8859-1"?><name>caf\u00e9</name>'
    payload = text.encode("iso-8859-1") if as_bytes else text
    assert parse_untrusted_xml(payload, max_bytes=1024).text == "caf\u00e9"


def test_namespaced_attributes_still_parse_without_enabling_saml_login():
    xml = """<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
      <saml:Subject><saml:NameID>user@example.test</saml:NameID></saml:Subject>
      <saml:AttributeStatement><saml:Attribute Name="groups">
        <saml:AttributeValue>ops</saml:AttributeValue>
        <saml:AttributeValue>network</saml:AttributeValue>
      </saml:Attribute></saml:AttributeStatement></saml:Assertion>"""
    assert SSOService._parse_saml_attributes(xml) == {
        "NameID": "user@example.test",
        "groups": ["ops", "network"],
    }


async def test_saml_acceptance_remains_disabled():
    with pytest.raises(SSONotSupportedError):
        await SSOService(None).saml_callback("unused-state", "unused-response")


@pytest.mark.parametrize("pretty", [False, True])
def test_provisioning_preserves_sensitive_values_as_literal_xml_text(pretty):
    values = {
        "P2": "  leading and trailing  ",
        "P35": '<!ENTITY x "y"> & <tag>',
        "P34": "界\nvalue",
    }
    result = GrandstreamProvisioner._build_xml(values, pretty=pretty)
    root = ElementTree.fromstring(result, forbid_dtd=True)
    assert {element.tag: element.text for element in root.find("config")} == values
    assert [element.tag for element in root.find("config")] == ["P2", "P34", "P35"]


@pytest.mark.parametrize("pretty", [False, True])
@pytest.mark.parametrize("key", ["P35><P2", "P2 injected='value'", "not_a_p_value"])
def test_provisioning_override_cannot_inject_xml_elements(pretty, key):
    with pytest.raises(ValueError, match="Provisioning keys"):
        GrandstreamProvisioner._build_xml({key: "sensitive"}, pretty=pretty)


@pytest.mark.parametrize("pretty", [False, True])
@pytest.mark.parametrize("value", ["secret\x00value", "secret\ud800value", "secret\uffffvalue"])
def test_provisioning_rejects_invalid_xml_without_echoing_secrets(pretty, value):
    with pytest.raises(ValueError, match="XML 1.0") as error:
        GrandstreamProvisioner._build_xml({"P34": value}, pretty=pretty)
    assert "secret" not in str(error.value)
