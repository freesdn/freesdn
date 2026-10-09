# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded XML parsing for device responses and identity-provider input."""

from xml.etree.ElementTree import Element, ParseError


class UnsafeXML(ValueError):
    """XML cannot be parsed safely; callers must not retry with a weaker parser."""


def parse_untrusted_xml(text: str | bytes, *, max_bytes: int) -> Element:
    """Reject oversized documents, DTDs and entities, even if defusedxml is missing.

    The limit applies to UTF-8 bytes for text inputs. It bounds parsing, not the
    preceding HTTP download; callers still need transport-level response limits.
    """
    if not isinstance(text, (str, bytes)) or len(text) > max_bytes:
        raise UnsafeXML("XML input is invalid or exceeds the size limit")
    try:
        payload = text.encode("utf-8") if isinstance(text, str) else text
    except UnicodeError as exc:
        raise UnsafeXML("XML input has invalid text encoding") from exc
    if len(payload) > max_bytes:
        raise UnsafeXML("XML input exceeds the size limit")

    try:
        from defusedxml import ElementTree as safe_et
        from defusedxml.common import DefusedXmlException
    except ImportError as exc:
        raise UnsafeXML("Safe XML parsing requires defusedxml") from exc

    try:
        # Preserve decoded text instead of decoding UTF-8 bytes again using a
        # stale XML declaration such as ISO-8859-1.
        root: Element = safe_et.fromstring(
            text, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
        return root
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise UnsafeXML("XML input is malformed or contains forbidden declarations") from exc
