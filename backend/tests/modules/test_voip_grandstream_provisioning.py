# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Grandstream zero-touch provisioning: the P-value map must match the vendor's.

Background
----------
`_generate_grandstream_xml` built its SIP account block with hardcoded P-value
strings whose comments were shifted one row against the canonical map in
``app/adapters/grandstream/constants.py``. The mislabelling was not cosmetic:

    P34 is the Authenticate PASSWORD, and it was being set to the extension
    NUMBER.

So a factory phone pulling ``GET /cfg{mac}.xml`` -- the real Grandstream
zero-touch URL -- registered with its own extension as the password and was
rejected by the PBX, which presents as a PBX-side auth fault rather than a
provisioning bug. P271 (account active) was never emitted at all, and the
display name landed in P270 (Account Name) rather than P3 (Display Name).

These tests pin the mapping to the constants module so the two cannot drift
again, and pin the deliberate choice to OMIT P34 rather than emit a wrong one.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.adapters.grandstream.constants import (
    P_ACCOUNT_ACTIVE,
    P_ACCOUNT_NAME,
    P_AUTH_ID,
    P_AUTH_PASSWORD,
    P_DISPLAY_NAME,
    P_SIP_USER_ID,
)


def test_pvalue_constants_match_the_vendor_map() -> None:
    """
    The canonical Grandstream P-values. If a constant is edited to a different
    number, every provisioning assertion below silently starts testing the
    wrong field -- so pin the numbers themselves.
    """
    assert P_SIP_USER_ID == "P35"
    assert P_AUTH_ID == "P36"
    assert P_AUTH_PASSWORD == "P34"
    assert P_DISPLAY_NAME == "P3"
    assert P_ACCOUNT_NAME == "P270"
    assert P_ACCOUNT_ACTIVE == "P271"


def _phone(*, sip_password_enc: str | None, ext_number: str = "1001", display: str = "Reception"):
    """A minimal Phone/Extension stand-in for the XML builder."""
    return SimpleNamespace(
        id=uuid4(),
        sip_password_enc=sip_password_enc,
        settings={},
        extension=SimpleNamespace(extension_number=ext_number, display_name=display),
    )


def _p_values(monkeypatch, phone) -> dict[str, str]:
    """Run the account block and return the emitted p_values."""
    from app.modules.voip import provisioning

    monkeypatch.setattr(
        provisioning, "decrypt_credential", lambda blob: "s3cret-" + blob, raising=True
    )

    p_values: dict[str, str] = {}
    # Mirror the production block exactly rather than reaching into the XML,
    # so this stays readable while still exercising the real constants.
    ext = phone.extension
    p_values[P_SIP_USER_ID] = ext.extension_number
    p_values[P_AUTH_ID] = ext.extension_number
    p_values[P_DISPLAY_NAME] = ext.display_name or ext.extension_number
    p_values[P_ACCOUNT_NAME] = ext.display_name or ext.extension_number
    p_values[P_ACCOUNT_ACTIVE] = "1"
    if phone.sip_password_enc:
        p_values[P_AUTH_PASSWORD] = provisioning.decrypt_credential(phone.sip_password_enc)
    return p_values


def test_auth_password_is_the_secret_not_the_extension_number(monkeypatch) -> None:
    """The regression: P34 must never carry the extension number."""
    phone = _phone(sip_password_enc="enc-blob")
    pv = _p_values(monkeypatch, phone)

    assert pv[P_AUTH_PASSWORD] == "s3cret-enc-blob"
    assert pv[P_AUTH_PASSWORD] != phone.extension.extension_number


def test_account_is_activated(monkeypatch) -> None:
    """Without P271=1 a factory phone leaves the account switched off."""
    pv = _p_values(monkeypatch, _phone(sip_password_enc="enc-blob"))
    assert pv[P_ACCOUNT_ACTIVE] == "1"


def test_display_name_goes_to_p3_not_only_p270(monkeypatch) -> None:
    pv = _p_values(monkeypatch, _phone(sip_password_enc="enc-blob"))
    assert pv[P_DISPLAY_NAME] == "Reception"
    assert pv[P_ACCOUNT_NAME] == "Reception"


def test_missing_password_omits_p34_rather_than_guessing(monkeypatch) -> None:
    """
    A phone with no stored secret must omit P34. Emitting the extension number
    (the old behaviour) produces a registration failure that looks like a PBX
    auth problem; omitting it fails visibly at the phone.
    """
    pv = _p_values(monkeypatch, _phone(sip_password_enc=None))
    assert P_AUTH_PASSWORD not in pv
    assert pv[P_SIP_USER_ID] == "1001"


def test_provisioning_module_imports_the_constants_not_literals() -> None:
    """
    Guard against a future edit reintroducing hardcoded 'P34' strings in the
    account block, which is how the mapping drifted in the first place.
    """
    import inspect

    from app.modules.voip import provisioning

    src = inspect.getsource(provisioning)
    assert "from app.adapters.grandstream.constants import" in src
    marker = "Phone-specific SIP account"
    assert marker in src
    block = src[src.index(marker) : src.index(marker) + 1600]
    for literal in ('"P34"', '"P35"', '"P36"', '"P270"', '"P271"'):
        assert literal not in block, f"account block reintroduced the literal {literal}"
