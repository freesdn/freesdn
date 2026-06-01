# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for the catastrophic-op confirmation gate: a naive
``bool(payload.get("confirmed"))`` treats the STRING ``"false"`` as True (every
non-empty string is truthy in Python), letting an operator bypass the confirm gate
with ``{"confirmed": "false"}``. ``payload_confirmed`` accepts ONLY a genuine
affirmative."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services.adapter_preflight_common import payload_confirmed


class TestPayloadConfirmed:
    def test_bool_true_is_confirmed(self) -> None:
        assert payload_confirmed({"confirmed": True}) is True

    def test_bool_false_not_confirmed(self) -> None:
        assert payload_confirmed({"confirmed": False}) is False

    def test_string_false_not_confirmed(self) -> None:
        # The bug: bool("false") is True. Must be rejected.
        assert payload_confirmed({"confirmed": "false"}) is False

    def test_string_true_confirmed(self) -> None:
        assert payload_confirmed({"confirmed": "true"}) is True
        assert payload_confirmed({"confirmed": "TRUE"}) is True

    @pytest.mark.parametrize("v", ["", "no", "0", "yolo", "False"])
    def test_arbitrary_strings_not_confirmed(self, v: str) -> None:
        assert payload_confirmed({"confirmed": v}) is False

    def test_missing_or_none_not_confirmed(self) -> None:
        assert payload_confirmed({}) is False
        assert payload_confirmed(None) is False


class TestVendorGatesRejectStringFalse:
    """The vendor preflight gates must reject ``{"confirmed": "false"}`` on a
    catastrophic op; the string-truthiness bypass applies across all vendors."""

    def test_pfsense_gate_rejects_string_false(self) -> None:
        from app.services.adapter_pfsense_preflight import enforce_pfsense_preflight

        with pytest.raises(HTTPException) as e:
            # any pfsense delete is catastrophic-by-default
            enforce_pfsense_preflight("pfsense.firewall.rule", "delete", {"confirmed": "false"})
        assert e.value.status_code == 409

    def test_pfsense_gate_allows_bool_true(self) -> None:
        from app.services.adapter_pfsense_preflight import enforce_pfsense_preflight

        # bool True clears the gate (no raise)
        enforce_pfsense_preflight("pfsense.firewall.rule", "delete", {"confirmed": True})

    def test_mikrotik_gate_rejects_string_false(self) -> None:
        from app.services.adapter_mikrotik_preflight import enforce_mikrotik_preflight

        with pytest.raises(HTTPException) as e:
            enforce_mikrotik_preflight("mikrotik.firewall.rule", "delete", {"confirmed": "false"})
        assert e.value.status_code == 409
