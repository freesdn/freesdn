# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the vendor-agnostic adapter input validators.

These run on every adapter (Omada today, MikroTik / UniFi tomorrow).
The whole point of the validators is to defend against path-traversal
injection, so the test surface must enumerate every nasty shape an
attacker might try to smuggle into a vendor-API URL.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.adapters.validation import validate_id, validate_mac


class TestValidateMac:
    """``validate_mac`` accepts canonical mac shapes and rejects
    everything else, including the path-traversal payloads that
    motivated the helper in the first place."""

    @pytest.mark.parametrize(
        "mac",
        [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "01:23:45:67:89:ab",
            "aa-bb-cc-dd-ee-ff",
            "AA-BB-CC-DD-EE-FF",
        ],
    )
    def test_accepts_canonical(self, mac: str) -> None:
        assert validate_mac(mac) == mac

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "aabbccddeeff",  # no separators
            "aa:bb:cc:dd:ee",  # too short
            "aa:bb:cc:dd:ee:ff:00",  # too long
            "gg:hh:ii:jj:kk:ll",  # non-hex
            "aa:bb:cc:dd:ee:ff/extra",
            "aa:bb:cc:dd:ee:ff/../../admin",
            "../../../etc/passwd",
            "aa:bb:cc:dd:ee:ff\x00/etc",  # null byte
            "aa.bb.cc.dd.ee.ff",  # dot-separated (some vendors use; not Omada)
            "aa:bb:cc:dd:ee:ff ",  # trailing space
            " aa:bb:cc:dd:ee:ff",  # leading space
        ],
    )
    def test_rejects_bad(self, bad: str) -> None:
        with pytest.raises(HTTPException) as exc:
            validate_mac(bad)
        assert exc.value.status_code == 400
        assert "mac" in exc.value.detail.lower()

    def test_rejects_none_input(self) -> None:
        # The validator is called from FastAPI handlers where the type
        # annotation is ``str`` — but defensive code shouldn't crash on
        # an accidental ``None``.
        with pytest.raises(HTTPException):
            validate_mac(None)  # type: ignore[arg-type]


class TestValidateId:
    """Generic opaque-ID validator covering backup_id, portal_id,
    wlan_id, ssid_id, target_id, etc."""

    @pytest.mark.parametrize(
        "value",
        [
            "abc123",
            "BACKUP_2026_05_09",
            "site-template.foo",
            "a",  # 1 char (lower bound)
            "a" * 64,  # 64 chars (upper bound)
            "0123456789",
            "WiFi-Guest_v2",
            # UniFi uses MAC addresses (``aa:bb:cc:dd:ee:ff``) as the
            # canonical row id for devices + clients. Added when the
            # stage-and-apply build-out landed; before that the
            # validator rejected ``:`` and every UniFi block /
            # forget / disable stage 400'd at the schema boundary.
            "aa:bb:cc:dd:ee:ff",
            "*A",        # RouterOS row id
            "*80000003", # RouterOS hex id
        ],
    )
    def test_accepts_canonical(self, value: str) -> None:
        assert validate_id(value, label="x") == value

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "../etc/passwd",
            "../../config",
            "foo/bar",
            "foo\\bar",
            "foo bar",  # spaces
            "foo;rm -rf /",
            "foo\x00",  # null byte
            "foo\nbar",
            "foo\rbar",  # CR (header injection)
            "abc%2F..%2Fadmin",  # URL-encoded traversal — must be
            # rejected too because the Omada client doesn't decode
            # path segments
            "foo$(whoami)",
            "a" * 65,  # one over the bound
            "x?y=1",  # query smuggling
            "x#frag",
        ],
    )
    def test_rejects_bad(self, bad: str) -> None:
        with pytest.raises(HTTPException) as exc:
            validate_id(bad, label="backup_id")
        assert exc.value.status_code == 400
        assert "backup_id" in exc.value.detail

    def test_label_echoed(self) -> None:
        """Operators should see WHICH field failed."""
        with pytest.raises(HTTPException) as exc:
            validate_id("../foo", label="portal_id")
        assert "portal_id" in exc.value.detail
        with pytest.raises(HTTPException) as exc:
            validate_id("../foo", label="wlan_id")
        assert "wlan_id" in exc.value.detail
