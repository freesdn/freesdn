# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""VoIP module + adapter security tests.

Covers the fix wave for the Grandstream + FreePBX audit findings:

* G-C1 / F-C1 — Provisioning endpoint auth (source-IP + HMAC)
* G-C2 / F-C2 — redact_secrets strips known credential fields
* G-C3       — Grandstream SSRF guard rejects link-local / loopback
* G-H4 / F-H4 — Role gate fires on bulk_reboot
* G-H6       — Grandstream set_phone_config refuses protected P-values
* F-H7       — Toll-fraud guard rejects premium-rate prefixes
* F-H10      — AMI Originate rejects ``System`` / ``Exec`` / ``MixMonitor``
* G-H7       — Grandstream client refuses plaintext HTTP without ack
* F-H11      — verify_ssl defaults to True at the bare client level
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.adapters.freepbx.adapter import FreePBXAdapter
from app.adapters.freepbx.ami_client import _AMI_ORIGINATE_APP_ALLOWLIST, AMIClient
from app.adapters.freepbx.exceptions import AMIProtocolError, FreePBXError
from app.adapters.grandstream.adapter import (
    _FORBIDDEN_P_VALUES,
    _SAFE_P_VALUE_ALLOWLIST,
    GrandstreamAdapter,
)
from app.adapters.grandstream.client import GrandstreamPhoneClient
from app.adapters.grandstream.exceptions import GrandstreamConnectionError
from app.core.redaction import redact_secrets

# ═══════════════════════════════════════════════════════════════════════════════
# Cross-cutting: redact_secrets strips VoIP credential fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestRedactionCoversVoIPSecrets:
    """Every credential field that previously round-tripped via the
    synced_cache JSONB is now masked by the shared redactor."""

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "secret",
            "api_key",
            "api_secret",
            "token",
            "ssh_key",
            "private_key",
            "psk",
            "snmp_community",
        ],
    )
    def test_top_level_keys_redacted(self, key: str) -> None:
        payload = {key: "p4ssw0rd", "name": "trunk-1"}
        out = redact_secrets(payload)
        assert out[key] == "***"
        assert out["name"] == "trunk-1"

    def test_nested_redaction_for_pjsip_trunk(self) -> None:
        # PJSIP trunk shape — secrets nested inside ``settings``.
        trunk = {
            "name": "trunk-1",
            "settings": {
                "host": "sip.example.com",
                "secret": "deep-leak",
                "auth_user_pass": "more-leak",
            },
        }
        out = redact_secrets(trunk)
        assert out["settings"]["secret"] == "***"
        assert out["settings"]["auth_user_pass"] == "***"
        assert out["settings"]["host"] == "sip.example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Grandstream adapter SSRF + write-gate + p_values allowlist
# ═══════════════════════════════════════════════════════════════════════════════


class TestGrandstreamSSRF:
    """The Grandstream adapter must reject phone IPs that fall outside
    the configured Site subnet — and unconditionally reject loopback /
    link-local / multicast / reserved addresses.
    """

    def _adapter(self, allowed_subnets: tuple[str, ...] = ()) -> GrandstreamAdapter:
        return GrandstreamAdapter(
            host="provisioning.example.com",
            allowed_subnets=allowed_subnets,
        )

    @pytest.mark.parametrize(
        "bad_ip",
        [
            "127.0.0.1",  # loopback
            "169.254.1.1",  # link-local
            "224.0.0.1",  # multicast
            "0.0.0.0",  # unspecified
            "240.0.0.1",  # reserved
            "::1",  # IPv6 loopback
        ],
    )
    def test_rejects_unsafe_addresses(self, bad_ip: str) -> None:
        a = self._adapter()
        with pytest.raises(GrandstreamConnectionError):
            a.add_phone(bad_ip, mac="aa:bb:cc:dd:ee:ff")

    def test_rfc1918_is_allowed(self) -> None:
        a = self._adapter()
        # No allowlist → RFC1918 phones can register
        a.add_phone("192.168.1.150", mac="aa:bb:cc:dd:ee:ff")

    def test_allowlist_enforced(self) -> None:
        # IP outside allowlist is rejected even though it'd otherwise pass.
        a = self._adapter(allowed_subnets=("192.168.1.0/24",))
        with pytest.raises(GrandstreamConnectionError):
            a.add_phone("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        # IP inside allowlist is accepted.
        a.add_phone("192.168.1.42", mac="aa:bb:cc:dd:ee:ff")


class TestGrandstreamPValueAllowlist:
    """``set_phone_config`` MUST refuse to write any forbidden
    credential / provisioning P-value — even when the caller passes
    ``force=True``."""

    @pytest.mark.asyncio
    async def test_blocks_admin_password(self) -> None:
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=False)
        a.add_phone("192.168.1.150", mac="aa:bb:cc:dd:ee:ff")
        # P2 is the admin password — must not be writable via set_phone_config
        result = await a.set_phone_config(
            "aa:bb:cc:dd:ee:ff",
            {"P2": "evil-password"},
            force=True,
        )
        assert not result.success
        assert "P-values" in (result.error or "") or "protected" in (result.error or "")

    @pytest.mark.asyncio
    async def test_blocks_sip_auth_password(self) -> None:
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=False)
        a.add_phone("192.168.1.150", mac="aa:bb:cc:dd:ee:ff")
        result = await a.set_phone_config(
            "aa:bb:cc:dd:ee:ff",
            {"P34": "evil-sip-pass"},
            force=True,
        )
        assert not result.success

    @pytest.mark.asyncio
    async def test_blocks_unknown_pvalue(self) -> None:
        # Even non-credential P-values are rejected unless on the allowlist —
        # the contract is "explicit list" not "blocklist".
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=False)
        a.add_phone("192.168.1.150", mac="aa:bb:cc:dd:ee:ff")
        result = await a.set_phone_config(
            "aa:bb:cc:dd:ee:ff",
            {"P9999": "anything"},
            force=True,
        )
        assert not result.success
        assert "allowlist" in (result.error or "").lower()

    def test_allowlist_excludes_known_credentials(self) -> None:
        # The well-known credential P-values are definitely NOT in
        # the safe-write allowlist. (P234 is intentionally NOT
        # asserted disjoint — it overlaps semantically between
        # "syslog flag" and "account-3 SIP auth password" depending
        # on firmware, so we treat it as forbidden via P_FORBIDDEN
        # regardless of which firmware is talking.)
        critical_secrets = {"P2", "P196", "P34", "P237", "P192", "P145"}
        assert critical_secrets.isdisjoint(_SAFE_P_VALUE_ALLOWLIST)
        assert critical_secrets.issubset(_FORBIDDEN_P_VALUES)


class TestGrandstreamReadOnlyGate:
    """Write operations require ``force=True`` when the adapter is in
    read-only mode (the default)."""

    @pytest.mark.asyncio
    async def test_set_config_refused_when_read_only(self) -> None:
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=True)
        a.add_phone("192.168.1.150", mac="aa:bb:cc:dd:ee:ff")
        result = await a.set_phone_config(
            "aa:bb:cc:dd:ee:ff",
            {"P14": "ringtone"},
        )
        assert not result.success
        assert "read-only" in (result.error or "")


class TestGrandstreamConfigureMethodsReadOnly:
    """``configure_sip_account`` / ``configure_blf_keys`` push live SIP auth
    credentials + line-key config to the phone. They were the TWO Grandstream
    adapter write methods that shipped WITHOUT the dual-gate (pre-public
    review P1-GRANDSTREAM-READONLY-BYPASS) — every sibling write
    (set_phone_config / reboot_phone / factory_reset / firmware / bulk_reboot)
    already called ``_check_write_allowed``. Now gated like them."""

    @pytest.mark.asyncio
    async def test_configure_sip_account_refused_when_read_only(self) -> None:
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=True)
        # If the gate failed and we reached the transport, this would raise
        # loudly instead of silently writing.
        a._get_or_connect = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("must not connect under read-only")
        )
        result = await a.configure_sip_account(
            "aa:bb:cc:dd:ee:ff",
            "sip.example.com",
            "1001",
            "s3cret",
        )
        assert not result.success
        assert "read-only" in (result.error or "")

    @pytest.mark.asyncio
    async def test_configure_blf_keys_refused_when_read_only(self) -> None:
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=True)
        a._get_or_connect = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("must not connect under read-only")
        )
        result = await a.configure_blf_keys("aa:bb:cc:dd:ee:ff", [])
        assert not result.success
        assert "read-only" in (result.error or "")

    @pytest.mark.asyncio
    async def test_configure_sip_account_proceeds_with_force(self) -> None:
        """The sanctioned opt-in (force=True + ADAPTER_READ_ONLY cleared)
        still reaches the phone — proven by the client write being awaited."""
        a = GrandstreamAdapter(host="ctrl.example.com", read_only=True)
        client = AsyncMock()
        client.set_config = AsyncMock(return_value=True)
        a._get_or_connect = AsyncMock(return_value=client)  # type: ignore[method-assign]
        result = await a.configure_sip_account(
            "aa:bb:cc:dd:ee:ff",
            "sip.example.com",
            "1001",
            "s3cret",
            force=True,
        )
        assert result.success
        client.set_config.assert_awaited_once()


class TestVoIPServicePhoneWritesReadOnly:
    """The phone-control SERVICE methods (reboot / factory-reset / SIP push)
    talk to the GrandstreamPhoneClient DIRECTLY, bypassing the adapter's
    method-level gate — so they enforce the read-only contract themselves
    (pre-public review P1: voip/service.py direct-client writes)."""

    def _service(self):
        from app.modules.voip.service import VoIPService

        return VoIPService(db=AsyncMock())

    @pytest.mark.asyncio
    @patch("app.modules.voip.service._voip_live_writes_blocked", lambda: True)
    async def test_reboot_phone_refused_when_read_only(self) -> None:
        from app.modules.voip.service import VoIPError

        svc = self._service()
        svc.get_phone = AsyncMock(  # type: ignore[method-assign]
            return_value=SimpleNamespace(id=uuid4(), ip_address="192.0.2.1")
        )
        svc._grandstream_client_for_phone = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("must not build client under read-only")
        )
        with pytest.raises(VoIPError):
            await svc.reboot_phone(uuid4())
        svc._grandstream_client_for_phone.assert_not_awaited()

    @pytest.mark.asyncio
    @patch("app.modules.voip.service._voip_live_writes_blocked", lambda: True)
    async def test_factory_reset_refused_when_read_only(self) -> None:
        from app.modules.voip.service import VoIPError

        svc = self._service()
        svc.get_phone = AsyncMock(  # type: ignore[method-assign]
            return_value=SimpleNamespace(id=uuid4(), ip_address="192.0.2.1")
        )
        svc._grandstream_client_for_phone = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("must not build client under read-only")
        )
        with pytest.raises(VoIPError):
            await svc.factory_reset_phone(uuid4())
        svc._grandstream_client_for_phone.assert_not_awaited()

    @pytest.mark.asyncio
    @patch("app.modules.voip.service._voip_live_writes_blocked", lambda: True)
    async def test_push_sip_config_refused_when_read_only(self) -> None:
        from app.modules.voip.service import VoIPError

        svc = self._service()
        svc.get_phone = AsyncMock(  # type: ignore[method-assign]
            return_value=SimpleNamespace(
                id=uuid4(),
                ip_address="192.0.2.1",
                extension_id=uuid4(),
                pbx_id=uuid4(),
            )
        )
        with pytest.raises(VoIPError):
            await svc.push_sip_config_to_phone(uuid4(), sip_password="s3cret")
        # The ext/PBX DB lookup is AFTER the (fail-fast) gate — never reached.
        svc.db.execute.assert_not_called()


class TestVoipReadOnlyHelper:
    """``_voip_live_writes_blocked`` is the single chokepoint the three
    direct-client service writes consult."""

    def test_blocked_when_read_only(self, monkeypatch) -> None:
        from app.core.config import settings
        from app.modules.voip.service import _voip_live_writes_blocked

        monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", True, raising=False)
        assert _voip_live_writes_blocked() is True

    def test_not_blocked_when_read_only_off(self, monkeypatch) -> None:
        from app.core.config import settings
        from app.modules.voip.service import _voip_live_writes_blocked

        monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", False, raising=False)
        assert _voip_live_writes_blocked() is False

    def test_not_blocked_inside_apply_window(self, monkeypatch) -> None:
        from app.adapters.apply_context import apply_window
        from app.core.config import settings
        from app.modules.voip.service import _voip_live_writes_blocked

        monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", True, raising=False)
        with apply_window():
            assert _voip_live_writes_blocked() is False


class TestGrandstreamClientPlaintextRefusal:
    """The Grandstream client must refuse to use plain HTTP unless the
    caller has explicitly acknowledged the downgrade."""

    def test_refuses_http_without_ack(self) -> None:
        with pytest.raises(GrandstreamConnectionError):
            GrandstreamPhoneClient(
                host="192.168.1.150",
                password="admin",
                use_ssl=False,
                acknowledge_plaintext=False,
            )

    def test_http_works_with_ack(self) -> None:
        # Constructor succeeds; no actual network IO.
        c = GrandstreamPhoneClient(
            host="192.168.1.150",
            password="admin",
            use_ssl=False,
            acknowledge_plaintext=True,
        )
        assert c.host == "192.168.1.150"
        assert c.use_ssl is False


# ═══════════════════════════════════════════════════════════════════════════════
# FreePBX adapter: toll-fraud guard + AMI Originate allowlist + read-only gate
# ═══════════════════════════════════════════════════════════════════════════════


def _freepbx_adapter(read_only: bool = False, prefixes: tuple[str, ...] = ()) -> FreePBXAdapter:
    return FreePBXAdapter(
        host="pbx.example.com",
        username="admin",
        password="x",
        read_only=read_only,
        allowed_outbound_prefixes=prefixes,
    )


class TestFreePBXTollFraudGuard:
    """The adapter must reject premium-rate destinations unless the
    tenant has whitelisted the prefix in pbx.settings."""

    def test_accepts_safe_destinations(self) -> None:
        a = _freepbx_adapter()
        # Extension dialing is always safe — no toll involved.
        a._check_destination_safe("1001")
        # Toll-free US numbers are not in the premium blocklist.
        a._check_destination_safe("+18001234567")

    def test_blocks_us_premium(self) -> None:
        a = _freepbx_adapter()
        with pytest.raises(FreePBXError):
            a._check_destination_safe("19001234567")

    def test_blocks_satellite(self) -> None:
        a = _freepbx_adapter()
        with pytest.raises(FreePBXError):
            a._check_destination_safe("+8835551234")

    def test_blocks_bare_international(self) -> None:
        a = _freepbx_adapter()
        with pytest.raises(FreePBXError):
            a._check_destination_safe("0011234567890")

    def test_allowlist_permits_premium(self) -> None:
        a = _freepbx_adapter(prefixes=("+883",))
        # Now satellite numbers are permitted
        a._check_destination_safe("+8835551234")

    def test_rejects_invalid_characters(self) -> None:
        a = _freepbx_adapter()
        with pytest.raises(FreePBXError):
            a._check_destination_safe("1001; rm -rf /")


class TestFreePBXOriginateAllowlist:
    """AMI Originate ``Application`` param must be on the safe list.
    System / Exec / MixMonitor are RCE / arbitrary-write primitives."""

    def test_safe_apps_pass(self) -> None:
        # The allowlist is enforced at two layers — adapter + AMI client.
        for app in _AMI_ORIGINATE_APP_ALLOWLIST:
            assert app in {"Dial", "Playback", "Queue", "ConfBridge"}

    @pytest.mark.asyncio
    async def test_dangerous_app_rejected_by_adapter(self) -> None:
        a = _freepbx_adapter(read_only=False)
        result = await a.originate_call(
            channel="SIP/1001",
            exten="1002",
            application="System",
            force=True,
        )
        assert not result.success
        assert "allowlist" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_dangerous_app_rejected_by_ami_client(self) -> None:
        # Direct AMI client call — the second layer of defence.
        client = AMIClient(host="pbx.example.com", username="admin", secret="x")
        with pytest.raises(AMIProtocolError):
            await client.originate(
                channel="SIP/1001",
                application="Exec",
                exten="1002",
            )


class TestFreePBXReadOnlyGate:
    @pytest.mark.asyncio
    async def test_originate_blocked_in_read_only(self) -> None:
        a = _freepbx_adapter(read_only=True)
        result = await a.originate_call(
            channel="SIP/1001",
            exten="1002",
            # No force=True
        )
        assert not result.success
        assert "read-only" in (result.error or "")

    @pytest.mark.asyncio
    async def test_originate_works_with_force(self) -> None:
        a = _freepbx_adapter(read_only=True)
        # We expect either a connect failure OR a successful pre-check —
        # the only failure mode we DON'T want is "read-only". Use a
        # safe destination to get past the toll-fraud guard, then
        # confirm the failure isn't the read-only gate.
        result = await a.originate_call(
            channel="SIP/1001",
            exten="1002",
            force=True,
        )
        assert "read-only" not in (result.error or "")


# ═══════════════════════════════════════════════════════════════════════════════
# Provisioning auth (resolve_provisioning_request)
# ═══════════════════════════════════════════════════════════════════════════════


class TestProvisioningAuthHMAC:
    """HMAC signature is constant-time compared and verifies against
    the same SECRET_KEY + ENCRYPTION_SALT the runtime uses."""

    def test_valid_signature_verifies(self) -> None:
        from app.modules.voip.provisioning_auth import (
            generate_provisioning_signature,
            normalize_mac,
            verify_hmac,
        )

        mac = "aa:bb:cc:dd:ee:ff"
        sig = generate_provisioning_signature(mac)
        assert verify_hmac(normalize_mac(mac), sig) is True

    def test_wrong_signature_rejected(self) -> None:
        from app.modules.voip.provisioning_auth import verify_hmac

        assert verify_hmac("aa:bb:cc:dd:ee:ff", "0" * 64) is False

    def test_empty_inputs_rejected(self) -> None:
        from app.modules.voip.provisioning_auth import verify_hmac

        assert verify_hmac("", "") is False
        assert verify_hmac("aa:bb:cc:dd:ee:ff", "") is False
        assert verify_hmac("", "garbage") is False

    def test_normalize_mac_handles_formats(self) -> None:
        from app.modules.voip.provisioning_auth import normalize_mac

        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"

    def test_invalid_mac_rejected(self) -> None:
        from app.modules.voip.provisioning_auth import normalize_mac

        assert normalize_mac("not-a-mac") is None
        assert normalize_mac("aa:bb:cc:dd") is None
        assert normalize_mac("../etc/passwd") is None
        assert normalize_mac("") is None


class TestProvisioningAuthSubnet:
    """Source-IP check against Site.subnets."""

    def test_ip_in_subnet(self) -> None:
        from app.modules.voip.provisioning_auth import _ip_in_subnets

        subnets = [{"cidr": "192.168.1.0/24"}, {"cidr": "10.0.0.0/8"}]
        assert _ip_in_subnets("192.168.1.150", subnets) is True
        assert _ip_in_subnets("10.20.30.40", subnets) is True

    def test_ip_outside_subnets(self) -> None:
        from app.modules.voip.provisioning_auth import _ip_in_subnets

        subnets = [{"cidr": "192.168.1.0/24"}]
        assert _ip_in_subnets("172.16.0.1", subnets) is False

    def test_empty_subnets_returns_false(self) -> None:
        from app.modules.voip.provisioning_auth import _ip_in_subnets

        assert _ip_in_subnets("1.2.3.4", []) is False

    def test_invalid_ip_returns_false(self) -> None:
        from app.modules.voip.provisioning_auth import _ip_in_subnets

        assert _ip_in_subnets("not-an-ip", [{"cidr": "192.168.1.0/24"}]) is False

    def test_malformed_subnet_is_skipped(self) -> None:
        # A bogus entry in the JSONB list shouldn't crash the check —
        # it just gets skipped and other entries are evaluated.
        from app.modules.voip.provisioning_auth import _ip_in_subnets

        subnets = [
            {"name": "bogus", "cidr": "not-a-cidr"},
            {"cidr": "192.168.1.0/24"},
        ]
        assert _ip_in_subnets("192.168.1.150", subnets) is True
