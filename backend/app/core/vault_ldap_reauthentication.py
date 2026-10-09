# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded fresh LDAP bind of an existing identity, never login or JIT.

Only LDAPv3 simple bind and StartTLS are implemented here. ldap3 supplies the
message definitions; its synchronous connection, search, referral and retry
machinery is deliberately not used. The caller still needs current SQL authority,
applicable MFA, operation binding and durable final export authorization.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import anyio
import dns.asyncresolver
from ldap3.protocol.rfc4511 import BindRequest, ExtendedRequest, LDAPMessage
from ldap3.protocol.sasl.sasl import validate_simple_password
from ldap3.utils.dn import parse_dn
from pyasn1.codec.ber.decoder import decode
from pyasn1.codec.ber.encoder import encode

from app.core.owned_async import complete_before_cancellation
from app.core.security_utils import validate_target_host
from app.core.vault_export_proof import VaultProofContext

_ERROR = "Fresh identity confirmation failed; start a new confirmation"
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_START_TLS = "1.3.6.1.4.1.1466.20037"
_RESPONSE_BYTES = 16_384
_OPERATION_SECONDS = 20
_CLOSE_SECONDS = 2
_ADMISSION = anyio.CapacityLimiter(2)


class LDAPConfirmationError(ValueError):
    """Fixed public error without credentials, DNs or directory diagnostics."""


def _refuse() -> LDAPConfirmationError:
    return LDAPConfirmationError(_ERROR)


def _text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or len(value.encode("utf-8")) > maximum
    ):
        raise _refuse()
    return value


@dataclass(frozen=True, repr=False)
class LDAPExportBinding:
    context: VaultProofContext
    request_binding: str
    provider_id: UUID
    provider_digest: str
    url: str
    subject_dn: str
    require_tls: bool
    ca_pem: str | None = None

    def __post_init__(self) -> None:
        try:
            if type(self.context) is not VaultProofContext or type(self.provider_id) is not UUID:
                raise _refuse()
            if any(
                type(x) is not str or not _HEX.fullmatch(x)
                for x in (self.request_binding, self.provider_digest)
            ):
                raise _refuse()
            parts = urlsplit(_text(self.url, 4096))
            if (
                parts.scheme not in {"ldap", "ldaps"}
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.path not in {"", "/"}
                or parts.query
                or parts.fragment
                or "\\" in self.url
                or "%" in self.url
                or parts.port == 0
                or type(self.require_tls) is not bool
                or (parts.scheme == "ldap" and not self.require_tls)
            ):
                raise _refuse()
            _text(parts.hostname, 253)
            if not parse_dn(_text(self.subject_dn, 512)):
                raise _refuse()
            if self.ca_pem is not None:
                if type(self.ca_pem) is not str or not 1 <= len(self.ca_pem.encode()) <= 65_536:
                    raise _refuse()
        except Exception:
            raise _refuse() from None


@dataclass(frozen=True, repr=False)
class LDAPConfirmationReceipt:
    """Internal fresh-factor observation; not an export bearer credential."""

    provider_id: UUID
    authenticated_at: int
    completed_at: int
    request_binding: str


async def _resolve(host: str) -> str:
    """Bounded asynchronous DNS followed by literal-IP admission and pinning.

    RFC1918 directory servers are supported. Loopback, metadata and the other
    existing target-policy exclusions remain refused. No OS resolver worker is
    left running after a cancelled or expired confirmation.
    """
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        answers = await dns.asyncresolver.resolve_name(host, lifetime=5)
        candidates = list(answers.addresses())
    if not candidates or len(candidates) > 32:
        raise _refuse()
    for candidate in candidates:
        ipaddress.ip_address(candidate)
        validate_target_host(candidate, allow_private=True)
    return candidates[0]


def _request(message_id: int, operation: str, request: object) -> bytes:
    message = LDAPMessage()
    message["messageID"] = message_id
    message["protocolOp"][operation] = request
    return cast(bytes, encode(message))


def _header(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read a bounded, definite BER TLV header before invoking the ASN.1 codec."""
    if offset + 2 > len(data):
        raise _refuse()
    tag, size = data[offset], data[offset + 1]
    offset += 2
    if size & 0x80:
        count = size & 0x7F
        if not 1 <= count <= 2 or offset + count > len(data):
            raise _refuse()
        size = int.from_bytes(data[offset : offset + count])
        offset += count
    if size > _RESPONSE_BYTES:
        raise _refuse()
    return tag, offset, size


async def _response(reader: asyncio.StreamReader, message_id: int, operation: str) -> None:
    prefix = await reader.readexactly(2)
    if prefix[0] != 0x30:
        raise _refuse()
    if prefix[1] & 0x80:
        count = prefix[1] & 0x7F
        if not 1 <= count <= 2:
            raise _refuse()
        prefix += await reader.readexactly(count)
    _, _, size = _header(prefix, 0)
    if size + len(prefix) > _RESPONSE_BYTES:
        raise _refuse()
    packet = prefix + await reader.readexactly(size)
    # Reject a request/filter tree before decoding. Only the two flat response
    # schemas can reach pyasn1, with a fixed total packet and integer bound.
    tag, offset, length = _header(packet, len(prefix))
    if tag != 2 or not 1 <= length <= 4 or offset + length >= len(packet):
        raise _refuse()
    if int.from_bytes(packet[offset : offset + length], signed=True) != message_id:
        raise _refuse()
    tag, offset, length = _header(packet, offset + length)
    if tag != {"bindResponse": 0x61, "extendedResp": 0x78}[operation]:
        raise _refuse()
    # Controls are unnecessary in this two-message protocol and not accepted.
    if offset + length != len(packet):
        raise _refuse()
    message, rest = decode(packet, asn1Spec=LDAPMessage())
    result = message["protocolOp"][operation]
    if rest or int(result["resultCode"]) != 0 or result["referral"].hasValue():
        raise _refuse()
    if operation == "bindResponse" and result["serverSaslCreds"].hasValue():
        raise _refuse()
    if operation == "extendedResp":
        if result["responseValue"].hasValue():
            raise _refuse()
        if result["responseName"].hasValue() and str(result["responseName"]) != _START_TLS:
            raise _refuse()


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(_CLOSE_SECONDS):
            await writer.wait_closed()
    finally:
        # Abort also handles a peer that refuses the TLS close handshake. The
        # transport owns no reusable pool and may never survive the operation.
        writer.transport.abort()


class VaultLDAPReauthentication:
    def __init__(
        self, *, binding: LDAPExportBinding, check_current: Callable[[], Awaitable[None]]
    ) -> None:
        if type(binding) is not LDAPExportBinding or not callable(check_current):
            raise _refuse()
        self.binding = binding
        self._check_current = check_current

    async def confirm(self, password: str) -> LDAPConfirmationReceipt:
        try:
            # Empty simple-bind passwords can select unauthenticated LDAP bind.
            # Reject locally before DNS, allocation or credential transmission.
            prepared = validate_simple_password(_text(password, 1024))
            # SASLprep can remove characters or expand their UTF-8 encoding.
            # Match ordinary ldap3 login while still forbidding anonymous bind.
            if type(prepared) is not bytes or not 1 <= len(prepared) <= 1024:
                raise _refuse()
            result = await self._owned_confirm(prepared)
            await anyio.lowlevel.checkpoint()
            return result
        except Exception:
            raise _refuse() from None

    @complete_before_cancellation
    async def _owned_confirm(self, password: bytes) -> LDAPConfirmationReceipt:
        writer = None
        _ADMISSION.acquire_nowait()
        try:
            deadline = asyncio.get_running_loop().time() + _OPERATION_SECONDS
            async with asyncio.timeout_at(deadline):
                await self._check_current()
                parts = urlsplit(self.binding.url)
                if parts.hostname is None:
                    raise _refuse()
                host = parts.hostname.encode("idna").decode("ascii")
                pin = await _resolve(host)
                context = ssl.create_default_context(cadata=self.binding.ca_pem)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                encrypted = parts.scheme == "ldaps"
                port = parts.port or (636 if encrypted else 389)
                reader, writer = await asyncio.open_connection(
                    pin,
                    port,
                    ssl=context if encrypted else None,
                    server_hostname=host if encrypted else None,
                    ssl_handshake_timeout=5 if encrypted else None,
                    ssl_shutdown_timeout=_CLOSE_SECONDS if encrypted else None,
                    limit=_RESPONSE_BYTES,
                )
                if not encrypted:
                    request = ExtendedRequest()
                    request["requestName"] = _START_TLS
                    writer.write(_request(1, "extendedReq", request))
                    await writer.drain()
                    await _response(reader, 1, "extendedResp")
                    await writer.start_tls(
                        context,
                        server_hostname=host,
                        ssl_handshake_timeout=5,
                        ssl_shutdown_timeout=_CLOSE_SECONDS,
                    )
                await self._check_current()
                request = BindRequest()
                request["version"] = 3
                request["name"] = self.binding.subject_dn
                request["authentication"]["simple"] = password
                writer.write(_request(2, "bindRequest", request))
                await writer.drain()
                await _response(reader, 2, "bindResponse")
                authenticated_at = int(time.time())
            # Closing and the final authority read are mandatory, even after a
            # request cancellation. A late close/read must not deliver success.
        finally:
            try:
                if writer is not None:
                    await _close(writer)
            finally:
                _ADMISSION.release()
        async with asyncio.timeout_at(deadline):
            await self._check_current()
        if asyncio.get_running_loop().time() >= deadline:
            raise _refuse()
        return LDAPConfirmationReceipt(
            self.binding.provider_id,
            authenticated_at,
            int(time.time()),
            self.binding.request_binding,
        )
