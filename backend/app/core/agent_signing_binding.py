# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded private signing-command/authority commitments, not bearer grants."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import cast
from uuid import UUID

type SigningJSON = None | bool | int | str | list[SigningJSON] | dict[str, SigningJSON]


def signing_commitment(value: object, *, key: bytes, domain: str) -> str:
    """Keyed, domain-separated binding without coercion or unbounded traversal.

    The coordinator supplies a persistent backend secret, never the agent signing
    private key, a public key or a caller secret. A commitment is not authorization.
    """
    if type(key) is not bytes or not 32 <= len(key) <= 4096:
        raise ValueError("Signing authority key is unavailable")
    if type(domain) is not str or domain not in {
        "account",
        "provider",
        "command",
        "authority",
        "key",
    }:
        raise ValueError("Signing commitment domain is unsupported")
    nodes, budget = 0, 0

    def normal(item: object, depth: int = 0) -> SigningJSON:
        nonlocal nodes, budget
        nodes += 1
        budget += 8
        if depth > 8 or nodes > 5000 or budget > 131072:
            raise ValueError("Signing authority value exceeds its bound")
        if isinstance(item, UUID):
            item = str(item)
        elif isinstance(item, datetime):
            item = item.isoformat()
        elif isinstance(item, Enum):
            item = item.value
        if item is None or type(item) is bool:
            return item
        if type(item) is int and -(2**63) <= item < 2**63:
            return item
        if type(item) is str and len(item) <= 8192:
            try:
                budget += len(item.encode("utf-8"))
            except UnicodeError:
                raise ValueError("Signing authority value is invalid") from None
            if budget <= 131072:
                return item
        elif type(item) is list:
            return [normal(child, depth + 1) for child in item]
        elif type(item) is dict:
            result: dict[str, SigningJSON] = {}
            for name, child in item.items():
                if type(name) is not str or len(name) > 128:
                    raise ValueError("Signing authority field is invalid")
                name = cast(str, normal(name, depth + 1))
                result[name] = normal(child, depth + 1)
            return result
        raise ValueError("Signing authority value is invalid")

    normalized = normal(value)
    encoded = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    if len(encoded) > 131072:
        raise ValueError("Signing authority value exceeds its bound")
    prefix = b"FreeSDN/agent-signing-authority/v1/" + domain.encode("ascii") + b"\x00"
    return hmac.new(key, prefix + encoded, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SigningCommand:
    """Exact operator intent; the coordinator must still resolve trusted DB state.

    Identifiers do not establish that an installation or operation exists. Fresh
    initialization, trusted legacy adoption and same-key recovery remain distinct.
    No raw private key, filesystem path, password or MFA code belongs in this value.
    """

    action: str
    operation_id: UUID
    installation_id: UUID
    identity_epoch: int
    expected_public_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.action) is not str or self.action not in {
            "initialize",
            "adopt",
            "resume",
            "cancel",
            "recover",
            "inspect",
        }:
            raise ValueError("Signing action is unsupported")
        if type(self.operation_id) is not UUID or type(self.installation_id) is not UUID:
            raise ValueError("Signing operation identity is invalid")
        if type(self.identity_epoch) is not int or not 1 <= self.identity_epoch < 2**63:
            raise ValueError("Signing identity epoch is invalid")
        if self.action == "inspect" and (
            self.operation_id.int != 0
            or self.installation_id.int != 0
            or self.identity_epoch != 1
            or self.expected_public_sha256 is not None
        ):
            raise ValueError("Signing inspection uses the fixed read-only resource identity")
        fingerprint = self.expected_public_sha256
        if fingerprint is not None and (
            type(fingerprint) is not str
            or len(fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint)
        ):
            raise ValueError("Expected signing fingerprint is invalid")
        if self.action == "initialize" and fingerprint is not None:
            raise ValueError("Initialization cannot adopt an existing fingerprint")
        if self.action in {"adopt", "recover"} and fingerprint is None:
            raise ValueError("Signing adoption and recovery require a trusted expected fingerprint")

    def commitment(self, *, key: bytes) -> str:
        return signing_commitment(
            {
                "action": self.action,
                "operation_id": self.operation_id,
                "installation_id": self.installation_id,
                "identity_epoch": self.identity_epoch,
                "expected_public_sha256": self.expected_public_sha256,
            },
            key=key,
            domain="command",
        )
