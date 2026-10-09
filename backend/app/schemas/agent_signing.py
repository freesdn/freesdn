# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Strict operator intent; fresh-factor receipts are never deserialized here."""

from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from app.core.agent_signing_binding import SigningCommand


class SigningCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    action: Literal["initialize", "adopt", "resume", "cancel", "recover"]
    operation_id: UUID
    installation_id: UUID
    identity_epoch: int = Field(strict=True, ge=1, lt=2**63)
    expected_public_sha256: str | None = Field(
        default=None, pattern="^[0-9a-f]{64}$", max_length=64
    )

    def command(self) -> SigningCommand:
        return SigningCommand(
            self.action,
            self.operation_id,
            self.installation_id,
            self.identity_epoch,
            self.expected_public_sha256,
        )

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        self.command()
        return self


class LocalSigningExecutionRequest(SigningCommandRequest):
    password: SecretStr = Field(min_length=1, max_length=1024)
    code: SecretStr | None = Field(default=None, min_length=1, max_length=10)
    acknowledge_identity_risk: bool = Field(strict=True)
    acknowledge_no_prior_identity: bool = Field(default=False, strict=True)
    acknowledge_independent_fingerprint: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def validate_acknowledgments(self) -> Self:
        if not self.acknowledge_identity_risk:
            raise ValueError("Explicit signing identity acknowledgment is required")
        if self.action == "initialize" and not self.acknowledge_no_prior_identity:
            raise ValueError("Explicit new-installation acknowledgment is required")
        if self.action in ("adopt", "recover") and not self.acknowledge_independent_fingerprint:
            raise ValueError("Independently trusted fingerprint acknowledgment is required")
        return self
