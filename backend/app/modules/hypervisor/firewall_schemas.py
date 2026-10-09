# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Strict, scope-bound firewall intents. Unrepresented options are never reset."""

from __future__ import annotations

from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.schemas.gateway_vpn import ProviderTaskResponse


class FirewallTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["cluster", "node", "guest"]
    node: str | None = Field(None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
    vm_type: Literal["qemu", "lxc"] | None = None
    vmid: int | None = Field(None, strict=True, ge=100, le=999999999)

    @model_validator(mode="after")
    def scoped(self) -> Self:
        if (self.scope != "cluster") != (self.node is not None):
            raise ValueError("Node must match firewall scope")
        if self.scope == "guest":
            if self.vmid is None or self.vm_type is None:
                raise ValueError("Guest identity required")
        elif self.vmid is not None or self.vm_type is not None:
            raise ValueError("Guest identity only applies to guest scope")
        return self


class FirewallRuleSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
    type: Literal["in", "out", "group"] = "in"
    enable: StrictBool = False
    source: str | None = Field(None, max_length=512)
    dest: str | None = Field(None, max_length=512)
    sport: str | None = Field(None, max_length=256)
    dport: str | None = Field(None, max_length=256)
    proto: str | None = Field(None, max_length=32)
    macro: str | None = Field(None, max_length=128)
    iface: str | None = Field(None, max_length=32)
    log: (
        Literal["nolog", "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        | None
    ) = None
    comment: str | None = Field(None, max_length=512)

    @field_validator("*", mode="before")
    @classmethod
    def no_control_chars(cls, value: Any) -> Any:
        if isinstance(value, str) and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not allowed")
        return value

    @model_validator(mode="after")
    def action_matches_type(self) -> Self:
        if self.type != "group" and self.action not in ("ACCEPT", "DROP", "REJECT"):
            raise ValueError("Invalid firewall action")
        if self.type == "group" and any(
            getattr(self, k) for k in ("source", "dest", "sport", "dport", "proto", "macro")
        ):
            raise ValueError("Security-group references cannot include match fields")
        return self


class FirewallOptionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enable: StrictBool | None = None
    policy_in: Literal["ACCEPT", "DROP", "REJECT"] | None = None
    policy_out: Literal["ACCEPT", "DROP", "REJECT"] | None = None
    dhcp: StrictBool | None = None
    ipfilter: StrictBool | None = None
    macfilter: StrictBool | None = None
    ndp: StrictBool | None = None
    radv: StrictBool | None = None


class FirewallReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: FirewallTarget
    action: Literal["create", "update", "delete", "move", "options"]
    pos: int | None = Field(None, strict=True, ge=0, le=9999)
    moveto: int | None = Field(None, strict=True, ge=0, le=9999)
    rule: FirewallRuleSettings | None = None
    options: FirewallOptionSettings | None = None

    @model_validator(mode="after")
    def contract(self) -> Self:
        if (self.action in ("update", "delete", "move")) != (self.pos is not None):
            raise ValueError("Rule position must match action")
        if (self.action == "move") != (self.moveto is not None):
            raise ValueError("Destination position must match action")
        if (self.action in ("create", "update")) != (self.rule is not None):
            raise ValueError("Rule settings must match action")
        if (self.action == "options") != (self.options is not None):
            raise ValueError("Options must match action")
        if self.options is not None:
            values = self.options.model_dump(exclude_none=True)
            allowed = {"enable"}
            if self.target.scope != "node":
                allowed |= {"policy_in", "policy_out"}
            if self.target.scope == "guest":
                allowed |= {"dhcp", "ipfilter", "macfilter", "ndp", "radv"}
            if not values or set(values) - allowed:
                raise ValueError("Unsupported or empty firewall options for scope")
        return self


class FirewallOperationRequest(FirewallReviewRequest):
    request_id: UUID
    expected_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    force: StrictBool = False
    confirmed: StrictBool = False
    recovery_confirmed: StrictBool = False


class FirewallReviewResponse(BaseModel):
    expected_digest: str
    target: FirewallTarget
    action: str
    before: dict[str, Any]
    desired: dict[str, Any]
    warnings: list[str]


class FirewallOperationResponse(BaseModel):
    request_id: UUID
    change_id: UUID
    status: str
    provider_task: ProviderTaskResponse | None = None
    message: str
