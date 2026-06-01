# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Capability maturity API
=================================

Exposes the project's honest capability **maturity** record so the UI can badge
each feature STABLE / BETA / EXPERIMENTAL instead of presenting everything as
equally production-ready. The single source of truth is
``app.core.capability_maturity`` — STABLE/BETA are never assumed, and anything
absent is EXPERIMENTAL. See that module + the FEATURE-READINESS rubric.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.capability_maturity import CAPABILITY_MATURITY, get_capability_maturity
from app.core.dependencies import CurrentUser, get_current_active_user

router = APIRouter()


class CapabilityMaturitySchema(BaseModel):
    """Honest readiness status for one capability."""

    maturity: str  # "stable" | "beta" | "experimental"
    title: str
    notes: str = ""


@router.get("/maturity", response_model=dict[str, CapabilityMaturitySchema])
async def get_capabilities_maturity(
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, CapabilityMaturitySchema]:
    """Honest maturity per capability id — drives the UI capability badges.

    Keys are capability ids (e.g. ``sso``, ``automation``, ``collector``). The
    record is authoritative; ids not present are EXPERIMENTAL (never assumed
    production-ready).
    """
    return {
        cap_id: CapabilityMaturitySchema(
            maturity=info.maturity.value, title=info.title, notes=info.notes
        )
        for cap_id, info in CAPABILITY_MATURITY.items()
    }


@router.get("/maturity/{capability_id}", response_model=CapabilityMaturitySchema)
async def get_one_capability_maturity(
    capability_id: str,
    current_user: CurrentUser = Depends(get_current_active_user),
) -> CapabilityMaturitySchema:
    """Honest maturity for a single capability id (absent ⇒ experimental)."""
    info = get_capability_maturity(capability_id)
    return CapabilityMaturitySchema(
        maturity=info.maturity.value, title=info.title, notes=info.notes
    )
