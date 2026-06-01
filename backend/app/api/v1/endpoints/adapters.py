# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Adapter catalog API
=============================

Exposes the project's honest adapter **maturity** record so the UI vendor
pickers (controllers / cameras / PBX) can badge each option Verified vs
Experimental instead of presenting everything as equally supported.

The single source of truth is ``app.adapters.maturity`` — VERIFIED is granted
only there (never self-claimed by an adapter), and anything absent is
EXPERIMENTAL. See that module + the feature-readiness rubric.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.adapters.maturity import ADAPTER_MATURITY
from app.core.dependencies import CurrentUser, get_current_active_user

router = APIRouter()


class AdapterMaturitySchema(BaseModel):
    """Honest live-validation status for one adapter.

    ``maturity`` grades the READ surface; ``write_maturity`` grades WRITES
    SEPARATELY (most adapters' writes are gated + mock-tested but not yet proven
    on real hardware) so the UI can badge "Reads: Verified · Writes: …" instead
    of a single label that oversells the writes.
    """

    maturity: str  # "verified" | "experimental" | "planned"
    notes: str = ""
    write_maturity: str = (
        "mock_tested"  # live_validated|partial|mock_tested|disabled|not_implemented|experimental
    )
    write_note: str = ""


@router.get("/maturity", response_model=dict[str, AdapterMaturitySchema])
async def get_adapter_maturity(
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, AdapterMaturitySchema]:
    """Honest maturity per adapter id — drives the UI maturity badges.

    Keys are adapter ids (e.g. ``omada``, ``opnsense``, ``onvif``). The project
    validation record is authoritative; ids not present are EXPERIMENTAL. Reads
    and writes are graded separately — see ``write_maturity``.
    """
    return {
        adapter_id: AdapterMaturitySchema(
            maturity=info.maturity.value,
            notes=info.notes,
            write_maturity=info.write_maturity.value,
            write_note=info.write_note,
        )
        for adapter_id, info in ADAPTER_MATURITY.items()
    }
