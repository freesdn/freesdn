"""Private final export proof boundary, not public routes or archive execution.

Only internal factor receipts issue proofs. Default PostgreSQL claims remain
independent of caller transactions. An admitted claim is owned through physical
session cleanup; elapsed-time refusal never cancels cleanup into a detached task.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, field
from typing import Any, cast

import anyio
from fastapi import HTTPException

from app.core.backup_artifacts import recorded_identity
from app.core.backup_downloads import DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.core.token_blacklist import claim_token_jti
from app.core.vault_export_authorization import (
    VerifiedExportAuthorization,
    create_fresh_export_proof,
    verify_fresh_export_proof,
)
from app.core.vault_export_proof import InvalidVaultProof
from app.services.vault_export_authority import FreshLocalFactor, VaultExportAuthority
from app.services.vault_export_operation_state import (
    ExportIntent,
    ResolvedExportOperation,
    resolve_current_operation,
)

_REDEMPTION_WORK = anyio.CapacityLimiter(2)
_CLAIM_ACCEPTANCE_SECONDS = 5.0


def _refuse(status: int = 401) -> HTTPException:
    return HTTPException(status, "Fresh vault export authorization ended; confirm again")


def _signing_key(authority: VaultExportAuthority) -> bytes:
    return hmac.digest(authority.secret_key, b"FreeSDN/vault-export/final-signature/v2", "sha256")


def _verify(token: str, state: ResolvedExportOperation) -> VerifiedExportAuthorization:
    try:
        verified = verify_fresh_export_proof(
            token,
            state.authority.context,
            binding=state.binding,
            operation=state.intent.operation,
            verification_key=_signing_key(state.authority),
            algorithm="HS256",
        )
        _fresh(verified, state)
        return verified
    except InvalidVaultProof:
        raise _refuse() from None


def _fresh(verified: VerifiedExportAuthorization, state: ResolvedExportOperation) -> None:
    now = time.time()
    expiry = min(verified.expires_at, verified.authentication_expires_at)
    if state.credential_expires_at is not None:
        expiry = min(expiry, state.credential_expires_at)
    if now >= expiry:
        raise _refuse()


async def issue_after_factors(
    factor: FreshLocalFactor, intent: ExportIntent, *, initiating_binding: str
) -> str:
    """Never accept factor timestamps or a legacy observation from HTTP input.

    The initiating binding was resolved before starting the factor flow. Local
    MFA may legitimately update the authority receipt, but not the operation.
    Legacy downloads can be issued only through an actual sealed observation.
    """
    if (
        type(factor) is not FreshLocalFactor
        or type(intent) is not ExportIntent
        or intent.operation == "download_legacy"
    ):
        raise _refuse()
    if time.time() >= factor.expires_at:
        raise _refuse()
    current = await resolve_current_operation(
        factor.authority, intent, expected_binding=initiating_binding
    )
    try:
        token = create_fresh_export_proof(
            current.authority.context,
            binding=current.binding,
            operation=intent.operation,
            authenticated_at=factor.authenticated_at,
            authentication_expires_at=factor.expires_at,
            credential_expires_at=current.credential_expires_at,
            signing_key=_signing_key(current.authority),
            algorithm="HS256",
        )
    except InvalidVaultProof:
        raise _refuse() from None
    await anyio.lowlevel.checkpoint()
    _verify(token, current)
    return token


@complete_before_cancellation
async def _claim_owned(verified: VerifiedExportAuthorization) -> None:
    """Keep default claim completion/close owned, then refuse any late grant.

    The configured security driver bounds connect/commands to three seconds.
    Five seconds is the admission acceptance bound, not permission to detach a
    session close. Stuck-driver/process-loss recovery remains separate work.
    """
    start = anyio.current_time()
    if time.time() >= verified.expires_at:
        raise _refuse()
    won = await claim_token_jti(verified.jti, verified.expires_at)
    if (
        won is not True
        or anyio.current_time() - start >= _CLAIM_ACCEPTANCE_SECONDS
        or time.time() >= verified.expires_at
    ):
        raise _refuse()


@dataclass(repr=False)
class _LegacyExchange:
    used: bool = False


@dataclass(frozen=True, repr=False)
class ConsumedExportPermission:
    """Server-only one-request receipt; do not expose/serialize it as a bearer."""

    state: ResolvedExportOperation
    verified: VerifiedExportAuthorization
    _marker: object = field(repr=False)
    _legacy_exchange: _LegacyExchange = field(default_factory=_LegacyExchange, repr=False)

    async def check(self) -> ResolvedExportOperation:
        if self._marker is not _CONSUMED_MARKER:
            raise _refuse()
        _fresh(self.verified, self.state)
        current = await resolve_current_operation(
            self.state.authority, self.state.intent, expected_binding=self.state.binding
        )
        _fresh(self.verified, current)
        return current


_CONSUMED_MARKER = object()


async def consume_export_permission(
    authority: VaultExportAuthority, intent: ExportIntent, token: str
) -> ConsumedExportPermission:
    """No archive access occurs before current verification and durable claim."""
    if type(token) is not str or not 1 <= len(token) <= 8192:
        raise _refuse()
    await anyio.lowlevel.checkpoint()
    try:
        _REDEMPTION_WORK.acquire_nowait()
    except anyio.WouldBlock:
        raise _refuse(503) from None
    try:
        current = await resolve_current_operation(authority, intent)
        verified = _verify(token, current)
        await _claim_owned(verified)
        # A cancelled owner never receives a reusable permission, even if its
        # default durable claim committed while cancellation was being drained.
        await anyio.lowlevel.checkpoint()
        newer = await resolve_current_operation(authority, intent, expected_binding=current.binding)
        _fresh(verified, newer)
        return ConsumedExportPermission(newer, verified, _CONSUMED_MARKER)
    finally:
        _REDEMPTION_WORK.release()


def _observed(snapshot: DownloadSnapshot) -> dict[str, Any]:
    try:
        if (
            type(snapshot) is not DownloadSnapshot
            or snapshot._fd < 0
            or snapshot.integrity != "legacy_unverified"
        ):
            raise _refuse()
        return cast(
            dict[str, Any],
            recorded_identity(
                {
                    "artifact_identity": {
                        "version": 1,
                        "sha256": snapshot._digest.hexdigest(),
                        "bytes": snapshot.size,
                    }
                }
            ),
        )
    except Exception:
        raise _refuse() from None


async def issue_after_legacy_observation(
    permission: ConsumedExportPermission, snapshot: DownloadSnapshot
) -> str:
    """A sealed owned snapshot supplies bytes, never a caller-provided digest.

    Caller must have created this snapshot from the permission's checked source
    after consumption, retain it through this call, and close it on every path.
    The signed digest describes this observation, not historical authenticity.
    A cancelled/failed exchange cannot be retried with this consumed receipt.
    """
    if (
        type(permission) is not ConsumedExportPermission
        or permission._marker is not _CONSUMED_MARKER
        or permission.state.intent.operation != "observe_legacy"
        or permission._legacy_exchange.used
    ):
        raise _refuse()
    observed = _observed(snapshot)
    # This state transition has no await. Two tasks sharing the same internal
    # receipt cannot each mint a new download proof from one observation.
    permission._legacy_exchange.used = True
    current = await permission.check()
    if _observed(snapshot) != observed:
        raise _refuse()
    intent = ExportIntent.download(
        current.intent.backup_id,
        operation="download_legacy",
        legacy_acknowledged=True,
        observed_identity=observed,
    )
    download = await resolve_current_operation(current.authority, intent)
    # Both bindings derive from the SAME second SQL snapshot. A third read of
    # the old observation alone would not prove the new target was unchanged.
    if download.legacy_observation_binding is None or not hmac.compare_digest(
        download.legacy_observation_binding, permission.state.binding
    ):
        raise _refuse()
    _fresh(permission.verified, download)
    if _observed(snapshot) != observed:
        raise _refuse()
    try:
        token = create_fresh_export_proof(
            download.authority.context,
            binding=download.binding,
            operation="download_legacy",
            authenticated_at=permission.verified.authenticated_at,
            authentication_expires_at=min(
                permission.verified.authentication_expires_at, permission.verified.expires_at
            ),
            credential_expires_at=download.credential_expires_at,
            signing_key=_signing_key(download.authority),
            algorithm="HS256",
        )
    except InvalidVaultProof:
        raise _refuse() from None
    await anyio.lowlevel.checkpoint()
    _verify(token, download)
    if _observed(snapshot) != observed:
        raise _refuse()
    return token
