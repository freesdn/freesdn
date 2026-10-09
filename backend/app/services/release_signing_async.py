# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bound and own signing workers and admitted administrative HTTP operations.

Normal cancellation drains admitted work before its request/session can close.
An admitted publication may therefore complete after its client disconnects.
This is not a durable job queue, whole-operation deadline, idempotency contract,
process-loss recovery, or a substitute for current authorization at commit.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Coroutine
from functools import partial, wraps
from typing import Any

import anyio
from fastapi import HTTPException

from app.core.owned_async import complete_before_cancellation
from app.services import release_signing
from app.services.agent_signing_identity import (
    TrustedSigningIdentity,
    read_trusted_signing_identity,
)

# These gates have no wait queue and span event loops within this worker process.
# Public reads cannot consume the administrative pool. The shipped Gunicorn
# entrypoint loads the application in each worker without --preload; arbitrary
# fork during an admitted operation remains outside this component's contract.
_ADMIN_OPERATIONS = threading.BoundedSemaphore(2)
_ADMIN_WORKERS = threading.BoundedSemaphore(2)
_PUBLIC_WORKERS = threading.BoundedSemaphore(2)
_PUBLIC_IDENTITY_READS = threading.BoundedSemaphore(4)
_ADMIN_IDENTITY_READS = threading.BoundedSemaphore(2)
_MANIFEST_FIELDS = ("agent_type", "channel", "digest", "platform", "v", "version")


class SigningBusyError(RuntimeError):
    """No worker was started; the caller may retry without changing key material."""


def _freeze_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Copy only bounded scalar values before any scheduling or worker wait."""
    if not isinstance(manifest, dict):
        raise ValueError("Signing manifest must be a dictionary")
    try:
        result = {key: manifest[key] for key in _MANIFEST_FIELDS}
    except KeyError:
        raise ValueError("Signing manifest is incomplete") from None
    if type(result["v"]) is not int or result["v"] != release_signing.RELEASE_MANIFEST_VERSION:
        raise ValueError("Signing manifest version is unsupported")
    for field in _MANIFEST_FIELDS:
        if field != "v" and (type(result[field]) is not str or not 1 <= len(result[field]) <= 1024):
            raise ValueError("Signing manifest fields must be bounded strings")
    # API schemas already cap these fields more tightly. This component bound
    # also prevents a private caller from handing a large object to the worker.
    if len(release_signing.canonical_manifest_bytes(result)) > 4096:
        raise ValueError("Signing manifest exceeds its byte limit")
    return result


@complete_before_cancellation
async def _offload[R](function: Callable[[], R]) -> R:
    # A per-call limiter avoids the unrelated default AnyIO pool's admission
    # queue. Process-wide gates below still bound total admitted work to four.
    return await anyio.to_thread.run_sync(
        function,
        abandon_on_cancel=False,
        limiter=anyio.CapacityLimiter(1),
    )


async def _worker[R](gate: threading.BoundedSemaphore, function: Callable[[], R]) -> R:
    await anyio.lowlevel.checkpoint()
    if not gate.acquire(blocking=False):
        raise SigningBusyError("Signing capacity is busy; retry later")
    try:
        try:
            result = await _offload(function)
        except Exception:
            # Mandatory drain is complete. Pending AnyIO cancellation takes
            # precedence over an ordinary worker failure before caller fallback.
            await anyio.lowlevel.checkpoint()
            raise
        await anyio.lowlevel.checkpoint()
        return result
    finally:
        gate.release()


@complete_before_cancellation
async def sign_manifest_async(manifest: dict[str, Any]) -> str:
    frozen = _freeze_manifest(manifest)
    if not _ADMIN_IDENTITY_READS.acquire(blocking=False):
        raise SigningBusyError("Signing identity capacity is busy")
    try:
        identity = await read_trusted_signing_identity()
        signature = await _worker(
            _ADMIN_WORKERS,
            partial(
                release_signing.sign_manifest_for_anchor,
                frozen,
                anchor_public_pem=identity.public_key_pem,
                anchor_sha256=identity.public_key_sha256,
            ),
        )
        # Immutable normal state can nevertheless change through restore or an
        # unsupported writer. Do not release a result bound to an old identity.
        if await read_trusted_signing_identity() != identity:
            raise release_signing.SigningKeyError("Trusted signing identity changed during signing")
        return signature
    finally:
        _ADMIN_IDENTITY_READS.release()


@complete_before_cancellation
async def public_key_pem_async(*, public_request: bool = False) -> bytes:
    admission = _PUBLIC_IDENTITY_READS if public_request else _ADMIN_IDENTITY_READS
    if not admission.acquire(blocking=False):
        raise SigningBusyError("Signing identity capacity is busy")
    gate = _PUBLIC_WORKERS if public_request else _ADMIN_WORKERS
    try:
        identity = await read_trusted_signing_identity()
        # Public distribution does no private-key I/O and remains available
        # during private-key loss. It never creates or repairs local key files.
        return await _worker(
            gate,
            partial(
                release_signing.public_key_for_anchor,
                anchor_public_pem=identity.public_key_pem,
                anchor_sha256=identity.public_key_sha256,
            ),
        )
    finally:
        admission.release()


def agent_release_operation[**P, R](
    function: Callable[P, Coroutine[Any, Any, R]],
) -> Callable[P, Coroutine[Any, Any, R]]:
    """Own an admitted endpoint through its original commit/cleanup path.

    FastAPI still resolves the original signature's authentication/permission and
    session dependencies before invocation. Every decorator use must be inside the
    router decorator; wraps retains that callable signature and annotations.
    """
    complete = complete_before_cancellation(function)

    @wraps(function)
    async def admitted(*args: P.args, **kwargs: P.kwargs) -> R:
        await anyio.lowlevel.checkpoint()
        if not _ADMIN_OPERATIONS.acquire(blocking=False):
            raise HTTPException(
                503, "Release operation capacity is busy", headers={"Retry-After": "1"}
            )
        try:
            try:
                result = await complete(*args, **kwargs)
            except Exception:
                await anyio.lowlevel.checkpoint()
                raise
            await anyio.lowlevel.checkpoint()
            return result
        finally:
            _ADMIN_OPERATIONS.release()

    return admitted


class InvalidReleaseSignature(ValueError):
    """The existing artifact cannot be promoted under the installation identity."""


@complete_before_cancellation
async def verify_manifest_async(
    manifest: dict[str, Any], signature: str | None
) -> TrustedSigningIdentity:
    """Verify existing bytes without private-key access; return the checked anchor."""
    frozen = _freeze_manifest(manifest)
    if type(signature) is not str or not 8 <= len(signature) <= 128:
        raise InvalidReleaseSignature("Release has no bounded manifest signature")
    if not _ADMIN_IDENTITY_READS.acquire(blocking=False):
        raise SigningBusyError("Signing identity capacity is busy")
    try:
        identity = await read_trusted_signing_identity()
        valid = await _worker(
            _ADMIN_WORKERS,
            partial(
                release_signing.verify_manifest_for_anchor,
                frozen,
                signature,
                anchor_public_pem=identity.public_key_pem,
                anchor_sha256=identity.public_key_sha256,
            ),
        )
        if not valid:
            raise InvalidReleaseSignature("Stored release signature does not verify")
        if await read_trusted_signing_identity() != identity:
            raise release_signing.SigningKeyError("Trusted identity changed during verification")
        return identity
    finally:
        _ADMIN_IDENTITY_READS.release()
