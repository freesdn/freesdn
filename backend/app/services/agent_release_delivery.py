# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private managed binary response; public/legacy routes are not enabled here.

Authority and release observations use short owned SQL transactions. No SQL lock
spans hash, file read or network send. A shared file lifetime spans the actual
ASGI response, including range/error/disconnect cleanup. No pathname is handed
to the server. Deployment must drain old readers/writers and exclude privileged
DDL/filesystem/database-restore changes before this protocol can be enabled.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Iterator
from contextlib import AsyncExitStack, contextmanager
from dataclasses import dataclass
from email.utils import formatdate
from functools import partial
from secrets import token_hex
from typing import Protocol, cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import case, func, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import (
    FileResponse,
    MalformedRangeHeader,
    PlainTextResponse,
    RangeNotSatisfiable,
)
from starlette.types import Message, Receive, Scope, Send

from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.services.agent_release_artifact_store import (
    ArtifactIntent,
    ArtifactLease,
    ArtifactUnavailable,
    PreparedArtifact,
)
from app.services.agent_release_cleanup import _record
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_legacy_storage import (
    LegacyReleaseFile,
    LegacyReleaseLease,
    VerifiedLegacyFile,
)
from app.services.agent_release_promotion import lock_verified_identity
from app.services.agent_release_read_authority import (
    ReleaseAgentReadAuthority,
    ReleaseOperatorReadAuthority,
)
from app.services.agent_release_reference_validation import validate_release_reference_installation
from app.services.agent_release_request import ReleaseMetadata, ReleasePublicationRequest, _encode
from app.services.agent_signing_identity import TrustedSigningIdentity
from app.services.release_signing import SigningKeyError, build_release_manifest
from app.services.release_signing_async import (
    InvalidReleaseSignature,
    SigningBusyError,
    verify_manifest_async,
)

logger = logging.getLogger(__name__)
_READERS = threading.BoundedSemaphore(8)
_AUTHORITY_TYPES = (ReleaseAgentReadAuthority, ReleaseOperatorReadAuthority)
_CHUNK = 65536

type ReadAuthority = ReleaseAgentReadAuthority | ReleaseOperatorReadAuthority
type ReadIntent = ArtifactIntent | LegacyReleaseFile
type ReadReceipt = PreparedArtifact | VerifiedLegacyFile
type ReadLease = ArtifactLease | LegacyReleaseLease


class ReleaseSnapshot(Protocol):
    """Common retained metadata contract for managed and legacy responses."""

    def metadata(self) -> ReleaseMetadata: ...


@dataclass(frozen=True)
class ManagedReleaseSnapshot:
    intent: ArtifactIntent
    organization_id: UUID | None
    metadata_bytes: bytes
    target_bytes: bytes
    signature: str | None
    unsigned_publication_opt_in: bool

    def metadata(self) -> ReleaseMetadata:
        # Only internal bounded, validated bytes are retained. A snapshot is not
        # authority or a public cleanup/retry capability.
        import json

        # _observe constructed these bytes through ReleasePublicationRequest's
        # complete metadata validator before creating this internal snapshot.
        return cast(ReleaseMetadata, json.loads(self.metadata_bytes))


async def _current(authority: ReadAuthority) -> None:
    authority.validate(await authority._read())


@complete_before_cancellation
async def _observe(
    authority: ReadAuthority,
    release_id: UUID,
    *,
    expected: ReleaseSnapshot | None = None,
    identity: TrustedSigningIdentity | None = None,
    attest: bool = False,
    count: bool = False,
) -> ManagedReleaseSnapshot:
    deadline = anyio.current_time() + 5
    try:
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                connection = await cleanup.enter_async_context(sessions.security_engine.connect())
                db = await cleanup.enter_async_context(
                    AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
                )
                async with db.begin():
                    await db.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                    await db.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                    await db.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    await db.execute(
                        text(
                            "LOCK TABLE agents.agent_release_operations, agents.agent_releases "
                            + (
                                "IN SHARE ROW EXCLUSIVE MODE NOWAIT"
                                if count
                                else "IN SHARE MODE NOWAIT"
                            )
                        )
                    )
                    fence = await authority.lock(db)
                    if identity is not None:
                        await lock_verified_identity(db, identity)
                    if attest:
                        await connection.run_sync(validate_release_reference_installation)
                    # Limit TEXT before fetching it into Python. Missing or
                    # unrepresentable metadata is not repaired during a download.
                    a = AgentRelease.__table__.c
                    release = (
                        (
                            await db.execute(
                                select(AgentRelease.__table__).where(
                                    a.id == release_id,
                                    func.length(a.release_notes) <= 20000,
                                    (a.signature.is_(None)) | (func.length(a.signature) <= 4096),
                                )
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if release is None:
                        raise HTTPException(404, "Release not found")
                    authority.require_scope(release["organization_id"])
                    c = AgentReleaseOperation.__table__.c
                    birth = (
                        (
                            await db.execute(
                                select(AgentReleaseOperation.__table__).where(
                                    c.release_id == release_id,
                                    c.kind == "publish",
                                )
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if birth is None:
                        raise HTTPException(
                            409, "Release needs explicit legacy verification; no managed fallback"
                        )
                    row = _record(birth)
                    if (
                        row["storage_kind"] != "owned"
                        or row["phase"] != "decided"
                        or row["decision"] != "published"
                    ):
                        raise HTTPException(409, "Release has no current managed publication")
                    await db.execute(
                        text("SELECT agents.assert_release_reference(:id)"), {"id": release_id}
                    )
                    metadata = {
                        name: release[name]
                        for name in (
                            "version",
                            "platform",
                            "agent_type",
                            "download_url",
                            "checksum_sha256",
                            "file_size",
                            "release_notes",
                            "min_backend_version",
                            "is_prerelease",
                            "is_latest",
                            "filename",
                        )
                    }
                    validated = ReleasePublicationRequest(
                        row["operation_id"],
                        release_id,
                        row["organization_id"],
                        "owned",
                        _encode(metadata),
                    )
                    target = ReleaseDeletionRequest.capture(
                        operation_id=row["operation_id"], release=release
                    )
                    result = ManagedReleaseSnapshot(
                        ArtifactIntent(
                            # _record plus the owned-publication check above
                            # require this exact artifact association.
                            cast(UUID, row["artifact_id"]),
                            row["operation_id"],
                            release_id,
                            row["request_sha256"],
                            row["expected_sha256"],
                            row["expected_size"],
                        ),
                        row["organization_id"],
                        validated.metadata_bytes,
                        target.metadata_bytes,
                        release["signature"],
                        metadata["is_latest"] is False
                        and row["request_bytes"] == validated.request_bytes(),
                    )
                    if expected is not None and result != expected:
                        raise HTTPException(409, "Release changed during delivery")
                    if count:
                        # Successful managed GET responses count once, best effort.
                        # Saturation cannot overflow the existing int4 column.
                        await db.execute(
                            update(AgentRelease)
                            .where(a.id == release_id)
                            .values(
                                download_count=case(
                                    (
                                        a.download_count < 2147483647,
                                        func.greatest(a.download_count, 0) + 1,
                                    ),
                                    else_=2147483647,
                                )
                            )
                        )
                    await fence.recheck()
        if anyio.current_time() >= deadline:
            raise TimeoutError("Managed release observation exceeded its bound")
        # Connection/transaction cleanup is also an authority wait boundary.
        await _current(authority)
        return result
    except HTTPException:
        await _current(authority)
        raise
    except (SQLAlchemyError, TimeoutError, RuntimeError, ValueError):
        await _current(authority)
        raise HTTPException(
            503, "Managed release state unavailable; no bytes are authorized"
        ) from None


class _ReadStorage:
    def __init__(self) -> None:
        self.lease: ReadLease | None = None

    def _acquire(self, root: str, intent: ReadIntent) -> ReadReceipt:
        # The managed response supplies ArtifactIntent. The legacy subclass
        # overrides this factory while sharing the same read/close lifetime.
        self.lease = ArtifactLease.acquire(
            root, cast(ArtifactIntent, intent), mode="shared", create=False
        )
        return self.lease.verify_prepared()

    @complete_before_cancellation
    async def acquire(self, root: str, intent: ReadIntent) -> ReadReceipt:
        return await anyio.to_thread.run_sync(
            partial(self._acquire, root, intent), abandon_on_cancel=False
        )

    @complete_before_cancellation
    async def read(self, offset: int, size: int) -> bytes:
        if self.lease is None:
            raise ArtifactUnavailable("Managed file lifetime is unavailable")
        return await anyio.to_thread.run_sync(
            partial(self.lease.read, offset, size), abandon_on_cancel=False
        )

    async def close(self) -> None:
        # Cleanup has no initial cancellable checkpoint before assigning its
        # owned task. Repeated raw Task.cancel cannot abandon descriptor closure.
        if self.lease is None:
            return
        cancelled = None
        with anyio.CancelScope(shield=True):

            async def close_worker() -> Exception | None:
                try:
                    await anyio.to_thread.run_sync(
                        cast(ReadLease, self.lease).close, abandon_on_cancel=False
                    )
                    return None
                except Exception as error:
                    return error

            task = asyncio.create_task(close_worker())
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError as cancellation:
                    if task.cancelled():
                        raise
                    cancelled = cancellation
            error = task.result()
            if cancelled is not None:
                if error is not None:
                    logger.warning(
                        "Cancelled release reader closure failed: %s", type(error).__name__
                    )
                raise cancelled
            if error is not None:
                raise error


@contextmanager
def _collapse_delivery_errors() -> Iterator[None]:
    """Unwrap a sole task-group error without relying on Starlette internals.

    Multiple independent failures remain grouped. BaseException subclasses,
    including cancellation, are propagated rather than converted to success.
    """
    try:
        yield
    except BaseExceptionGroup as grouped:
        error: BaseException = grouped
        while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
            error = error.exceptions[0]
        raise error


class ManagedReleaseResponse(FileResponse):
    """Single-use owned response; construction allocates no SQL/file resources.

    The pinned FileResponse range parser/header helpers are reused. Its path-opening
    and pathsend handlers are never invoked. This component does not register GET or
    HEAD routes, adopt legacy files, or relax the store's120second lease bound.
    """

    _storage_errors: tuple[type[Exception], ...] = (
        ArtifactUnavailable,
        OSError,
        TimeoutError,
        SigningKeyError,
        SigningBusyError,
        InvalidReleaseSignature,
    )

    def __init__(self, *, authority: ReadAuthority, release_id: UUID, root: str) -> None:
        if (
            type(authority) not in _AUTHORITY_TYPES
            or type(release_id) is not UUID
            or not release_id.int
        ):
            raise HTTPException(422, "Current managed read authority and release identity required")
        if type(root) is not str:
            raise HTTPException(422, "Configured managed artifact root required")
        # Placeholder is never opened or sent; no caller-supplied pathname exists.
        super().__init__(path="", media_type="application/octet-stream")
        self.authority, self.release_id, self.root = authority, release_id, root
        self._used = self._started = self._completed = False
        self._storage = _ReadStorage()
        self._snapshot: ReleaseSnapshot | None = None
        self._identity: TrustedSigningIdentity | None = None

    async def _check(self, *, attest: bool = False) -> ReleaseSnapshot:
        return await _observe(
            self.authority,
            self.release_id,
            expected=self._snapshot,
            identity=self._identity,
            attest=attest,
        )

    async def _send(self, send: Send, message: Message) -> None:
        # Recheck after every file read and preceding send wait. This does not
        # retract a chunk already handed to the network before a later revocation.
        await self._check()
        with anyio.fail_after(10):
            if message["type"] == "http.response.start":
                self._started = True
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                self._completed = True

    async def _body(self, send: Send, start: int, end: int) -> None:
        while start < end:
            data = await self._storage.read(start, min(_CHUNK, end - start))
            if not data:
                raise ArtifactUnavailable("Managed binary ended before its verified size")
            start += len(data)
            await self._send(send, {"type": "http.response.body", "body": data, "more_body": True})

    async def _prepare(self) -> tuple[str | None, int, str, int]:
        """Verify managed history, retained bytes and original signing policy."""
        self._snapshot = await _observe(self.authority, self.release_id, attest=True)
        # This response's constructor selects the managed lease factory.
        prepared = cast(
            PreparedArtifact, await self._storage.acquire(self.root, self._snapshot.intent)
        )
        metadata = self._snapshot.metadata()
        if self._snapshot.signature is not None:
            manifest = build_release_manifest(
                digest_hex=metadata["checksum_sha256"],
                version=metadata["version"],
                platform=metadata["platform"],
                agent_type=metadata["agent_type"],
                channel="prerelease" if metadata["is_prerelease"] else "stable",
            )
            self._identity = await verify_manifest_async(manifest, self._snapshot.signature)
        elif not self._snapshot.unsigned_publication_opt_in:
            # Current non-latest state is insufficient: a previously latest
            # signed release may have been demoted. Require the original exact
            # publication commitment to opt into non-latest behavior as well.
            raise HTTPException(409, "Release lacks a signature or original non-latest opt-in")
        await self._check(attest=True)
        # Recheck the retained descriptor/path state after signature/SQL waits,
        # including an empty artifact, before constructing response headers.
        await self._storage.read(0, 1)
        return (
            metadata["filename"],
            prepared.intent.size,
            prepared.intent.payload_sha256,
            prepared.file_state[7],
        )

    async def _record_download(self) -> None:
        await _observe(
            self.authority,
            self.release_id,
            expected=self._snapshot,
            identity=self._identity,
            count=True,
        )

    async def _run(self, scope: Scope, receive: Receive, send: Send) -> None:
        filename, size, digest, modified_ns = await self._prepare()
        headers = FileResponse(
            path="", media_type="application/octet-stream", filename=filename
        ).headers
        headers["content-length"] = str(size)
        headers["last-modified"] = formatdate(modified_ns / 1_000_000_000, usegmt=True)
        headers["etag"] = '"' + digest + '"'
        headers["cache-control"] = "private, no-store"
        self.raw_headers = list(headers.raw)
        self._headers = MutableHeaders(raw=self.raw_headers)
        request_headers = Headers(scope=scope)
        requested = request_headers.get("range")
        if_range = request_headers.get("if-range")
        ranges = []
        if requested is not None and (if_range is None or self._should_use_range(if_range)):
            try:
                ranges = self._parse_range_header(requested, size)
            except MalformedRangeHeader as error:
                return await PlainTextResponse(error.content, status_code=400)(
                    scope, receive, partial(self._send, send)
                )
            except RangeNotSatisfiable:
                return await PlainTextResponse(
                    status_code=416, headers={"Content-Range": f"bytes */{size}"}
                )(scope, receive, partial(self._send, send))
        head = scope["method"].upper() == "HEAD"
        response_headers = MutableHeaders(raw=list(self.raw_headers))
        status = 200 if not ranges else 206
        multipart = None
        if len(ranges) == 1:
            start, end = ranges[0]
            response_headers["content-range"] = f"bytes {start}-{end - 1}/{size}"
            response_headers["content-length"] = str(end - start)
        elif len(ranges) > 1:
            boundary = token_hex(13)
            length, header = self.generate_multipart(
                ranges, boundary, size, self.headers["content-type"]
            )
            response_headers["content-type"] = f"multipart/byteranges; boundary={boundary}"
            response_headers["content-length"] = str(length)
            multipart = boundary, header
        await self._send(
            send, {"type": "http.response.start", "status": status, "headers": response_headers.raw}
        )
        if not head:
            if multipart:
                boundary, header = multipart
                for start, end in ranges:
                    await self._send(
                        send,
                        {
                            "type": "http.response.body",
                            "body": header(start, end),
                            "more_body": True,
                        },
                    )
                    await self._body(send, start, end)
                    await self._send(
                        send, {"type": "http.response.body", "body": b"\r\n", "more_body": True}
                    )
                await self._send(
                    send,
                    {
                        "type": "http.response.body",
                        "body": f"--{boundary}--".encode(),
                        "more_body": True,
                    },
                )
            else:
                await self._body(send, *(ranges[0] if ranges else (0, size)))
        await self._check(attest=True)
        await self._storage.read(0, 1)
        await self._send(send, {"type": "http.response.body", "body": b"", "more_body": False})
        if not head:
            try:
                await self._record_download()
            except HTTPException as error:
                # Already completed bytes cannot be recalled by a counter error.
                # Do not start another response or emit credential/storage data.
                logger.warning(
                    "Managed release download counter was not recorded: HTTP %s", error.status_code
                )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._used or scope["type"] != "http" or scope["method"].upper() not in ("GET", "HEAD"):
            raise HTTPException(409, "Managed binary response cannot be reused")
        self._used = True
        if not _READERS.acquire(blocking=False):
            raise HTTPException(
                503, "Managed binary delivery capacity is busy", headers={"Retry-After": "1"}
            )
        try:
            with anyio.fail_after(120), _collapse_delivery_errors():
                async with anyio.create_task_group() as group:

                    async def disconnected() -> None:
                        while True:
                            message = await receive()
                            if message["type"] == "http.disconnect":
                                if not self._completed:
                                    group.cancel_scope.cancel()
                                return

                    group.start_soon(disconnected)
                    try:
                        await self._run(scope, receive, send)
                    finally:
                        group.cancel_scope.cancel()
        except HTTPException:
            if self._started:
                raise RuntimeError(
                    "Managed binary authority or release changed after response start"
                ) from None
            raise
        except self._storage_errors:
            if self._started:
                raise RuntimeError(
                    "Managed binary delivery ended before verified completion"
                ) from None
            raise HTTPException(
                503, "Managed binary unavailable; existing files were preserved"
            ) from None
        finally:
            try:
                await self._storage.close()
            finally:
                _READERS.release()
