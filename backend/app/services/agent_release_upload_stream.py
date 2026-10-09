# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private bounded multipart ingress with no spool, pathname or file mutation.

The standard form contains an `intent` JSON field followed by one `file` part.
Only the preparation coordinator may allocate/write the managed artifact after
its acknowledged reservation. Its retained operation/file ownership spans the
consumer of this stream. This module neither publishes nor cleans up anything.
"""

import re
import threading
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal, cast, overload
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from python_multipart import MultipartParser
from python_multipart.exceptions import FormParserError
from python_multipart.multipart import parse_options_header
from starlette.requests import ClientDisconnect

from app.schemas.agent_release_operations import MAX_COMMAND_BYTES, decode_release_command
from app.services.agent_release_request import ReleasePublicationRequest

_UPLOADS = threading.BoundedSemaphore(8)
_FEED = 65536
_MAX_FILE = 500 * 1024 * 1024
_OVERHEAD = 65536


def _invalid(
    detail: str = "Malformed release upload; preserve and inspect the operation",
) -> HTTPException:
    return HTTPException(400, detail)


@overload
def _single_header(request: Request, name: str, *, optional: Literal[False] = False) -> str: ...


@overload
def _single_header(request: Request, name: str, *, optional: Literal[True]) -> str | None: ...


def _single_header(request: Request, name: str, *, optional: bool = False) -> str | None:
    values = request.headers.getlist(name)
    if not values and optional:
        return None
    if len(values) != 1:
        raise _invalid("Missing or ambiguous upload header")
    return values[0]


class ReleaseUploadStream:
    """Single request/consumer. Callers must use the owned_upload_stream context."""

    def __init__(self, request: Request, operation_id: UUID) -> None:
        if type(operation_id) is not UUID or not operation_id.int:
            raise HTTPException(422, "Valid upload operation identity required")
        content_type = _single_header(request, "content-type")
        if len(content_type) > 1024:
            raise _invalid("Upload content type exceeds its bound")
        kind, options = parse_options_header(content_type)
        boundary = options.get(b"boundary", b"")
        if (
            kind != b"multipart/form-data"
            or type(boundary) is not bytes
            or re.fullmatch(rb"[0-9A-Za-z'()+_,./:=? -]{1,70}", boundary) is None
            or boundary.endswith(b" ")
        ):
            raise HTTPException(415, "Upload requires bounded multipart/form-data")
        encoding = _single_header(request, "content-encoding", optional=True)
        if encoding is not None and encoding.strip().lower() != "identity":
            raise HTTPException(415, "Encoded uploads are not supported")
        declared = _single_header(request, "content-length", optional=True)
        if declared is not None and (
            len(declared) > 10 or not declared.isascii() or not declared.isdecimal()
        ):
            raise _invalid("Invalid upload content length")
        self.declared = int(declared) if declared is not None else None
        self.limit = _MAX_FILE + MAX_COMMAND_BYTES + _OVERHEAD
        if self.declared is not None and self.declared > self.limit:
            raise HTTPException(413, "Upload exceeds its wire limit")
        self.operation_id = operation_id
        self.command: ReleasePublicationRequest | None = None
        self.expected_size: int | None = None
        self.received = self.file_bytes = self.part = 0
        self.part_ends = 0
        self.ended = self.eof = self.closed = self.consumed = False
        self._headers: dict[bytes, bytes] = {}
        self._field = bytearray()
        self._value = bytearray()
        self._intent = bytearray()
        self._payload: deque[bytes] = deque()
        self._queued_bytes = 0
        self._incoming: AsyncIterator[bytes] | None = request.stream()
        self._buffer = b""
        self._offset = 0
        self._parser: MultipartParser | None = MultipartParser(
            boundary,
            {
                "on_part_begin": self._part_begin,
                "on_header_field": self._header_field,
                "on_header_value": self._header_value,
                "on_header_end": self._header_end,
                "on_headers_finished": self._headers_finished,
                "on_part_data": self._part_data,
                "on_part_end": self._part_end,
                "on_end": self._end,
            },
            max_size=self.limit,
            max_header_count=4,
            max_header_size=8192,
        )

    def _part_begin(self) -> None:
        self.part += 1
        if self.part > 2:
            raise _invalid("Upload permits exactly one intent and one file")
        self._headers = {}
        self._field.clear()
        self._value.clear()

    def _header_field(self, data: bytes, start: int, end: int) -> None:
        self._field.extend(data[start:end])

    def _header_value(self, data: bytes, start: int, end: int) -> None:
        self._value.extend(data[start:end])

    def _header_end(self) -> None:
        name = bytes(self._field).lower()
        if name in self._headers or name not in (b"content-disposition", b"content-type"):
            raise _invalid("Duplicate or unsupported upload part header")
        self._headers[name] = bytes(self._value)
        self._field.clear()
        self._value.clear()

    def _headers_finished(self) -> None:
        disposition, options = parse_options_header(self._headers.get(b"content-disposition", b""))
        if disposition != b"form-data":
            raise _invalid("Upload part requires form-data disposition")
        if self.part == 1:
            if options.get(b"name") != b"intent" or b"filename" in options:
                raise _invalid("Upload must begin with the intent field")
            content_type = self._headers.get(b"content-type")
            if (
                content_type is not None
                and parse_options_header(content_type)[0] != b"application/json"
            ):
                raise HTTPException(415, "Upload intent must be JSON")
        elif (
            self.command is None
            or options.get(b"name") != b"file"
            or b"filename" not in options
            or parse_options_header(self._headers.get(b"content-type", b""))[0].startswith(
                b"multipart/"
            )
        ):
            raise _invalid("Intent must be followed by one binary file part")
        # The transport filename is never a storage path or trusted metadata.
        # The canonical intent supplies the filename; its checksum binds bytes.

    def _part_data(self, data: bytes, start: int, end: int) -> None:
        if self.part == 1:
            if len(self._intent) + end - start > MAX_COMMAND_BYTES:
                raise HTTPException(413, "Upload intent exceeds its bound")
            self._intent.extend(data[start:end])
        elif self.part == 2 and self.command is not None:
            size = end - start
            self.file_bytes += size
            # A validated first part sets command and its committed size before
            # the parser can deliver any second-part payload callback.
            if self.file_bytes > cast(int, self.expected_size):
                raise HTTPException(413, "Upload exceeds the committed payload size")
            if self._queued_bytes + size > 2 * _FEED:
                raise HTTPException(503, "Upload parser backpressure bound exceeded")
            if size:
                self._payload.append(bytes(data[start:end]))
                self._queued_bytes += size
        else:
            raise _invalid()

    def _part_end(self) -> None:
        self.part_ends += 1
        if self.part == 1:
            try:
                command = decode_release_command(bytes(self._intent))
            except (ValueError, TypeError, RecursionError):
                raise HTTPException(422, "Invalid upload operation intent") from None
            if (
                type(command) is not ReleasePublicationRequest
                or command.storage_kind != "owned"
                or command.operation_id != self.operation_id
            ):
                raise HTTPException(422, "Upload requires matching owned publication intent")
            self.command = command
            self.expected_size = command.metadata()["file_size"]
            self.limit = self.expected_size + MAX_COMMAND_BYTES + _OVERHEAD
            if self.received > self.limit or (
                self.declared is not None and self.declared > self.limit
            ):
                raise HTTPException(413, "Upload exceeds its intent-bound wire limit")
            self._intent.clear()

    def _end(self) -> None:
        if self.part != 2 or self.part_ends != 2:
            raise _invalid("Upload is missing its binary part")
        self.ended = True

    async def _pump(self) -> None:
        if self.closed or self.eof:
            raise _invalid("Upload stream is no longer available")
        if self._offset == len(self._buffer):
            try:
                with anyio.fail_after(10):
                    # close clears these references only after the owned
                    # consumer drains; the closed guard above rejects reuse.
                    self._buffer = await anext(cast(AsyncIterator[bytes], self._incoming))
                self._offset = 0
            except StopAsyncIteration:
                self.eof = True
                # In the pinned parser finalize() is a no-op. Require its actual
                # closing-boundary callback, both part ends and exact byte counts.
                cast(MultipartParser, self._parser).finalize()
                if (
                    not self.ended
                    or self.command is None
                    or self.file_bytes != self.expected_size
                    or (self.declared is not None and self.received != self.declared)
                ):
                    raise _invalid("Upload ended before its verified framing and size")
                return
            except TimeoutError:
                raise HTTPException(
                    408, "Upload body deadline exceeded; inspect retained operation"
                ) from None
            except ClientDisconnect:
                raise _invalid("Upload disconnected; inspect retained operation") from None
        data = self._buffer[self._offset : self._offset + _FEED]
        self._offset += len(data)
        self.received += len(data)
        if self.received > self.limit or (
            self.declared is not None and self.received > self.declared
        ):
            raise HTTPException(413, "Upload wire size exceeds its bound")
        try:
            consumed = cast(MultipartParser, self._parser).write(data)
        except FormParserError:
            raise _invalid() from None
        if consumed != len(data):
            raise _invalid("Upload parser did not consume its complete bounded input")
        await anyio.lowlevel.checkpoint()

    async def read_intent(self) -> ReleasePublicationRequest:
        if self.closed or self.command is not None:
            raise _invalid("Upload intent cannot be read twice")
        try:
            with anyio.fail_after(10):
                while self.command is None:
                    await self._pump()
        except TimeoutError:
            raise HTTPException(408, "Upload intent deadline exceeded") from None
        return self.command

    async def chunks(self) -> AsyncIterator[bytes]:
        if self.closed or self.consumed or self.command is None:
            raise _invalid("Upload payload requires one validated intent and consumer")
        self.consumed = True
        pending = bytearray()
        while not self.eof or self._payload:
            if self._payload:
                chunk = self._payload.popleft()
                self._queued_bytes -= len(chunk)
                offset = 0
                while offset < len(chunk):
                    count = min(_FEED - len(pending), len(chunk) - offset)
                    pending.extend(chunk[offset : offset + count])
                    offset += count
                    if len(pending) == _FEED:
                        yield bytes(pending)
                        pending.clear()
            else:
                await self._pump()
        # Coalesce transport fragmentation before the coordinator's SQL phase;
        # a one-byte transport chunk must not force one SQL transaction per byte.
        # The final short block is emitted only after framing/size verification.
        if pending:
            yield bytes(pending)

    def close(self) -> None:
        # The route exits only after its owned coordinator and file workers drain.
        # There are no parser-created temporary files or child tasks to abandon.
        self.closed = True
        self._buffer = b""
        self._intent.clear()
        self._payload.clear()
        self._incoming = None
        self._parser = None


@asynccontextmanager
async def owned_upload_stream(
    request: Request, operation_id: UUID
) -> AsyncIterator[ReleaseUploadStream]:
    if not _UPLOADS.acquire(blocking=False):
        raise HTTPException(503, "Upload capacity is busy", headers={"Retry-After": "1"})
    stream = None
    try:
        stream = ReleaseUploadStream(request, operation_id)
        yield stream
    finally:
        if stream is not None:
            stream.close()
        _UPLOADS.release()
