"""Owned SDK preparation into an immutable, client-free S3 download plan.

This private factory is download-specific. It does not replace upload/delete
support or bound arbitrary SDK credential helper processes. Admitted SDK work
and close operations are drained; late results are refused. Storage-host DNS
uses the owned native resolver, outside the event loop and before data I/O.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import SplitResult, urlsplit

import anyio

from app.core.backup_downloads import DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.services.vault_native_resolution import resolve_storage_host
from app.services.vault_s3_stream import (
    RemoteTransferError,
    _copy_prepared_into,
    _freeze_client,
    _live,
)

_ADMISSION = anyio.CapacityLimiter(2)
_THREADS = anyio.CapacityLimiter(2)
_SECONDS = 5.0
_MAX_CONTROL = 65536
_ERROR = "S3 download preparation failed; verify the destination and retry"


def _endpoint(url: str) -> SplitResult:
    if not isinstance(url, str) or len(url) > 8192:
        raise ValueError(_ERROR)
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(c) < 33 for c in url)
    ):
        raise ValueError(_ERROR)
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError(_ERROR)
    return parsed


@dataclass(frozen=True, slots=True)
class PreparedS3Download:
    """Copied operation data only; repr never reveals credential material."""

    _plan_json: str = field(repr=False)

    async def copy_download_into(
        self,
        path: str,
        expected: dict[str, Any] | None,
        snapshot: DownloadSnapshot,
    ) -> None:
        async def prepare() -> dict[str, Any]:
            await anyio.lowlevel.checkpoint()
            value: dict[str, Any] = json.loads(self._plan_json)
            prefix = "s3://" + value["bucket"] + "/"
            if not isinstance(path, str) or not path:
                raise ValueError(_ERROR)
            if path.startswith("s3://"):
                if not path.startswith(prefix):
                    raise ValueError(_ERROR)
                path_key = path[len(prefix) :]
            else:
                path_key = path
            if not path_key:
                raise ValueError(_ERROR)
            value["key"], value["limit"] = path_key, snapshot.limit
            return value

        await _copy_prepared_into(prepare, expected, snapshot)


@complete_before_cancellation
async def _collect_owned(config: dict[str, Any]) -> dict[str, Any]:
    def collect() -> dict[str, Any]:
        import boto3
        from botocore.config import Config

        kwargs: dict[str, Any] = {
            "region_name": config.get("region", "us-east-1"),
            "config": Config(s3={"addressing_style": "path"}),
        }
        if config.get("endpoint_url"):
            kwargs["endpoint_url"] = config["endpoint_url"]
        if config.get("access_key"):
            kwargs["aws_access_key_id"] = config["access_key"]
            kwargs["aws_secret_access_key"] = config.get("secret_key", "")
            if config.get("session_token"):
                kwargs["aws_session_token"] = config["session_token"]
        # Independent Session preserves the SDK credential provider chain
        # without silently reusing another operation's global cached identity.
        client = boto3.session.Session().client("s3", **kwargs)
        try:
            parsed = _endpoint(client.meta.endpoint_url)
            adapter = SimpleNamespace(
                bucket=config["bucket"],
                client=client,
                _sni_hostname=parsed.hostname if parsed.scheme == "https" else None,
            )
            result = _freeze_client(adapter, ".prepared-download", 200 * 1024 * 1024)
            result["original_endpoint"] = client.meta.endpoint_url
            return result
        finally:
            client.close()

    return await anyio.to_thread.run_sync(collect, limiter=_THREADS)


class _PreparationRefused(Exception):
    """Preserve the caller's already-safe authority refusal across redaction."""

    def __init__(self, cause: Exception) -> None:
        self.cause = cause


async def prepare_s3_download(
    config: dict[str, Any],
    *,
    revalidate: Callable[[], Awaitable[None]] | None = None,
) -> PreparedS3Download:
    async def checked() -> None:
        if revalidate is not None:
            try:
                await revalidate()
            except Exception as error:
                raise _PreparationRefused(error) from None

    await anyio.lowlevel.checkpoint()
    try:
        _ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise RemoteTransferError(
            "S3 destination preparation capacity is busy; retry later"
        ) from None
    try:
        try:
            started = time.monotonic()
            copied = deepcopy(config)
            if (
                not isinstance(copied, dict)
                or len(json.dumps(copied, ensure_ascii=True).encode()) > _MAX_CONTROL
            ):
                raise ValueError(_ERROR)
            if not isinstance(copied.get("bucket"), str) or not copied["bucket"]:
                raise ValueError(_ERROR)
            endpoint = copied.get("endpoint_url")
            pin = None
            if endpoint:
                parsed = _endpoint(endpoint)
                pin = await resolve_storage_host(cast(str, parsed.hostname), allow_private=False)
                await checked()
            await anyio.lowlevel.checkpoint()
            result = await _collect_owned(copied)
            await anyio.lowlevel.checkpoint()
            await checked()
            original = result.pop("original_endpoint")
            parsed = _endpoint(original)
            if endpoint and _endpoint(endpoint) != parsed:
                raise ValueError(_ERROR)
            if pin is None:
                pin = await resolve_storage_host(cast(str, parsed.hostname), allow_private=False)
                await checked()
            result["endpoint_host"] = pin
            # Retain the original HTTP custom-endpoint Host behavior. HTTPS
            # carries the original hostname for both TLS and SigV4 Host.
            if parsed.scheme == "http":
                result["hostname"] = pin
            _live(result)
            if time.monotonic() - started >= _SECONDS:
                raise ValueError(_ERROR)
            encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
            if len(encoded.encode()) > _MAX_CONTROL:
                raise ValueError(_ERROR)
            await anyio.lowlevel.checkpoint()
            return PreparedS3Download(encoded)
        except _PreparationRefused as error:
            raise error.cause from None
        except Exception:
            raise RemoteTransferError(_ERROR) from None
    finally:
        _ADMISSION.release()
