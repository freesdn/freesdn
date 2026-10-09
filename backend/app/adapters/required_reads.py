"""Required adapter reads cannot silently become successful empty components."""

import asyncio
from collections.abc import Awaitable
from typing import Any

from app.adapters.base import AdapterResult


class RequiredReadUnavailableError(ValueError):
    """One or more required reads did not supply a usable result."""


async def gather_required_reads(*reads: Awaitable[Any]) -> list[Any]:
    """Finish all reads, preserve cancellation, and reject failed components.

    Endpoint-specific parsers still own successful-payload schema validation.
    This only checks completion and the common result envelope.
    """
    results = await asyncio.gather(*reads, return_exceptions=True)
    for result in results:
        if isinstance(result, asyncio.CancelledError):
            raise result
    for result in results:
        if isinstance(result, BaseException):
            raise RequiredReadUnavailableError("A required read failed")
        if isinstance(result, AdapterResult):
            if result.success is not True or not isinstance(result.data, dict):
                raise RequiredReadUnavailableError("A required read is unavailable")
        elif not isinstance(result, (dict, list)):
            raise RequiredReadUnavailableError("A required read returned invalid data")
    return results
