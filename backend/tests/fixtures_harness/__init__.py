# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Recorded-fixture (cassette) harness for vendor-adapter tests.

WHY THIS EXISTS
---------------
Every adapter test mocks the HTTP boundary with hand-written canned payloads. The
risk is that the canned payload does not match what the real device returns, so a
vendor firmware/API change (a renamed field, a restructured list) ships undetected:
the mock keeps passing while the adapter's parsing/normalization silently breaks.

This harness closes that gap. It lets you RECORD the real request/response pairs once
against real hardware in your lab, commit them as a cassette, and REPLAY them in CI so
the adapter's parsing is exercised against *real captured payloads*. When a vendor
changes their API, you re-record, the diff shows the change, and the replay tests catch
any normalization break.

USAGE
-----
Replay (default — CI/dev, no hardware needed)::

    async def test_omada_parses_site_list(omada_client_factory):
        with use_cassette("omada/sites_list"):
            client = omada_client_factory()       # any code that builds httpx.AsyncClient
            sites = await client.list_sites()
            assert sites[0].name == "HQ"           # asserts parsing of the REAL payload

Record (run in your lab against real hardware)::

    FREESDN_RECORD_FIXTURES=1 \
    OMADA_HOST=https://10.x.x.x OMADA_USER=... OMADA_PASS=... \
    poetry run pytest backend/tests/adapters/test_omada_cassette.py -k sites_list

    # then review + commit backend/tests/fixtures_harness/cassettes/omada/sites_list.json

The cassette is JSON (human-reviewable). Bodies are stored as text when decodable,
else base64. Matching is by (METHOD, path) in recorded order (VCR-style sequential).

NOTE: adapters MUST construct the client module-qualified as ``httpx.AsyncClient(...)``
(all current adapters do) so the transport injection below takes effect.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx

# Real-device cassettes are recorded in the maintainer's lab and contain device
# fingerprints (MACs, IPs, serials, hostnames), so they are kept OUTSIDE the repo:
# set FREESDN_CASSETTE_DIR to a folder away from git. RECORDING REQUIRES it — a
# real-device capture can therefore never land in the repo by accident. REPLAY
# looks there first, then falls back to the small scrubbed in-repo sample set;
# a missing cassette SKIPS the test (public CI / contributors have no lab) — it
# never fails. The in-repo ``cassettes/`` dir holds only reviewed, scrubbed
# samples that are safe to ship.
IN_REPO_CASSETTE_DIR = Path(__file__).parent / "cassettes"
_RECORD_ENV = "FREESDN_RECORD_FIXTURES"
_DIR_ENV = "FREESDN_CASSETTE_DIR"


def recording_enabled() -> bool:
    return os.environ.get(_RECORD_ENV, "").strip().lower() in {"1", "true", "yes"}


def external_cassette_dir() -> Path | None:
    """The off-repo cassette folder (``FREESDN_CASSETTE_DIR``), or None if unset."""
    raw = os.environ.get(_DIR_ENV, "").strip()
    return Path(raw) if raw else None


def _encode_body(raw: bytes) -> dict[str, Any]:
    try:
        return {"text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(raw).decode("ascii")}


def _decode_body(stored: dict[str, Any]) -> bytes:
    if "text" in stored:
        return stored["text"].encode("utf-8")
    return base64.b64decode(stored.get("b64", ""))


class Cassette:
    """A recorded list of (request -> response) interactions on disk."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.interactions: list[dict[str, Any]] = []
        self._cursor = 0
        ext = external_cassette_dir()
        # Save target: the external lab dir when set (recording enforces it), else
        # the in-repo dir (only the shipped scrubbed samples are written there).
        self.save_path = (ext or IN_REPO_CASSETTE_DIR) / f"{name}.json"
        # Load order: the lab's private recordings first, then the in-repo sample.
        candidates = [p / f"{name}.json" for p in (ext, IN_REPO_CASSETTE_DIR) if p is not None]
        self.load_path: Path | None = next((p for p in candidates if p.exists()), None)

    def load(self) -> None:
        if self.load_path is None:
            raise FileNotFoundError(
                f"No cassette '{self.name}'. Record it against real hardware with "
                f"{_RECORD_ENV}=1 + {_DIR_ENV}=<off-repo folder>, or point {_DIR_ENV} "
                f"at an existing recordings folder."
            )
        self.interactions = json.loads(self.load_path.read_text(encoding="utf-8")).get(
            "interactions", []
        )
        self._cursor = 0

    def save(self) -> None:
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        self.save_path.write_text(
            json.dumps({"interactions": self.interactions}, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    # ---- replay -----------------------------------------------------------
    def next_for(self, request: httpx.Request) -> httpx.Response:
        want = (request.method.upper(), request.url.path)
        # Sequential VCR-style: serve the next interaction whose (method, path) matches.
        for idx in range(self._cursor, len(self.interactions)):
            it = self.interactions[idx]
            if (it["request"]["method"], it["request"]["path"]) == want:
                self._cursor = idx + 1
                resp = it["response"]
                return httpx.Response(
                    resp["status"],
                    headers=resp.get("headers", {}),
                    content=_decode_body(resp["body"]),
                    request=request,
                )
        raise AssertionError(
            f"Cassette '{self.name}' has no recorded interaction for {want[0]} {want[1]} "
            f"(consumed {self._cursor}/{len(self.interactions)}). The adapter made a call the "
            f"recording does not cover. Re-record against real hardware ({_RECORD_ENV}=1)."
        )

    # ---- record -----------------------------------------------------------
    def record(self, request: httpx.Request, status: int, headers: dict[str, str], body: bytes) -> None:
        self.interactions.append(
            {
                "request": {
                    "method": request.method.upper(),
                    "path": request.url.path,
                    "query": request.url.query.decode() if request.url.query else "",
                },
                "response": {
                    "status": status,
                    # Drop hop-by-hop / volatile headers; keep content-type for realism.
                    "headers": {
                        k: v for k, v in headers.items()
                        if k.lower() in {"content-type"}
                    },
                    "body": _encode_body(body),
                },
            }
        )


class _RecordTransport(httpx.AsyncBaseTransport):
    """Forwards to real hardware, buffers + records each response into the cassette."""

    def __init__(self, cassette: Cassette, inner: httpx.AsyncBaseTransport) -> None:
        self._cassette = cassette
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = await self._inner.handle_async_request(request)
        body = await resp.aread()
        await resp.aclose()
        self._cassette.record(request, resp.status_code, dict(resp.headers), body)
        return httpx.Response(resp.status_code, headers=resp.headers, content=body, request=request)


@contextmanager
def use_cassette(name: str, *, verify_ssl: bool = False) -> Iterator[Cassette]:
    """Inject a record-or-replay transport into every ``httpx.AsyncClient`` built inside.

    Replay (default): serves recorded responses; no hardware needed; safe in CI.
    Record (``FREESDN_RECORD_FIXTURES=1``): forwards to real hardware and writes the cassette.
    """
    cassette = Cassette(name)
    record = recording_enabled()
    if record:
        # Recording captures REAL device responses (lab fingerprints) — force it
        # to a folder outside the repo so a capture can never be committed.
        if external_cassette_dir() is None:
            raise RuntimeError(
                f"Recording requires {_DIR_ENV} set to a folder OUTSIDE the repo. "
                "Real-device cassettes contain lab fingerprints (MACs/IPs/serials) "
                "and must not land in git."
            )
        transport: httpx.AsyncBaseTransport = _RecordTransport(
            cassette, httpx.AsyncHTTPTransport(verify=verify_ssl)
        )
    else:
        try:
            cassette.load()
        except FileNotFoundError:
            # No lab recording available (public CI / contributor): skip, never fail.
            import pytest

            pytest.skip(
                f"no cassette '{name}' — set {_DIR_ENV} to your recordings folder, "
                f"or record with {_RECORD_ENV}=1 (in your lab)."
            )
        transport = httpx.MockTransport(cassette.next_for)

    original = httpx.AsyncClient

    def _patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        # `verify`/`cert`/`proxies` only apply to the default transport, which we override.
        kwargs.pop("verify", None)
        return original(*args, **kwargs)

    httpx.AsyncClient = _patched  # type: ignore[misc,assignment]
    try:
        yield cassette
    finally:
        httpx.AsyncClient = original  # type: ignore[misc,assignment]
        if record:
            cassette.save()
