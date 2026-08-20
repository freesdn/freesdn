# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
One UDP datagram must not be able to stall the collector.

Background
----------
The RFC 3164 pattern had three overlapping variable-length runs competing for
the same characters::

    (?P<timestamp>...)?\\s*(?P<hostname>\\S+)?\\s+(?P<tag>[^:]+):

``\\s*`` against ``\\s+`` over a run of spaces, and ``\\S+`` against ``[^:]+``
over the non-space tail. On input shaped ``"<13>" + " "*n + "A"*n`` -- which
never contains the colon the tag requires -- the engine explores every split of
both runs before it can fail. Measured on the shipped pattern:

    204 bytes   0.0023s
    404 bytes   0.0182s     x8
    804 bytes   0.1448s     x8

A clean cubic. Extrapolated to a 4 KB datagram: ~20 seconds, which is what a
run through the real datagram handler measured.

That is not one slow packet. ``_process`` runs inline on the event loop, so the
whole worker stalls -- every other syslog source, every NetFlow packet, and
every HTTP request served by that process. The sender needs no credentials;
only the source allowlist stands in front of it. And nothing capped the
datagram, so an attacker had the full 65507-byte UDP payload to work with.

The fix bounds the quantifiers to the real protocol limits (RFC 3164 caps TAG
at 32 characters and a hostname at 255) and truncates the datagram before
parsing. Both halves are pinned here, along with the parses that must not have
changed -- a "fix" that broke real syslog ingest would be worse than the DoS.
"""

from __future__ import annotations

import time

import pytest

from app.modules.collector.services.syslog import _MAX_PARSE_BYTES, _RFC3164


def _attack(n: int) -> str:
    """The pathological shape: a run of spaces, then a colon-free run."""
    return "<13>" + " " * n + "A" * n


# ── The DoS ──────────────────────────────────────────────────────


@pytest.mark.parametrize("size", [1000, 2000, 4000])
def test_pathological_input_is_fast(size: int) -> None:
    """
    The pre-fix pattern needed ~20s on the 4000 case. Anything even close to a
    second here means the bounds were loosened back into ambiguity.
    """
    payload = _attack(size)
    start = time.perf_counter()
    _RFC3164.match(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"{len(payload)} bytes took {elapsed:.3f}s — backtracking is back"


def test_cost_does_not_grow_superlinearly() -> None:
    """
    The signature of the bug was x8 per doubling. Timing is noisy, so this
    asserts the SHAPE: quadrupling the input must not quadruple the cost the
    way a cubic would (which would be ~64x).
    """

    def timed(n: int) -> float:
        payload = _attack(n)
        start = time.perf_counter()
        for _ in range(20):
            _RFC3164.match(payload)
        return time.perf_counter() - start

    small = timed(250)
    large = timed(1000)  # 4x the input
    assert large < small * 8 + 0.05, (
        f"250->1000 chars grew {large / max(small, 1e-9):.1f}x; a bounded pattern "
        "should be roughly flat, a cubic one would be ~64x"
    )


def test_datagram_is_truncated_before_parsing() -> None:
    """
    Defence in depth: even a pathological pattern cannot be fed 65507 bytes.
    RFC 3164 requires relays to handle 1024 and RFC 5426 puts the practical UDP
    ceiling at 2048, so the cap is generous for real traffic.
    """
    assert _MAX_PARSE_BYTES <= 16384
    assert _MAX_PARSE_BYTES >= 2048


def test_handler_truncates_the_payload_it_decodes() -> None:
    """The cap has to be applied at ingest, not after the parse."""
    import inspect

    from app.modules.collector.services import syslog

    src = inspect.getsource(syslog._SyslogProtocol.datagram_received)
    assert "_MAX_PARSE_BYTES" in src, "datagram_received no longer bounds the payload"


# ── The parses that must not have changed ────────────────────────


@pytest.mark.parametrize(
    ("line", "hostname", "tag", "message"),
    [
        (
            "<34>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick",
            "myhost",
            "su",
            "'su root' failed for lonvick",
        ),
        ("<34>Oct 11 22:14:15 fw01 kernel: link down", "fw01", "kernel", "link down"),
        ("<13>myhost app: no timestamp here", "myhost", "app", "no timestamp here"),
        (
            "<13>Aug 18 12:00:00 host.example.com sshd[1234]: Accepted password",
            "host.example.com",
            "sshd[1234]",
            "Accepted password",
        ),
    ],
)
def test_real_messages_still_parse(line: str, hostname: str, tag: str, message: str) -> None:
    """
    Bounding the quantifiers must not narrow what the collector accepts. These
    are the shapes the existing ingest tests and RFC 3164 itself use.
    """
    m = _RFC3164.match(line)
    assert m is not None, f"stopped parsing a valid RFC 3164 line: {line!r}"
    assert m.group("hostname") == hostname
    assert m.group("tag") == tag
    assert m.group("message") == message


def test_colon_free_line_still_simply_fails() -> None:
    """It must fail — the point is that it fails FAST, not that it now matches."""
    assert _RFC3164.match("<13>this line has no colon so there is no tag") is None
