#!/usr/bin/env python3
"""Bounded GET-only benchmark; no device mutation, fixture seeding or fleet claim."""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--path", choices=["/api/v1/health/live", "/api/v1/health/ready",
                                         "/api/v1/devices/"], default="/api/v1/health/live")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--rate", type=float, default=5)
    parser.add_argument("--allow-remote", action="store_true",
                        help="Only use with the target owner's approval for this load")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.base_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        parser.error("Use an HTTP(S) origin without credentials, path, query or fragment")
    try:
        local = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = False  # Require a literal loopback address; no DNS assumption.
    if not local and not args.allow_remote:
        parser.error("Remote load requires --allow-remote and target-owner approval")
    if not (1 <= args.requests <= 3000 and 1 <= args.concurrency <= 16 and 0 < args.rate <= 20):
        parser.error("Limits: 1..3000 requests, 1..16 concurrent, rate >0 and <=20/s")
    token = os.environ.get("FREESDN_BENCHMARK_TOKEN")
    if token and parsed.scheme != "https" and not local:
        parser.error("Remote authenticated requests require HTTPS")
    url = args.base_url.rstrip("/") + args.path
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    def request_once():
        start = time.monotonic()
        try:
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as response:
                # Drain a bounded body; a huge response is an explicit failure.
                body = response.read(2 * 1024 * 1024 + 1)
                status = str(response.status) if len(body) <= 2 * 1024 * 1024 else "body_limit"
        except urllib.error.HTTPError as error:
            status = str(error.code)
            error.close()
        except (OSError, TimeoutError):
            status = "connection_error"
        return status, (time.monotonic() - start) * 1000

    started = datetime.now(UTC).isoformat()
    clock = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        pending = set()
        for index in range(args.requests):
            if len(pending) >= args.concurrency:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                results.extend(item.result() for item in done)
            time.sleep(max(0, clock + index / args.rate - time.monotonic()))
            pending.add(executor.submit(request_once))
        results.extend(item.result() for item in pending)
    elapsed = time.monotonic() - clock
    durations = sorted(ms for _, ms in results)
    counts = Counter(status for status, _ in results)
    report = {
        "started_at_utc": started, "target_origin": args.base_url, "path": args.path,
        "requests": len(results), "concurrency": args.concurrency,
        "offered_rate_per_second": args.rate, "completed_rate_per_second": len(results) / elapsed,
        "elapsed_seconds": elapsed, "status_counts": dict(counts),
        "latency_ms": {f"p{p}": durations[math.ceil(len(durations) * p / 100) - 1]
                       for p in (50, 95, 99)},
        "scope": "Specified GET endpoint only; no fleet capacity or hardware claim",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return int(any(not status.startswith("2") for status in counts))


if __name__ == "__main__":
    raise SystemExit(main())
