"""Isolated Linux system-resolver child; stdin contains only a bounded hostname."""

import json
import resource
import signal
import socket
import sys


def _limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    signal.alarm(6)  # Independent guard if the parent disappears during lookup.
    _limit(resource.RLIMIT_CORE, 0)
    _limit(resource.RLIMIT_AS, 128 * 1024 * 1024)
    _limit(resource.RLIMIT_CPU, 3)
    _limit(resource.RLIMIT_NOFILE, 64)
    # Native NSS/DNS runs in this one owned process, never a spawned helper.
    _limit(resource.RLIMIT_NPROC, 0)
    raw = sys.stdin.buffer.read(1025)
    if len(raw) > 1024:
        return 2
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"host"}:
        return 2
    host = value["host"]
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or any(ord(c) < 33 for c in host):
        return 2
    addresses = []
    for item in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
        address = str(item[4][0])
        if not 1 <= len(address) <= 96:
            return 2
        if address not in addresses:
            addresses.append(address)
        if len(addresses) > 32:
            return 2
    encoded = json.dumps(addresses, separators=(",", ":")).encode()
    if not addresses or len(encoded) > 4096:
        return 2
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2  # Never emit OS/NSS diagnostics or the supplied hostname.
    raise SystemExit(code)
