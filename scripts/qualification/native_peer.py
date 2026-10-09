"""Owned local child behaviors for command-boundary qualification only."""
import errno
import json
import os
import signal
import sys
import time
from pathlib import Path

mode, marker_name, *extra = sys.argv[1:]
marker = Path(marker_name)
signal.alarm(8)  # Fixture lifeline; never a product deadline or retry.
if mode in ("ignore-term", "descendant-pipe"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def mark(path):
    stat = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    path.write_text(json.dumps({"pid": os.getpid(), "ppid": os.getppid(),
                               "pgid": os.getpgrp(), "starttime": stat[19],
                               "mode": mode, "network": os.readlink("/proc/self/ns/net"),
                               "term_ignored": signal.getsignal(signal.SIGTERM) == signal.SIG_IGN}))


def write_all(fd, value):
    view = memoryview(value)
    while view:
        view = view[os.write(fd, view):]


mark(marker)
if mode == "binary":
    data = sys.stdin.buffer.read()
    write_all(1, b"\x00\xff" + data[::-1])
    write_all(2, b"\xfe\x00error\xff")
elif mode == "args":
    write_all(1, json.dumps(extra).encode())
elif mode == "nonzero":
    write_all(1, b"ordinary output")
    write_all(2, b"ordinary error")
    sys.exit(7)
elif mode == "cap":
    write_all(1, b"a" * 16)
    write_all(2, b"b" * 16)
elif mode == "flood":
    for _ in range(2048):
        write_all(1, b"PRIVATE_SYNTHETIC_MARKER" * 256)
elif mode in ("blocked-stdin", "ignore-term"):
    time.sleep(6)
elif mode in ("slow", "slow-valid"):
    for _ in range(4 if mode == "slow-valid" else 200):
        write_all(1, b"x")
        time.sleep(0.03)
elif mode == "closed-pipes":
    os.close(1)
    os.close(2)
    time.sleep(6)
elif mode == "descendant-pipe":
    child = os.fork()
    if child:
        # Wait for the child's owned marker so the test observes a real fork.
        until = time.monotonic() + 2
        while not marker.with_suffix(".descendant").exists():
            if time.monotonic() >= until:
                sys.exit(9)
            time.sleep(0.002)
    else:
        signal.alarm(8)
        mark(marker.with_suffix(".descendant"))
        time.sleep(6)
elif mode == "cancel":
    # Reading input proves the parent has assigned its Popen child and entered
    # its I/O loop. This does not qualify interruption during process creation.
    if sys.stdin.buffer.read(1) != b"x":
        sys.exit(9)
    mark(marker.with_suffix(".cancel-ready"))
    os.kill(os.getppid(), signal.SIGUSR1)
    time.sleep(6)
elif mode == "signal-exit":
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "cwd-env":
    write_all(1, json.dumps({"cwd": os.getcwd(), "value": os.environ["OWNED_VALUE"]}).encode())
elif mode == "fd-closed":
    try:
        os.fstat(int(extra[0]))
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        write_all(1, b"closed")
    else:
        write_all(1, b"open")
        sys.exit(9)
elif mode == "close-stdin":
    os.close(0)
    write_all(1, b"done")
else:
    raise ValueError("Unknown owned fixture mode")
