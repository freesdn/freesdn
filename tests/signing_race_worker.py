"""Owned future concurrency fixture. Not an application helper or executed tool."""
from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def main():
    source = Path(os.environ["FREESDN_SIGNING_PROBE_SOURCE"])
    expected = os.environ["FREESDN_SIGNING_PROBE_SHA256"]
    root = Path(os.environ["FREESDN_SIGNING_KEY_DIR"])
    # Parent owns the root; no default path is possible in this worker.
    if not root.is_absolute() or not root.is_dir() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
        raise RuntimeError("fixture source/root binding invalid")
    spec = importlib.util.spec_from_file_location("owned_race_signing", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixture module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    real_generate = ec.generate_private_key
    real_flock = fcntl.flock
    busy_reported = False

    def generate(*args, **kwargs):
        if sys.argv[1] == "A":
            emit("generation-paused")
            # Parent imposes a hard process deadline and owns stdin closure.
            # Candidate A holds its real directory lock here; baseline A does not.
            if sys.stdin.readline() != "release\n":
                raise RuntimeError("fixture generation release missing")
        return real_generate(*args, **kwargs)

    def flock(fd, operation):
        nonlocal busy_reported
        try:
            return real_flock(fd, operation)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN) and not busy_reported:
                busy_reported = True
                emit("actual-lock-busy")
            raise

    ec.generate_private_key = generate
    fcntl.flock = flock
    emit("starting", pid=os.getpid())
    try:
        public = module.public_key_pem()
        emit("completed", public_sha256=hashlib.sha256(public).hexdigest())
    except Exception as exc:
        emit("refused", exception_type=type(exc).__name__)
        raise SystemExit(2) from None
    finally:
        ec.generate_private_key = real_generate
        fcntl.flock = real_flock


if __name__ == "__main__":
    main()
