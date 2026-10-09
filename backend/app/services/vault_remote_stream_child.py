"""Fixed read-only protocol worker; secrets arrive on stdin, archive on stdout."""

import importlib.util
import ipaddress
import json
import os
import resource
import signal
import sys
from pathlib import Path

REQUEST_BYTES = 4096
CHUNK_BYTES = 65536
MAX_BYTES = 200 * 1024 * 1024


def limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    signal.alarm(61)
    limit(resource.RLIMIT_CORE, 0)
    limit(resource.RLIMIT_AS, 256 * 1024 * 1024)
    limit(resource.RLIMIT_CPU, 20)
    limit(resource.RLIMIT_NOFILE, 64)
    limit(resource.RLIMIT_FSIZE, 0)
    raw = sys.stdin.buffer.read(REQUEST_BYTES + 1)
    if len(raw) > REQUEST_BYTES:
        return 2
    value = json.loads(raw)
    fields = {
        "protocol",
        "hostname",
        "pin",
        "port",
        "username",
        "password",
        "private_key_path",
        "host_key_sha256",
        "use_tls",
        "path",
        "limit",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return 2
    if value["protocol"] not in {"sftp", "ftps"}:
        return 2
    for name in ["hostname", "pin", "username", "password", "path"]:
        if not isinstance(value[name], str) or len(value[name]) > REQUEST_BYTES:
            return 2
    ipaddress.ip_address(value["pin"])  # A worker never resolves an operator hostname.
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        return 2
    if type(value["limit"]) is not int or not 1 <= value["limit"] <= MAX_BYTES:
        return 2
    if value["private_key_path"] is not None and not isinstance(value["private_key_path"], str):
        return 2
    # Load this exact trusted companion without importing the application's
    # eager service package or inheriting its database and signing environment.
    spec = importlib.util.spec_from_file_location(
        "_owned_backup_transport", Path(__file__).with_name("vault_remote_transport.py")
    )
    if spec is None or spec.loader is None:
        return 2
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    size = 0

    def emit(chunk: bytes) -> None:
        nonlocal size
        if (
            not isinstance(chunk, bytes)
            or len(chunk) > CHUNK_BYTES
            or len(chunk) > value["limit"] - size
        ):
            raise ValueError("Bounded transfer refused")
        size += len(chunk)
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()

    if value["protocol"] == "sftp":
        with transport.sftp_connection(
            value["pin"],
            value["port"],
            value["username"],
            value["password"],
            value["private_key_path"],
            value["host_key_sha256"],
        ) as client:
            with client.open(value["path"], "rb") as source:
                while chunk := source.read(min(CHUNK_BYTES, value["limit"] - size + 1)):
                    emit(chunk)
    else:
        with transport.ftps_connection(
            value["hostname"],
            value["pin"],
            value["port"],
            value["username"],
            value["password"],
            value["use_tls"],
        ) as client:
            client.retrbinary("RETR " + value["path"], emit, blocksize=CHUNK_BYTES)
    if not size:
        return 2
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2  # No provider responses, credentials, paths or OS errors emitted.
    os._exit(code)
