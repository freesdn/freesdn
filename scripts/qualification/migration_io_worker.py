# SPDX-License-Identifier: AGPL-3.0-only
"""Private migration worker, launched by migration_io with explicit owned FDs.

Only this expendable process performs potentially blocking filesystem I/O. Its
parent supervises the whole process group. Kernel uninterruptible I/O and an
untrusted privileged filesystem/daemon are outside this contract.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import stat
import subprocess
import sys

BLOCK = 65536
MIB = 1024**2
GIB = 1024**3
WORK_NAMES = {"roles.sql", "database.dump", "digest.tmp", "receipt.pending", "receipt.json"}


class Refused(Exception):
    """No data or command arguments belong in worker diagnostics."""


def require(value):
    if not value:
        raise Refused


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(_value):
    raise Refused


def state(fd):
    info = os.fstat(fd)
    return {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid,
            "mode": info.st_mode, "nlink": info.st_nlink, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def directory(fd):
    require(type(fd) is int and fd >= 3)
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077)


def check_file(spec, *, output=False, complete=False, written=0):
    require(type(spec) is dict and set(spec) == {"fd", "parent", "name", "identity", "position"})
    require(type(spec["fd"]) is int and spec["fd"] >= 3)
    directory(spec["parent"])
    name = spec["name"]
    require(type(name) is str and name not in {"", ".", ".."} and "/" not in name and "\x00" not in name)
    current = state(spec["fd"])
    expected = spec["identity"]
    require(stat.S_ISREG(current["mode"]) and current["uid"] == os.geteuid()
            and current["nlink"] == 1 and not current["mode"] & 0o022)
    named = os.stat(name, dir_fd=spec["parent"], follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (current["dev"], current["ino"]))
    if output:
        require(all(current[key] == expected[key] for key in ("dev", "ino", "uid", "mode", "nlink")))
        require(expected["size"] == spec["position"] == 0 and current["size"] == written)
        require(os.lseek(spec["fd"], 0, os.SEEK_CUR) == written)
    else:
        require(current == expected and 0 <= spec["position"] <= expected["size"])
        if complete:
            require(os.lseek(spec["fd"], 0, os.SEEK_CUR) == expected["size"])
    return current


def workspace(fd, policy, increment=0):
    if fd is None:
        return
    directory(fd)
    total = 0
    count = 0
    with os.scandir(fd) as entries:
        for entry in entries:
            count += 1
            require(count <= len(WORK_NAMES) and entry.name in WORK_NAMES)
            info = entry.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and not info.st_mode & 0o077)
            total += info.st_size
    require(total + increment <= policy["workspace_bytes"])


def space(fd, policy, increment):
    info = os.fstatvfs(fd)
    floor = policy["min_free_bytes"]
    if floor is None:
        # Small dedicated filesystems still keep a meaningful reserve. On
        # ordinary large disks this is4GiB. Not a reservation against others.
        floor = min(4 * GIB, max(1, info.f_blocks * info.f_frsize // 4))
    require(info.f_bavail * info.f_frsize >= floor + increment)


def write_all(fd, value):
    pending = memoryview(value)
    while pending:
        done = os.write(fd, pending)
        require(done > 0)
        pending = pending[done:]


def request():
    # No buffered reader: bytes after the newline belong to the input stream.
    raw = bytearray()
    while len(raw) <= BLOCK:
        char = os.read(0, 1)
        require(char)
        raw.extend(char)
        if char == b"\n":
            break
    require(len(raw) <= BLOCK and raw.endswith(b"\n"))
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    require(type(value) is dict and set(value) == {"kind", "policy", "argv", "input_size", "stdin", "stdout", "workspace"})
    require(value["kind"] in {"command", "read", "hash", "receipt"})
    policy = value["policy"]
    require(type(policy) is dict and set(policy) == {"capture_bytes", "input_bytes", "file_bytes", "workspace_bytes", "min_free_bytes", "operation_seconds"})
    for name in ("capture_bytes", "input_bytes"):
        require(type(policy[name]) is int and 1 <= policy[name] <= 64 * MIB)
    for name in ("file_bytes", "workspace_bytes"):
        require(type(policy[name]) is int and 1 <= policy[name] <= 4 * 1024**4)
    require(policy["min_free_bytes"] is None or type(policy["min_free_bytes"]) is int and 1 <= policy["min_free_bytes"] <= 4 * 1024**4)
    duration = policy["operation_seconds"]
    require(type(duration) in (int, float) and math.isfinite(duration) and 0 < duration <= 7 * 86400)
    require(type(value["input_size"]) is int and 0 <= value["input_size"] <= policy["input_bytes"])
    require(not (value["input_size"] and value["stdin"] is not None))
    if value["stdin"] is not None:
        initial = check_file(value["stdin"])
        bound = policy["input_bytes"] if value["kind"] == "read" else policy["file_bytes"]
        require(initial["size"] <= bound)
        require(os.lseek(value["stdin"]["fd"], 0, os.SEEK_CUR) == value["stdin"]["position"])
    if value["stdout"] is not None:
        check_file(value["stdout"], output=True)
        if value["stdin"] is not None:
            require((value["stdout"]["identity"]["dev"], value["stdout"]["identity"]["ino"])
                    != (value["stdin"]["identity"]["dev"], value["stdin"]["identity"]["ino"]))
        if value["workspace"] is not None:
            current, parent = os.fstat(value["workspace"]), os.fstat(value["stdout"]["parent"])
            require((current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino))
    workspace(value["workspace"], policy)
    return value


def command(spec):
    argv, policy = spec["argv"], spec["policy"]
    require(type(argv) is list and argv and all(type(v) is str and v and "\x00" not in v for v in argv))
    input_spec, output_spec = spec["stdin"], spec["stdout"]
    remaining = input_spec["identity"]["size"] - input_spec["position"] if input_spec else spec["input_size"]
    source = input_spec["fd"] if input_spec else 0
    captured = written = 0
    pending = b""
    child = None
    try:
        # Inherit the worker's session/group; only the outer supervisor owns
        # group termination. Pinned file descriptors are NOT inherited again.
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True, bufsize=0)
        with selectors.DefaultSelector() as selector:
            for label in ("stdout", "stderr"):
                stream = getattr(child, label)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if remaining:
                os.set_blocking(child.stdin.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                child.stdin.close()
            while selector.get_map() or child.poll() is None:
                for key, _ in selector.select(0.05):
                    if key.data == "stdin":
                        if not pending:
                            if input_spec:
                                check_file(input_spec)
                                require(os.lseek(source, 0, os.SEEK_CUR) == input_spec["identity"]["size"] - remaining)
                            pending = os.read(source, min(BLOCK, remaining))
                            require(pending)
                            remaining -= len(pending)
                        try:
                            sent = os.write(key.fd, pending)
                        except BlockingIOError:
                            continue
                        require(sent > 0)
                        pending = pending[sent:]
                        if not remaining and not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    try:
                        chunk = os.read(key.fd, BLOCK)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if key.data == "stdout" and output_spec:
                        require(written + len(chunk) <= policy["file_bytes"])
                        check_file(output_spec, output=True, written=written)
                        workspace(spec["workspace"], policy, len(chunk))
                        space(output_spec["fd"], policy, len(chunk))
                        write_all(output_spec["fd"], chunk)
                        written += len(chunk)
                    else:
                        captured += len(chunk)
                        require(captured <= policy["capture_bytes"])
                        if key.data == "stdout":
                            write_all(1, chunk)
            require(child.wait(timeout=0.2) == 0 and not remaining and not pending)
        if input_spec:
            check_file(input_spec, complete=True)
        require(os.read(0, 1) == b"")
        if output_spec:
            os.fsync(output_spec["fd"])
            check_file(output_spec, output=True, written=written)
        workspace(spec["workspace"], policy)
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=0.2)
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()


def read_file(spec):
    require(spec["stdin"] is not None and spec["stdout"] is None and not spec["input_size"] and spec["argv"] is None)
    require(os.read(0, 1) == b"")
    item = spec["stdin"]
    remaining = item["identity"]["size"] - item["position"]
    digest = hashlib.sha256()
    while remaining:
        check_file(item)
        require(os.lseek(item["fd"], 0, os.SEEK_CUR) == item["identity"]["size"] - remaining)
        chunk = os.read(item["fd"], min(BLOCK, remaining))
        require(chunk)
        remaining -= len(chunk)
        if spec["kind"] == "hash":
            digest.update(chunk)
        else:
            write_all(1, chunk)
    check_file(item, complete=True)
    workspace(spec["workspace"], spec["policy"])
    if spec["kind"] == "hash":
        write_all(1, digest.hexdigest().encode())


def receipt(spec):
    fd, policy = spec["workspace"], spec["policy"]
    require(fd is not None and spec["stdin"] is None and spec["stdout"] is None and spec["argv"] is None)
    require(0 < spec["input_size"] <= policy["capture_bytes"])
    directory(fd)
    output = os.open("receipt.pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        remaining = spec["input_size"]
        while remaining:
            chunk = os.read(0, min(BLOCK, remaining))
            require(chunk)
            workspace(fd, policy, len(chunk))
            space(output, policy, len(chunk))
            write_all(output, chunk)
            remaining -= len(chunk)
        require(os.read(0, 1) == b"")
        os.fsync(output)
        named, opened = os.stat("receipt.pending", dir_fd=fd, follow_symlinks=False), os.fstat(output)
        require(stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)
                and opened.st_nlink == 1 and opened.st_size == spec["input_size"])
        # Exclusive, atomic publication; an existing receipt is never replaced.
        os.link("receipt.pending", "receipt.json", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink("receipt.pending", dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(output)


def interrupted(_signum, _frame):
    raise InterruptedError


def main():
    signal.signal(signal.SIGTERM, interrupted)
    try:
        spec = request()
        if spec["kind"] == "command":
            command(spec)
        elif spec["kind"] in {"hash", "read"}:
            read_file(spec)
        else:
            receipt(spec)
        return 0
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, Refused, subprocess.SubprocessError):
        # Never echo exception repr, argv, file names, bytes, SQL or diagnostics.
        return 74


if __name__ == "__main__":
    sys.exit(main())
