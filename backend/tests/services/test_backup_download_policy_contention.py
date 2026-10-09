# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual independent process metadata locks with unchanged transfer capacity."""

import concurrent.futures
import fcntl
import os
import select
import subprocess
import sys
import threading
import time

import pytest

from app.core.backup_downloads import DownloadCapacityError, DownloadPool
from tests.services.test_backup_download_pool import open_owned


@pytest.mark.parametrize("initialized", [False, True])
@pytest.mark.parametrize("behavior", ["release", "hold", "free"])
def test_transient_metadata_lock_does_not_consume_transfer_capacity(
    tmp_path, monkeypatch, request, initialized, behavior
):
    root = tmp_path / "pool"
    pool = DownloadPool(root, slots=2, limit=65536, free_floor=0)
    if initialized:
        pool.acquire().close()
    else:
        root.mkdir(mode=0o700)
    child = None
    contended = threading.Event()
    original = fcntl.flock

    def observed(fd, operation):
        try:
            return original(fd, operation)
        except BlockingIOError:
            if os.readlink(f"/proc/self/fd/{fd}") == str(root / "pool-policy.json"):
                contended.set()
            raise

    monkeypatch.setattr(fcntl, "flock", observed)
    if behavior != "free":
        child = subprocess.Popen([
            sys.executable, "-c",
            "import os,fcntl,sys; f=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600); "
            "fcntl.flock(f,fcntl.LOCK_EX); print('owned-lock',flush=True); "
            "sys.stdin.readline(); os.close(f)",
            str(root / "pool-policy.json"),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "owned-lock"
    lease = None
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            began = time.monotonic()
            future = executor.submit(pool.acquire)
            if child:
                assert contended.wait(2), "Actual held policy flock was not encountered"
            if behavior == "release":
                child.stdin.write("release\n")
                child.stdin.flush()
                child.wait(timeout=2)
            if behavior == "hold":
                with pytest.raises(DownloadCapacityError):
                    future.result(timeout=2)
                elapsed = time.monotonic() - began
                assert elapsed < 1.8, "Metadata lock admission must remain bounded"
            else:
                lease = future.result(timeout=2)
                elapsed = time.monotonic() - began
                assert elapsed < 1.8
                # The other actual slot remains available; no fictitious
                # transfer reservation was consumed by metadata contention.
                second = pool.acquire()
                second.close()
            request.node.user_properties.extend({
                "independent_process_policy_lock": bool(child),
                "actual_lock_contention": contended.is_set(),
                "admitted_after_release_or_free": lease is not None,
                "metadata_wait_seconds": elapsed,
                "transfer_slots_unchanged": pool.slots == 2,
            }.items())
    finally:
        if lease:
            lease.close()
        if child:
            if child.poll() is None:
                child.stdin.write("release\n")
                child.stdin.flush()
            child.communicate(timeout=3)
        assert not open_owned(root)
