# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The TrueNAS write gate applies the shared read-only rule.

Since 26.12 every adapter write gate refuses while ``ADAPTER_READ_ONLY`` is on
unless the call runs inside an approved staged apply
(``apply_context.read_only_refuses_write``); ``force=True`` alone no longer
lifts it. The TrueNAS management writes (dataset create, snapshot create and
delete, scrub start) and ``upload_file`` checked only ``force``, so the lock
depended on every caller being the staged applier. They now apply the same
rule, and the staged applier, which runs inside ``apply_window()``, is
unaffected.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.adapters.apply_context import apply_window
from app.adapters.exceptions import AdapterReadOnlyError
from app.adapters.truenas.adapter import TrueNASAdapter


class _FakeApi:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def create_dataset(self, name: str, *, comments: str | None = None) -> dict:
        self.calls.append("create_dataset")
        return {"id": name}

    async def create_snapshot(self, dataset: str, name: str, *, recursive: bool = False) -> dict:
        self.calls.append("create_snapshot")
        return {"id": f"{dataset}@{name}"}

    async def delete_snapshot(self, snapshot_id: str) -> bool:
        self.calls.append("delete_snapshot")
        return True

    async def start_scrub(self, pool_name: str) -> int:
        self.calls.append("start_scrub")
        return 7

    async def upload_blob(self, *, dest_path: str, blob: bytes, mode: Any = None) -> int:
        self.calls.append("upload_blob")
        return 9

    async def job_wait(self, job_id: int, *, timeout: float = 120.0) -> dict:
        return {"id": job_id, "state": "SUCCESS", "error": None}


def _adapter() -> TrueNASAdapter:
    a = TrueNASAdapter(host="nas.lab", api_key="k", verify_ssl=False)
    a._transport = "ws"
    a._api = _FakeApi()
    return a


WRITES: list[tuple[str, dict[str, Any]]] = [
    ("create_dataset", {"name": "tank/backups"}),
    ("create_snapshot", {"dataset": "tank/data", "name": "nightly"}),
    ("delete_snapshot", {"snapshot_id": "tank/data@nightly"}),
    ("start_scrub", {"pool_name": "tank"}),
    ("upload_file", {"dataset_path": "/mnt/tank/freesdn", "filename": "x.jpg", "blob": b"x"}),
]


@pytest.fixture
def read_only(monkeypatch: pytest.MonkeyPatch):
    import app.core.runtime_flags as flags

    def _set(value: bool) -> None:
        monkeypatch.setattr(flags, "is_adapter_read_only", lambda: value)

    return _set


@pytest.mark.parametrize(("method", "kwargs"), WRITES)
async def test_force_alone_does_not_lift_read_only(read_only, method, kwargs) -> None:
    read_only(True)
    a = _adapter()

    with pytest.raises(AdapterReadOnlyError):
        await getattr(a, method)(**kwargs, force=True)

    assert a._api.calls == [], "the appliance was called while read-only"


@pytest.mark.parametrize(("method", "kwargs"), WRITES)
async def test_an_approved_staged_apply_still_writes(read_only, method, kwargs) -> None:
    read_only(True)
    a = _adapter()

    with apply_window():
        await getattr(a, method)(**kwargs, force=True)

    assert a._api.calls, "the staged apply was refused"


@pytest.mark.parametrize(("method", "kwargs"), WRITES)
async def test_read_write_mode_is_unchanged(read_only, method, kwargs) -> None:
    read_only(False)
    a = _adapter()

    await getattr(a, method)(**kwargs, force=True)

    assert a._api.calls
