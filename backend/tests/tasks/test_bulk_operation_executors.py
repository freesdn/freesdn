# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The bulk executors must call the interface the factory actually returns.

Two rounds of repair were needed here, and the first one is the lesson.

fixed ``from app.adapters import adapter_factory`` -- a name that had
never existed -- and added ``test_task_imports_resolve.py``, which proves every
deferred import resolves. That test passes. It also never executes an operation,
so it could not see that the very next lines were wrong against ``BaseAdapter``:

    get_running_config(device_id)        was called with no argument
    normalize_config(config)             is async; was not awaited
    diff_config(desired, running)        args passed reversed, and unawaited
    push_full_config(device_id, config)  was called without the device id
    reboot_device(device_id)             was called as a bare reboot()
    upgrade_firmware(device_id)          was called as firmware_update(url, ver)

So the feature stayed dead: the import worked and every call after it raised,
and ``_execute_on_device``'s broad except recorded each device as failed.

These tests drive the real executors against adapters shaped like the documented
contract, so a signature drift fails here rather than in the field.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.tasks import bulk_operations as bulk


class _ContractAdapter:
    """An adapter shaped like ``BaseAdapter``. Records how it was called."""

    def __init__(self, *, success: bool = True) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self._success = success

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    def _result(self):
        return SimpleNamespace(success=self._success, message="device refused")

    async def get_running_config(self, device_id: str) -> dict:
        self.calls.append(("get_running_config", (device_id,)))
        return {"running": True}

    async def normalize_config(self, config: dict) -> dict:
        self.calls.append(("normalize_config", (config,)))
        return dict(config)

    async def diff_config(self, desired: dict, running: dict):
        self.calls.append(("diff_config", (desired, running)))
        return {"changed": ["x"]}

    async def push_full_config(self, device_id: str, config: dict):
        self.calls.append(("push_full_config", (device_id, config)))
        return self._result()

    async def reboot_device(self, device_id: str):
        self.calls.append(("reboot_device", (device_id,)))
        return self._result()

    async def upgrade_firmware(self, device_id: str):
        self.calls.append(("upgrade_firmware", (device_id,)))
        return self._result()


def _device():
    return SimpleNamespace(
        id=uuid4(),
        external_id="EXT-1",
        mac_address="aa:bb:cc:dd:ee:ff",
        model="TestModel",
        controller=SimpleNamespace(id=uuid4()),
    )


@pytest.fixture()
def adapter(monkeypatch):
    ad = _ContractAdapter()
    monkeypatch.setattr(bulk, "_adapter_for_device", lambda _d: ad)
    return ad


@pytest.mark.asyncio
async def test_reboot_calls_reboot_device_with_the_device_id(adapter) -> None:
    """Fails before the fix: it probed for a bare ``reboot()`` and raised
    NotImplementedError for every adapter the factory returns."""
    device = _device()
    await bulk._reboot_device(device)

    names = [c[0] for c in adapter.calls]
    assert names == ["reboot_device"], f"unexpected calls: {adapter.calls}"
    assert adapter.calls[0][1] == ("EXT-1",)


@pytest.mark.asyncio
async def test_firmware_calls_upgrade_firmware_with_the_device_id(adapter) -> None:
    """Fails before the fix: ``firmware_update(url, version)`` is not the
    interface, and where the name exists it takes no positional arguments."""
    device = _device()
    await bulk._firmware_update_device(device, {"firmware_url": "https://x/fw.bin"})

    names = [c[0] for c in adapter.calls]
    assert names == ["upgrade_firmware"], f"unexpected calls: {adapter.calls}"
    assert adapter.calls[0][1] == ("EXT-1",)


@pytest.mark.asyncio
async def test_config_push_uses_the_documented_signatures(monkeypatch, adapter) -> None:
    """Arity, await-ness and argument ORDER all have to be right."""
    device = _device()

    class _Resolver:
        def __init__(self, _db):
            ...

        async def resolve(self, _device):
            return {"desired": True}

    monkeypatch.setattr(bulk, "TemplateResolver", _Resolver)

    await bulk._push_config_to_device(AsyncMock(), device, None)

    by_name = dict(adapter.calls)
    assert ("get_running_config", ("EXT-1",)) in adapter.calls, adapter.calls
    # diff_config(desired, running) -- NOT (running, desired)
    desired_arg, running_arg = by_name["diff_config"]
    assert desired_arg == {"desired": True}, "diff_config received the args reversed"
    assert running_arg == {"running": True}, "diff_config received the args reversed"
    # push_full_config(device_id, config)
    dev_arg, cfg_arg = by_name["push_full_config"]
    assert dev_arg == "EXT-1"
    assert cfg_arg == {"desired": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation,call",
    [
        ("reboot", lambda d: bulk._reboot_device(d)),
        ("firmware", lambda d: bulk._firmware_update_device(d, {"firmware_url": "https://x"})),
    ],
)
async def test_a_refused_operation_is_not_reported_as_success(
    monkeypatch, operation, call
) -> None:
    """An adapter reports failure two ways; a non-throwing
    ``AdapterResult(success=False)`` must not pass silently."""
    refusing = _ContractAdapter(success=False)
    monkeypatch.setattr(bulk, "_adapter_for_device", lambda _d: refusing)

    with pytest.raises(RuntimeError, match="refused"):
        await call(_device())


@pytest.mark.asyncio
async def test_an_adapter_missing_the_capability_says_so_clearly(monkeypatch) -> None:
    """The operator should learn FreeSDN cannot do this for that vendor, not
    read an AttributeError that looks like the device refused."""

    class _Bare:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(bulk, "_adapter_for_device", lambda _d: _Bare())

    with pytest.raises(NotImplementedError, match="does not support"):
        await bulk._reboot_device(_device())


# ---------------------------------------------------------------------------
# A placeholder is not a capability (F-03)
# ---------------------------------------------------------------------------
#
# BaseAdapter defines these methods and returns
# AdapterResult.fail(error_code="NOT_SUPPORTED"), so an adapter that never
# overrode them still answers hasattr() with True. The capability check passed,
# the placeholder ran, and the operator saw a DEVICE failure for something
# FreeSDN does not implement for that vendor.
#
# The _ContractAdapter above is a standalone class, so it could never surface
# this -- the fake implemented what no production adapter does.


def test_an_inherited_placeholder_is_not_treated_as_support() -> None:
    """Fails before the fix: hasattr() saw the base method and allowed it."""
    from app.adapters.base import BaseAdapter

    class _NeverOverrode(BaseAdapter):
        """Inherits the NOT_SUPPORTED placeholder, like every real adapter."""

    # BaseAdapter is abstract and the check only reads ``type(adapter).<name>``,
    # so clear the abstract set rather than stubbing six unrelated methods.
    _NeverOverrode.__abstractmethods__ = frozenset()
    adapter = _NeverOverrode("h", "u", "p")

    with pytest.raises(NotImplementedError, match="does not support"):
        bulk._require_adapter_capability(adapter, _device(), "push_full_config")


def test_a_real_override_is_accepted() -> None:
    """The check must not reject an adapter that genuinely implements it."""
    from app.adapters.base import BaseAdapter

    class _Overrode(BaseAdapter):
        async def push_full_config(self, device_id: str, config: dict):  # type: ignore[override]
            return SimpleNamespace(success=True)

    _Overrode.__abstractmethods__ = frozenset()
    bulk._require_adapter_capability(_Overrode("h", "u", "p"), _device(), "push_full_config")


def test_the_bulk_config_push_capability_is_honestly_reported() -> None:
    """Documents the live state: no production adapter implements the push.

    This is deliberately an assertion about the CODEBASE, not a mock. If someone
    implements push_full_config for a vendor, this test fails and tells them to
    update the record -- which is the moment bulk push_config becomes real.
    """
    from pathlib import Path

    adapters_dir = Path(__file__).resolve().parents[2] / "app" / "adapters"
    implementers = sorted(
        p.parent.name
        for p in adapters_dir.glob("*/adapter.py")
        if "def push_full_config" in p.read_text(encoding="utf-8")
    )
    assert implementers == [], (
        f"push_full_config is now implemented by {implementers}. Bulk push_config "
        "can finally apply drift for those vendors -- update this test, and make "
        "sure the UI no longer advertises the operation as universally available."
    )


@pytest.mark.asyncio
async def test_a_firmware_job_from_the_UI_reaches_the_adapter(adapter) -> None:
    """The UI/backend seam (F-04).

    The shipped Bulk Operations page renders the config textarea for push_config
    ONLY, so a firmware job created from the product arrives with config=None.
    The executor used to require firmware_url and raise before touching an
    adapter, so the operation could not be run from the UI at all -- and the
    earlier test masked it by hand-supplying a URL the UI cannot produce.

    Fails before the fix with ValueError: firmware_url is required.
    """
    await bulk._firmware_update_device(_device(), None)

    assert [c[0] for c in adapter.calls] == ["upgrade_firmware"], (
        f"a UI-created firmware job must reach the adapter; got {adapter.calls}"
    )
