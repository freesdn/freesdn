"""A post-backup check must reuse the pool's live loop and dispose before exit."""

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("fail", [False, True])
def test_pooled_checks_share_loop_and_cleanup_on_failure(monkeypatch, fail):
    source = Path(__file__).parents[1] / "qualification/install_acceptance_probe.py"
    spec = importlib.util.spec_from_file_location("install_probe", source)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    loops = []

    async def query():
        loop = asyncio.get_running_loop()
        if loops:
            assert loop is loops[0]
        loops.append(loop)

    async def dispose():
        assert asyncio.get_running_loop() is loops[0]
        assert not loops[0].is_closed()
        loops.append(asyncio.get_running_loop())

    monkeypatch.setitem(
        sys.modules, "app.db.session", SimpleNamespace(dispose_api_engines=dispose)
    )
    try:
        with probe.database_probe_loop() as runner:
            runner.run(query())
            runner.run(query())
            if fail:
                raise ValueError("HTTP acceptance failed")
    except ValueError:
        assert fail
    assert len(loops) == 3
    assert loops[0].is_closed()
