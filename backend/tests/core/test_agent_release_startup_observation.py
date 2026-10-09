# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real local root plus controlled DB/key boundaries: orchestration, not SQL proof."""

import asyncio
import fcntl
import os

import pytest

from app.core.agent_release_runtime_policy import ReleaseRuntimePolicy
from app.core.agent_release_storage_root import initialize_release_storage_root
from app.services import agent_release_startup as startup


def policy_for(parent):
    parent.mkdir(mode=0o700)
    return ReleaseRuntimePolicy(str(parent), str(parent / ".managed-v1"), 1000, 100, 1000000, 100000)


@pytest.mark.asyncio
@pytest.mark.parametrize("storage_ready", (True, False))
@pytest.mark.parametrize("schema_ready", (True, False))
@pytest.mark.parametrize("identity_ready", (True, False))
async def test_prerequisites_are_independent_and_public_output_contains_no_paths_or_errors(
    tmp_path, monkeypatch, storage_ready, schema_ready, identity_ready,
):
    policy = policy_for(tmp_path / "release-parent")
    if not storage_ready:
        os.mkdir(policy.managed_root, mode=0o700)  # Existing unmarked data is refused.
    calls = []

    async def schema():
        calls.append("schema")
        if not schema_ready:
            raise RuntimeError("private database host and SQL details")

    async def identity():
        calls.append("identity")
        if not identity_ready:
            raise RuntimeError("private signing filesystem path")

    monkeypatch.setattr(startup, "_reference_schema", schema)
    monkeypatch.setattr(startup, "read_trusted_signing_identity", identity)
    observed = await startup.observe_release_startup(policy)
    assert calls == ["schema", "identity"]
    assert (observed.storage, observed.reference_schema, observed.signing_identity) == tuple(
        "observed" if ready else "unavailable" for ready in (storage_ready, schema_ready, identity_ready)
    )
    assert observed.all_observed == (storage_ready and schema_ready and identity_ready)
    public = observed.public()
    assert set(public) == {"checked_at", "storage", "reference_schema", "signing_identity",
                           "observation_only", "actions_revalidate_current_state"}
    assert public["observation_only"] is True and public["actions_revalidate_current_state"] is True
    assert str(tmp_path) not in str(public) and "private" not in str(public)
    if not storage_ready:
        assert os.listdir(policy.managed_root) == []  # No adoption/repair after other checks succeed.


@pytest.mark.asyncio
async def test_direct_cancellation_drains_native_initializer_before_returning(tmp_path, monkeypatch):
    policy = policy_for(tmp_path / "release-parent")
    calls = []

    async def observed():
        calls.append("observed")

    monkeypatch.setattr(startup, "_reference_schema", observed)
    monkeypatch.setattr(startup, "read_trusted_signing_identity", observed)
    parent = os.open(policy.legacy_root, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(parent, fcntl.LOCK_EX)
    task = asyncio.create_task(startup.observe_release_startup(policy))
    try:
        await asyncio.sleep(0.1)
        task.cancel()
        await asyncio.sleep(0.05)
        assert not task.done() and not os.path.exists(policy.managed_root)
        fcntl.flock(parent, fcntl.LOCK_UN)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        # Cancellation is delivered only after the admitted worker and both
        # controlled prerequisite probes have drained; no detached creation.
        assert calls == ["observed", "observed"]
        assert not initialize_release_storage_root(policy.managed_root).created
    finally:
        os.close(parent)
        if not task.done():
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=6)
