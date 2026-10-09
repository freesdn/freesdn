# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unfrozen owned-filesystem contracts, not runtime findings or NFS proof."""

import os

import pytest

from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from app.services.backup import LocalStorageBackend


async def outcome(awaitable):
    try:
        return await awaitable, None
    except (OSError, ValueError) as error:
        return None, type(error).__name__


@pytest.mark.parametrize("operation", ["delete", "exists", "get_size"])
@pytest.mark.parametrize("alias", ["final_symlink", "ancestor_symlink", "hardlink"])
async def test_archive_metadata_operations_refuse_aliases_and_preserve_target(
    tmp_path, request, operation, alias,
):
    root = tmp_path / "backup-root"
    objects = root / "objects"
    objects.mkdir(parents=True, mode=0o700)
    target = objects / "original.fsdn"
    sentinel = b"owned original archive bytes"
    target.write_bytes(sentinel)
    target.chmod(0o600)
    if alias == "final_symlink":
        selected = root / "alias.fsdn"
        selected.symlink_to(target)
    elif alias == "ancestor_symlink":
        (root / "alias-directory").symlink_to(objects, target_is_directory=True)
        selected = root / "alias-directory" / target.name
    else:
        selected = root / "alias.fsdn"
        os.link(target, selected)
    backend = LocalStorageBackend({"path": str(root)})
    value, error = await outcome(getattr(backend, operation)(str(selected.relative_to(root))))
    preserved = target.exists() and target.read_bytes() == sentinel
    request.node.user_properties.extend([
        ("operation", operation), ("alias", alias), ("result", value),
        ("controlled_error", error is not None), ("original_target_preserved", preserved),
    ])
    assert error is not None
    assert preserved


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o660])
async def test_supported_existing_regular_archive_modes_are_not_silently_changed(
    tmp_path, request, mode,
):
    root = tmp_path / "shared-root"
    root.mkdir(mode=0o770)
    root.chmod(0o770)
    target = root / "legacy.fsdn"
    payload = b"owned legacy regular archive"
    target.write_bytes(payload)
    target.chmod(mode)
    before = (target.stat().st_mode, root.stat().st_mode)
    backend = LocalStorageBackend({"path": str(root)})
    loaded = await backend.load(target.name)
    exists = await backend.exists(target.name)
    size = await backend.get_size(target.name)
    after = (target.stat().st_mode, root.stat().st_mode)
    request.node.user_properties.extend([
        ("exact_bytes", loaded == payload), ("original_modes_preserved", before == after),
        ("primary_group_matches", root.stat().st_gid == os.getegid()),
    ])
    assert loaded == payload and exists and size == len(payload)
    assert before == after


@pytest.mark.parametrize("extra", [-1, 0, 1])
async def test_local_load_enforces_the_shipping_bound_on_sparse_regular_files(tmp_path, request, extra):
    # The unchanged shipping limit, not a smaller patched test constant.
    size = MAX_BACKUP_IMPORT_BYTES + extra
    target = tmp_path / "owned-sparse.fsdn"
    with target.open("wb") as handle:
        handle.truncate(size)
    target.chmod(0o600)
    loaded, error = await outcome(LocalStorageBackend({"path": str(tmp_path)}).load(target.name))
    returned_size = len(loaded) if loaded is not None else None
    sparse_zero_edges = loaded is not None and loaded[:1] == loaded[-1:] == b"\x00"
    request.node.user_properties.extend([
        ("shipping_limit", MAX_BACKUP_IMPORT_BYTES), ("file_size", size),
        ("returned_size", returned_size), ("controlled_error", error is not None),
        ("file_size_unchanged", target.stat().st_size == size),
    ])
    if extra <= 0:
        assert error is None and returned_size == size and sparse_zero_edges
    else:
        assert error is not None and loaded is None
    assert target.stat().st_size == size


@pytest.mark.parametrize("operation", ["delete", "exists"])
@pytest.mark.parametrize("missing_parent", [False, True])
async def test_absent_archive_operations_keep_their_idempotent_contract(tmp_path, request, operation, missing_parent):
    path = "missing/date/archive.fsdn" if missing_parent else "archive.fsdn"
    backend = LocalStorageBackend({"path": str(tmp_path)})
    value = await getattr(backend, operation)(path)
    expected = operation == "delete"
    request.node.user_properties.extend([
        ("original_idempotent_result", value is expected),
        ("no_directories_created", not any(tmp_path.iterdir())),
    ])
    assert value is expected
    assert not any(tmp_path.iterdir())
