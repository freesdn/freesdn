# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private unfrozen real-filesystem probes; no production or deployment claim.

All targets, aliases and sentinels belong to the pytest temporary directory.
These are proposed Linux archive-storage contracts, not confirmed findings.
"""

import os

import pytest

import app.services.backup as backup_module
from app.services.backup import LocalStorageBackend


async def outcome(awaitable):
    try:
        return await awaitable, None
    except (OSError, ValueError) as error:
        return None, type(error).__name__


@pytest.mark.parametrize("length", [0, 31, 32, 33, 96])
async def test_local_load_respects_a_real_bounded_file(monkeypatch, tmp_path, request, length):
    monkeypatch.setattr(backup_module, "MAX_BACKUP_IMPORT_BYTES", 32)
    path = tmp_path / "archive.fsdn"
    original = bytes(range(length))
    path.write_bytes(original)
    path.chmod(0o600)
    loaded, error = await outcome(LocalStorageBackend({"path": str(tmp_path)}).load(path.name))
    request.node.user_properties.extend([
        ("file_bytes", length), ("returned_bytes", len(loaded) if loaded is not None else None),
        ("controlled_error", error is not None), ("source_unchanged", path.read_bytes() == original),
    ])
    if length <= 32:
        assert error is None and loaded == original
    else:
        assert loaded is None and error is not None
    assert path.read_bytes() == original


@pytest.mark.parametrize("alias", ["final_symlink", "ancestor_symlink", "hardlink"])
async def test_local_load_refuses_aliases_without_touching_the_target(tmp_path, request, alias):
    root = tmp_path / "backup-root"
    root.mkdir(mode=0o700)
    # The target is also in the selected root: path-containment alone cannot
    # distinguish a legitimate archive inode from a symlink/hardlink alias.
    store = root / "objects"
    store.mkdir(mode=0o700)
    target = store / "original.fsdnvault"
    sentinel = b"owned nonsecret sentinel"
    target.write_bytes(sentinel)
    target.chmod(0o600)
    if alias == "final_symlink":
        selected = root / "alias.fsdnvault"
        selected.symlink_to(target)
    elif alias == "ancestor_symlink":
        (root / "alias-directory").symlink_to(store, target_is_directory=True)
        selected = root / "alias-directory" / target.name
    else:
        selected = root / "alias.fsdnvault"
        os.link(target, selected)
    loaded, error = await outcome(LocalStorageBackend({"path": str(root)}).load(str(selected.relative_to(root))))
    unchanged = target.read_bytes() == sentinel and target.stat().st_mode & 0o777 == 0o600
    request.node.user_properties.extend([
        ("controlled_error", error is not None), ("returned_target_bytes", loaded == sentinel),
        ("target_content_and_mode_unchanged", unchanged),
    ])
    assert loaded is None and error is not None
    assert unchanged


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
async def test_preexisting_temporary_alias_cannot_overwrite_an_owned_external_sentinel(tmp_path, request, alias):
    root = tmp_path / "backup-root"
    root.mkdir(mode=0o700)
    backend = LocalStorageBackend({"path": str(root)})
    backup_id, filename = "owned-id", "owned.fsdnvault"
    directory = root / backend._date_prefix()
    directory.mkdir(parents=True, mode=0o700)
    target = tmp_path / "outside-owned-sentinel"
    sentinel = b"owned external bytes must survive"
    target.write_bytes(sentinel)
    target.chmod(0o600)
    fixed_temporary = directory / (backup_id + "_" + filename + ".tmp")
    if alias == "symlink":
        fixed_temporary.symlink_to(target)
    else:
        os.link(target, fixed_temporary)
    payload = b"owned encrypted archive stand-in"
    selected, error = await outcome(backend.save(backup_id, payload, filename))
    unchanged = target.read_bytes() == sentinel
    returned_exact = bool(selected and (root / selected).is_file() and (root / selected).read_bytes() == payload)
    request.node.user_properties.extend([
        ("controlled_error", error is not None), ("outside_owned_sentinel_unchanged", unchanged),
        ("returned_archive_exact", returned_exact),
    ])
    assert unchanged
    assert error is not None or returned_exact


@pytest.mark.parametrize("credential_shape", ["config", "vault"])
async def test_normal_save_and_load_preserves_shared_application_uid_compatibility(tmp_path, request, credential_shape):
    root = tmp_path / "shared-backup-volume"
    root.mkdir(mode=0o700)
    writer = LocalStorageBackend({"path": str(root)})
    reader = LocalStorageBackend({"path": str(root)})
    suffix = "fsdn" if credential_shape == "config" else "fsdnvault"
    payload = b"owned binary envelope stand-in\x00\xff"
    selected = await writer.save("owned", payload, "archive." + suffix)
    loaded = await reader.load(selected)
    file = root / selected
    request.node.user_properties.extend([
        ("same_process_uid", file.stat().st_uid == os.geteuid()),
        ("exact_roundtrip", loaded == payload), ("selected_path_stays_in_root", file.resolve().is_relative_to(root.resolve())),
    ])
    assert file.stat().st_uid == os.geteuid() and loaded == payload
    assert file.resolve().is_relative_to(root.resolve())
    assert await reader.get_size(selected) == len(payload)
    assert await reader.exists(selected)
