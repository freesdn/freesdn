# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A tracked shell script must be executable in the git index.

``./install.sh`` is the first command in the README, the docs and the install
guide. On a fresh clone on Linux it did this::

    $ ./install.sh --tier lite
    bash: ./install.sh: Permission denied     (exit 126)

The file was mode 100644 in the index -- and so were fourteen others, including
``setup.sh``, ``scripts/start.sh``, ``scripts/reset-dev.sh`` and four container
entrypoints. Nothing was wrong with any of the scripts. Git records the execute
bit as part of the object mode, and Windows checkouts run with
``core.fileMode=false``, so a script added or re-added from Windows is committed
644 and no local run ever notices: the author invokes ``bash install.sh``, and
the Dockerfiles ``chmod +x`` their own entrypoints after COPY. The only person
who meets it is someone doing exactly what the docs say on a machine that
enforces the bit -- i.e. every new user.

Scope is shell scripts only, deliberately. Twelve tracked ``.py`` files also
carry a shebang, but Python entrypoints in this repo are invoked as
``python scripts/foo.py`` and do not need the bit; including them would add
twelve findings of no consequence and make the ratchet easy to dismiss. The
one ``.ps1`` is Windows, where the bit means nothing.

The git INDEX is the source of truth here, not ``os.stat``: on Windows the
filesystem reports every file as executable, so a filesystem check would pass
on the machine where this bug is produced.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest


def _repo_root() -> pathlib.Path | None:
    """Nearest ancestor that is a git work tree."""
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None


_ROOT = _repo_root()

pytestmark = pytest.mark.skipif(
    _ROOT is None or shutil.which("git") is None,
    reason="not a git checkout, or git is unavailable (backend-only mount)",
)

_EXECUTABLE = "100755"


def _tracked_shell_scripts() -> list[tuple[str, str]]:
    """(mode, path) for every tracked ``*.sh``, straight from the index."""
    assert _ROOT is not None
    result = subprocess.run(
        ["git", "ls-files", "-s", "--", "*.sh"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    entries: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        # "<mode> <object> <stage>\t<path>"
        meta, _, path = line.partition("\t")
        if path:
            entries.append((meta.split()[0], path))
    return entries


def _is_installer(path: str) -> bool:
    """True for the installer in EITHER checkout layout.

    This file ships. In the monorepo the installer is ``freesdn/install.sh``; the
    flatten puts it at the repo root as ``install.sh``, so a hardcoded
    monorepo-relative name fails in the published repo -- turning the public
    CI red on the very test that guards the exec bit, while every script in it is
    correctly executable. Matching on the trailing component covers both layouts
    and any future relocation, and still fails if the installer disappears.
    """
    return path == "install.sh" or path.endswith("/install.sh")


@pytest.mark.parametrize(
    "layout,paths,expected",
    [
        ("monorepo", {"freesdn/install.sh", "freesdn/scripts/start.sh"}, True),
        ("public flatten", {"install.sh", "scripts/start.sh"}, True),
        ("installer missing", {"scripts/start.sh", "docker/entrypoint.sh"}, False),
        ("lookalike only", {"scripts/uninstall.sh", "tools/reinstall.shx"}, False),
    ],
)
def test_the_installer_is_recognised_in_both_layouts(
    layout: str, paths: set[str], expected: bool
) -> None:
    """Both checkouts, pinned -- only one of them can be exercised at a time."""
    assert any(_is_installer(p) for p in paths) is expected, layout


def test_the_repo_actually_has_shell_scripts_to_check() -> None:
    """Guard the guard: an empty listing would make the check below vacuous."""
    scripts = _tracked_shell_scripts()
    assert len(scripts) >= 10, f"expected the repo's shell scripts, found {len(scripts)}"
    paths = {path for _, path in scripts}
    assert any(_is_installer(p) for p in paths), (
        "install.sh is the documented one-command install and must be covered. "
        f"Looked for it in {len(paths)} tracked shell scripts and found none."
    )


def test_tracked_shell_scripts_are_executable() -> None:
    not_executable = sorted(path for mode, path in _tracked_shell_scripts() if mode != _EXECUTABLE)
    assert not not_executable, (
        "these shell scripts are not executable in the git index, so `./script.sh` "
        "fails with 'Permission denied' (exit 126) on a fresh clone:\n  "
        + "\n  ".join(not_executable)
        + "\n\nFix: git update-index --chmod=+x <path>   (git add alone will NOT "
        "set it on a Windows checkout, where core.fileMode is false)"
    )
