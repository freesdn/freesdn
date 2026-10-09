# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A committed blob must honour its own declared line endings, and an
executable's shebang must actually resolve on Linux.

``registry/build.py`` was committed with CRLF throughout, including its shebang
line, at mode 100755. Two consequences, both silent:

* ``registry/.gitattributes`` declares ``* text eol=lf`` for that whole
  directory, and says why: ``build.py`` packages worktree bytes and publishes a
  SHA-256 per plugin archive, so a CRLF/LF divergence changed the archive and
  its published checksum between Windows and Linux. A blob that violates that
  attribute does not round-trip -- ``git clone`` of main came up instantly dirty
  with a phantom 557-line diff. That matters beyond tidiness, because
  ``launch-kit/release/release.py`` runs ``git add -A`` over the flattened export
  worktree, which is exactly how a non-round-tripping file gets staged as a
  spurious change.

* The kernel passes everything after ``#!`` verbatim, so a CR became part of the
  interpreter name. Observed on debian:trixie-slim::

      env: 'python\\r': No such file or directory

  The documented invocation is ``python build.py``, which ignores the shebang,
  so nothing in the normal workflow failed -- the exec bit was simply a lie.

The shebang also named ``python``, not ``python3``. Stock Debian and Ubuntu ship
no ``python`` binary, so even with LF endings a direct exec fails outside a
virtualenv.

Only files that DECLARE ``eol=lf`` are held to it. 110 other tracked files carry
CRLF with no ``eol`` attribute; those are a Windows-origin artifact, they
round-trip consistently, and CRLF is harmless in an imported Python module. This
checks the invariant that was actually declared, not a blanket preference.
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


def _git(*args: str) -> str:
    assert _ROOT is not None
    return subprocess.run(
        ["git", "-C", str(_ROOT), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _index_eol() -> dict[str, str]:
    """path -> the index blob's line-ending classification, per git itself."""
    out: dict[str, str] = {}
    for line in _git("ls-files", "--eol").splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        marker = fields[0].split()[0]  # e.g. "i/crlf"
        if marker.startswith("i/"):
            out[fields[-1]] = marker[2:]
    return out


def test_the_scan_sees_the_tree() -> None:
    """Guard the guard: an empty inventory would pass every check below."""
    inventory = _index_eol()
    assert len(inventory) > 1000, (
        f"git ls-files --eol reported only {len(inventory)} paths, so the checks "
        "in this file would pass without examining anything meaningful."
    )


def test_no_tracked_blob_violates_its_declared_eol() -> None:
    """A blob with CRLF under a declared ``eol=lf`` does not round-trip."""
    assert _ROOT is not None
    suspects = [p for p, eol in _index_eol().items() if eol in ("crlf", "mixed")]
    if not suspects:
        return
    # One check-attr call for the whole batch; per-file would be ~110 processes.
    declared = subprocess.run(
        ["git", "-C", str(_ROOT), "check-attr", "--stdin", "eol"],
        input="\n".join(suspects),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    violations: list[str] = []
    for line in declared.splitlines():
        path, _, value = line.rpartition(": ")
        if value.strip() == "lf":
            violations.append(path.removesuffix(": eol"))
    assert not violations, (
        "these blobs carry CRLF while their .gitattributes declares eol=lf, so a "
        "fresh clone is immediately dirty and release.py's `git add -A` over the "
        "export worktree stages a spurious change:\n  " + "\n  ".join(sorted(violations))
    )


def test_executable_scripts_have_a_shebang_that_resolves() -> None:
    """Mode 100755 + ``#!`` means the kernel will read that line literally.

    Reads the BLOB, never the working tree. This checkout has
    ``core.autocrlf=true``, so an LF blob is written to disk as CRLF and every
    one of the ~60 executables here looks CR-terminated on Windows while being
    perfectly fine as committed. An earlier draft of this test read the worktree
    and produced exactly that false positive, flagging ``release.py``,
    ``export_openapi.py`` and a dozen qualification scripts that are all
    ``i/lf``. The blob is what a Linux build checks out and what the published
    repository receives, so the blob is the thing to assert on.

    One real hazard this deliberately does NOT assert, because it is a property
    of the build host rather than of the tree: ``release.py`` copies WORKTREE
    bytes (``shutil.copy2``), and only ``*.sh``/Dockerfile/compose/sql/conf
    carry ``eol=lf``. A release exported from a Windows checkout would therefore
    ship CRLF ``.py`` files. Releases are built on Linux, so it stays latent --
    but it is a reason never to export from this checkout.
    """
    assert _ROOT is not None
    executables: list[tuple[str, str]] = []
    for line in _git("ls-files", "-s").splitlines():
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if fields[0] != "100755":
            continue
        if path.startswith("docs/history/"):
            continue  # archived receipts, deliberately frozen as-committed
        executables.append((path, fields[1]))

    assert executables, (
        "no mode-100755 tracked files found, so this check examined nothing. "
        "Either the exec bits are gone -- which is its own bug, see "
        "test_shell_scripts_are_executable.py -- or `git ls-files -s` output "
        "stopped parsing."
    )

    batch = subprocess.run(
        ["git", "-C", str(_ROOT), "cat-file", "--batch"],
        input="\n".join(sha for _, sha in executables).encode(),
        capture_output=True,
        check=True,
    ).stdout

    problems: list[str] = []
    cursor = 0
    for path, _sha in executables:
        header_end = batch.index(b"\n", cursor)
        size = int(batch[cursor:header_end].split()[2])
        body = batch[header_end + 1 : header_end + 1 + size]
        cursor = header_end + 1 + size + 1  # trailing newline after each object
        if not body.startswith(b"#!"):
            continue
        first = body.split(b"\n", 1)[0]
        if first.endswith(b"\r"):
            problems.append(f"{path}: CR in the shebang -> {first!r}")
        elif first.endswith(b"/env python") or first.endswith(b" python"):
            problems.append(
                f"{path}: shebang names bare `python`, absent on stock Debian/Ubuntu "
                f"-> {first.decode(errors='replace')}"
            )
    assert not problems, (
        "an executable whose shebang does not resolve fails only when someone runs "
        "it directly, which is exactly when there is no one watching:\n  "
        + "\n  ".join(problems)
    )
