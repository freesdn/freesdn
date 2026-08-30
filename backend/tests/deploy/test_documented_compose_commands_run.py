# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A ``docker compose`` command printed in the docs must be a runnable command.

Most of this repo's compose files are OVERLAYS: they override services that
``docker-compose.yml`` defines and reference volumes and networks it declares.
Passing one on its own is not a degraded stack, it is a hard config error --

    $ docker compose -f docker-compose.dev.yml up -d
    service "scheduler" refers to undefined volume celerybeat_data

-- and that exact line was the bring-up command in three places, including
``freesdn/docs/guides/CONTRIBUTING.md``, i.e. the first command a new public
contributor runs. ``install.sh`` had it right the whole time (it appends the
overlay to a ``-f docker-compose.yml`` base), so nothing that anyone actually
executed ever failed, and the docs drifted for months.

Self-sufficiency is derived from the compose files, not hardcoded: a file stands
alone if it pulls in another via ``include:``, or if every service it declares
brings its own image/build and every named volume, network and ``depends_on``
target it references is declared in that same file.
"""

from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

#: Depth-first walk up from this test until the directory holding the monorepo's
#: docs is found. The CI backend leg mounts only ``backend/``, where none of this
#: exists -- hence the module-level skip below rather than a collection-time one.
_MARKER_DIRS = ("freesdn", "docs")


def _monorepo_root() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        if all((parent / marker).is_dir() for marker in _MARKER_DIRS):
            return parent
    return None


_ROOT = _monorepo_root()

pytestmark = pytest.mark.skipif(
    _ROOT is None,
    reason="monorepo root is not in this checkout (backend-only mount)",
)

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".venv", "__pycache__", ".astro"}

#: ``-f path`` / ``--file path``, tolerating ``=`` and quotes.
_FILE_FLAG = re.compile(r"(?:-f|--file)[=\s]+['\"]?([^\s'\";|&]+)")


def _iter_compose_files() -> dict[str, pathlib.Path]:
    """basename -> path, for every compose file in the repo's compose directory."""
    assert _ROOT is not None
    found: dict[str, pathlib.Path] = {}
    for path in sorted((_ROOT / "freesdn").glob("docker-compose*.yml")):
        found[path.name] = path
    return found


def _named_sources(service: dict) -> set[str]:
    """Named volumes a service mounts (bind mounts and tmpfs are not declared)."""
    sources: set[str] = set()
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            source = entry.split(":", 1)[0]
        elif isinstance(entry, dict):
            if entry.get("type") not in (None, "volume"):
                continue
            source = str(entry.get("source") or "")
        else:
            continue
        # bind mounts and interpolated paths are not top-level declarations
        if source and not source.startswith((".", "/", "~", "$")):
            sources.add(source)
    return sources


def _is_self_sufficient(path: pathlib.Path) -> bool:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if doc.get("include"):
        return True
    services = doc.get("services") or {}
    if not services:
        return False
    declared_volumes = set(doc.get("volumes") or {})
    declared_networks = set(doc.get("networks") or {})
    for service in services.values():
        if not isinstance(service, dict):
            continue
        # A service with neither image nor build is an override of one defined
        # in another file -- the defining signature of an overlay.
        if not service.get("image") and not service.get("build"):
            return False
        if _named_sources(service) - declared_volumes:
            return False
        networks = service.get("networks") or {}
        names = set(networks) if isinstance(networks, dict) else set(networks)
        if names - declared_networks - {"default"}:
            return False
        depends = service.get("depends_on") or {}
        targets = set(depends) if isinstance(depends, dict) else set(depends)
        if targets - set(services):
            return False
    return True


def _documented_commands() -> list[tuple[pathlib.Path, int, str, list[str]]]:
    """Every ``docker compose`` line in the docs that names explicit -f files."""
    assert _ROOT is not None
    out: list[tuple[pathlib.Path, int, str, list[str]]] = []
    for path in sorted(_ROOT.rglob("*.md")) + sorted(_ROOT.rglob("*.mdx")):
        if _SKIP_DIRS & set(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "docker compose" not in text and "docker-compose" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip("|# \t")
            if not re.match(r"^`?(?:[A-Z_]+=\S+\s+)*docker[- ]compose\b", stripped):
                continue
            files = [pathlib.PurePosixPath(m).name for m in _FILE_FLAG.findall(stripped)]
            files = [f for f in files if f.startswith("docker-compose")]
            if files:
                out.append((path.relative_to(_ROOT), lineno, stripped.strip(), files))
    return out


def test_repo_has_both_kinds_of_compose_file() -> None:
    """Guard the guard: if this stops being true the check below proves nothing."""
    compose = _iter_compose_files()
    assert compose, "found no docker-compose*.yml to classify"
    kinds = {name: _is_self_sufficient(path) for name, path in compose.items()}
    assert any(kinds.values()), f"no self-sufficient compose file found: {kinds}"
    assert not all(kinds.values()), f"no overlay compose file found: {kinds}"
    assert kinds.get("docker-compose.yml") is True, "the base must stand alone"


def test_documented_compose_commands_name_a_self_sufficient_file() -> None:
    compose = _iter_compose_files()
    self_sufficient = {name for name, path in compose.items() if _is_self_sufficient(path)}

    broken: list[str] = []
    for doc_path, lineno, command, files in _documented_commands():
        unknown = [f for f in files if f not in compose]
        if unknown:
            broken.append(
                f"{doc_path}:{lineno} names a compose file that does not exist: {unknown}\n    {command}"
            )
            continue
        if not any(f in self_sufficient for f in files):
            broken.append(
                f"{doc_path}:{lineno} runs overlay(s) {files} with no base -- "
                f"docker compose rejects this as an invalid project\n    {command}"
            )

    assert not broken, (
        "documented docker compose command(s) cannot run as written; add "
        "`-f docker-compose.yml` before the overlay:\n\n" + "\n\n".join(broken)
    )
