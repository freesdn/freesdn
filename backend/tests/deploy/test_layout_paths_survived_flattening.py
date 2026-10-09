# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cross-directory paths must survive the repository flattening.

Private main used to nest the app under ``freesdn/`` (``freesdn/backend``,
``freesdn/frontend``). The 26.10.0 layout transformation moved those to the
repository root. Anything that reached ACROSS directories with a hardcoded
``freesdn/`` segment therefore broke, and nothing failed loudly:

* ``demo/wrangler.toml`` declared ``pages_build_output_dir =
  "../freesdn/frontend/dist"``. Cloudflare Pages resolves that against the
  project directory, so the demo deploy pointed at a directory that no longer
  exists. ``demo/DEMO.md`` carried the same path in its documented
  ``wrangler pages deploy`` command.

* ``registry/build.py`` defaulted ``--seed-out`` to
  ``ROOT.parent/"freesdn"/"backend"/app/data/marketplace_seed.json``. That is
  the offline catalogue an air-gapped instance falls back to. The writer guards
  with ``if seed_path.parent.is_dir()`` and otherwise prints
  ``seed: skipped, ... is not a directory`` and continues at exit 0 -- so a
  publisher would sign and publish a catalogue, see ordinary output, and never
  learn the bundled seed had stopped being updated.

The two production site configs were never affected: ``website`` and
``website-docs`` declare a bare ``dist``, resolved inside their own directory.
Only configs that traverse upward could break, which is why this file checks
the traversing ones specifically rather than trusting that one fix was enough.
"""

from __future__ import annotations

import pathlib
import re

import pytest


def _repo_root() -> pathlib.Path | None:
    """Nearest ancestor that is a git work tree."""
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None


_ROOT = _repo_root()

pytestmark = pytest.mark.skipif(
    _ROOT is None,
    reason="not a git checkout (backend-only mount)",
)

#: Directories whose wrangler project we ship. Listed explicitly rather than
#: globbed, so a NEW site that forgets its config is a failure here instead of
#: silently reducing coverage to zero.
_WRANGLER_PROJECTS = ("website", "website-docs", "demo")

_OUTPUT_DIR = re.compile(r'^\s*pages_build_output_dir\s*=\s*"([^"]+)"', re.M)


def _declared_output_dir(project: str) -> tuple[pathlib.Path, str]:
    assert _ROOT is not None
    toml = _ROOT / project / "wrangler.toml"
    assert toml.is_file(), f"{project}/wrangler.toml is missing"
    match = _OUTPUT_DIR.search(toml.read_text(encoding="utf-8"))
    assert match, (
        f"{project}/wrangler.toml declares no pages_build_output_dir, so either the "
        "deployment target moved or this parser has gone blind and the project is "
        "now unchecked."
    )
    return toml.parent, match.group(1)


@pytest.mark.parametrize("project", _WRANGLER_PROJECTS)
def test_every_wrangler_build_output_dir_resolves(project: str) -> None:
    """The output dir's PARENT must exist; ``dist`` itself is a build artifact.

    Checking the parent is the whole point: ``dist`` is absent on a clean
    checkout, so asserting it exists would only pass after a build and would
    tell us nothing about whether the path is correct. The parent is committed
    source, so a wrong path shows up immediately.
    """
    base, declared = _declared_output_dir(project)
    resolved = (base / declared).resolve()
    assert resolved.parent.is_dir(), (
        f"{project}/wrangler.toml points pages_build_output_dir at {declared!r}, "
        f"whose parent {resolved.parent} does not exist. A Pages deploy would "
        f"fail on a missing build output directory. If the layout moved, this "
        f"path has to move with it."
    )


def test_no_shipped_config_or_doc_still_says_freesdn_slash() -> None:
    """A leftover ``freesdn/<subdir>/`` path means something was missed.

    Deliberately narrow: only the traversing configs and operator docs for the
    demo, which is where the real breakage was. Test fixtures legitimately
    contain monorepo-layout strings -- ``test_shell_scripts_are_executable.py``
    pins both layouts on purpose -- so source trees are out of scope here.
    """
    assert _ROOT is not None
    stale: list[str] = []
    for rel in ("demo/wrangler.toml", "demo/DEMO.md", "registry/README.md"):
        path = _ROOT / rel
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"freesdn/(backend|frontend|scripts|docker|agent)/", line):
                stale.append(f"{rel}:{number}: {line.strip()}")
    assert not stale, (
        "these still name the pre-flattening layout, so an operator following "
        "them lands on a path that does not exist:\n  " + "\n  ".join(stale)
    )


def test_the_registry_seed_default_points_at_the_app() -> None:
    """``build.py``'s ``--seed-out`` default must resolve to the real seed file.

    Extracted from source rather than imported, because importing ``build.py``
    requires PyYAML and ``cryptography``, which the backend test environment
    does not carry. If the expression form changes, the match fails and this
    test fails loudly -- it does not quietly stop checking.
    """
    assert _ROOT is not None
    source = (_ROOT / "registry" / "build.py").read_text(encoding="utf-8")
    match = re.search(
        r'ROOT\.parent\s*/\s*(?P<segs>(?:"[^"]+"\s*/\s*)*"marketplace_seed\.json")',
        source,
    )
    assert match, (
        "could not find the --seed-out default in registry/build.py. Either it "
        "moved -- in which case point this test at it -- or this regex no longer "
        "matches and the default is now unchecked."
    )
    segments = re.findall(r'"([^"]+)"', match.group("segs"))
    resolved = _ROOT.joinpath(*segments)
    assert resolved.is_file(), (
        f"registry/build.py defaults --seed-out to {'/'.join(segments)}, which is "
        f"not a file. build.py does not fail on this: it prints "
        f"'seed: skipped, ... is not a directory' and exits 0, so the bundled "
        f"offline catalogue would silently stop being updated."
    )
