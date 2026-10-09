# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The applier-map sweep must keep seeing every applier map there is.

``tests/services/test_adapter_apply_signature_bind.py`` carries the class-wide
ratchet: for each staged-write service it resolves every ``_APPLY`` value
against the vendor client/adapter and fails if the method does not exist. It
finds those services by globbing ``app/services/adapter_*.py``, importing each
one and skipping any whose ``_APPLY`` is missing or empty.

Both of those steps can go quietly blind, and its own non-vacuity guard
(``len(_APPLY_SERVICES) > 50``) does not notice:

* a map that moves, or is written, outside ``app/services/adapter_*.py`` is
  never globbed, so nothing grades it;
* a map that is emptied -- refactored into a helper, gutted mid-change --
  stops being skipped-by-design and starts being skipped-by-accident. Sixty-four
  graded cases silently becoming fifty-five is still ">= 50" and still green.

So this file is a census rather than a second sweep: WHERE the maps are, and
WHICH ones are legitimately empty. It reads the sources with ``ast`` instead of
importing them, so a map in a module the sweep never imports still shows up.
"""

from __future__ import annotations

import ast
from pathlib import Path

# tests/adapters/ -> tests/ -> backend/
BACKEND = Path(__file__).resolve().parents[2]
APP = BACKEND / "app"
SERVICES_GLOB = "services/adapter_*.py"

# The five services that ship an intentionally empty ``_APPLY``: live reads, no
# write verbs on the adapter yet, and the map kept in place so that adding one
# is a one-line diff. Each says so at its declaration. Asserted as an EQUALITY,
# because that is the whole point -- a sixth entry appearing here means some
# applier stopped being graded by the sweep, and an entry disappearing means
# this list is stale and would hide the next one.
READ_ONLY_STUBS = frozenset(
    {
        "app/services/adapter_pfsense_routing.py",
        "app/services/adapter_pfsense_vpn.py",
        "app/services/adapter_proxmox_ceph.py",
        "app/services/adapter_proxmox_replication.py",
        # 2026-09-18: legacy SDN writes deliberately removed; native management
        # is required until reviewed lock/apply semantics are qualified.
        "app/services/adapter_proxmox_sdn.py",
    }
)

# Non-empty maps the sweep grades today (2026-08-27). A floor, not an equality:
# appliers get added, and a new one must not force an edit here. It dropping is
# what matters -- that is a module deleted or a map that stopped being found.
# 2026-09-18: 64 -> 63 for the explicitly documented SDN write withdrawal.
# The equality above and SDN no-dispatch regressions guard this boundary.
GRADED_MAPS_FLOOR = 63


def _apply_dict(module: ast.Module) -> ast.Dict | None:
    """The module-level ``_APPLY = {...}`` literal, if there is one."""
    for node in module.body:
        target: ast.expr | None = None
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "_APPLY":
            return node.value if isinstance(node.value, ast.Dict) else None
    return None


def census(root: Path = APP) -> dict[str, int]:
    """``{repo-relative path: number of entries}`` for every ``_APPLY`` under root."""
    found: dict[str, int] = {}
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "_APPLY" not in text:
            continue
        literal = _apply_dict(ast.parse(text))
        if literal is None:
            continue
        found[f"{root.name}/{path.relative_to(root).as_posix()}"] = len(literal.keys)
    return found


CENSUS = census()


def test_the_census_itself_found_something() -> None:
    """Guard against an AST walk that silently matches nothing."""
    assert len(CENSUS) > 60, f"only {len(CENSUS)} _APPLY map(s) found under {APP}"
    assert "app/services/adapter_omada_firewall.py" in CENSUS


def test_census_counts_entries_and_ignores_non_maps(tmp_path: Path) -> None:
    """Non-vacuity: an emptied map must read as 0, not as absent.

    If ``census`` reported a gutted ``_APPLY`` the same way it reports a module
    with no map at all, the equality below would pass on exactly the regression
    it is there to catch.
    """
    app = tmp_path / "app" / "services"
    app.mkdir(parents=True)
    (app / "adapter_full.py").write_text(
        '_APPLY: dict[tuple[str, str], str] = {\n    ("a", "update"): "do_a",\n}\n',
        encoding="utf-8",
    )
    (app / "adapter_gutted.py").write_text(
        "_APPLY: dict[tuple[str, str], str] = {}\n", encoding="utf-8"
    )
    (app / "adapter_none.py").write_text(
        "X = 1  # mentions _APPLY only in this comment\n", encoding="utf-8"
    )
    assert census(tmp_path / "app") == {
        "app/services/adapter_full.py": 1,
        "app/services/adapter_gutted.py": 0,
    }


def test_every_apply_map_lives_where_the_sweep_globs() -> None:
    """A map outside ``app/services/adapter_*.py`` is graded by nothing.

    ``build_applier`` looks its method name up in ``_APPLY`` wherever the map
    lives; the sweep only ever looks in one directory. Move one and the staged
    write still dispatches, it just stops being checked -- which is exactly the
    state that let an applier route to a method that did not exist.
    """
    globbed = {f"app/{p.relative_to(APP).as_posix()}" for p in APP.glob(SERVICES_GLOB)}
    stranded = sorted(set(CENSUS) - globbed)
    assert not stranded, (
        "these modules declare an _APPLY map that tests/services/"
        "test_adapter_apply_signature_bind.py never globs, so nothing checks "
        "that their staged writes route to a real method: "
        f"{stranded}. Move the map back under app/services/adapter_*.py, or "
        "widen the sweep's glob and this one together."
    )


def test_the_empty_apply_maps_are_exactly_the_documented_read_only_stubs() -> None:
    """An emptied map is skipped by the sweep and looks identical to a stub.

    Mutation this catches: delete the entries from any one applier's ``_APPLY``.
    The sweep drops it from 64 graded modules to 63 and stays green; this fails
    and names the module.
    """
    empty = {path for path, size in CENSUS.items() if size == 0}
    assert empty == set(READ_ONLY_STUBS), (
        "the set of services shipping an EMPTY _APPLY changed. Newly empty "
        f"{sorted(empty - READ_ONLY_STUBS)}: that applier is no longer graded "
        "by the sweep -- restore its entries, or add it here with the reason "
        "its writes are deferred. No longer empty "
        f"{sorted(READ_ONLY_STUBS - empty)}: drop it from READ_ONLY_STUBS."
    )


def test_the_number_of_graded_maps_never_drops() -> None:
    graded = sum(1 for size in CENSUS.values() if size)
    assert graded >= GRADED_MAPS_FLOOR, (
        f"{graded} non-empty _APPLY map(s), down from {GRADED_MAPS_FLOOR}. The "
        "sweep in tests/services/test_adapter_apply_signature_bind.py grades one "
        "parametrised case per map, so this many staged-write appliers just "
        "stopped being checked. Raise the floor only when the drop is a "
        "deliberate deletion."
    )
