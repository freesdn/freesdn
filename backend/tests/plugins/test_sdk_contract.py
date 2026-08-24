# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The published SDK and the runtime it stands in for had drifted, both ways.

Plugin authors ``pip install freesdn-sdk`` and write ``from freesdn_sdk import
FreeSDNPlugin``. There is no ``freesdn_sdk`` package inside FreeSDN: the loader
calls ``install_freesdn_sdk_alias()`` to put the real ``app.plugins.*``
implementations into ``sys.modules`` under that name before exec'ing a plugin.
So the published package is a promise about what the runtime will provide, and
nothing was checking it.

Both directions fail silently, which is why this went unnoticed.

A name the SDK advertises but the runtime does not provide type-checks green,
autocompletes, and passes the SDK's own offline tests -- then raises ImportError
the instant FreeSDN loads the plugin. The module never executes, so the plugin
does not exist. Measured against the published v0.1.0, ELEVEN of its twenty-five
exported names were in this state:

    PluginError            PluginPermissionError     PluginValidationError
    PluginNotInstalledError SSRFBlockedError         TokenBudgetExceededError
    PluginState            BLOCKED_MODULES           SAFE_BUILTINS
    PLUGIN_LIMITS          RESERVED_PLUGIN_IDS

Six of those were an invented exception hierarchy. The runtime raises builtin
``PermissionError`` for permission violations and builtin ``ValueError`` for a
blocked SSRF target; ``PluginError`` and its five subclasses exist nowhere in
the product. The better an author's error handling, the more certainly their
plugin failed to load.

The reverse is just as quiet: a name the runtime provides but the SDK omits
makes working code fail type-checking. ``PluginNotReady`` and
``PluginCoordinator`` were in this state, and SIX shipping registry plugins
import them -- jira-tickets, servicenow-incidents, pagerduty-incidents,
netbox-sync, librenms-sync, zabbix-sync. Anyone who installed the SDK and opened
one of those as a template, which is the documented workflow, got an error on
code that demonstrably runs in production.

The constants had drifted too, and those are load-bearing: ``freesdn-sdk
validate`` scans a plugin for blocked imports before publish using its own copy
of BLOCKED_MODULES. That copy was missing seven entries -- ``imp``,
``importlib.abc``, ``importlib.machinery``, ``importlib.util``, ``linecache``,
``pkgutil``, ``tokenize`` -- every one of them import machinery, which is what a
sandbox escape reaches for first. The CLI reported such a plugin clean.
RESERVED_PLUGIN_IDS was missing all nine module names, so an author could build
a plugin on a slug the backend would refuse at install.

The SDK keeps its own copies on purpose: it is installed by people who do not
have FreeSDN. What was missing is anything that fails when they diverge.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest


def _find_sdk_root() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "freesdn-sdk" / "sdk" / "src" / "freesdn_sdk"
        if candidate.is_dir():
            return candidate
    return None


# The SDK is a separate public repo, so it is absent from the flattened
# freesdn/freesdn tree that ships. Skipping at module level rather than inside
# each test means the order of statements within a test cannot turn a missing
# SDK into a red build there -- a test that imports from ``app`` before it
# touches the SDK would otherwise error instead of skipping.
pytestmark = pytest.mark.skipif(
    _find_sdk_root() is None,
    reason="the SDK source is not present in this checkout",
)


def _sdk_root() -> Path:
    root = _find_sdk_root()
    assert root is not None  # guarded by pytestmark
    return root


@pytest.fixture(scope="module")
def sdk_all() -> set[str]:
    """``__all__`` from the published package, read without importing it."""
    source = (_sdk_root() / "__init__.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    pytest.fail("the SDK no longer declares __all__")


@pytest.fixture(scope="module")
def runtime_surface() -> set[str]:
    """What ``freesdn_sdk`` actually resolves to inside FreeSDN.

    Installs the real alias, exactly as the loader does. Submodules are dropped:
    ``base`` and ``context`` are import paths, not names a plugin uses.
    """
    from app.plugins.sdk_alias import install_freesdn_sdk_alias

    install_freesdn_sdk_alias()
    module = sys.modules["freesdn_sdk"]
    return {
        name
        for name in dir(module)
        if not name.startswith("_") and name not in {"base", "context"}
    }


def test_everything_the_sdk_advertises_exists_at_runtime(sdk_all, runtime_surface):
    """
    A name in ``__all__`` that the alias does not provide is an ImportError at
    plugin load. Nothing before this point catches it: not the SDK's tests,
    which never see the runtime, and not the backend's, which never read the
    SDK.
    """
    missing = sorted(sdk_all - runtime_surface)

    assert not missing, (
        "the SDK promises names FreeSDN does not provide; a plugin importing "
        f"any of these fails to load: {missing}"
    )


def test_everything_the_runtime_provides_is_advertised(sdk_all, runtime_surface):
    """
    The quiet direction. Working code that fails type-checking teaches authors
    to distrust the SDK, and it is how the shipping examples ended up using
    names the published package did not export.
    """
    unadvertised = sorted(runtime_surface - sdk_all)

    assert not unadvertised, (
        "FreeSDN provides names the SDK does not export, so plugins using them "
        f"cannot be type-checked against the published package: {unadvertised}"
    )


def test_the_shipping_registry_plugins_only_import_advertised_names(sdk_all):
    """
    The property that actually matters, checked against real plugins rather
    than against the contract in the abstract. These are what an author copies.
    """
    root = _sdk_root().parents[3]
    plugins = sorted((root / "registry" / "plugins").glob("*/plugin.py"))
    if not plugins:
        pytest.skip("the plugin registry is not present in this checkout")

    offenders: dict[str, list[str]] = {}
    for path in plugins:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module == "freesdn_sdk":
                unknown = [a.name for a in node.names if a.name not in sdk_all]
                if unknown:
                    offenders[path.parent.name] = unknown

    assert not offenders, f"registry plugins import names the SDK does not export: {offenders}"


# ── the copied constants ────────────────────────────────────────


def _sdk_constant(name: str):
    """Evaluate one literal from the SDK's ``types.py`` without importing it.

    Importing is not an option here: the module is named ``types``, and putting
    its directory on ``sys.path`` shadows the standard library module of the
    same name.
    """
    source = (_sdk_root() / "types.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = getattr(node.targets[0], "id", None)
        if target == name and node.value is not None:
            value = node.value
            # ``frozenset({...})`` is a Call, not a literal; evaluate the set
            # it wraps. A bare dict or set literal is already evaluable.
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in {"frozenset", "set"}
                and value.args
            ):
                value = value.args[0]
            return ast.literal_eval(value)
    pytest.fail(f"the SDK no longer defines {name}")


def test_the_blocked_module_list_matches():
    """
    ``freesdn-sdk validate`` refuses a plugin that imports one of these, and it
    runs before publish -- so a short list here is a plugin passing its own
    security check and being rejected by the runtime. The seven that were
    missing were all import machinery.
    """
    from app.plugins.sandbox import BLOCKED_MODULES

    assert set(_sdk_constant("BLOCKED_MODULES")) == set(BLOCKED_MODULES)


def test_the_safe_builtin_list_matches():
    """
    Wrong in the other direction is just as bad: the SDK omitted ``getattr``,
    ``super`` and ``__build_class__``, and ``__build_class__`` is required to
    define any class at all -- including the ``FreeSDNPlugin`` subclass every
    plugin must declare.
    """
    from app.plugins.sandbox import _SAFE_BUILTINS

    assert set(_sdk_constant("SAFE_BUILTINS")) == set(_SAFE_BUILTINS)


def test_the_reserved_id_list_matches():
    """
    A reserved id is rejected at install. The SDK was missing all nine module
    names, so ``freesdn-sdk init cameras`` scaffolded a plugin that could never
    be installed.
    """
    from app.plugins.schema import PluginManifest

    assert set(_sdk_constant("RESERVED_PLUGIN_IDS")) == set(PluginManifest._RESERVED_IDS)


def test_the_sdk_still_states_where_its_copies_come_from():
    """
    The copies exist because the SDK is installed by people who do not have
    FreeSDN. Someone editing ``types.py`` needs to know a backend test governs
    it, or the next drift is reintroduced by hand with a green SDK suite.
    """
    source = (_sdk_root() / "types.py").read_text(encoding="utf-8")

    assert "app.plugins.sandbox" in source


def test_the_stand_in_enums_stringify_like_the_runtime_ones():
    """
    ``class X(str, Enum)`` and ``StrEnum`` are not interchangeable:
    ``str(EventPriority.HIGH)`` is "EventPriority.HIGH" under the first and
    "high" under the second. The runtime uses StrEnum; the SDK used the other,
    so an author formatting a priority into a log line or an outbound payload
    got one answer offline and a different one in production -- with nothing
    raising, which is the worst way for a value to be wrong.
    """
    source = (_sdk_root() / "types.py").read_text(encoding="utf-8")

    offenders = [
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ClassDef)
        and {b.id for b in node.bases if isinstance(b, ast.Name)} >= {"str", "Enum"}
    ]

    assert not offenders, (
        "these SDK enums stringify differently from the StrEnum the runtime "
        f"substitutes: {offenders}"
    )


def test_the_event_enums_carry_the_same_members_as_the_runtime():
    """
    A category the SDK does not know is one an author cannot name offline; one
    the runtime does not know is a value it will reject.
    """
    from app.core.events import EventCategory, EventPriority

    source = (_sdk_root() / "types.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    def members(cls_name: str) -> set[str]:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == cls_name:
                return {
                    stmt.value.value
                    for stmt in node.body
                    if isinstance(stmt, ast.Assign)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)
                }
        pytest.fail(f"the SDK no longer defines {cls_name}")

    assert members("EventPriority") == {e.value for e in EventPriority}
    assert members("EventCategory") == {e.value for e in EventCategory}


def test_the_cli_agrees_with_the_sandbox_about_blocked_imports():
    """
    ``freesdn-sdk check`` predicts what the sandbox will refuse, and predicting
    it wrongly is worse in both directions: too lax and an author publishes a
    plugin that cannot load, too strict and they are told working code is a
    security violation and stop trusting the tool.

    It had inverted the relationship. The sandbox blocks a name whose PARENT is
    blocked; the CLI blocked any name whose top-level package appeared in the
    list. ``asyncio.subprocess`` is blocked and ``asyncio`` is not, so
    ``import asyncio`` -- in every plugin that awaits anything -- was reported
    as a violation, and three of the twelve registry plugins failed the check.

    Rather than restate the rule a third time, this runs both implementations
    over the same names and requires the same answer.
    """
    import ast

    from app.plugins.sandbox import BLOCKED_MODULES, _PluginImportBlocker

    source = (_sdk_root() / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    fn = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_is_blocked"),
        None,
    )
    assert fn is not None, "the CLI no longer has a single blocked-import decision"

    namespace: dict[str, object] = {"BLOCKED_MODULES": BLOCKED_MODULES}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<cli>", "exec"), namespace)
    cli_is_blocked = namespace["_is_blocked"]

    runtime_is_blocked = _PluginImportBlocker.__dict__["_is_blocked"]

    class _Probe:
        pass

    corpus = sorted(BLOCKED_MODULES)
    corpus += [f"{m}.child" for m in sorted(BLOCKED_MODULES)[:20]]
    corpus += [m.split(".")[0] for m in BLOCKED_MODULES if "." in m]
    corpus += ["asyncio", "re", "json", "httpx", "typing", "datetime", "collections.abc"]

    disagreements = [
        name
        for name in corpus
        if bool(cli_is_blocked(name)) != bool(runtime_is_blocked(_Probe(), name))
    ]

    assert not disagreements, (
        "the CLI and the sandbox disagree about these imports, so `freesdn-sdk "
        f"check` no longer predicts what the runtime does: {sorted(set(disagreements))[:12]}"
    )


def test_the_registry_plugins_pass_the_check_that_gates_publishing():
    """
    The property that matters, against the real plugins rather than the rule in
    the abstract: FreeSDN's own registry must survive FreeSDN's own pre-publish
    check. Three of the twelve did not.
    """
    import subprocess
    import sys

    root = _sdk_root().parents[3]
    plugins = sorted(p for p in (root / "registry" / "plugins").glob("*/") if p.is_dir())
    if not plugins:
        pytest.skip("the plugin registry is not present in this checkout")

    failures = {}
    for plugin in plugins:
        result = subprocess.run(
            [sys.executable, "-m", "freesdn_sdk.cli", "check", str(plugin)],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(_sdk_root().parent)},
        )
        if result.returncode != 0:
            failures[plugin.name] = [
                ln.strip() for ln in result.stdout.splitlines() if "ERROR" in ln
            ]

    assert not failures, f"registry plugins rejected by `freesdn-sdk check`: {failures}"
