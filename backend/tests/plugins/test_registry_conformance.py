# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Twelve plugins are published on registry.freesdn.org and nothing ran them.

They are the catalogue FreeSDN offers from its own marketplace UI, and the
worked examples an author copies. Until now the only thing standing between a
broken manifest and an operator's install button was somebody remembering to
look, and the parts most likely to rot are exactly the parts a reader's eye
slides over: a permission code renamed in the backend, an event that stopped
being published, a class renamed without its manifest.

Each check here is parameterised over the whole registry rather than written
per plugin, because the failure mode is drift across all of them at once when
something in core changes.

What this deliberately does NOT do is execute a plugin's code. Loading one for
real means the sandbox, a database session and an org context; that is the
loader's own test surface. These are the static promises the manifest makes,
which is where the drift lives.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml


def _find_registry() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "registry" / "plugins"
        if candidate.is_dir():
            return candidate
    return None


pytestmark = pytest.mark.skipif(
    _find_registry() is None,
    reason="the plugin registry is not present in this checkout",
)


def _plugin_dirs() -> list[Path]:
    """Every plugin directory, or nothing when the registry is not here.

    Returns a list rather than raising, because this runs at IMPORT time: the
    ``@pytest.mark.parametrize`` decorators below call it while the module is
    being read, which is before ``pytestmark`` can skip anything.

    Getting that wrong did not skip the file -- it aborted collection for the
    ENTIRE backend suite with "AttributeError: 'NoneType' object has no
    attribute 'iterdir'". Only the Docker gate caught it, because that is the
    environment that matches what ships: the backend leg mounts backend/ alone,
    and registry/ lives at the repo root and never reaches the public tree.
    """
    root = _find_registry()
    if root is None:
        return []
    return sorted(d for d in root.iterdir() if d.is_dir() and (d / "plugin.yaml").is_file())


def _ids() -> list[str]:
    return [d.name for d in _plugin_dirs()]


@pytest.fixture(scope="module")
def registry() -> dict[str, dict]:
    """Every manifest in the registry, parsed once."""
    return {
        d.name: yaml.safe_load((d / "plugin.yaml").read_text(encoding="utf-8"))
        for d in _plugin_dirs()
    }


@pytest.fixture(scope="module")
def sources() -> dict[str, ast.Module]:
    return {
        d.name: ast.parse((d / "plugin.py").read_text(encoding="utf-8"))
        for d in _plugin_dirs()
        if (d / "plugin.py").is_file()
    }


def test_the_registry_is_not_empty():
    """
    Guards the rest of the file: every check below is parameterised over the
    registry, so an empty one would make them all pass vacuously.
    """
    assert len(_plugin_dirs()) >= 12


# ── the manifest ────────────────────────────────────────────────


@pytest.mark.parametrize("name", _ids())
def test_the_manifest_validates_against_the_real_schema(registry, name):
    """
    ``PluginManifest`` is what the backend applies at install. A manifest that
    fails it is a plugin nobody can install, published and listed.
    """
    from app.plugins.schema import PluginManifest

    PluginManifest(**registry[name])


@pytest.mark.parametrize("name", _ids())
def test_the_directory_name_is_the_plugin_id(registry, name):
    """
    The registry builder keys the catalogue by directory. A mismatch publishes
    a plugin under a slug its own manifest does not claim.
    """
    assert registry[name]["id"] == name


def test_no_two_plugins_claim_the_same_id(registry):
    ids = [m["id"] for m in registry.values()]

    assert len(ids) == len(set(ids)), f"duplicate ids: {sorted({i for i in ids if ids.count(i) > 1})}"


def test_no_two_plugins_claim_the_same_api_prefix(registry):
    """
    Routers mount at ``api_prefix``. Two plugins sharing one means whichever
    loads second silently shadows the first.
    """
    seen: dict[str, str] = {}
    clashes = []
    for name, manifest in registry.items():
        prefix = manifest.get("api_prefix")
        if not prefix:
            continue
        if prefix in seen:
            clashes.append(f"{prefix} claimed by {seen[prefix]} and {name}")
        seen[prefix] = name

    assert not clashes, clashes


# ── the manifest against the code ───────────────────────────────


@pytest.mark.parametrize("name", _ids())
def test_the_entry_point_exists(registry, name):
    entry = registry[name].get("entry_point", "plugin.py")

    assert (_find_registry() / name / entry).is_file(), f"{name} declares a missing {entry}"


@pytest.mark.parametrize("name", _ids())
def test_the_declared_class_exists_and_is_a_plugin(registry, sources, name):
    """
    ``class_name`` is what the loader looks up after exec'ing the module. A
    rename that misses the manifest fails at install with nothing to point at.
    """
    declared = registry[name]["class_name"]
    classes = {n.name: n for n in ast.walk(sources[name]) if isinstance(n, ast.ClassDef)}

    assert declared in classes, f"{name} declares {declared!r}, which plugin.py does not define"

    bases = {b.id for b in classes[declared].bases if isinstance(b, ast.Name)}
    assert "FreeSDNPlugin" in bases, f"{name}.{declared} does not subclass FreeSDNPlugin (got {bases})"


@pytest.mark.parametrize("name", _ids())
def test_declared_schedule_methods_exist(registry, sources, name):
    """
    A schedule naming a method that is not there validates fine and then never
    runs -- the plugin looks installed and scheduled and does nothing.
    """
    schedules = registry[name].get("schedules") or []
    if not schedules:
        pytest.skip("no schedules declared")

    declared = registry[name]["class_name"]
    cls = next(
        n for n in ast.walk(sources[name]) if isinstance(n, ast.ClassDef) and n.name == declared
    )
    methods = {
        n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    missing = [s["method"] for s in schedules if s.get("method") and s["method"] not in methods]
    assert not missing, f"{name} schedules methods it does not define: {missing}"


# ── the manifest against the platform ───────────────────────────


@pytest.mark.parametrize("name", _ids())
def test_subscribed_events_are_real(registry, name):
    """
    An event that is never published leaves a plugin enabled, healthy and
    permanently idle -- the exact failure the jira-tickets manifest warns about
    in a comment, having been bitten by ``alert.created``.

    Patterns are legitimate: the bus matches with wildcards, so ``device.*``
    is fine. What is not fine is a pattern matching nothing.
    """
    import fnmatch

    from app.api.v1.endpoints.integrations import _ALL_KNOWN_EVENTS

    dead = []
    for subscription in registry[name].get("event_subscriptions") or []:
        if any(ch in subscription for ch in "*#"):
            if not any(fnmatch.fnmatch(e, subscription) for e in _ALL_KNOWN_EVENTS):
                dead.append(f"{subscription} (pattern matches no published event)")
        elif subscription not in _ALL_KNOWN_EVENTS:
            dead.append(subscription)

    assert not dead, f"{name} subscribes to events FreeSDN does not publish: {dead}"


@pytest.mark.parametrize("name", _ids())
def test_the_plugin_id_is_not_reserved(registry, name):
    """
    Reserved ids are refused at install, so publishing one lists a plugin that
    can never be added.
    """
    from app.plugins.schema import PluginManifest

    assert registry[name]["id"] not in PluginManifest._RESERVED_IDS


@pytest.mark.parametrize("name", _ids())
def test_secret_settings_are_marked_secret(registry, name):
    """
    ``secret: true`` is what makes the platform encrypt a value on write and
    withhold it on read. A credential without it is stored and returned in
    clear through the settings API, and nothing about the UI would look wrong.
    """
    schema = (registry[name].get("settings_schema") or {}).get("properties") or {}

    suspicious = [
        key
        for key, spec in schema.items()
        if any(word in key.lower() for word in ("token", "password", "secret", "api_key", "apikey"))
        and not spec.get("secret")
    ]

    assert not suspicious, f"{name} stores credentials in the clear: {suspicious}"


# ── the plugins nobody publishes but everybody copies ───────────


def _teaching_plugins() -> list[Path]:
    """The example and the template: what an author starts from.

    They are not in the registry, so nothing above covers them, and they are
    more consequential than a published plugin -- a mistake here is copied into
    every plugin somebody writes next.
    """
    for parent in Path(__file__).resolve().parents:
        found = []
        examples = parent / "freesdn-sdk" / "examples" / "plugins"
        if examples.is_dir():
            found += [d for d in sorted(examples.iterdir()) if (d / "plugin.yaml").is_file()]
        template = parent / "launch-kit" / "repos" / "plugins" / "plugin-template"
        if (template / "plugin.yaml").is_file():
            found.append(template)
        if found:
            return found
    return []


_TEACHING = _teaching_plugins()


@pytest.mark.skipif(not _TEACHING, reason="examples/template not in this checkout")
@pytest.mark.parametrize("path", _TEACHING, ids=lambda p: p.name)
def test_the_examples_and_template_validate(path):
    """
    Copied far more often than any published plugin, and gated by nothing.
    """
    from app.plugins.schema import PluginManifest

    manifest = yaml.safe_load((path / "plugin.yaml").read_text(encoding="utf-8"))
    PluginManifest(**manifest)

    entry = path / manifest.get("entry_point", "plugin.py")
    assert entry.is_file()

    declared = manifest["class_name"]
    classes = {
        n.name: n
        for n in ast.walk(ast.parse(entry.read_text(encoding="utf-8")))
        if isinstance(n, ast.ClassDef)
    }
    assert declared in classes, f"{path.name} declares {declared!r}, absent from {entry.name}"
    bases = {b.id for b in classes[declared].bases if isinstance(b, ast.Name)}
    assert "FreeSDNPlugin" in bases


@pytest.mark.skipif(not _TEACHING, reason="examples/template not in this checkout")
@pytest.mark.parametrize("path", _TEACHING, ids=lambda p: p.name)
def test_the_examples_and_template_subscribe_to_real_events(path):
    """
    An example subscribing to an event that is not published teaches the
    mistake, and the reader has no way to notice: the plugin installs, enables
    and stays quiet.
    """
    import fnmatch

    from app.api.v1.endpoints.integrations import _ALL_KNOWN_EVENTS

    manifest = yaml.safe_load((path / "plugin.yaml").read_text(encoding="utf-8"))
    dead = []
    for subscription in manifest.get("event_subscriptions") or []:
        if any(ch in subscription for ch in "*#"):
            if not any(fnmatch.fnmatch(e, subscription) for e in _ALL_KNOWN_EVENTS):
                dead.append(f"{subscription} (matches nothing)")
        elif subscription not in _ALL_KNOWN_EVENTS:
            dead.append(subscription)

    assert not dead, f"{path.name} subscribes to unpublished events: {dead}"


@pytest.mark.skipif(not _TEACHING, reason="examples/template not in this checkout")
@pytest.mark.parametrize("path", _TEACHING, ids=lambda p: p.name)
def test_the_examples_and_template_mark_their_credentials_secret(path):
    """
    The setting most likely to be copied verbatim into a real plugin.
    """
    manifest = yaml.safe_load((path / "plugin.yaml").read_text(encoding="utf-8"))
    schema = (manifest.get("settings_schema") or {}).get("properties") or {}

    suspicious = [
        key
        for key, spec in schema.items()
        if any(w in key.lower() for w in ("token", "password", "secret", "api_key", "apikey"))
        and not spec.get("secret")
    ]

    assert not suspicious, f"{path.name} demonstrates storing credentials in clear: {suspicious}"


def test_the_two_copies_of_hello_world_are_the_same_plugin():
    """
    ``examples/plugins/hello-world`` ships in the freesdn/plugins repo and
    ``registry/plugins/hello-world`` is what registry.freesdn.org serves. They
    claim the SAME id, so they are not two plugins -- they are one plugin
    stored twice, and one copy went stale.

    The example was at 1.1.0 against the registry's 1.2.0, and the difference
    was not cosmetic: 1.2.0 fixed the lifecycle hooks. ``self.ctx`` is only
    assigned in ``on_start``, so it is None in ``on_install``,
    ``on_upgrade`` and ``on_uninstall``, and the 1.1.0 example called
    ``self.ctx.logger.info(...)`` in two of them. The loader wraps on_install
    in a try/except, so it does not break the install -- the log line just
    never appears, and an author who copies the pattern for something that
    matters gets the same silence.

    Comparing content rather than version numbers, because a version that
    matches while the code does not is the same bug with better paperwork.
    Line endings are normalised: the release pipeline rewrites them anyway.

    If these ever need to diverge -- a deliberately simpler teaching copy --
    the fix is to give them different ids, not to relax this.
    """
    registry_root = _find_registry()
    published = registry_root / "hello-world"
    example = next((p for p in _TEACHING if p.name == "hello-world"), None)
    if example is None or not published.is_dir():
        pytest.skip("both copies of hello-world are not present")

    for filename in ("plugin.py", "plugin.yaml"):
        left = (example / filename).read_bytes().replace(b"\r\n", b"\n")
        right = (published / filename).read_bytes().replace(b"\r\n", b"\n")

        assert left == right, (
            f"{filename} differs between the example authors copy and the "
            "plugin the marketplace installs, and both claim the id 'hello-world'"
        )


def test_this_file_is_import_safe_without_the_registry():
    """
    The decorators above call ``_plugin_dirs()`` while the module is being
    imported, which is before ``pytestmark`` can skip anything. Raising there
    does not skip the file -- it aborts collection for the whole backend suite.

    That is not hypothetical: it happened, and only the Docker gate found it,
    because that is the environment matching what ships. The backend leg mounts
    ``backend/`` alone, and ``registry/`` sits at the repo root and never
    reaches the public tree at all.
    """
    import inspect

    src = inspect.getsource(_plugin_dirs)

    assert "if root is None:" in src, "a missing registry would raise at import time"
    assert "return []" in src


# ---------------------------------------------------------------------------
# A plugin may only gate on severities the platform actually emits
# ---------------------------------------------------------------------------
#
# AlertSDK validates severity against {"info", "warning", "error", "critical"}.
# Three incident plugins ranked on ["critical", "high", "medium", "low", "info"],
# a vocabulary FreeSDN never produces. Only "critical" and "info" overlapped, so
# every "warning" and "error" alert fell into the unknown-severity branch of
# _meets_floor -- which fails OPEN. A PagerDuty integration configured to page
# only for criticals therefore paged for every warning in the estate, and the
# operator could not fix it, because the manifest's own enum offered values the
# platform never emits.
#
# config-drift-guard and new-device-watch already used the right vocabulary,
# so this assertion was true for them before it was written.


def _severity_vocabulary() -> set[str]:
    from app.plugins.sdk import AlertSDK

    return set(AlertSDK._VALID_SEVERITIES)


def test_no_plugin_ranks_on_a_severity_the_platform_never_emits() -> None:
    """Fails before the fix on high/medium/low in three plugins."""
    import ast

    valid = _severity_vocabulary()
    offenders: list[str] = []

    for d in _plugin_dirs():
        path = d / "plugin.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if not any("SEVERIT" in n.upper() for n in names):
                continue
            if not isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            values = {
                e.value.lower()
                for e in node.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            }
            unknown = values - valid
            if unknown:
                offenders.append(
                    f"{path.parent.name}/plugin.py:{node.lineno} {names[0]} "
                    f"contains {sorted(unknown)}, which AlertSDK never emits"
                )

    assert not offenders, (
        "these plugins rank alerts on severities the platform does not produce, "
        "so their severity filter admits everything:\n  " + "\n  ".join(offenders)
    )


def test_no_manifest_offers_a_severity_the_platform_never_emits() -> None:
    """The UI must not offer a setting value that cannot match anything."""
    import yaml as _yaml

    valid = _severity_vocabulary()
    offenders: list[str] = []

    for d in _plugin_dirs():
        path = d / "plugin.py"
        manifest_path = d / "plugin.yaml"
        if not manifest_path.is_file():
            continue
        manifest = _yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        schema = (manifest.get("config_schema") or manifest.get("settings") or {})
        if not isinstance(schema, dict):
            continue
        for key, spec in schema.items():
            if not isinstance(spec, dict) or "severity" not in key.lower():
                continue
            values = {str(v).lower() for v in (spec.get("enum") or [])}
            unknown = values - valid
            if unknown:
                offenders.append(
                    f"{path.parent.name}/plugin.yaml {key} offers {sorted(unknown)}"
                )

    assert not offenders, (
        "these manifests offer severity values the platform never emits, so the "
        "operator can select a filter that silently matches nothing:\n  "
        + "\n  ".join(offenders)
    )
