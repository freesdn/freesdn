# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Plugin sandbox conformance tests.

Validates that the plugin sandbox allows legitimate Python operations
while blocking dangerous ones.
"""

import pytest

from app.plugins.sandbox import (
    _SAFE_BUILTINS,
    BLOCKED_MODULES,
    PluginSecurityError,
    _PluginImportBlocker,
    plugin_import_guard,
    restrict_plugin_builtins,
)
from app.plugins.schema import PluginManifest

# ---------------------------------------------------------------------------
# _SAFE_BUILTINS: allowlist checks
# ---------------------------------------------------------------------------


# Test 1: Class definition works
def test_class_definition_allowed():
    """Plugins must be able to define classes."""
    assert "__build_class__" in _SAFE_BUILTINS


# Test 2: json import works (requires _io not blocked)
def test_stdlib_json_import_not_blocked():
    """Plugins must be able to import json (requires _io internally).

    _io is the C-accelerated I/O layer used by json, csv, etc.
    Blocking it would break many safe stdlib imports.
    """
    assert "_io" not in BLOCKED_MODULES


# Test 3: Dangerous modules ARE blocked
@pytest.mark.parametrize(
    "module",
    [
        "os",
        "subprocess",
        "shutil",
        "ctypes",
        "socket",
        "multiprocessing",
        "signal",
        "importlib",
        "pickle",
        "marshal",
        "inspect",
        "gc",
        "atexit",
        "builtins",
        "threading",
    ],
)
def test_dangerous_modules_blocked(module):
    """Dangerous modules must remain in the block list."""
    assert module in BLOCKED_MODULES


# Test 4: Safe builtins include essential functions
@pytest.mark.parametrize(
    "builtin",
    [
        "print",
        "len",
        "range",
        "dict",
        "list",
        "tuple",
        "set",
        "str",
        "int",
        "float",
        "bool",
        "isinstance",
        "hasattr",
        "property",
        "staticmethod",
        "classmethod",
        "__build_class__",
    ],
)
def test_safe_builtins_include_essentials(builtin):
    """Essential builtins must be in the safe set."""
    assert builtin in _SAFE_BUILTINS


# Test 5: __import__ is NOT in the raw safe builtins (it's injected as a
# sandboxed wrapper by restrict_plugin_builtins, never exposed directly)
def test_raw_import_not_in_safe_builtins():
    """__import__ must NOT be in _SAFE_BUILTINS.

    restrict_plugin_builtins() injects a sandboxed _blocked_import wrapper
    instead, so having the real __import__ in the allowlist would be a bypass.
    """
    assert "__import__" not in _SAFE_BUILTINS


# Test 6: Import blocker blocks dangerous modules via find_spec
def test_import_blocker_blocks_os_via_find_spec():
    """The import blocker should raise PluginSecurityError for 'os' via find_spec."""
    blocker = _PluginImportBlocker("test-plugin")
    with pytest.raises(PluginSecurityError, match="os"):
        blocker.find_spec("os", None, None)


# Test 7: Import blocker blocks dangerous modules via find_module (legacy API)
def test_import_blocker_blocks_os_via_find_module():
    """find_module returns self for blocked modules (load_module then raises)."""
    blocker = _PluginImportBlocker("test-plugin")
    # find_module returns self for blocked modules
    result = blocker.find_module("os", None)
    assert result is blocker
    # load_module raises the actual error
    with pytest.raises(PluginSecurityError, match="os"):
        blocker.load_module("os")


# Test 8: Import blocker allows safe modules
def test_import_blocker_allows_json():
    """The import blocker should allow importing json (returns None)."""
    blocker = _PluginImportBlocker("test-plugin")
    # find_spec returns None for allowed modules (letting normal import proceed)
    result = blocker.find_spec("json", None, None)
    assert result is None
    # find_module also returns None for allowed modules
    result = blocker.find_module("json", None)
    assert result is None


# Test 9: Import blocker blocks sub-modules of blocked parents
def test_import_blocker_blocks_submodules():
    """Importing os.path should be blocked because os is blocked."""
    blocker = _PluginImportBlocker("test-plugin")
    with pytest.raises(PluginSecurityError, match="os\\.path"):
        blocker.find_spec("os.path", None, None)


# Test 10: Import blocker blocks deeply nested sub-modules
def test_import_blocker_blocks_deep_submodules():
    """Importing http.client should be blocked because http is blocked."""
    blocker = _PluginImportBlocker("test-plugin")
    with pytest.raises(PluginSecurityError, match="http\\.client"):
        blocker.find_spec("http.client", None, None)


# Test 11: Plugin manifest validation rejects invalid version
def test_manifest_rejects_invalid_version():
    """Plugin manifest must reject non-semver versions."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="semver"):
        PluginManifest(
            id="test-plugin",
            name="Test",
            version="not-a-version",
            description="Test plugin",
            author="Test",
            entry_point="main.py",
            class_name="TestPlugin",
        )


# Test 12: Plugin manifest accepts valid manifest
def test_manifest_accepts_valid():
    """Valid plugin manifests should pass validation."""
    m = PluginManifest(
        id="test-plugin",
        name="Test Plugin",
        version="1.0.0",
        description="A test plugin",
        author="FreeSDN",
        entry_point="main.py",
        class_name="TestPlugin",
    )
    assert m.id == "test-plugin"
    assert m.version == "1.0.0"
    assert m.class_name == "TestPlugin"


# Test 13: Plugin manifest rejects reserved IDs
@pytest.mark.parametrize(
    "reserved_id",
    ["admin", "auth", "core", "system", "plugins", "internal"],
)
def test_manifest_rejects_reserved_id(reserved_id):
    """Plugin manifest should reject reserved plugin IDs."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="reserved"):
        PluginManifest(
            id=reserved_id,
            name="Test",
            version="1.0.0",
            description="Test",
            author="Test",
            entry_point="main.py",
            class_name="TestPlugin",
        )


# Test 14: Dependency validation rejects dangerous patterns
@pytest.mark.parametrize(
    "dep",
    [
        "--index-url http://evil.com package",
        "package[extra]",
        "-r requirements.txt",
        "package; python_version>='3'",
        "requests>=2.28.0",  # loose specifier (>=) rejected
        "pydantic",  # unpinned rejected
        "my-package~=1.0",  # compatible release (~=) rejected
        "flask!=2.0.0",  # exclusion (!=) rejected
    ],
)
def test_dep_validation_rejects_dangerous(dep):
    """Dangerous and loosely-pinned dependency patterns should be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PluginManifest(
            id="test-plugin",
            name="Test",
            version="1.0.0",
            description="Test",
            author="Test",
            entry_point="main.py",
            class_name="TestPlugin",
            python_dependencies=[dep],
        )


# Test 15: Valid dependency specs are accepted (exact pin == required)
@pytest.mark.parametrize(
    "dep",
    [
        "requests==2.28.0",
        "pydantic==2.5.3",
        "numpy==1.24.0",
        "my-package==1.0.0",
    ],
)
def test_dep_validation_accepts_valid(dep):
    """Exactly-pinned dependency specs should be accepted."""
    m = PluginManifest(
        id="test-plugin",
        name="Test",
        version="1.0.0",
        description="Test",
        author="Test",
        entry_point="main.py",
        class_name="TestPlugin",
        python_dependencies=[dep],
    )
    assert dep in m.python_dependencies


# Test 16: Entry point validation blocks traversal
@pytest.mark.parametrize(
    "entry",
    [
        "../escape.py",
        "/etc/passwd.py",
        "\\windows\\system32.py",
    ],
)
def test_manifest_rejects_path_traversal_entry_point(entry):
    """Entry points with path traversal must be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PluginManifest(
            id="test-plugin",
            name="Test",
            version="1.0.0",
            description="Test",
            author="Test",
            entry_point=entry,
            class_name="TestPlugin",
        )


# Test 17: class_name must be a valid Python identifier
@pytest.mark.parametrize(
    "cls",
    [
        "_Private",
        "not valid",
        "123Bad",
    ],
)
def test_manifest_rejects_invalid_class_name(cls):
    """class_name must be a valid Python identifier not starting with _."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PluginManifest(
            id="test-plugin",
            name="Test",
            version="1.0.0",
            description="Test",
            author="Test",
            entry_point="main.py",
            class_name=cls,
        )


# Test 18: restrict_plugin_builtins wires up sandboxed __import__
def test_restrict_plugin_builtins_sets_import():
    """restrict_plugin_builtins must inject a sandboxed __import__ wrapper."""
    from types import ModuleType

    mod = ModuleType("test_module")
    restrict_plugin_builtins(mod, "test-plugin")

    builtins_dict = mod.__builtins__  # type: ignore[attr-defined]
    assert "__import__" in builtins_dict
    # The injected __import__ is NOT the real builtins.__import__
    import builtins as _builtins

    assert builtins_dict["__import__"] is not _builtins.__import__


# Test 19: restrict_plugin_builtins removes exec/eval/compile/open
def test_restrict_plugin_builtins_removes_dangerous():
    """exec, eval, compile, open must NOT be available to plugins."""
    from types import ModuleType

    mod = ModuleType("test_module")
    restrict_plugin_builtins(mod, "test-plugin")

    builtins_dict = mod.__builtins__  # type: ignore[attr-defined]
    for dangerous in ("exec", "eval", "compile", "open", "breakpoint", "exit", "quit"):
        assert dangerous not in builtins_dict, f"{dangerous} should not be in plugin builtins"


# Test 20: plugin_import_guard context manager blocks and restores
def test_plugin_import_guard_restores_sys_modules():
    """plugin_import_guard must restore sys.modules after exiting."""
    import sys

    # os should be in sys.modules (it's imported at module level)
    assert "os" in sys.modules

    with plugin_import_guard("test-plugin"):
        # os should be temporarily removed from sys.modules
        assert "os" not in sys.modules

    # os should be restored after context exit
    assert "os" in sys.modules


# Test 21: _is_blocked checks parent modules correctly
def test_is_blocked_parent_modules():
    """_is_blocked should block children of blocked parent modules."""
    blocker = _PluginImportBlocker("test-plugin")
    assert blocker._is_blocked("os") is True
    assert blocker._is_blocked("os.path") is True
    assert blocker._is_blocked("os.path.join") is True
    assert blocker._is_blocked("json") is False
    assert blocker._is_blocked("json.decoder") is False


# Test 22: Error messages include plugin ID
def test_error_message_includes_plugin_id():
    """Security error messages should identify the offending plugin."""
    blocker = _PluginImportBlocker("acme-exploit")
    with pytest.raises(PluginSecurityError, match="acme-exploit"):
        blocker.find_spec("os", None, None)


# Test 23: Manifest rejects IDs that don't match the regex pattern
def test_manifest_rejects_invalid_id_format():
    """Plugin IDs must match ^[a-z0-9][a-z0-9\\-]{0,98}[a-z0-9]$."""
    from pydantic import ValidationError

    for bad_id in ["A_UPPER", "has spaces", "-starts-dash", "x"]:
        with pytest.raises(ValidationError):
            PluginManifest(
                id=bad_id,
                name="Test",
                version="1.0.0",
                description="Test",
                author="Test",
                entry_point="main.py",
                class_name="TestPlugin",
            )


# Test 24: Safe builtins includes all exception classes needed for try/except
def test_safe_builtins_include_exception_classes():
    """Common exception types must be available for plugin try/except blocks."""
    for exc_name in (
        "Exception",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "AttributeError",
        "RuntimeError",
        "StopIteration",
        "ImportError",
    ):
        assert exc_name in _SAFE_BUILTINS, f"{exc_name} missing from _SAFE_BUILTINS"


# Test 25: Safe builtins includes async primitives
def test_safe_builtins_include_async_primitives():
    """aiter and anext must be available for async plugin code."""
    assert "aiter" in _SAFE_BUILTINS
    assert "anext" in _SAFE_BUILTINS


# Test 26: BLOCKED_MODULES is a frozenset (immutable)
def test_blocked_modules_is_immutable():
    """BLOCKED_MODULES must be a frozenset to prevent runtime mutation."""
    assert isinstance(BLOCKED_MODULES, frozenset)


# Test 27: _SAFE_BUILTINS is a frozenset (immutable)
def test_safe_builtins_is_immutable():
    """_SAFE_BUILTINS must be a frozenset to prevent runtime mutation."""
    assert isinstance(_SAFE_BUILTINS, frozenset)
