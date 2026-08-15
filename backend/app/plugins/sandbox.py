# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Runtime Import Hygiene
=======================================

NOTE: This is NOT a security sandbox. A loaded plugin runs in the same
Python process as the FreeSDN backend and has full access to the interpreter.
A malicious plugin can easily escape any import restrictions by walking
``().__class__.__base__.__subclasses__()`` or using ``gc.get_objects()`` to
reach arbitrary classes — including ``subprocess.Popen``. **This is hygiene,
not security.**

What this module actually does:

- Removes some common accident-prone builtins (``exec``, ``eval``, ``compile``,
  ``open``, ``__import__``) from plugins during initial load so that a typo
  or a lazy copy-paste does not silently grant the plugin raw OS access.
- Blocks a small set of filesystem/network/process imports during plugin
  **load time only** (not at runtime). This catches ordinary mistakes where
  a plugin author forgets they are supposed to use the SDK, but it is
  trivially defeatable by a hostile author.

What IS blocked at load-time (see ``BLOCKED_MODULES`` for full list):

- OS / filesystem: ``os``, ``os.path``, ``sys``, ``shutil``, ``pathlib``,
  ``io``, ``tempfile``, ``tokenize``, ``linecache``
- Process execution: ``subprocess``, ``asyncio.subprocess``
- Network: ``socket``, ``http``, ``urllib``, ``webbrowser``
- Dynamic loading / code execution: ``importlib``, ``importlib.util``,
  ``importlib.abc``, ``pkgutil``, ``imp`` (legacy), ``runpy``, ``compileall``,
  ``codeop``, ``code``
- Native code / FFI: ``ctypes``, ``cffi``
- Serialization: ``pickle``, ``marshal``, ``shelve``
- Concurrency: ``multiprocessing``, ``threading``
- System primitives: ``signal``, ``resource``, ``pwd``, ``grp``, ``pty``,
  ``tty``, ``termios``, ``sysconfig``, ``site``
- Introspection: ``inspect``, ``gc``
- Builtins override: ``builtins``

What ISN'T blocked (and why these remain escape routes):

- ``traceback`` is importable: legitimate plugins format exceptions. A
  hostile plugin can still reach ``tb_frame`` on an exception object and
  walk back to the caller's locals. We do not wrap traceback objects.
- ``().__class__.__base__.__subclasses__()`` — Python's built-in object
  hierarchy is always reachable; this leaks ``subprocess.Popen`` and
  every other class in the runtime.
- ``gc.get_objects()`` — blocked at import time, but the plugin can read
  any live object via attribute walks once it has a reference.
- Anything in ``sys.modules`` cache from an already-imported third-party
  package that the plugin can name.

**Threat model**: cooperative plugins written by trusted authors. Plugin
install is restricted to ``super_admin`` in
``backend/app/api/v1/endpoints/plugins.py`` and the plugin manifest must be
reviewed before installation. Treat plugin install like installing a Python
package into your production environment — because that is what it is.

If you need actual isolation, run plugins in a subprocess via a real
sandbox implementation. Proper subprocess-level plugin isolation is
scheduled for a future release.

Usage::

    from app.plugins.sandbox import plugin_import_guard, restrict_plugin_builtins

    mod = importlib.util.module_from_spec(spec)
    restrict_plugin_builtins(mod, plugin_id)
    with plugin_import_guard(plugin_id):
        spec.loader.exec_module(mod)
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import logging
import sys
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from types import ModuleType
from typing import Any

logger = logging.getLogger(__name__)

# Global lock to serialize plugin loading (sys.meta_path is global state)
_sandbox_lock = threading.Lock()


class PluginSecurityError(Exception):
    """Raised when a plugin trips an import-hygiene check during load.

    NOTE: This is NOT a security boundary — see the module docstring. It
    catches accidental misuse, not a determined attacker.
    """


#: Modules blocked for plugin code during LOAD TIME. These provide
#: OS/process/network access that cooperative plugins should not need
#: directly — they should use the SDK instead. This is a tripwire against
#: accidents, not a security barrier: a hostile plugin can trivially reach
#: these modules at runtime via ``__subclasses__()`` or ``gc.get_objects()``.
BLOCKED_MODULES: frozenset[str] = frozenset(
    {
        # OS & filesystem
        "os",
        "os.path",
        "sys",
        "shutil",
        "pathlib",
        "io",
        "tempfile",
        # File-reading / source-introspection helpers that can read
        # arbitrary files off the host filesystem.
        "tokenize",
        "linecache",
        # Process execution
        "subprocess",
        "asyncio.subprocess",
        "_subprocess",
        # Network
        "socket",
        "_socket",
        "http",
        "http.client",
        "http.server",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "webbrowser",
        # Dynamic loading / code execution.
        # NOTE (hardening pass): the plain ``importlib`` parent was already
        # in the blocklist, but the sub-modules ``importlib.util`` /
        # ``importlib.abc`` and the helpers ``pkgutil`` / legacy ``imp``
        # could still be imported directly because ``_is_blocked()`` only
        # walks parents (a child like ``importlib.util`` IS caught by the
        # parent walk, but listing them explicitly documents intent and
        # protects against a future refactor that loosens the parent check).
        "importlib",
        "importlib.util",
        "importlib.abc",
        "importlib.import_module",
        "importlib.machinery",
        "pkgutil",
        "imp",
        "runpy",
        "compileall",
        "codeop",
        "code",
        # Native code / FFI
        "ctypes",
        "cffi",
        "_ctypes",
        # Serialization (code execution risk)
        "pickle",
        "_pickle",
        "marshal",
        "shelve",
        # Concurrency (resource exhaustion)
        "multiprocessing",
        "threading",
        # System primitives
        "signal",
        "resource",
        "pwd",
        "grp",
        "pty",
        "tty",
        "termios",
        "sysconfig",
        "site",
        # Introspection (frame access, caller variable access).
        # NOTE: ``traceback`` is intentionally NOT blocked — plugins
        # legitimately format exceptions. A hostile plugin can still reach
        # ``tb_frame`` on an exception object once it has one; we don't
        # wrap it. See the module docstring's "what ISN'T blocked" section.
        "inspect",
        "gc",
        # Exit hooks
        "atexit",
        # Builtins override
        "builtins",
    }
)

#: Builtins that are SAFE for plugin code (allowlist approach)
_SAFE_BUILTINS: frozenset[str] = frozenset(
    {
        # Types & constructors
        "bool",
        "int",
        "float",
        "complex",
        "str",
        "bytes",
        "bytearray",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "property",
        "classmethod",
        "staticmethod",
        "slice",
        "range",
        "memoryview",
        # Functions
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "callable",
        "chr",
        "divmod",
        "enumerate",
        "filter",
        "format",
        "getattr",
        "hasattr",
        "hash",
        "hex",
        "id",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "map",
        "max",
        "min",
        "next",
        "oct",
        "ord",
        "pow",
        "print",
        "repr",
        "reversed",
        "round",
        "sorted",
        "sum",
        "zip",
        "super",
        # Exceptions (needed for try/except)
        "ArithmeticError",
        "AssertionError",
        "AttributeError",
        "BaseException",
        "BlockingIOError",
        "BrokenPipeError",
        "BufferError",
        "BytesWarning",
        "ChildProcessError",
        "ConnectionAbortedError",
        "ConnectionError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "DeprecationWarning",
        "EOFError",
        "EnvironmentError",
        "Exception",
        "FileExistsError",
        "FileNotFoundError",
        "FloatingPointError",
        "FutureWarning",
        "GeneratorExit",
        "IOError",
        "ImportError",
        "ImportWarning",
        "IndentationError",
        "IndexError",
        "InterruptedError",
        "IsADirectoryError",
        "KeyError",
        "KeyboardInterrupt",
        "LookupError",
        "MemoryError",
        "ModuleNotFoundError",
        "NameError",
        "NotADirectoryError",
        "NotImplemented",
        "NotImplementedError",
        "OSError",
        "OverflowError",
        "PendingDeprecationWarning",
        "PermissionError",
        "ProcessLookupError",
        "RecursionError",
        "ReferenceError",
        "ResourceWarning",
        "RuntimeError",
        "RuntimeWarning",
        "StopAsyncIteration",
        "StopIteration",
        "SyntaxError",
        "SyntaxWarning",
        "SystemError",
        "SystemExit",
        "TabError",
        "TimeoutError",
        "TypeError",
        "UnboundLocalError",
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        "UnicodeError",
        "UnicodeTranslateError",
        "UnicodeWarning",
        "UserWarning",
        "ValueError",
        "Warning",
        "ZeroDivisionError",
        # Constants
        "None",
        "True",
        "False",
        "Ellipsis",
        "__name__",
        "__doc__",
        # Needed for class definitions
        "__build_class__",
        # Needed for async
        "aiter",
        "anext",
    }
)


class _PluginImportBlocker(importlib.abc.MetaPathFinder):
    """
    MetaPath finder that refuses imports of OS/process/network modules
    while a plugin is being loaded.

    NOTE: load-time only. This is not a runtime security boundary —
    see the module docstring.

    Installed into sys.meta_path only during plugin loading, then removed.
    Each instance is scoped to a single plugin_id for clear error messages.
    Implements both find_spec() (modern) and find_module() (legacy) for
    maximum coverage across Python versions.
    """

    def __init__(self, plugin_id: str) -> None:
        self.plugin_id = plugin_id

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        """Modern finder API — blocks dangerous module imports."""
        if self._is_blocked(fullname):
            raise PluginSecurityError(
                f"Plugin '{self.plugin_id}' attempted to import blocked module: "
                f"{fullname}. Use the Plugin SDK (self.ctx) for safe system access."
            )
        return None

    def find_module(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
    ) -> _PluginImportBlocker | None:
        """Legacy finder API — kept for Python versions that check it."""
        if self._is_blocked(fullname):
            return self  # Returning self means load_module will be called
        return None

    def load_module(self, fullname: str) -> None:
        """Raise security error for blocked imports (legacy API)."""
        raise PluginSecurityError(
            f"Plugin '{self.plugin_id}' attempted to import blocked module: "
            f"{fullname}. Use the Plugin SDK (self.ctx) for safe system access."
        )

    def _is_blocked(self, fullname: str) -> bool:
        """Check if a module name or any of its parents are in the blocklist."""
        # Direct match
        if fullname in BLOCKED_MODULES:
            return True
        # Check parent modules (e.g., "os.path" blocks "os.path.join")
        parts = fullname.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[:i])
            if parent in BLOCKED_MODULES:
                return True
        return False


def restrict_plugin_builtins(mod: ModuleType, plugin_id: str) -> None:
    """
    Install a reduced builtins dict on a plugin module before exec.

    Removes accident-prone builtins like ``__import__``, ``exec``, ``eval``,
    ``compile``, and ``open`` and replaces them with an allowlisted set.
    This is import hygiene, not a security boundary: a hostile plugin
    author can still reach raw classes via ``().__class__.__base__``
    at runtime. See the module docstring for the actual threat model.

    Must be called BEFORE ``spec.loader.exec_module(mod)``.
    """
    import builtins as _builtins

    def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        # Check if this import would be blocked
        blocker = _PluginImportBlocker(plugin_id)
        if blocker._is_blocked(name):
            raise PluginSecurityError(
                f"Plugin '{plugin_id}' attempted to import blocked module: "
                f"{name}. Use the Plugin SDK (self.ctx) for safe system access."
            )
        # Also check the fromlist (e.g., `from os import path` passes name="os", fromlist=["path"])
        if len(args) >= 3 and args[2]:
            for fromname in args[2]:
                submod = f"{name}.{fromname}"
                if blocker._is_blocked(submod):
                    raise PluginSecurityError(
                        f"Plugin '{plugin_id}' attempted to import blocked module: "
                        f"{submod}. Use the Plugin SDK (self.ctx) for safe system access."
                    )
        # Allow other imports through the real __import__. Do NOT rewrite
        # builtins on imported modules: they may be shared core modules, and
        # mutating them corrupts runtime behavior outside the plugin itself.
        return _builtins.__import__(name, *args, **kwargs)

    # Build restricted builtins dict
    restricted = {}
    for name in _SAFE_BUILTINS:
        if hasattr(_builtins, name):
            restricted[name] = getattr(_builtins, name)

    # Replace __import__ with our checking version
    restricted["__import__"] = _blocked_import

    # Set restricted builtins on the module
    mod.__builtins__ = restricted  # type: ignore[attr-defined]


@contextmanager
def plugin_import_guard(plugin_id: str) -> Any:
    """
    Context manager that refuses imports of OS/process/network modules
    during plugin loading.

    NOTE: this only protects load-time behaviour. Nothing stops a loaded
    plugin from reaching the same modules at runtime. See the module
    docstring for the full threat model.

    What it does:
    1. Installs a MetaPathFinder that refuses the load-time blocklist
    2. Temporarily removes those modules from sys.modules so a plugin
       cannot reach them via the import cache
    3. Restores sys.modules on exit

    Thread-safe: uses a lock to prevent concurrent plugin loads from
    interfering with sys.meta_path and sys.modules manipulation.

    Example::

        mod = importlib.util.module_from_spec(spec)
        restrict_plugin_builtins(mod, plugin_id)
        with plugin_import_guard(plugin_id):
            spec.loader.exec_module(mod)
    """
    with _sandbox_lock:
        blocker = _PluginImportBlocker(plugin_id)

        # Snapshot and temporarily remove blocked modules from sys.modules
        # so that `import os` cannot succeed via the cache
        saved_modules: dict[str, ModuleType] = {}
        for name in list(sys.modules):
            if blocker._is_blocked(name):
                saved_modules[name] = sys.modules.pop(name)

        sys.meta_path.insert(0, blocker)
        logger.debug("Import blocker installed for plugin '%s'", plugin_id)
        try:
            yield blocker
        finally:
            # Remove the blocker
            try:
                sys.meta_path.remove(blocker)
            except ValueError:
                pass  # Already removed

            # Restore removed modules to sys.modules
            sys.modules.update(saved_modules)
            logger.debug("Import blocker removed for plugin '%s'", plugin_id)
