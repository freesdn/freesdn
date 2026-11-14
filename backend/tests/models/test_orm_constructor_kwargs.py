# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A keyword passed to an ORM model must name something the model persists.

SQLAlchemy's default constructor accepts a keyword only when ``hasattr(cls, k)``
and raises ``TypeError`` otherwise, so a misspelt field is a guaranteed crash the
first time the line runs, and nothing catches it before then: mypy sees the
constructor as ``**kwargs: Any``. That is not hypothetical. Gateway sync wrote
``GatewaySyncLog(error_message=None, items_synced=<dict>)`` against a model whose
field is ``error``, and every periodic gateway sync on every install ended as
failed after doing its work (fixed in 70f47b6f, found on real gear).

The same shape fails three other ways, and this gate covers them too:

* a keyword that names a read-only ``property`` raises ``AttributeError``;
* a keyword that names a method or a plain class attribute is accepted and
  silently not persisted;
* ``Model.k`` at class level (``select(Device).where(Device.type == t)``) raises
  ``AttributeError`` when the query is built;
* ``insert(Model).values(k=...)`` / ``update(Model).values(...)`` /
  ``on_conflict_do_update(set_={...})`` with a key that is not a column raise
  ``CompileError: Unconsumed column names`` at execute time, and
  ``select(Model).filter_by(k=...)`` raises ``InvalidRequestError``.

Calls are resolved through each file's own imports to the actual class object, so
two models that share a class name in different modules are never confused.

Module models register when the module loads at app lifespan, not on import, so
the gate imports every ``app.models.*`` and ``app.modules.*.models`` itself, and
``test_every_table_class_is_loaded`` proves that set is complete.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[2] / "app"

#: SQL statement constructors whose ``.values()`` keys must be columns.
_DML_ROOTS = {"insert", "update"}


# ---------------------------------------------------------------------------
# The model side: what each mapped class accepts
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Shape:
    cls: type
    persisted: frozenset[str]  # ORM descriptors + settable properties
    columns: frozenset[str]  # what insert()/update() .values() accept
    custom_params: frozenset[str] | None  # explicit params of a custom __init__
    custom_varkw: bool

    def judge(self, kw: str) -> str | None:
        """Why constructing with ``kw=`` is wrong, or None if it is fine."""
        if self.custom_params is not None:
            if kw in self.custom_params:
                return None
            if not self.custom_varkw:
                return "TypeError: not a parameter of its custom __init__"
        if kw in self.persisted:
            return None
        if not hasattr(self.cls, kw):
            return "TypeError: not an attribute of the model"
        attr = inspect.getattr_static(self.cls, kw)
        if isinstance(attr, property):
            return "AttributeError: read-only property"
        return "accepted and silently not persisted (not a mapped attribute)"


@cache
def _mapped_classes() -> tuple[type, ...]:
    import app.main  # noqa: F401  (core models + eager module models)
    import app.models
    import app.modules

    for _f, name, _p in pkgutil.iter_modules(app.models.__path__, "app.models."):
        importlib.import_module(name)
    importlib.import_module("app.modules.models")
    for _f, mod, _p in pkgutil.iter_modules(app.modules.__path__, "app.modules."):
        try:
            importlib.import_module(f"{mod}.models")
        except ModuleNotFoundError as exc:
            if exc.name != f"{mod}.models":
                raise

    from app.db.base import Base, LogBase

    return tuple(m.class_ for base in (Base, LogBase) for m in base.registry.mappers)


@cache
def _shapes() -> dict[type, _Shape]:
    from sqlalchemy import inspect as sa_inspect

    from app.db.base import Base, LogBase

    default_inits = {Base.registry.constructor, LogBase.registry.constructor}
    shapes: dict[type, _Shape] = {}
    for cls in _mapped_classes():
        mapper = sa_inspect(cls)
        persisted = set(mapper.attrs.keys())
        for name, desc in mapper.all_orm_descriptors.items():
            fset = getattr(desc, "fset", True)  # hybrid_property without a setter
            if fset is not None and name != "__mapper__":
                persisted.add(name)
        for klass in cls.__mro__:
            for name, value in vars(klass).items():
                if isinstance(value, property) and value.fset is not None:
                    persisted.add(name)
        columns = {c.key for c in mapper.columns} | set(mapper.column_attrs.keys())
        columns |= {c.key for c in cls.__table__.columns}

        custom_params: frozenset[str] | None = None
        custom_varkw = False
        init = cls.__init__
        if init not in default_inits:
            sig = inspect.signature(init)
            custom_params = frozenset(
                p.name
                for p in sig.parameters.values()
                if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) and p.name != "self"
            )
            custom_varkw = any(p.kind is p.VAR_KEYWORD for p in sig.parameters.values())
        shapes[cls] = _Shape(
            cls, frozenset(persisted), frozenset(columns), custom_params, custom_varkw
        )
    return shapes


# ---------------------------------------------------------------------------
# The call side: resolve each call to a class through the file's imports
# ---------------------------------------------------------------------------
@cache
def _import(name: str) -> ModuleType | None:
    try:
        return importlib.import_module(name)
    except Exception:  # noqa: BLE001 - an unimportable module just resolves nothing
        return None


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(APP_ROOT.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class _Resolver:
    """Maps a name used in one file to the object it denotes."""

    def __init__(self, tree: ast.Module, module: str, is_package: bool) -> None:
        self.module = module
        self.names: dict[str, tuple[str, str | None]] = {}  # alias -> (module, attr|None)
        package = module if is_package else module.rpartition(".")[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.split(".")
                    base = base[: len(base) - (node.level - 1)]
                    src = ".".join(base + ([node.module] if node.module else []))
                else:
                    src = node.module or ""
                for a in node.names:
                    self.names[a.asname or a.name] = (src, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.names[a.asname] = (a.name, None)
                    else:
                        top = a.name.split(".")[0]
                        self.names[top] = (top, None)
        self.local_classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}

    def resolve(self, node: ast.expr) -> Any:
        if isinstance(node, ast.Name):
            if node.id in self.local_classes:
                mod = _import(self.module)
                return getattr(mod, node.id, None) if mod else None
            src = self.names.get(node.id)
            if src is None:
                return None
            module, attr = src
            if attr is None:
                return _import(module)
            mod = _import(module)
            if mod is None:
                return None
            if hasattr(mod, attr):
                return getattr(mod, attr)
            return _import(f"{module}.{attr}")
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            if base is None:
                return None
            if isinstance(base, ModuleType) and not hasattr(base, node.attr):
                return _import(f"{base.__name__}.{node.attr}")
            return getattr(base, node.attr, None)
        return None

    def source_of(self, node: ast.expr) -> tuple[str, str] | None:
        """``(module, attr)`` for a bare imported name or ``mod.attr``."""
        if isinstance(node, ast.Name):
            src = self.names.get(node.id)
            return (src[0], src[1]) if src and src[1] else None
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            src = self.names.get(node.value.id)
            if src and src[1] is None:
                return (src[0], node.attr)
            if src:
                return (f"{src[0]}.{src[1]}", node.attr)
        return None


def _dict_keys(node: ast.expr) -> list[str]:
    if isinstance(node, ast.Dict):
        return [
            k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        return [kw.arg for kw in node.keywords if kw.arg]
    if isinstance(node, ast.List | ast.Tuple):
        return [k for elt in node.elts for k in _dict_keys(elt)]
    return []


def _chain_root(node: ast.expr) -> tuple[ast.Call | None, list[str]]:
    """Walk ``a(...).b(...).c`` down to its innermost call; return it and the method names."""
    methods: list[str] = []
    cur: ast.expr = node
    root: ast.Call | None = None
    while True:
        if isinstance(cur, ast.Call):
            root = cur
            cur = cur.func
        elif isinstance(cur, ast.Attribute):
            methods.append(cur.attr)
            cur = cur.value
        else:
            return root, methods


def scan_source(source: str, module: str, label: str, is_package: bool = False) -> list[str]:
    """Every wrong keyword in one file's model constructions and DML statements."""
    shapes = _shapes()
    tree = ast.parse(source)
    res = _Resolver(tree, module, is_package)
    findings: list[str] = []

    def shape_of(node: ast.expr) -> _Shape | None:
        obj = res.resolve(node)
        return shapes.get(obj) if isinstance(obj, type) else None

    def visit(node: ast.AST, enclosing_model: _Shape | None) -> None:
        if isinstance(node, ast.ClassDef):
            mod = _import(module)
            obj = getattr(mod, node.name, None) if mod else None
            enclosing_model = shapes.get(obj) if isinstance(obj, type) else None
        if isinstance(node, ast.Call):
            check_call(node, enclosing_model)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            # Model.attr at class level, e.g. select(...).where(Device.type == x)
            owner = shape_of(node.value)
            if owner is not None and not hasattr(owner.cls, node.attr):
                findings.append(
                    f"{label}:{node.lineno}: {owner.cls.__name__}.{node.attr} "
                    "AttributeError: the model has no such attribute"
                )
        for child in ast.iter_child_nodes(node):
            visit(child, enclosing_model)

    def report(node: ast.AST, what: str, kw: str, why: str) -> None:
        findings.append(f"{label}:{node.lineno}: {what}({kw}=) {why}")

    def check_call(node: ast.Call, enclosing_model: _Shape | None) -> None:
        func = node.func
        # 1. Model(...) and, inside a model's own classmethods, cls(...)
        shape = None
        if isinstance(func, ast.Name) and func.id == "cls" and enclosing_model is not None:
            shape = enclosing_model
        elif isinstance(func, ast.Name | ast.Attribute):
            shape = shape_of(func)
        if shape is not None:
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                why = shape.judge(kw.arg)
                if why:
                    report(node, shape.cls.__name__, kw.arg, why)
            return

        # 2. insert(M).values(...) / update(M)...values(...) / .on_conflict_do_update(set_=)
        #    / select(M).filter_by(...)
        if not isinstance(func, ast.Attribute):
            return
        method = func.attr
        if method not in {"values", "on_conflict_do_update", "on_conflict_do_nothing", "filter_by"}:
            return
        root, chain = _chain_root(func.value)
        if root is None or not root.args:
            return
        src = res.source_of(root.func)
        if src is None or not src[0].startswith("sqlalchemy"):
            return
        verb = src[1]
        target = shape_of(root.args[0])
        if target is None:
            return
        name = target.cls.__name__
        if method == "filter_by":
            if verb != "select" or len(root.args) != 1 or any("join" in m for m in chain):
                return
            for kw in node.keywords:
                if kw.arg and kw.arg not in target.persisted:
                    report(node, f"select({name}).filter_by", kw.arg, "InvalidRequestError")
            return
        if verb not in _DML_ROOTS:
            return
        keys: list[str] = []
        if method == "values":
            keys = [kw.arg for kw in node.keywords if kw.arg]
            for arg in node.args:
                keys += _dict_keys(arg)
        else:
            for kw in node.keywords:
                if kw.arg == "set_":
                    keys += _dict_keys(kw.value)
                elif kw.arg == "index_elements" and isinstance(kw.value, ast.List | ast.Tuple):
                    keys += [
                        e.value
                        for e in kw.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ]
        for key in keys:
            if key not in target.columns:
                report(node, f"{verb}({name}).{method}", key, "CompileError: not a column")

    visit(tree, None)
    return findings


def _scan_app() -> list[str]:
    findings: list[str] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        findings += scan_source(
            source,
            _module_name(path),
            path.relative_to(APP_ROOT.parent).as_posix(),
            is_package=path.name == "__init__.py",
        )
    return findings


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------
def test_every_table_class_is_loaded():
    """The scanner can only judge models it has loaded: prove that is all of them."""
    loaded = {(c.__module__, c.__name__) for c in _mapped_classes()}
    declared = set()
    for path in APP_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                isinstance(stmt, ast.Assign | ast.AnnAssign)
                and any(
                    isinstance(t, ast.Name) and t.id == "__tablename__"
                    for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
                )
                for stmt in node.body
            ):
                declared.add((_module_name(path), node.name))
    missing = sorted(declared - loaded)
    assert not missing, f"table classes the gate never loaded: {missing}"
    assert len(loaded) > 150, f"only {len(loaded)} mapped classes loaded"


def test_no_model_construction_passes_a_keyword_the_model_lacks():
    findings = _scan_app()
    assert not findings, "\n".join(
        ["ORM constructions/DML with keys the model does not persist:", *findings]
    )


# ---------------------------------------------------------------------------
# Proof the gate bites: the real regressions, planted
# ---------------------------------------------------------------------------
_GATEWAY = "app.modules.gateway.services.sync_service"


def test_gate_flags_the_gateway_sync_log_regression():
    """The exact construction from before 70f47b6f, resolved through a real import."""
    planted = (
        "from app.modules.firewall.models import GatewaySyncLog\n"
        "def f(gw, t0, synced):\n"
        "    return GatewaySyncLog(gateway_id=gw.id, started_at=t0, status='success',\n"
        "                          items_synced=synced, error_message=None)\n"
    )
    findings = scan_source(planted, _GATEWAY, "planted.py")
    assert len(findings) == 1, findings
    assert "GatewaySyncLog(error_message=)" in findings[0]
    assert "TypeError" in findings[0]


def test_gate_resolves_aliases_relative_imports_and_module_attributes():
    planted = (
        "from ...firewall import models as fw\n"
        "from app.modules.firewall.models import GatewaySyncLog as Log\n"
        "def f():\n"
        "    fw.GatewaySyncLog(nope=1)\n"
        "    Log(also_nope=2)\n"
    )
    findings = scan_source(planted, _GATEWAY, "planted.py")
    assert [f.split(": ", 1)[1].split("(")[1] for f in findings] == [
        "nope=) TypeError: not an attribute of the model",
        "also_nope=) TypeError: not an attribute of the model",
    ]


def test_gate_flags_dml_keys_that_are_not_columns():
    planted = (
        "from sqlalchemy import update\n"
        "from sqlalchemy.dialects.postgresql import insert as pg_insert\n"
        "from app.modules.firewall.models import GatewaySyncLog\n"
        "def f(x):\n"
        "    update(GatewaySyncLog).where(GatewaySyncLog.id == x).values(error_message='e')\n"
        "    pg_insert(GatewaySyncLog).values({'status': 's', 'bogus': 1}).on_conflict_do_update(\n"
        "        index_elements=['id'], set_={'status': 's', 'nonsense': 2})\n"
    )
    findings = scan_source(planted, _GATEWAY, "planted.py")
    keys = sorted(f.split("(", 2)[2].split("=)")[0] for f in findings)
    assert keys == ["bogus", "error_message", "nonsense"], findings


def test_gate_accepts_every_real_field():
    """No false positive on a construction that names only real fields."""
    planted = (
        "from app.modules.firewall.models import GatewaySyncLog\n"
        "GatewaySyncLog(gateway_id=1, status='success', items_synced=3, error=None, details={})\n"
    )
    assert scan_source(planted, _GATEWAY, "planted.py") == []


def test_gate_flags_a_class_level_attribute_the_model_lacks():
    """analytics.get_devices_health filtered on Device.type; the column is device_type."""
    planted = (
        "from sqlalchemy import select\n"
        "from app.models.devices import Device\n"
        "def f(t):\n"
        "    return select(Device).where(Device.type == t, Device.device_type == t)\n"
    )
    findings = scan_source(planted, "app.services.analytics", "planted.py")
    assert findings == ["planted.py:4: Device.type AttributeError: the model has no such attribute"]
