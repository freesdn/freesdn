"""Build-time backports fail closed without altering unrelated Python files."""

import copy
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "python-security"
SPEC = importlib.util.spec_from_file_location("freesdn_python_backports", DIRECTORY / "apply_backports.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def inputs(tmp_path):
    stdlib = tmp_path / "stdlib"
    stdlib.mkdir()
    manifest = {"format": 2, "python_version": "3.14.8", "files": []}
    for name in ("poplib.py", "tarfile.py", "tempfile.py", "shutil.py"):
        before, after = b"value = 1\n", b"value = 2\n"
        target = stdlib / name
        target.write_bytes(before)
        target.chmod(0o640)
        manifest["files"].append({"name": name, "before_sha256": hashlib.sha256(before).hexdigest(),
                                  "after_sha256": hashlib.sha256(after).hexdigest(),
                                  "patches": [{"old_text": before.decode(), "new_text": after.decode()}]})
    return stdlib, manifest


def test_applies_both_and_preserves_permissions(inputs):
    stdlib, manifest = inputs
    result = MODULE.apply(stdlib, manifest)
    assert [row["action"] for row in result] == ["applied"] * 4
    for row in manifest["files"]:
        target = stdlib / row["name"]
        assert hashlib.sha256(target.read_bytes()).hexdigest() == row["after_sha256"]
        assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_idempotent_apply_and_readonly_verification(inputs):
    stdlib, manifest = inputs
    MODULE.apply(stdlib, manifest)
    before = {p.name: p.stat() for p in stdlib.iterdir()}
    assert all(x["action"] == "already_applied" for x in MODULE.apply(stdlib, manifest))
    assert all(x["action"] == "verified" for x in MODULE.apply(stdlib, manifest, verify_only=True))
    assert before == {p.name: p.stat() for p in stdlib.iterdir()}


def test_verification_refuses_unpatched_source_without_changes(inputs):
    stdlib, manifest = inputs
    with pytest.raises(ValueError, match="unpatched"):
        MODULE.apply(stdlib, manifest, verify_only=True)
    assert all((stdlib / row["name"]).read_text() == "value = 1\n" for row in manifest["files"])


@pytest.mark.parametrize("fault", ["source", "hash", "context", "empty", "syntax", "missing", "symlink", "hardlink"])
def test_second_module_refusal_does_not_modify_first(inputs, tmp_path, fault):
    stdlib, manifest = inputs
    first = stdlib / "poplib.py"
    second = stdlib / "tarfile.py"
    original = first.read_bytes()
    if fault == "source":
        second.write_text("unexpected = True\n")
    elif fault == "hash":
        manifest["files"][1]["after_sha256"] = "0" * 64
    elif fault == "context":
        manifest["files"][1]["patches"][0]["old_text"] = "not present"
    elif fault == "empty":
        manifest["files"][1]["patches"][0]["old_text"] = ""
    elif fault == "syntax":
        manifest["files"][1]["patches"][0]["new_text"] = "def\n"
        manifest["files"][1]["after_sha256"] = hashlib.sha256(b"def\n").hexdigest()
    elif fault == "missing":
        second.unlink()
    elif fault == "symlink":
        second.unlink()
        second.symlink_to(first)
    elif fault == "hardlink":
        os.link(second, tmp_path / "second-shared")
    with pytest.raises((ValueError, FileNotFoundError, SyntaxError)):
        MODULE.apply(stdlib, manifest)
    assert first.read_bytes() == original
    assert not list(stdlib.glob(".freesdn-*"))


@pytest.mark.parametrize("fault", ["version", "duplicate", "traversal", "extra", "digest"])
def test_invalid_manifest_refused_before_writes(inputs, fault):
    stdlib, manifest = inputs
    bad = copy.deepcopy(manifest)
    if fault == "version":
        bad["python_version"] = "3.14.9"
    elif fault == "duplicate":
        bad["files"][1] = copy.deepcopy(bad["files"][0])
    elif fault == "traversal":
        bad["files"][1]["name"] = "../tarfile.py"
    elif fault == "extra":
        bad["files"].append(copy.deepcopy(bad["files"][0]))
    elif fault == "digest":
        bad["files"][1]["before_sha256"] = "not a digest"
    with pytest.raises(ValueError):
        MODULE.apply(stdlib, bad)
    assert all((stdlib / row["name"]).read_text() == "value = 1\n" for row in manifest["files"])


def test_only_reviewed_modules_bytecode_removed(inputs):
    stdlib, manifest = inputs
    cache = stdlib / "__pycache__"
    cache.mkdir()
    for name in ("poplib.cpython-314.pyc", "tarfile.cpython-314.opt-1.pyc",
                 "tempfile.cpython-314.pyc", "shutil.cpython-314.opt-2.pyc", "other.cpython-314.pyc"):
        (cache / name).write_bytes(b"synthetic stale cache")
    MODULE.apply(stdlib, manifest)
    assert sorted(p.name for p in cache.iterdir()) == ["other.cpython-314.pyc"]


def test_symlink_cache_refused_without_touching_destination(inputs, tmp_path):
    stdlib, manifest = inputs
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "poplib.cpython-314.pyc"
    protected.write_bytes(b"keep")
    (stdlib / "__pycache__").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="cache"):
        MODULE.apply(stdlib, manifest)
    assert protected.read_bytes() == b"keep"
    assert (stdlib / "poplib.py").read_text() == "value = 1\n"


def test_symlink_bytecode_refused_before_module_changes(inputs, tmp_path):
    stdlib, manifest = inputs
    cache = stdlib / "__pycache__"
    cache.mkdir()
    protected = tmp_path / "outside.pyc"
    protected.write_bytes(b"keep")
    (cache / "tarfile.cpython-314.pyc").symlink_to(protected)
    with pytest.raises(ValueError, match="bytecode"):
        MODULE.apply(stdlib, manifest)
    assert protected.read_bytes() == b"keep"
    assert (stdlib / "poplib.py").read_text() == "value = 1\n"


def test_manifest_records_exact_reviewed_modules():
    manifest = json.loads((DIRECTORY / "manifest.json").read_text())
    assert manifest["python_version"] == "3.14.8"
    assert manifest["format"] == 2
    assert {row["name"] for row in manifest["files"]} == {"poplib.py", "tarfile.py", "tempfile.py", "shutil.py"}
    assert {row["upstream_commit"] for row in manifest["files"]} == {
        "b234a2b67539f787e191d2ef19a7cbdce32874e7", "a4919937a4e1e69a0d178909c6f20557eca5d1d0",
        "5c20517a4fc56683efe63a7751020db9573f538d"}
    cleanup = [row for row in manifest["files"] if row["name"] in {"tempfile.py", "shutil.py"}]
    assert all(row["backport_head"] == "fb187f1eaace3d4f47397b754cf928a73c5b0d9f" for row in cleanup)
    assert all(row["backport_status_at_review"] == "open_unmerged" for row in cleanup)


def test_last_module_failure_preserves_all_sources_and_bytecode(inputs):
    stdlib, manifest = inputs
    cache = stdlib / "__pycache__"
    cache.mkdir()
    for row in manifest["files"]:
        (cache / (Path(row["name"]).stem + ".cpython-314.pyc")).write_bytes(b"keep")
    original = {str(p.relative_to(stdlib)): (p.read_bytes(), MODULE.identity(p.stat()))
                for p in stdlib.rglob("*") if p.is_file()}
    manifest["files"][-1]["after_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        MODULE.apply(stdlib, manifest)
    assert {str(p.relative_to(stdlib)): (p.read_bytes(), MODULE.identity(p.stat()))
            for p in stdlib.rglob("*") if p.is_file()} == original


@pytest.mark.parametrize("fault", ["none", "empty", "too_many", "not_list", "not_dict",
                                  "missing", "extra", "old_empty", "new_empty", "same", "obsolete"])
def test_malformed_last_patch_refused_before_writes(inputs, fault):
    stdlib, manifest = inputs
    row = manifest["files"][-1]
    if fault == "none":
        row.pop("patches")
    elif fault == "empty":
        row["patches"] = []
    elif fault == "too_many":
        row["patches"] *= 17
    elif fault == "not_list":
        row["patches"] = {}
    elif fault == "not_dict":
        row["patches"] = [None]
    elif fault == "missing":
        row["patches"][0].pop("new_text")
    elif fault == "extra":
        row["patches"][0]["unreviewed"] = True
    elif fault == "old_empty":
        row["patches"][0]["old_text"] = ""
    elif fault == "new_empty":
        row["patches"][0]["new_text"] = ""
    elif fault == "same":
        row["patches"][0]["new_text"] = row["patches"][0]["old_text"]
    elif fault == "obsolete":
        row["old_text"] = "value = 1\n"
    with pytest.raises(ValueError):
        MODULE.apply(stdlib, manifest)
    assert all((stdlib / x["name"]).read_text() == "value = 1\n" for x in manifest["files"])
    assert not list(stdlib.glob(".freesdn-*"))


@pytest.mark.parametrize("fault", [None, "omitted", "reordered", "repeated_context"])
def test_multiple_contexts_require_exact_final_hash(inputs, fault):
    stdlib, manifest = inputs
    row = manifest["files"][-1]
    before = "value = 1\nother = 3\n"
    after = "value = 2\nother = 4\n"
    row["patches"] = [{"old_text": "value = 1\n", "new_text": "value = 2\n"},
                      {"old_text": "value = 2\nother = 3\n", "new_text": after}]
    if fault == "omitted":
        row["patches"].pop()
    elif fault == "reordered":
        row["patches"].reverse()
    elif fault == "repeated_context":
        before += "value = 1\n"
    (stdlib / row["name"]).write_text(before)
    row["before_sha256"] = hashlib.sha256(before.encode()).hexdigest()
    row["after_sha256"] = hashlib.sha256(after.encode()).hexdigest()
    if fault:
        with pytest.raises(ValueError):
            MODULE.apply(stdlib, manifest)
        assert (stdlib / row["name"]).read_text() == before
        assert (stdlib / "poplib.py").read_text() == "value = 1\n"
    else:
        assert all(x["action"] == "applied" for x in MODULE.apply(stdlib, manifest))
        assert (stdlib / row["name"]).read_text() == after
        assert all(x["action"] == "verified" for x in MODULE.apply(stdlib, manifest, verify_only=True))


def test_mixed_reviewed_before_and_after_sources(inputs):
    stdlib, manifest = inputs
    (stdlib / "tarfile.py").write_text("value = 2\n")
    result = MODULE.apply(stdlib, manifest)
    assert [row["action"] for row in result] == ["applied", "already_applied", "applied", "applied"]
    assert all(x["action"] == "verified" for x in MODULE.apply(stdlib, manifest, verify_only=True))


@pytest.mark.parametrize("fault", ["old_format", "missing_cleanup", "row_type", "name_type"])
def test_four_module_contract_cannot_be_downgraded(inputs, fault):
    stdlib, manifest = inputs
    if fault == "old_format":
        manifest["format"] = 1
    elif fault == "missing_cleanup":
        manifest["files"] = manifest["files"][:2]
    elif fault == "row_type":
        manifest["files"][-1] = None
    else:
        manifest["files"][-1]["name"] = []
    with pytest.raises(ValueError):
        MODULE.apply(stdlib, manifest)
    assert all(p.read_text() == "value = 1\n" for p in stdlib.glob("*.py"))
