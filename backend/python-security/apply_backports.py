"""Apply reviewed CPython backports during image construction, never at startup.

The exact before and after source hashes are required. A different Python patch
release must receive a new upstream review; this script does not guess whether
an unknown source is compatible. Keep this file identical in both build contexts.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sysconfig
import tempfile
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(info: os.stat_result) -> tuple:
    """Exclude read-induced atime changes from the mutation guard."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_gid, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def apply(stdlib: Path, manifest: dict, *, verify_only: bool = False) -> list[dict]:
    """Validate every input before replacing any module or its bytecode."""
    if not isinstance(manifest, dict) or manifest.get("format") != 2 or manifest.get("python_version") != "3.14.8":
        raise ValueError("Unsupported backport manifest")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 4:
        raise ValueError("Expected exactly four reviewed modules")
    if not all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in files):
        raise ValueError("Invalid module record")
    if {row["name"] for row in files} != {"poplib.py", "tarfile.py", "tempfile.py", "shutil.py"}:
        raise ValueError("Unexpected module names")
    if not stdlib.is_absolute() or stdlib.resolve() != stdlib or not stdlib.is_dir():
        raise ValueError("Expected a real absolute standard-library directory")
    cache = stdlib / "__pycache__"
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise ValueError("Unexpected bytecode-cache path")
    planned = []
    for row in files:
        for field in ("before_sha256", "after_sha256"):
            if not isinstance(row.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", row[field]):
                raise ValueError("Invalid source digest")
        if row["before_sha256"] == row["after_sha256"]:
            raise ValueError("Backport must change the source")
        patches = row.get("patches")
        if not isinstance(patches, list) or not 1 <= len(patches) <= 16:
            raise ValueError("Expected bounded patch contexts")
        if "old_text" in row or "new_text" in row:
            raise ValueError("Obsolete patch context format")
        for patch in patches:
            if not isinstance(patch, dict) or set(patch) != {"old_text", "new_text"}:
                raise ValueError("Invalid patch context")
            if not all(isinstance(patch[key], str) and patch[key] for key in ("old_text", "new_text")):
                raise ValueError("Missing patch context")
            if patch["old_text"] == patch["new_text"]:
                raise ValueError("Patch context must change source")
        path = stdlib / row["name"]
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Module must be a regular, unshared file")
        original = path.read_bytes()
        current = digest(original)
        if current == row["after_sha256"]:
            patched = original
            action = "already_applied"
        elif current == row["before_sha256"] and not verify_only:
            patched = original
            for patch in patches:
                old, new = patch["old_text"].encode(), patch["new_text"].encode()
                if patched.count(old) != 1:
                    raise ValueError("Patch context must match exactly once")
                patched = patched.replace(old, new, 1)
            action = "applied"
        else:
            raise ValueError("Unexpected or unpatched standard-library source")
        if digest(patched) != row["after_sha256"]:
            raise ValueError("Patched source digest mismatch")
        compile(patched, str(path), "exec")
        bytecode = list(cache.glob(path.stem + ".*.pyc")) if cache.exists() else []
        for entry in bytecode:
            cache_info = entry.lstat()
            if not stat.S_ISREG(cache_info.st_mode) or cache_info.st_nlink != 1:
                raise ValueError("Unexpected cached-bytecode file")
        planned.append((path, info, original, patched, bytecode, action))

    result = []
    for path, info, original, patched, bytecode, action in planned:
        if not verify_only:
            # No downloaded code, runtime monkeypatch, or source-version fallback.
            # A failed RUN discards the image layer rather than shipping a partial
            # build. Preserve file permissions and invalidate only these modules.
            if path.read_bytes() != original or identity(path.lstat()) != identity(info):
                raise ValueError("Module changed after validation")
            if action == "applied":
                descriptor, temporary = tempfile.mkstemp(prefix=".freesdn-" + path.name + "-", dir=stdlib)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(patched)
                        os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                        os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, path)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            for entry in bytecode:
                entry.unlink()
        if digest(path.read_bytes()) != digest(patched):
            raise ValueError("Installed source verification failed")
        result.append({"name": path.name, "sha256": digest(patched),
                       "action": "verified" if verify_only else action})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Require patched files without changing them")
    args = parser.parse_args()
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.14.8":
        raise SystemExit("Reviewed CPython 3.14.8 is required; review newer sources before updating")
    manifest = json.loads(Path(__file__).with_name("manifest.json").read_bytes())
    result = apply(Path(sysconfig.get_path("stdlib")), manifest, verify_only=args.verify)
    print(json.dumps({"python": platform.python_version(), "modules": result}, sort_keys=True))


if __name__ == "__main__":
    main()
