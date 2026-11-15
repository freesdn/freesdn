#!/usr/bin/env python3
"""Create or update installer configuration without exposing or rotating secrets.

Run from the installation directory. Only regular, singly linked files owned by
the invoking account may be updated. Existing credentials are preserved; all
writes use mode 0600, including under a permissive caller umask.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import stat
import string
import tempfile
from pathlib import Path


def validate_origin(domain: str, email: str) -> None:
    if domain and (
        len(domain) > 253
        or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in domain.split(".")
        )
    ):
        raise ValueError(
            "--domain requires a DNS hostname without a scheme, port or path"
        )
    if email and (
        not domain
        or len(email) > 254
        or not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", email)
    ):
        raise ValueError("--email requires --domain and a single valid email address")


def read_existing(path: Path) -> tuple[str, os.stat_result] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
        ):
            raise ValueError(
                "Configuration must be a regular, singly linked file owned by this account"
            )
        return stream.read(), info


def write_private(path: Path, content: str, previous: os.stat_result | None) -> None:
    def enforce_private(fd: int) -> None:
        os.fchmod(fd, 0o600)
        if os.fstat(fd).st_mode & 0o777 != 0o600:
            raise ValueError(
                "Filesystem cannot enforce private configuration permissions; use a Linux filesystem"
            )

    if previous is None:
        # O_EXCL also refuses dangling symlinks and a concurrent installation.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            try:
                enforce_private(stream.fileno())
            except (OSError, ValueError):
                if path.lstat().st_ino == os.fstat(stream.fileno()).st_ino:
                    path.unlink()
                raise
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                enforce_private(stream.fileno())
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            current = path.lstat()
            if (
                current.st_dev,
                current.st_ino,
                current.st_mtime_ns,
                current.st_size,
            ) != (
                previous.st_dev,
                previous.st_ino,
                previous.st_mtime_ns,
                previous.st_size,
            ) or current.st_nlink != 1:
                raise ValueError(
                    "Configuration changed during installation; retry after other writers stop"
                )
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def env_value(content: str, key: str) -> str | None:
    """Last assignment wins, as with ``docker compose --env-file``."""
    found = None
    for line in content.splitlines():
        item = line.strip()
        if item.startswith(key + "="):
            found = item.split("=", 1)[1].strip()
    return found


def ensure_backup_key_placeholder(root: Path, env_path: Path) -> str:
    """Pre-create the pg-backup public-key file so Docker never makes it a directory.

    The tier env files point BACKUP_GPG_PUBLIC_KEY_PATH at a file no install
    ships. Compose short-syntax binds create a MISSING source as a root-owned
    directory, after which the documented ``gpg --export > <path>`` fails and
    even removing it needs root. An empty regular file instead is mounted as a
    file; pg-backup treats it as "no key yet", and writing the key into it later
    (same inode) is seen by the running container.

    Returns ``present``, ``missing`` (placeholder created or already empty),
    ``directory``, ``unmanaged`` (absolute/outside path left to the operator) or
    ``unset``.
    """
    value = env_value(env_path.read_text(encoding="utf-8"), "BACKUP_GPG_PUBLIC_KEY_PATH")
    if not value:
        return "unset"
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        return "unmanaged"
    target = root / relative
    parent = target.parent
    try:
        parent_info = os.lstat(parent)
    except FileNotFoundError:
        return "unmanaged"
    if not stat.S_ISDIR(parent_info.st_mode):
        return "unmanaged"
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
        return "missing"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if not stat.S_ISREG(info.st_mode):
        return "unmanaged"
    return "present" if info.st_size > 0 else "missing"


# Generated values an EXISTING environment file gains when it lacks them.
#
# Deliberately an allow-list, not "every __CHANGE_ME__ key in the example":
# backfilling ENCRYPTION_SALT or SECRET_KEY into a file that predates them would
# silently re-key every stored credential. METRICS_AUTH_TOKEN is safe to add:
# it only authorises Prometheus to read /metrics, and an install created before
# the tier examples carried it has a Prometheus whose own API target is DOWN.
BACKFILLED_SECRETS = ("METRICS_AUTH_TOKEN",)


def _generate(key: str) -> str:
    if key == "SECRET_KEY":
        return secrets.token_urlsafe(48)
    value = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
    )
    return "admin:" + value if key == "FLOWER_BASIC_AUTH" else value


def configure(
    root: Path, tier: str, dev: bool = False, domain: str = "", email: str = ""
) -> tuple[Path, bool, list[str]]:
    validate_origin(domain, email)
    if tier not in {"lite", "pro", "max"}:
        raise ValueError("Unknown deployment tier")
    path = root / (".env.dev" if dev else ".env." + tier)
    existing = read_existing(path)
    fresh = existing is None
    content = (
        (root / (path.name + ".example")).read_text(encoding="utf-8")
        if fresh
        else existing[0]
    )
    overrides: dict[str, str] = {}
    if domain:
        overrides = {
            "CADDY_SITE_ADDRESS": domain,
            "EDGE_HTTP_PORT": "80",
            "EDGE_HTTPS_PORT": "443",
            "PUBLIC_BASE_URL": "https://" + domain,
            "FRONTEND_URL": "https://" + domain,
            "CORS_ORIGINS": '["https://' + domain + '"]',
        }
        if email:
            overrides["CADDY_ACME_EMAIL"] = email
    elif fresh and not dev and tier != "lite":
        overrides = {
            "CADDY_SITE_ADDRESS": "localhost",
            "PUBLIC_BASE_URL": "https://localhost",
            "CORS_ORIGINS": '["https://localhost"]',
        }
    example = root / (path.name + ".example")
    example_text = example.read_text(encoding="utf-8") if example.is_file() else ""
    backfill = [
        key
        for key in BACKFILLED_SECRETS
        if re.search(r"^" + key + r"=__CHANGE_ME__\s*$", example_text, re.MULTILINE)
    ]
    output = []
    seen = set()
    present = set()
    added = []
    for line in content.splitlines():
        item = line.strip()
        if not item or item.startswith("#") or "=" not in item:
            output.append(line)
            continue
        key, value = (part.strip() for part in item.split("=", 1))
        present.add(key)
        if "__CHANGE_ME__" in value and (fresh or key in backfill):
            line = key + "=" + _generate(key)
            if not fresh:
                added.append(key)
        if key in overrides:
            line = key + "=" + overrides[key]
            seen.add(key)
        output.append(line)
    for key in backfill:
        if key not in present:
            output.append(key + "=" + _generate(key))
            added.append(key)
    output.extend(
        key + "=" + value for key, value in overrides.items() if key not in seen
    )
    write_private(path, "\n".join(output) + "\n", None if fresh else existing[1])
    return path, fresh, added


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("lite", "pro", "max"), default="lite")
    parser.add_argument("--dev", action="store_true")
    parser.add_argument("--domain", default="")
    parser.add_argument("--email", default="")
    args = parser.parse_args()
    try:
        path, fresh, added = configure(
            Path.cwd(), args.tier, args.dev, args.domain, args.email
        )
    except (OSError, UnicodeError, ValueError) as exc:
        # Do not include file contents, supplied values or exception repr in logs.
        parser.exit(
            3,
            "Configuration refused: "
            + (
                str(exc)
                if isinstance(exc, ValueError)
                else "cannot safely read or write the environment file"
            )
            + "\n",
        )
    print(
        f"{path.name}: {'generated with random secrets' if fresh else 'existing credentials preserved'}; permissions 0600"
    )
    if added:
        # Names only: generated values never reach the installer's output.
        print(f"{path.name}: generated missing {', '.join(added)}")
    if not args.dev:
        try:
            key_state = ensure_backup_key_placeholder(Path.cwd(), path)
        except OSError:
            key_state = "unmanaged"
        key_path = env_value(path.read_text(encoding="utf-8"), "BACKUP_GPG_PUBLIC_KEY_PATH")
        if key_state == "missing":
            print(
                f"Database backups are OFF until a GPG public key is in {key_path}. "
                f"Run ./scripts/backup-keygen.sh --env-file {path.name} after the stack is up."
            )
        elif key_state == "directory":
            print(
                f"WARNING: {key_path} is a directory (Docker created it). Database backups "
                f"stay OFF until it is removed (sudo rmdir {key_path}) and "
                "./scripts/backup-keygen.sh is run."
            )
    if args.domain:
        print(
            "HTTPS origin configured; DNS and inbound ports 80/443 must be provisioned separately."
        )
    elif fresh and not args.dev and args.tier != "lite":
        print(
            "Local HTTPS selected. Configure a production DNS hostname before exposing the service."
        )


if __name__ == "__main__":
    main()
