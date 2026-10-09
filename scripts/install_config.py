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


def configure(
    root: Path, tier: str, dev: bool = False, domain: str = "", email: str = ""
) -> tuple[Path, bool]:
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
    output = []
    seen = set()
    for line in content.splitlines():
        item = line.strip()
        if not item or item.startswith("#") or "=" not in item:
            output.append(line)
            continue
        key, value = (part.strip() for part in item.split("=", 1))
        if fresh and "__CHANGE_ME__" in value:
            if key == "SECRET_KEY":
                value = secrets.token_urlsafe(48)
            else:
                value = "".join(
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(32)
                )
                if key == "FLOWER_BASIC_AUTH":
                    value = "admin:" + value
            line = key + "=" + value
        if key in overrides:
            line = key + "=" + overrides[key]
            seen.add(key)
        output.append(line)
    output.extend(
        key + "=" + value for key, value in overrides.items() if key not in seen
    )
    write_private(path, "\n".join(output) + "\n", None if fresh else existing[1])
    return path, fresh


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("lite", "pro", "max"), default="lite")
    parser.add_argument("--dev", action="store_true")
    parser.add_argument("--domain", default="")
    parser.add_argument("--email", default="")
    args = parser.parse_args()
    try:
        path, fresh = configure(
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
