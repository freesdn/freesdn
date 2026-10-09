"""Read-only backup status exporter; never serve archive or credential contents."""

from __future__ import annotations

import os
import re
import stat
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOCAL = "freesdn_pg_backup_"
REMOTE = "freesdn_pg_backup_offsite_"
LOCAL_FIELDS = (
    "enabled",
    "encryption_enabled",
    "last_attempt_failed",
    "last_success_timestamp",
)
REMOTE_FIELDS = (
    "last_attempt_failed",
    "last_success_timestamp",
    "source_timestamp",
    "retention_failed",
)


def read_small(path: Path) -> str:
    # A corrupted status volume must not turn a scrape into an unbounded read,
    # block on a FIFO, or follow a symlink to another mounted file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("status is not a regular file")
        data = stream.read(4097)
    if len(data) > 4096:
        raise ValueError("status exceeds limit")
    return data.decode("ascii")


def read_metrics(
    path: Path, prefix: str, fields: tuple[str, ...], now: int
) -> dict[str, int]:
    result = {}
    for line in read_small(path).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, value = line.split()
        if name not in {prefix + field for field in fields} or name in result:
            raise ValueError("unexpected or duplicate metric")
        if not re.fullmatch(r"[0-9]{1,12}", value):
            raise ValueError("invalid metric value")
        number = int(value)
        if number > (now if name.endswith("timestamp") else 1):
            raise ValueError("metric outside range")
        result[name] = number
    if len(result) != len(fields):
        raise ValueError("incomplete status")
    return result


def number(env: dict[str, str], key: str, default: int, maximum: int) -> int:
    value = env.get(key, str(default))
    if not re.fullmatch(r"[0-9]{1,9}", value) or not 0 < int(value) <= maximum:
        raise ValueError("invalid backup timing configuration")
    return int(value)


def collect(
    backups: Path, offsite: Path, env: dict[str, str], now: int
) -> dict[str, int]:
    metrics = {LOCAL + key: 0 for key in LOCAL_FIELDS}
    metrics.update({REMOTE + key: 0 for key in REMOTE_FIELDS})
    metrics.update(
        {
            LOCAL + "status_valid": 0,
            LOCAL + "pair_present": 0,
            REMOTE + "status_valid": 0,
            LOCAL + "config_valid": 0,
        }
    )
    # An explicitly required remote alerts even before its first status file.
    # Remembering a previous remote also catches an accidentally removed dr profile.
    required = env.get("BACKUP_OFFSITE_REQUIRED", "0")
    metrics[REMOTE + "required"] = int(
        required != "0"
        or "dr" in env.get("COMPOSE_PROFILES", "").split(",")
        or (offsite / "offsite.prom").exists()
    )
    try:
        if required not in ("0", "1"):
            raise ValueError("invalid offsite requirement")
        interval = number(env, "BACKUP_INTERVAL_SECONDS", 86400, 31536000)
        grace = number(env, "BACKUP_FRESHNESS_GRACE_SECONDS", 7200, 31536000)
        remote_interval = number(env, "BACKUP_OFFSITE_INTERVAL_HOURS", 24, 8760) * 3600
        metrics[LOCAL + "max_age_seconds"] = interval + grace
        metrics[REMOTE + "max_age_seconds"] = interval + remote_interval + grace
        metrics[LOCAL + "config_valid"] = 1
    except ValueError:
        metrics[LOCAL + "max_age_seconds"] = 0
        metrics[REMOTE + "max_age_seconds"] = 0
    try:
        local = read_metrics(
            backups / ".metrics/pg_backup.prom", LOCAL, LOCAL_FIELDS, now
        )
        metrics.update(local)
        metrics[LOCAL + "status_valid"] = 1
        success, batch, extension = read_small(
            backups / ".metrics/pg_backup.last_success"
        ).split()
        if (
            not re.fullmatch(r"[0-9]{1,12}", success)
            or not re.fullmatch(r"[0-9]{8}_[0-9]{6}", batch)
            or extension not in ("sql.gz", "sql.gz.gpg")
            or not 0 < int(success) == local[LOCAL + "last_success_timestamp"] <= now
        ):
            raise ValueError("invalid completion pointer")
        files = [
            backups / f"{database}_{batch}.{extension}"
            for database in ("freesdn", "logdb")
        ]
        metrics[LOCAL + "pair_present"] = int(
            all(
                stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_size > 0
                for path in files
            )
        )
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        remote = read_metrics(offsite / "offsite.prom", REMOTE, REMOTE_FIELDS, now)
        if (
            remote[REMOTE + "source_timestamp"]
            > remote[REMOTE + "last_success_timestamp"]
        ):
            raise ValueError("source newer than verified copy")
        metrics.update(remote)
        metrics[REMOTE + "status_valid"] = 1
    except (OSError, ValueError, UnicodeError):
        pass
    return metrics


def render() -> bytes:
    metrics = collect(
        Path("/backups"), Path("/offsite-status"), dict(os.environ), int(time.time())
    )
    return "".join(
        f"# TYPE {key} gauge\n{key} {value}\n" for key, value in sorted(metrics.items())
    ).encode()


class Handler(BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def do_GET(self) -> None:
        if self.path not in ("/metrics", "/healthz"):
            self.send_error(404)
            return
        body = render() if self.path == "/metrics" else b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    # Internal Docker network only; Compose publishes no host port.
    HTTPServer(("0.0.0.0", 9788), Handler).serve_forever()
