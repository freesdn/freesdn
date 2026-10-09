"""Exercise actual exporter and shell decisions, including false-green failure modes."""

from __future__ import annotations

import os
import runpy
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(
    not (ROOT / "docker/backup_metrics.py").is_file(), reason="requires shipped docker sources"
)
NOW = 1_800_000_000
LOCAL = "freesdn_pg_backup_"
REMOTE = LOCAL + "offsite_"
BATCH = "20260915_120000.sql.gz.gpg"


def fixture_pair(root: Path, success: int = NOW - 60) -> tuple[Path, Path]:
    backups, offsite = root / "backups", root / "offsite-status"
    (backups / ".metrics").mkdir(parents=True)
    offsite.mkdir()
    for database in ("freesdn", "logdb"):
        (backups / f"{database}_{BATCH}").write_bytes(
            b"synthetic archive, not a real encrypted dump"
        )
    (backups / ".metrics/pg_backup.last_success").write_text(
        f"{success} 20260915_120000 sql.gz.gpg\n"
    )
    (backups / ".metrics/pg_backup.prom").write_text(
        f"{LOCAL}enabled 1\n{LOCAL}encryption_enabled 1\n{LOCAL}last_attempt_failed 0\n{LOCAL}last_success_timestamp {success}\n"
    )
    return backups, offsite


def collect(backups: Path, offsite: Path, env: dict[str, str] | None = None):
    return runpy.run_path(str(ROOT / "docker/backup_metrics.py"))["collect"](
        backups, offsite, env or {}, NOW
    )


def test_missing_state_emits_failure_signals_instead_of_missing_series(tmp_path: Path):
    metrics = collect(tmp_path, tmp_path, {"BACKUP_OFFSITE_REQUIRED": "1"})
    assert metrics[LOCAL + "status_valid"] == metrics[LOCAL + "pair_present"] == 0
    assert metrics[REMOTE + "status_valid"] == 0
    assert metrics[REMOTE + "required"] == 1
    assert metrics[LOCAL + "last_success_timestamp"] == 0


@pytest.mark.parametrize(
    "damage",
    [
        "none",
        "missing",
        "empty",
        "symlink",
        "pointer",
        "future",
        "duplicate",
        "malformed",
        "oversize",
        "fifo",
        "injection",
    ],
)
def test_exporter_validates_status_and_the_actual_pair(tmp_path: Path, damage: str):
    backups, offsite = fixture_pair(tmp_path)
    metrics = backups / ".metrics/pg_backup.prom"
    archive = backups / f"logdb_{BATCH}"
    if damage == "missing":
        archive.unlink()
    elif damage == "empty":
        archive.write_bytes(b"")
    elif damage == "symlink":
        archive.unlink()
        archive.symlink_to(backups / f"freesdn_{BATCH}")
    elif damage == "pointer":
        (backups / ".metrics/pg_backup.last_success").write_text(
            f"{NOW - 60} ../../escape sql.gz\n"
        )
    elif damage == "future":
        metrics.write_text(metrics.read_text().replace(str(NOW - 60), str(NOW + 1)))
    elif damage == "duplicate":
        metrics.write_text(metrics.read_text() + f"{LOCAL}enabled 1\n")
    elif damage == "malformed":
        metrics.write_text("not prometheus data")
    elif damage == "oversize":
        metrics.write_text("#" * 10000)
    elif damage == "fifo":
        metrics.unlink()
        os.mkfifo(metrics)
    elif damage == "injection":
        metrics.write_text(metrics.read_text() + "secret_metric 123\n")
    result = collect(backups, offsite)
    assert result[LOCAL + "pair_present"] == (1 if damage == "none" else 0)
    assert "secret_metric" not in result


@pytest.mark.parametrize("value", ["0", "-1", "nan", "1e6", "9999999999999", "5;id"])
def test_invalid_timing_never_silently_falls_back(tmp_path: Path, value: str):
    backups, offsite = fixture_pair(tmp_path)
    assert (
        collect(backups, offsite, {"BACKUP_INTERVAL_SECONDS": value})[LOCAL + "config_valid"] == 0
    )


def test_offsite_source_age_survives_recent_copy_and_requirement_survives_profile_removal(
    tmp_path: Path,
):
    backups, offsite = fixture_pair(tmp_path)
    (offsite / "offsite.prom").write_text(
        f"{REMOTE}last_attempt_failed 0\n{REMOTE}last_success_timestamp {NOW - 1}\n{REMOTE}source_timestamp 12345\n{REMOTE}retention_failed 0\n"
    )
    metrics = collect(
        backups, offsite, {"BACKUP_INTERVAL_SECONDS": "300", "BACKUP_FRESHNESS_GRACE_SECONDS": "60"}
    )
    assert metrics[REMOTE + "required"] == metrics[REMOTE + "status_valid"] == 1
    assert metrics[REMOTE + "source_timestamp"] == 12345
    assert metrics[LOCAL + "max_age_seconds"] == 360
    assert metrics[REMOTE + "max_age_seconds"] == 86760


FAKE_RCLONE = """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args=sys.argv[1:]; args=args[2:]; command=args[0]; case=os.environ['CASE']
source=pathlib.Path(os.environ['FIXTURE_BACKUPS']); dest=pathlib.Path(os.environ['FIXTURE_REMOTE'])
if command == 'listremotes': print('fixture:'); sys.exit(0)
if command == 'copy':
    if case == 'copy': sys.exit(41)
    for name in pathlib.Path(args[args.index('--files-from')+1]).read_text().splitlines(): shutil.copyfile(source/name,dest/name)
elif command == 'check':
    if case == 'check': sys.exit(42)
    names=pathlib.Path(args[args.index('--files-from')+1]).read_text().splitlines()
    pathlib.Path(args[args.index('--match')+1]).write_text('' if case == 'incomplete' else '\\n'.join(names)+'\\n')
elif command == 'copyto':
    if case == 'marker': sys.exit(43)
    shutil.copyfile(args[1],dest/'pointer')
elif command == 'cat': print((dest/'pointer').read_text(),end='')
elif command == 'delete':
    if case == 'retention': sys.exit(44)
else: sys.exit(45)
"""


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "copy",
        "check",
        "incomplete",
        "marker",
        "retention",
        "missing",
        "orphan",
        "traversal",
        "bad_interval",
    ],
)
def test_offsite_acknowledges_only_verified_pairs(tmp_path: Path, case: str):
    backups, offsite = fixture_pair(tmp_path, int(time.time()) - 60)
    previous = int(time.time()) - 120
    (offsite / "offsite.prom").write_text(
        f"{REMOTE}last_attempt_failed 0\n{REMOTE}last_success_timestamp {previous}\n{REMOTE}source_timestamp {previous}\n{REMOTE}retention_failed 0\n"
    )
    (backups / "freesdn_20260915_130000.sql.gz.gpg.partial").write_bytes(b"partial")
    (backups / "freesdn_20260915_140000.sql.gz.gpg").write_bytes(b"orphan")
    if case == "missing":
        (backups / ".metrics/pg_backup.last_success").unlink()
    elif case == "orphan":
        (backups / f"logdb_{BATCH}").unlink()
    elif case == "traversal":
        (backups / ".metrics/pg_backup.last_success").write_text(
            f"{previous} ../../escape sql.gz\n"
        )
    remote = tmp_path / "remote"
    remote.mkdir()
    binary = tmp_path / "bin"
    binary.mkdir()
    executable = binary / "rclone"
    executable.write_text(FAKE_RCLONE)
    executable.chmod(0o700)
    script = (ROOT / "docker/backup-offsite.sh").read_text()
    script = script.replace("/backups", str(backups)).replace("/offsite-status", str(offsite))
    script = script.replace("/tmp/offsite.", str(tmp_path / "work."))
    script = script.replace('sleep "$INTERVAL_SECONDS"', "exit 0")
    result = subprocess.run(
        ["sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env={
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "BACKUP_OFFSITE_REMOTE": "fixture",
            "BACKUP_OFFSITE_PATH": "backups",
            "BACKUP_OFFSITE_INTERVAL_HOURS": "invalid" if case == "bad_interval" else "24",
            "BACKUP_OFFSITE_RETENTION_DAYS": "30",
            "CASE": case,
            "FIXTURE_BACKUPS": str(backups),
            "FIXTURE_REMOTE": str(remote),
        },
    )
    state = dict(line.split() for line in (offsite / "offsite.prom").read_text().splitlines())
    if case in ("success", "retention"):
        assert result.returncode == 0, result.stderr
        assert state[REMOTE + "last_attempt_failed"] == "0"
        assert int(state[REMOTE + "last_success_timestamp"]) > previous
        assert state[REMOTE + "retention_failed"] == str(int(case == "retention"))
        assert {path.name for path in remote.iterdir()} == {
            "pointer",
            f"freesdn_{BATCH}",
            f"logdb_{BATCH}",
        }
    else:
        assert state[REMOTE + "last_attempt_failed"] == "1"
        assert state[REMOTE + "last_success_timestamp"] == str(previous)
        assert "completion recorded" not in result.stdout


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "failed",
        "retention",
        "stale",
        "future",
        "missing",
        "duplicate",
        "malformed",
        "short_cadence",
    ],
)
def test_offsite_health_uses_verified_source_age_and_failure_state(tmp_path: Path, case: str):
    now = int(time.time())
    source = now - (200000 if case == "stale" else 1000)
    verified = now + 1 if case == "future" else now - 1
    text = (
        f"{REMOTE}last_attempt_failed {int(case == 'failed')}\n"
        f"{REMOTE}last_success_timestamp {verified}\n"
        f"{REMOTE}source_timestamp {source}\n"
        f"{REMOTE}retention_failed {int(case == 'retention')}\n"
    )
    if case == "duplicate":
        text += f"{REMOTE}source_timestamp {source}\n"
    if case == "malformed":
        text = "invalid status"
    if case != "missing":
        (tmp_path / "offsite.prom").write_text(text)
    script = (
        (ROOT / "docker/backup-offsite-health.sh")
        .read_text()
        .replace("/offsite-status", str(tmp_path))
    )
    # Fractional hours are invalid, rather than silently accepted by awk math.
    env = {
        **os.environ,
        "BACKUP_INTERVAL_SECONDS": "10",
        "BACKUP_FRESHNESS_GRACE_SECONDS": "10",
        "BACKUP_OFFSITE_INTERVAL_HOURS": "0.1" if case == "short_cadence" else "24",
    }
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, timeout=5)
    assert (result.returncode == 0) == (case == "valid"), result.stderr
