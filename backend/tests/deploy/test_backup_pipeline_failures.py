# SPDX-License-Identifier: AGPL-3.0-only
"""Execute the shipped backup shell with failing producers, not live credentials.

gzip is real; pg_dump/GPG are controlled fault injectors. Encryption and database
restore are verified separately by scripts/restore_drill.sh against containers.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[3] / "docker-compose.yml"
pytestmark = pytest.mark.skipif(
    not COMPOSE.is_file() or not shutil.which("bash") or not shutil.which("gzip"),
    reason="requires shipped Compose file, bash and gzip",
)


def _run_pipeline(
    tmp_path: Path,
    encrypted: bool,
    fail: str,
    previous_success: int = 0,
    *,
    key: str | None = "synthetic key for the GPG fault injector",
    extra_env: dict[str, str] | None = None,
    sleep_script: str = "#!/bin/bash\nexit 99\n",
) -> tuple[int, str, Path]:
    entrypoint = yaml.safe_load(COMPOSE.read_text())["services"]["pg-backup"]["entrypoint"]
    command = shlex.split(entrypoint)[2].replace("$$", "$")
    backups = tmp_path / "backups"
    backups.mkdir()
    if previous_success:
        (backups / ".metrics").mkdir()
        (backups / ".metrics/pg_backup.prom").write_text(
            f"freesdn_pg_backup_last_success_timestamp {previous_success}\n"
        )
    command = command.replace("/backups", str(backups))
    command = command.replace("/tmp/gnupg", str(tmp_path / "gnupg"))
    key_path = tmp_path / "public.asc"
    if key == "<directory>":
        key_path.mkdir()
    elif key is not None:
        key_path.write_text(key)
    command = command.replace("/etc/freesdn/gpg/backup-public.asc", str(key_path))
    command = command.replace("/tmp/gpg-import.log", str(tmp_path / "gpg-import.log"))
    binary = tmp_path / "bin"
    binary.mkdir()
    scripts = {
        "pg_dump": '#!/bin/bash\n[[ "$2" != "$FAIL_AT" ]] || exit 42\nprintf "SELECT 1;\\n"\n',
        # FAKE_KEYS = public keys the file "holds"; FAKE_FPR = the imported
        # fingerprint; ACCEPT_RECIPIENT limits which recipient can encrypt; the
        # --output /dev/null call is the startup encryption probe (PROBE_EXIT).
        "gpg": """#!/bin/bash
if [[ "$*" == *"--show-keys"* ]]; then
  for i in $(seq 1 "${FAKE_KEYS:-1}"); do echo "pub:u:255:22:K$i:1:::u:::scESC:"; done
  exit 0
fi
if [[ "$*" == *"--list-keys"* ]]; then
  echo "pub:u:255:22:K1:1:::u:::scESC:"; echo "fpr:::::::::${FAKE_FPR:-FPR1}:"; exit 0
fi
if [[ "$*" == *"--import"* ]]; then exit 0; fi
args=("$@"); recipient=""
for ((i = 0; i < ${#args[@]}; i++)); do
  [[ "${args[i]}" != "--recipient" ]] || recipient="${args[i+1]}"
done
[[ -z "${ACCEPT_RECIPIENT:-}" || "$recipient" == "$ACCEPT_RECIPIENT" ]] || exit 45
if [[ "$*" == *"--output /dev/null"* ]]; then cat > /dev/null; exit "${PROBE_EXIT:-0}"; fi
[[ "$FAIL_AT" != "gpg" ]] || exit 43
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then cat > "$2"; exit; fi
  shift
done
exit 44
""",
        # End the infinite service loop only after its first successful iteration.
        "sleep": sleep_script,
    }
    for name, content in scripts.items():
        executable = binary / name
        executable.write_text(content)
        executable.chmod(0o700)
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
        "PGUSER": "fixture",
        "PG_PASSWORD": "fixture-only",
        "LOGDB_USER": "fixture",
        "LOGDB_PASS": "fixture-only",
        "LOGDB_DB": "fixture",
        "BACKUP_GPG_RECIPIENT": "fixture" if encrypted else "",
        "BACKUP_ALLOW_PLAINTEXT": "0" if encrypted or fail == "disabled" else "1",
        "BACKUP_INTERVAL_SECONDS": "86400",
        "BACKUP_RETENTION_DAYS": "7",
        "FAIL_AT": fail,
        # The default key file is not an OpenPGP key unless the test says so.
        "FAKE_KEYS": "1" if encrypted else "0",
        **(extra_env or {}),
    }
    result = subprocess.run(
        ["bash", "-c", command], env=env, capture_output=True, text=True, timeout=10
    )
    return result.returncode, result.stdout + result.stderr, backups


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("database", ["postgres", "logdb"])
def test_failed_dump_never_publishes_success(tmp_path: Path, encrypted: bool, database: str):
    code, output, backups = _run_pipeline(tmp_path, encrypted, database)
    assert code == 42, output
    assert "Backup complete" not in output
    metrics = (backups / ".metrics/pg_backup.prom").read_text()
    assert "freesdn_pg_backup_last_attempt_failed 1" in metrics
    assert "freesdn_pg_backup_last_success_timestamp 0" in metrics
    assert not list(backups.glob("*.sql.gz*"))


def test_failed_encryption_never_publishes_success(tmp_path: Path):
    code, output, backups = _run_pipeline(tmp_path, True, "gpg")
    assert code == 43, output
    assert "Backup complete" not in output
    metrics = (backups / ".metrics/pg_backup.prom").read_text()
    assert "freesdn_pg_backup_last_attempt_failed 1" in metrics
    assert "freesdn_pg_backup_last_success_timestamp 0" in metrics
    assert not list(backups.glob("*.gpg"))
    assert not list(backups.glob("*.partial"))


@pytest.mark.parametrize("encrypted", [False, True])
def test_success_publishes_both_databases_and_timestamp(tmp_path: Path, encrypted: bool):
    code, output, backups = _run_pipeline(tmp_path, encrypted, "")
    assert code == 99, output
    assert "Backup complete" in output
    assert "last_success_timestamp" in (backups / ".metrics/pg_backup.prom").read_text()
    extension = "*.sql.gz.gpg" if encrypted else "*.sql.gz"
    assert len(list(backups.glob(extension))) == 2
    assert not list(backups.glob("*.partial"))


def _health(backups: Path, interval: str = "86400", grace: str = "7200") -> int:
    command = yaml.safe_load(COMPOSE.read_text())["services"]["pg-backup"]["healthcheck"]["test"][1]
    command = command.replace("$$", "$").replace("/backups", str(backups))
    result = subprocess.run(
        ["sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=5,
        env={
            **os.environ,
            "BACKUP_INTERVAL_SECONDS": interval,
            "BACKUP_FRESHNESS_GRACE_SECONDS": grace,
        },
    )
    return result.returncode


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "disabled",
        "failed",
        "stale",
        "future",
        "malformed",
        "duplicate",
        "short_interval",
    ],
)
def test_old_archives_never_mask_bad_backup_health(tmp_path: Path, case: str):
    import time

    backups = tmp_path / "backups"
    (backups / ".metrics").mkdir(parents=True)
    # Reproduces the old healthcheck false positive, even without metrics.
    (backups / "freesdn_20000101_000000.sql.gz").write_text("old archive")
    stamp = str(int(time.time()) - (100000 if case == "stale" else 1000))
    if case == "future":
        stamp = str(int(time.time()) + 1000)
    if case == "malformed":
        stamp = "not-a-timestamp"
    values = f"freesdn_pg_backup_enabled {0 if case == 'disabled' else 1}\nfreesdn_pg_backup_last_attempt_failed {1 if case == 'failed' else 0}\nfreesdn_pg_backup_last_success_timestamp {stamp}\n"
    if case == "duplicate":
        values += f"freesdn_pg_backup_last_success_timestamp {stamp}\n"
    (backups / ".metrics/pg_backup.last_success").write_text(f"{stamp} 20000101_000000 sql.gz\n")
    (backups / "logdb_20000101_000000.sql.gz").write_text("old log archive")
    if case != "missing":
        (backups / ".metrics/pg_backup.prom").write_text(values)
    assert _health(backups, "300" if case == "short_interval" else "86400", "60") != 0


@pytest.mark.parametrize("encrypted", [False, True])
def test_completed_pair_passes_the_shipped_healthcheck(tmp_path: Path, encrypted: bool):
    _, _, backups = _run_pipeline(tmp_path, encrypted, "")
    assert _health(backups) == 0
    assert _health(backups, "invalid") != 0
    assert _health(backups, "0") != 0


@pytest.mark.parametrize("damage", ["primary_missing", "logdb_empty", "pointer_mismatch"])
def test_recent_metrics_cannot_mask_a_missing_completed_pair(tmp_path: Path, damage: str):
    _, _, backups = _run_pipeline(tmp_path, False, "")
    assert _health(backups) == 0
    if damage == "primary_missing":
        next(backups.glob("freesdn_*.sql.gz")).unlink()
    elif damage == "logdb_empty":
        next(backups.glob("logdb_*.sql.gz")).write_bytes(b"")
    else:
        pointer = backups / ".metrics/pg_backup.last_success"
        pointer.write_text("1 " + pointer.read_text().split(" ", 1)[1])
    assert _health(backups) != 0


def test_failure_preserves_previous_success_without_healthy_state(tmp_path: Path):
    import time

    previous = int(time.time()) - 60
    code, _, backups = _run_pipeline(tmp_path, False, "postgres", previous_success=previous)
    assert code == 42
    metrics = (backups / ".metrics/pg_backup.prom").read_text()
    assert f"freesdn_pg_backup_last_success_timestamp {previous}\n" in metrics
    assert "freesdn_pg_backup_last_attempt_failed 1\n" in metrics
    assert _health(backups) != 0


def test_disabled_encryption_is_explicitly_unhealthy(tmp_path: Path):
    _, output, backups = _run_pipeline(tmp_path, False, "disabled")
    assert "Backups DISABLED" in output
    assert "freesdn_pg_backup_enabled 0" in (backups / ".metrics/pg_backup.prom").read_text()
    assert _health(backups) != 0


def _reason(backups: Path) -> str:
    return (backups / ".metrics/pg_backup.reason").read_text().strip()


def test_single_key_is_used_when_no_recipient_is_configured(tmp_path: Path):
    """A fresh tier env leaves BACKUP_GPG_RECIPIENT empty: the key file decides."""
    code, output, backups = _run_pipeline(
        tmp_path,
        False,
        "",
        extra_env={
            "FAKE_KEYS": "1",
            "FAKE_FPR": "A1B2C3",
            "ACCEPT_RECIPIENT": "A1B2C3",
            "BACKUP_ALLOW_PLAINTEXT": "0",
        },
    )
    assert code == 99, output
    assert "recipient: A1B2C3" in output
    assert len(list(backups.glob("*.sql.gz.gpg"))) == 2
    assert not list(backups.glob("*.sql.gz"))
    assert (
        "freesdn_pg_backup_encryption_enabled 1"
        in (backups / ".metrics/pg_backup.prom").read_text()
    )
    assert _reason(backups) == "encrypted"


def test_ambiguous_key_file_without_recipient_never_writes_plaintext(tmp_path: Path):
    code, output, backups = _run_pipeline(tmp_path, False, "disabled", extra_env={"FAKE_KEYS": "2"})
    assert code == 99, output
    assert "Backups DISABLED (ambiguous_key)" in output
    assert not list(backups.glob("*.sql.gz*"))
    assert _reason(backups) == "ambiguous_key"


def test_unusable_recipient_is_refused_at_startup_instead_of_crash_looping(tmp_path: Path):
    """The env example once named backup@example.com: a key with any other user ID
    imported fine, then every pg_dump | gpg failed and the container restarted."""
    code, output, backups = _run_pipeline(tmp_path, True, "", extra_env={"PROBE_EXIT": "2"})
    assert code == 99, output
    assert "Backups DISABLED (recipient_unusable)" in output
    assert "freesdn_pg_backup_enabled 0" in (backups / ".metrics/pg_backup.prom").read_text()
    assert not list(backups.glob("*.sql.gz*"))
    assert _reason(backups) == "recipient_unusable"


def test_key_path_created_as_a_directory_is_explained(tmp_path: Path):
    """Docker creates a missing bind-mount source as a root-owned directory."""
    code, output, backups = _run_pipeline(tmp_path, True, "", key="<directory>")
    assert code == 99, output
    assert "Backups DISABLED (key_path_is_directory)" in output
    assert "sudo rmdir" in output
    assert _reason(backups) == "key_path_is_directory"


def test_key_installed_while_idle_starts_encrypted_backups_without_restart(tmp_path: Path):
    """The operator drops the public key in place; the next re-check enables backups."""
    key_path = tmp_path / "public.asc"
    marker = tmp_path / "sleep-count"
    sleep = (
        "#!/bin/bash\n"
        f'n=$(cat "{marker}" 2>/dev/null || echo 0); echo $((n + 1)) > "{marker}"\n'
        f'if [ "$n" = 0 ]; then echo "real key" > "{key_path}"; exit 0; fi\n'
        "exit 99\n"
    )
    code, output, backups = _run_pipeline(
        tmp_path,
        False,
        "",
        key="",
        extra_env={"FAKE_KEYS": "1", "BACKUP_ALLOW_PLAINTEXT": "0"},
        sleep_script=sleep,
    )
    assert code == 99, output
    assert "Backups DISABLED (no_key)" in output
    assert "Public key detected" in output
    assert len(list(backups.glob("*.sql.gz.gpg"))) == 2
    metrics = (backups / ".metrics/pg_backup.prom").read_text()
    assert "freesdn_pg_backup_enabled 1" in metrics
    assert "freesdn_pg_backup_encryption_enabled 1" in metrics
    assert _reason(backups) == "encrypted"
