"""Run the shipped backup-key helper against a stub Docker, never a real key store.

The real generation path (gpg inside the PostgreSQL image) is exercised on a Linux
host by running the helper for real and decrypting a pg-backup dump with the key it
hands out; these tests pin the host-side contract: where each half goes, what is
refused, and that nothing is installed unless the private key was handed over.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX helper")

FPR = "0123456789ABCDEF0123456789ABCDEF01234567"
PUBLIC = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nPUBLICBODY\n-----END PGP PUBLIC KEY BLOCK-----"
PRIVATE = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nPRIVATEBODY\n-----END PGP PRIVATE KEY BLOCK-----"


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/backup-keygen.sh").write_text(
        (ROOT / "scripts/backup-keygen.sh").read_text()
    )
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets/backup-public.asc").write_text("")
    (tmp_path / ".env.max").write_text(
        "BACKUP_GPG_RECIPIENT=\nBACKUP_GPG_PUBLIC_KEY_PATH=./secrets/backup-public.asc\n"
    )
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    # `docker run` records its stdin (the passphrase) and UID_EMAIL, then emits the
    # sections the in-container script prints. STUB_OUTPUT=broken drops them.
    docker.write_text(
        "#!/bin/bash\n"
        'if [ "$1" = image ]; then exit "${STUB_IMAGE_EXIT:-0}"; fi\n'
        'cat > "$STUB_DIR/stdin"\n'
        'for a in "$@"; do case "$a" in UID_EMAIL=*) echo "${a#UID_EMAIL=}" > "$STUB_DIR/uid";; esac; done\n'
        'if [ "${STUB_OUTPUT:-}" = broken ]; then echo garbage; exit 0; fi\n'
        f'printf "%s\\n" "-----FREESDN FINGERPRINT-----" "{FPR}" "-----FREESDN PUBLIC-----"\n'
        f"printf '%s\\n' '{PUBLIC}'\n"
        'printf "%s\\n" "-----FREESDN PRIVATE-----"\n'
        f"printf '%s\\n' '{PRIVATE}'\n"
        'printf "%s\\n" "-----FREESDN END-----"\n'
    )
    docker.chmod(0o700)
    return tmp_path


def run(tree, *args, stdin="a-long-enough-passphrase\n", **env):
    return subprocess.run(
        [shutil.which("bash"), "scripts/backup-keygen.sh", *args],
        cwd=tree,
        input=stdin,
        env={
            **os.environ,
            "PATH": str(tree / "bin") + os.pathsep + os.environ["PATH"],
            "STUB_DIR": str(tree),
            **env,
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_public_key_installed_in_place_and_private_key_only_on_stdout(tree):
    key = tree / "secrets/backup-public.asc"
    inode = key.stat().st_ino
    result = run(tree)
    assert result.returncode == 0, result.stderr
    # Same inode: the running pg-backup container has THIS file bind-mounted.
    assert key.stat().st_ino == inode
    assert key.read_text().strip() == PUBLIC
    assert stat.S_IMODE(key.stat().st_mode) == 0o644
    assert result.stdout.strip() == PRIVATE
    assert FPR in result.stderr
    assert "PRIVATEBODY" not in result.stderr
    for path in tree.rglob("*"):
        if path.is_file() and path.name not in ("stdin", "docker"):
            assert "PRIVATEBODY" not in path.read_text(errors="replace"), path
    assert (tree / "stdin").read_text() == "a-long-enough-passphrase\n"


def test_private_key_out_is_private_and_never_overwritten(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("usb") / "private.asc"
    result = run(tree, "--private-key-out", str(outside))
    assert result.returncode == 0, result.stderr
    assert outside.read_text().strip() == PRIVATE
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert "PRIVATEBODY" not in result.stdout
    (tree / "secrets/backup-public.asc").write_text("")
    again = run(tree, "--private-key-out", str(outside))
    assert again.returncode == 3
    assert outside.read_text().strip() == PRIVATE
    assert (tree / "secrets/backup-public.asc").read_text() == ""


def test_an_installed_key_is_never_rotated_silently(tree):
    key = tree / "secrets/backup-public.asc"
    key.write_text("existing key\n")
    result = run(tree)
    assert result.returncode == 3
    assert "already installed" in result.stderr
    assert key.read_text() == "existing key\n"
    assert not (tree / "stdin").exists()


def test_directory_made_by_docker_is_explained_not_followed(tree):
    key = tree / "secrets/backup-public.asc"
    key.unlink()
    key.mkdir()
    result = run(tree)
    assert result.returncode == 3
    assert "DIRECTORY" in result.stderr
    assert "sudo rmdir" in result.stderr
    assert key.is_dir() and not any(key.iterdir())


def test_symlinked_key_path_is_refused(tree):
    key = tree / "secrets/backup-public.asc"
    key.unlink()
    target = tree / "target"
    key.symlink_to(target)
    result = run(tree)
    assert result.returncode == 3
    assert not target.exists()


def test_short_passphrase_is_refused_before_generation(tree):
    result = run(tree, stdin="short\n")
    assert result.returncode == 3
    assert not (tree / "stdin").exists()
    assert (tree / "secrets/backup-public.asc").read_text() == ""


def test_no_passphrase_sends_an_empty_line(tree):
    result = run(tree, "--no-passphrase", stdin="")
    assert result.returncode == 0, result.stderr
    assert (tree / "stdin").read_text() == "\n"


def test_failed_generation_installs_nothing(tree):
    result = run(tree, STUB_OUTPUT="broken")
    assert result.returncode == 4
    assert (tree / "secrets/backup-public.asc").read_text() == ""
    assert "PRIVATE" not in result.stdout


def test_unwritable_private_destination_installs_no_public_key(tree, tmp_path_factory):
    """Never encrypt backups to a key nobody holds."""
    blocked = tmp_path_factory.mktemp("ro")
    blocked.chmod(0o500)
    try:
        result = run(tree, "--private-key-out", str(blocked / "private.asc"))
    finally:
        blocked.chmod(0o700)
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    assert result.returncode == 4
    assert (tree / "secrets/backup-public.asc").read_text() == ""


def test_missing_image_is_reported(tree):
    result = run(tree, STUB_IMAGE_EXIT="1")
    assert result.returncode == 2
    assert "build the stack first" in result.stderr


@pytest.mark.parametrize(
    ("recipient", "uid", "action"),
    [
        ("backup@example.com", "backup@example.com", False),
        ("", "freesdn-backup@localhost", False),
        ("__CHANGE_ME_OR_UNCOMMENT_PLAINTEXT_BELOW__", "freesdn-backup@localhost", True),
    ],
)
def test_configured_recipient_is_honoured_or_flagged(tree, recipient, uid, action):
    (tree / ".env.max").write_text(
        f"BACKUP_GPG_RECIPIENT={recipient}\nBACKUP_GPG_PUBLIC_KEY_PATH=./secrets/backup-public.asc\n"
    )
    result = run(tree)
    assert result.returncode == 0, result.stderr
    assert (tree / "uid").read_text().strip() == uid
    assert ("ACTION NEEDED" in result.stderr) is action
