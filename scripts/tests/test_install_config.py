"""Run the shipped installer while replacing Docker, never a customer stack."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX installer")


@pytest.fixture
def installation(tmp_path):
    (tmp_path / "scripts").mkdir()
    for relative in (
        "install.sh",
        "scripts/install_config.py",
        ".env.lite.example",
        ".env.pro.example",
        ".env.max.example",
        ".env.dev.example",
    ):
        # Public release normalizes line endings; model that on Windows checkouts.
        (tmp_path / relative).write_text((ROOT / relative).read_text())
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_CALLS"\n')
    docker.chmod(0o700)
    return tmp_path


def run(root, *args):
    return subprocess.run(
        [
            shutil.which("bash"),
            "-c",
            'umask 000; exec bash install.sh --skip-prereqs --no-start "$@"',
            "installer",
            *args,
        ],
        cwd=root,
        env={
            **os.environ,
            "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
            "DOCKER_CALLS": str(root / "docker-calls"),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def values(path):
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )


@pytest.mark.parametrize("tier", ["lite", "pro", "max", "dev"])
def test_new_installation_secrets_are_private_even_with_open_umask(installation, tier):
    result = run(installation, *(["--dev"] if tier == "dev" else ["--tier", tier]))
    assert result.returncode == 0, result.stderr
    path = installation / (".env." + tier)
    assert path.stat().st_mode & 0o777 == 0o600
    env = values(path)
    secret_names = (
        "SECRET_KEY",
        "ENCRYPTION_SALT",
        "POSTGRES_PASSWORD",
        "LOGDB_PASSWORD",
        "REDIS_PASSWORD",
    )
    assert len({env[key] for key in secret_names}) == len(secret_names)
    for name in secret_names:
        assert "__CHANGE_ME__" not in env[name]
        assert len(env[name]) >= 32
        assert env[name] not in result.stdout + result.stderr
    template = values(installation / (".env." + tier + ".example"))
    if "BACKUP_GPG_RECIPIENT" in template:
        assert env["BACKUP_GPG_RECIPIENT"] == template["BACKUP_GPG_RECIPIENT"]
    assert " build" in (installation / "docker-calls").read_text()


def test_rerun_tightens_permissions_without_rotating_vault_or_passwords(installation):
    assert run(installation).returncode == 0
    path = installation / ".env.lite"
    before = values(path)
    path.chmod(0o644)
    result = run(
        installation, "--domain", "controller.example.com", "--email", "ops@example.com"
    )
    assert result.returncode == 0, result.stderr
    after = values(path)
    for key in (
        "SECRET_KEY",
        "ENCRYPTION_SALT",
        "JWT_SIGNING_KEY",
        "POSTGRES_PASSWORD",
        "LOGDB_PASSWORD",
        "REDIS_PASSWORD",
        "SLA_REPORT_DELIVERY_EPOCH",
    ):
        assert after[key] == before[key]
    assert (
        after["FRONTEND_URL"]
        == after["PUBLIC_BASE_URL"]
        == "https://controller.example.com"
    )
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "kind", ["symlink", "dangling", "hardlink", "directory", "fifo"]
)
def test_unsafe_configuration_target_is_never_followed_or_modified(installation, kind):
    path = installation / ".env.lite"
    sentinel = installation / "sentinel"
    sentinel.write_text("do not change\n")
    if kind == "symlink":
        path.symlink_to(sentinel)
    elif kind == "dangling":
        path.symlink_to(installation / "absent")
    elif kind == "hardlink":
        os.link(sentinel, path)
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    result = run(installation)
    assert result.returncode == 3
    assert sentinel.read_text() == "do not change\n"
    assert not (installation / "docker-calls").exists()
    assert not (installation / "absent").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["--tier"],
        ["--domain"],
        ["--email"],
        ["--unexpected"],
        ["--tier", "wrong"],
        ["--domain", "https://example.com"],
        ["--domain", "host:443"],
        ["--domain", "example.com\nADAPTER_READ_ONLY=false"],
        ["--domain", "example.com$INJECT"],
        ["--domain", "-invalid.example"],
        ["--email", "ops@example.com"],
        ["--domain", "example.com", "--email", "ops@example.com\nSECRET_KEY=x"],
    ],
)
def test_bad_arguments_do_not_generate_configuration_or_start_docker(
    installation, args
):
    result = run(installation, *args)
    assert result.returncode == 3
    assert not (installation / ".env.lite").exists()
    assert not (installation / "docker-calls").exists()


def test_two_fresh_installs_get_distinct_credentials(installation, tmp_path):
    assert run(installation).returncode == 0
    previous = values(installation / ".env.lite")
    (installation / ".env.lite").unlink()
    assert run(installation).returncode == 0
    current = values(installation / ".env.lite")
    for key in (
        "SECRET_KEY",
        "ENCRYPTION_SALT",
        "POSTGRES_PASSWORD",
        "LOGDB_PASSWORD",
        "REDIS_PASSWORD",
    ):
        assert previous[key] != current[key]


def config_module():
    spec = importlib.util.spec_from_file_location(
        "install_config_under_test", ROOT / "scripts/install_config.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("existing", [False, True])
def test_unenforceable_permissions_never_publish_secrets(
    tmp_path, monkeypatch, existing
):
    module = config_module()
    path = tmp_path / ".env.lite"
    if existing:
        path.write_text("existing-private-value\n")
    previous = path.stat() if existing else None
    original = os.fstat

    def public_permissions(fd):
        info = list(original(fd))
        info[0] |= 0o044
        return os.stat_result(info)

    monkeypatch.setattr(module.os, "fstat", public_permissions)
    with pytest.raises(ValueError, match="Filesystem cannot enforce"):
        module.write_private(path, "new-private-value\n", previous)
    if existing:
        assert path.read_text() == "existing-private-value\n"
    else:
        assert not path.exists()
    assert not list(tmp_path.glob(".env.lite.*"))


def test_concurrent_change_is_preserved_instead_of_overwritten(tmp_path):
    module = config_module()
    path = tmp_path / ".env.lite"
    path.write_text("original\n")
    _, previous = module.read_existing(path)
    path.write_text("concurrent credential change\n")
    with pytest.raises(ValueError, match="changed during installation"):
        module.write_private(path, "stale configuration\n", previous)
    assert path.read_text() == "concurrent credential change\n"
    assert not list(tmp_path.glob(".env.lite.*"))
