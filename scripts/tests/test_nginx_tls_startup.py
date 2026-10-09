"""Execute the shipped selector: missing TLS material must never start HTTP."""

import os
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "frontend/nginx/docker-entrypoint.sh"


def run_selector(tmp_path, mode, material):
    nginx = tmp_path / "nginx"
    runtime = tmp_path / "runtime"
    for name in ("templates", "conf.d", "ssl"):
        (nginx / name).mkdir(parents=True)
    runtime.mkdir()
    (nginx / "templates/http-only.conf").write_text("HTTP ONLY\n")
    (nginx / "templates/ssl.conf").write_text(
        "TLS CONFIG\nssl_dhparam /tmp/ssl/dhparam.pem;\n"
        "ssl_stapling on;\nssl_stapling_verify on;\n"
    )
    for name, contents in material.items():
        (nginx / "ssl" / name).write_text(contents)
    # Relocate filesystem constants only. The shell control flow, checks and
    # actual copy/exec operations remain those in the shipped entrypoint.
    script = tmp_path / "selector.sh"
    script.write_text(
        SOURCE.read_text().replace("/etc/nginx", str(nginx)).replace("/tmp/ssl", str(runtime))
    )
    marker = tmp_path / "server-started"
    result = subprocess.run(
        ["sh", str(script), "sh", "-c", "touch " + shlex.quote(str(marker))],
        env={**os.environ, "SSL_MODE": mode},
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result, marker, nginx, runtime


@pytest.mark.parametrize("mode", ["self-signed", "letsencrypt"])
@pytest.mark.parametrize(
    "material",
    [
        {},
        {"fullchain.pem": "certificate"},
        {"privkey.pem": "key"},
        {"fullchain.pem": "", "privkey.pem": "key"},
        {"fullchain.pem": "certificate", "privkey.pem": ""},
    ],
    ids=["both-missing", "key-missing", "certificate-missing", "empty-certificate", "empty-key"],
)
def test_tls_mode_refuses_incomplete_material_without_starting_server(tmp_path, mode, material):
    result, marker, nginx, _ = run_selector(tmp_path, mode, material)
    assert result.returncode != 0
    assert not marker.exists()
    assert not (nginx / "conf.d/default.conf").exists()
    assert "refusing" in (result.stdout + result.stderr).lower()


def test_explicit_http_mode_still_starts_without_certificates(tmp_path):
    result, marker, nginx, _ = run_selector(tmp_path, "off", {})
    assert result.returncode == 0 and marker.exists()
    assert (nginx / "conf.d/default.conf").read_text() == "HTTP ONLY\n"


@pytest.mark.parametrize("mode", ["self-signed", "letsencrypt"])
def test_present_tls_material_selects_tls_and_protects_runtime_key(tmp_path, mode):
    result, marker, nginx, runtime = run_selector(
        tmp_path, mode, {"fullchain.pem": "certificate", "privkey.pem": "key"}
    )
    assert result.returncode == 0 and marker.exists()
    assert (nginx / "conf.d/default.conf").read_text().startswith("TLS CONFIG\n")
    assert (runtime / "privkey.pem").read_text() == "key"
    assert stat.S_IMODE((runtime / "privkey.pem").stat().st_mode) == 0o600
    assert (nginx / "ssl/privkey.pem").read_text() == "key"


def test_unknown_mode_refuses_to_start(tmp_path):
    result, marker, _, _ = run_selector(tmp_path, "unknown", {})
    assert result.returncode != 0 and not marker.exists()
