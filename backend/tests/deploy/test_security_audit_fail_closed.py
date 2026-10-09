"""A failed or incomplete local image audit must never look like a clean scan."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def audit(monkeypatch):
    path = Path(__file__).resolve().parents[3] / "scripts/security-audit.py"
    spec = importlib.util.spec_from_file_location("freesdn_security_audit_test", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "DOCKER_IMAGES", ["example:tested"])
    monkeypatch.setattr(module, "tool_available", lambda _: True)
    return module


def response(payload, code=0, stderr=""):
    return subprocess.CompletedProcess([], code, json.dumps(payload), stderr)


def test_missing_scanner_is_a_failure(audit, monkeypatch):
    monkeypatch.setattr(audit, "tool_available", lambda _: False)
    result = audit.scan_docker_images()
    assert not result.passed and not result.skipped


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_high_and_critical_findings_block(audit, monkeypatch, severity):
    payload = {
        "Results": [{"Vulnerabilities": [{"VulnerabilityID": "TEST-1", "Severity": severity}]}]
    }
    monkeypatch.setattr(audit, "run_cmd", lambda *_args, **_kwargs: response(payload))
    result = audit.scan_docker_images()
    assert not result.passed
    assert any("TEST-1" in finding for finding in result.findings)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"Results": []},
        {"Results": None},
        {"Results": [None]},
        {"Results": [{"Vulnerabilities": {}}]},
        {"Results": [{"Vulnerabilities": [{}]}]},
    ],
)
def test_invalid_or_empty_inventory_is_a_failure(audit, monkeypatch, payload):
    monkeypatch.setattr(audit, "run_cmd", lambda *_args, **_kwargs: response(payload))
    result = audit.scan_docker_images()
    assert not result.passed
    assert "scan errors" in result.summary


def test_process_failure_blocks_even_with_clean_json(audit, monkeypatch):
    monkeypatch.setattr(audit, "run_cmd", lambda *_args, **_kwargs: response({"Results": [{}]}, 1))
    assert not audit.scan_docker_images().passed


def test_partial_image_coverage_cannot_pass(audit, monkeypatch):
    monkeypatch.setattr(audit, "DOCKER_IMAGES", ["one:tested", "two:missing"])
    results = iter([response({"Results": [{}]}), response({}, 127, "image not found")])
    monkeypatch.setattr(audit, "run_cmd", lambda *_args, **_kwargs: next(results))
    result = audit.scan_docker_images()
    assert not result.passed
    assert "1/2 images scanned" in result.summary


def test_valid_clean_scan_passes_with_explicit_unsuppressed_options(audit, monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return response({"Results": [{"Target": "Debian", "Vulnerabilities": []}]})

    monkeypatch.setattr(audit, "run_cmd", run)
    result = audit.scan_docker_images()
    assert result.passed
    assert "1/1 images scanned" in result.summary
    assert calls[0][calls[0].index("--ignorefile") + 1] == audit.os.devnull
    assert "--ignore-unfixed=false" in calls[0]


@pytest.fixture
def local_scan(audit, monkeypatch, tmp_path):
    backend = tmp_path / "backend"
    (backend / "app").mkdir(parents=True)
    (backend / "poetry.lock").write_text('[[package]]\nname="example"\nversion="1.0.0"\n')
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package-lock.json").write_text("{}")
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")
    monkeypatch.setattr(audit, "BACKEND_DIR", backend)
    monkeypatch.setattr(audit, "FRONTEND_DIR", frontend)
    monkeypatch.setattr(audit, "DOCKERFILES", [dockerfile])
    return audit


SCANNERS = ["scan_python_deps", "scan_npm_deps", "lint_dockerfiles", "scan_python_sast"]
CLEAN_RESULTS = [
    {"dependencies": [{"name": "example", "version": "1.0.0", "vulns": []}]},
    {
        "metadata": {
            "vulnerabilities": dict.fromkeys(
                ["info", "low", "moderate", "high", "critical", "total"], 0
            )
        },
        "vulnerabilities": {},
    },
    [],
    {"results": [], "errors": [], "metrics": {"_totals": {"loc": 20}}},
]


@pytest.mark.parametrize("scanner", SCANNERS)
def test_missing_local_scanner_blocks(local_scan, monkeypatch, scanner):
    monkeypatch.setattr(local_scan, "tool_available", lambda _: False)
    result = getattr(local_scan, scanner)()
    assert not result.passed and not result.skipped


@pytest.mark.parametrize("scanner,payload", zip(SCANNERS, CLEAN_RESULTS, strict=True))
def test_complete_local_scan_can_pass(local_scan, monkeypatch, scanner, payload):
    monkeypatch.setattr(local_scan, "run_cmd", lambda *_args, **_kwargs: response(payload))
    assert getattr(local_scan, scanner)().passed


@pytest.mark.parametrize("scanner,payload", zip(SCANNERS, CLEAN_RESULTS, strict=True))
def test_local_scan_failure_cannot_pass_with_clean_json(local_scan, monkeypatch, scanner, payload):
    monkeypatch.setattr(local_scan, "run_cmd", lambda *_args, **_kwargs: response(payload, 1))
    assert not getattr(local_scan, scanner)().passed


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("output", ["not json", "{}", "null"])
def test_malformed_local_scan_cannot_pass_even_on_exit_zero(
    local_scan, monkeypatch, scanner, output
):
    monkeypatch.setattr(
        local_scan,
        "run_cmd",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, output, ""),
    )
    assert not getattr(local_scan, scanner)().passed


def test_python_audit_covers_lock_and_does_not_fall_back_to_active_environment(
    local_scan, monkeypatch
):
    def run(command, **_kwargs):
        path = Path(command[command.index("--requirement") + 1])
        assert path.read_text() == "example==1.0.0\n"
        assert "--disable-pip" in command and "--no-deps" in command and "--strict" in command
        return response({"dependencies": [{"name": "different", "version": "1.0.0", "vulns": []}]})

    monkeypatch.setattr(local_scan, "run_cmd", run)
    assert not local_scan.scan_python_deps().passed


def test_npm_moderate_advisory_blocks_at_configured_threshold(local_scan, monkeypatch):
    payload = {
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 1,
                "high": 0,
                "critical": 0,
                "total": 1,
            }
        },
        "vulnerabilities": {"example": {"severity": "moderate"}},
    }
    monkeypatch.setattr(local_scan, "run_cmd", lambda *_args, **_kwargs: response(payload, 1))
    assert not local_scan.scan_npm_deps().passed


def test_bandit_partial_parse_is_not_a_clean_scan(local_scan, monkeypatch):
    payload = {
        "results": [],
        "errors": [{"filename": "unreadable.py"}],
        "metrics": {"_totals": {"loc": 20}},
    }
    monkeypatch.setattr(local_scan, "run_cmd", lambda *_args, **_kwargs: response(payload))
    assert not local_scan.scan_python_sast().passed


@pytest.mark.parametrize("results", [[], ["skipped"]])
def test_no_scans_cannot_be_saved_as_passed(local_scan, monkeypatch, tmp_path, results):
    monkeypatch.setattr(local_scan, "PROJECT_DIR", tmp_path)
    output = tmp_path / "results.json"
    monkeypatch.setattr(local_scan, "RESULTS_FILE", output)
    scans = [local_scan.ScanResult("example", passed=True, skipped=True)] if results else []
    local_scan.save_results(scans)
    assert json.loads(output.read_text())["overall_passed"] is False
