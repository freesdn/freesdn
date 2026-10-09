# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exercise the frontend gate's process boundary without a real Docker daemon."""

import json
import os
import subprocess
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[3]
# release.py deliberately omits the private local gate from the public app.
# Keep a missing script fatal in the monorepo, where this contract applies.
pytestmark = pytest.mark.skipif(
    not (APP_ROOT.parent / "launch-kit" / "release" / "release.py").is_file(),
    reason="Private monorepo CI gate is intentionally excluded from public exports",
)


@pytest.mark.parametrize(
    ("build_exit", "run_exit", "expected_exit"),
    [(27, 0, 1), (0, 19, 1), (0, 0, 0)],
)
def test_frontend_gate_requires_a_successful_fresh_build(
    tmp_path: Path, build_exit: int, run_exit: int, expected_exit: int
) -> None:
    docker = tmp_path / "docker"
    calls = tmp_path / "calls.jsonl"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.environ['GATE_TEST_CALLS'], 'a') as log:\n"
        "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "command = sys.argv[1]\n"
        "if command == 'build': sys.exit(int(os.environ['GATE_TEST_BUILD_EXIT']))\n"
        "if command == 'run': sys.exit(int(os.environ['GATE_TEST_RUN_EXIT']))\n"
        "# A stale image would be found by an image-inspect fallback.\n"
        "sys.exit(0)\n"
    )
    docker.chmod(0o700)
    script = APP_ROOT / "scripts" / "ci-gate.sh"
    result = subprocess.run(
        ["bash", str(script), "--frontend", "--keep"],
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "GATE_TEST_CALLS": str(calls),
            "GATE_TEST_BUILD_EXIT": str(build_exit),
            "GATE_TEST_RUN_EXIT": str(run_exit),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == expected_exit, result.stdout + result.stderr
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    build = next(command for command in commands if command[0] == "build")
    assert build[build.index("--target") + 1] == "builder"
    assert not any(command[:2] == ["image", "inspect"] for command in commands)
    if build_exit:
        assert not any(command[0] == "run" for command in commands)
        assert "frontend:build" in result.stdout
    else:
        assert any(command[0] == "run" for command in commands)
