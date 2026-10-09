# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exercise the optional observer through an actual failing pytest process."""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def test_failure_diagnostics_remain_independent_and_preserve_results(tmp_path):
    cases = tmp_path / "test_owned_cases.py"
    cases.write_text(
        "import pytest\n"
        "@pytest.mark.parametrize('case', range(6))\n"
        "def test_failure(case):\n"
        "    assert False, 'owned diagnostic failure'\n"
        "def test_success():\n"
        "    assert True\n"
    )
    evidence = tmp_path / "evidence"
    junit = tmp_path / "junit.xml"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "tests.qualification_observer",
         "-p", "no:cacheprovider", "-c", os.devnull, "--confcutdir", str(tmp_path),
         "--rootdir", str(tmp_path), "--junitxml", str(junit), "-q", "--tb=no", str(cases)],
        cwd=tmp_path,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "",
             "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
             "FREESDN_TEST_DIAGNOSTIC_DIR": str(evidence)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    suite = ET.parse(junit).getroot().find("testsuite")
    assert suite is not None
    assert (suite.get("tests"), suite.get("failures"), suite.get("errors")) == ("7", "6", "0")
    events = [json.loads(line) for line in (evidence / "timing.jsonl").read_text().splitlines()]
    failures = [event for event in events if event["kind"] == "test_failure"]
    assert len(failures) == 6
    assert all(event["phase"] == "call" for event in failures)
    assert all(
        prior["kind"] != "test_failure"
        for failure in failures for prior in failure["recent_events"]
    ), "Earlier failure snapshots must not recursively expand subsequent diagnostics"
    assert events[-1]["kind"] == "session_finish" and events[-1]["exitstatus"] == 1
