# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The backend suite runs as contiguous parts; the Backend verdict must prove they add up.

A split that silently drops a file, runs one twice, or lets a part fail unnoticed
would turn a green check into a claim about fewer tests than it names.
"""

import json
import pathlib
import re

import pytest

from scripts import backend_test_parts as parts

yaml = pytest.importorskip("yaml")

COUNTS = {"tests/a/test_one.py": 40, "tests/a/test_two.py": 3, "tests/b/test_three.py": 25,
          "tests/b/test_four.py": 31, "tests/c/test_five.py": 12, "tests/c/test_six.py": 9}
NODES = [f"{name}::test_{i}" for name, n in COUNTS.items() for i in range(n)]


def test_split_is_contiguous_complete_and_balanced():
    files, chosen = parts.split(NODES, 3)
    assert files == list(COUNTS)
    assert [name for names, _ in chosen for name in names] == files
    assert [tests for _, tests in chosen] == [sum(COUNTS[n] for n in names) for names, _ in chosen]
    assert sum(tests for _, tests in chosen) == len(NODES)
    assert max(tests for _, tests in chosen) <= len(NODES) / 3 + max(COUNTS.values())


def test_split_balances_by_recorded_time():
    # By count this is [one, two, three] | [four, five, six]; by time, the four
    # cheap files together balance the two slow ones.
    seconds = {"tests/a/test_one.py": 4.0, "tests/a/test_two.py": 300.0, "tests/b/test_three.py": 5.0,
               "tests/b/test_four.py": 6.0, "tests/c/test_five.py": 280.0}
    assert [names for names, _ in parts.split(NODES, 2)[1]] == [list(COUNTS)[:3], list(COUNTS)[3:]]
    assert [names for names, _ in parts.split(NODES, 2, seconds)[1]] == [list(COUNTS)[:4], list(COUNTS)[4:]]


def test_a_file_without_a_recorded_time_is_priced_at_the_mean_per_test():
    # Only test_one is timed, at 10 s per test, so every file costs 10 s per test
    # and the split must equal the plain count split. Pricing the others at 1 s a
    # test would put all of test_one's 400 s past the first part and empty it.
    assert parts.split(NODES, 3, {"tests/a/test_one.py": 400.0}) == parts.split(NODES, 3)


def test_durations_sum_each_files_junit_times(tmp_path, monkeypatch):
    monkeypatch.setattr(parts, "DURATIONS", tmp_path / "part_durations.json")
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuites><testsuite tests="3">'
        '<testcase classname="tests.deploy.test_backend_test_parts" name="a" time="1.25"/>'
        '<testcase classname="tests.deploy.test_backend_test_parts" name="b" time="2.5"/>'
        '<testcase classname="tests.deploy.test_release_is_gated" name="c" time="0.5"/>'
        "</testsuite></testsuites>"
    )
    assert parts.main(["durations", "--source", "unit", str(report)]) == 0
    recorded = json.loads((tmp_path / "part_durations.json").read_text())
    assert recorded["source"] == "unit"
    assert recorded["seconds"] == {"tests/deploy/test_backend_test_parts.py": 3.8,
                                   "tests/deploy/test_release_is_gated.py": 0.5}


def test_the_recorded_times_describe_this_suite():
    # A file deleted since the last refresh only unbalances the parts; a table
    # keyed some other way (wrong root, module names) would weigh nothing.
    seconds = json.loads(parts.DURATIONS.read_text())["seconds"]
    present = sum((parts.ROOT / name).is_file() for name in seconds)
    assert len(seconds) > 500 and present >= 0.9 * len(seconds)


def test_one_collection_means_the_same_files_and_counts_not_the_same_test_ids():
    # Some parametrize ids are random per process, so every part names those tests
    # differently. Comparing ids failed the verdict of a run that was complete.
    renamed = [node.replace("::test_", "::test_random_") for node in NODES]
    assert parts.collection_digest(renamed) == parts.collection_digest(NODES)
    assert parts.collection_digest([*NODES, "tests/c/test_six.py::test_extra"]) != parts.collection_digest(NODES)
    moved = NODES[40:43] + NODES[:40] + NODES[43:]
    assert parts.collection_digest(moved) != parts.collection_digest(NODES)


def test_split_refuses_a_part_with_nothing_to_run():
    with pytest.raises(ValueError, match="empty"):
        parts.split(NODES[:2], 2)


def test_split_refuses_a_file_whose_tests_are_not_together():
    with pytest.raises(ValueError, match="contiguous"):
        parts.split(["tests/x.py::a", "tests/y.py::b", "tests/x.py::c"], 2)


def test_collection_output_must_match_its_own_count():
    good = "\n".join(NODES) + "\n\n=== warnings summary ===\ntests/a/test_one.py::x\n\n" + f"{len(NODES)} tests collected in 1.0s\n"
    assert parts.parse_collection(good) == NODES
    with pytest.raises(ValueError):
        parts.parse_collection("\n".join(NODES) + f"\n\n{len(NODES) + 1} tests collected in 1.0s\n")
    with pytest.raises(ValueError):
        parts.parse_collection("tests/a/test_one.py: 40\n\n40 tests collected in 1.0s\n")


def test_run_reaches_the_part_runner_with_the_whole_pytest_command(monkeypatch, tmp_path):
    # The pytest command once shared its argument name with the subcommand, so
    # every part silently ran the verdict instead of its tests.
    seen = []
    monkeypatch.setattr(parts, "run", lambda args: seen.append(args) or 0)
    monkeypatch.setattr(parts, "verify", lambda _args: pytest.fail("run dispatched to verify"))
    argv = ["run", "--part", "2", "--parts", "8", "--evidence", str(tmp_path),
            "--", "python", "-m", "pytest", "-p", "tests.qualification_observer", "-q"]
    assert parts.main(argv) == 0
    (args,) = seen
    assert (args.part, args.parts, args.evidence) == (2, 8, str(tmp_path))
    assert [a for a in args.pytest_command if a != "--"] == argv[-6:]


def evidence(root, count=3, *, failures=0, skip_part=None, tamper=None):
    files, chosen = parts.split(NODES, count)
    for index, (names, tests) in enumerate(chosen, start=1):
        if index == skip_part:
            continue
        manifest = {"part": index, "parts": count, "collected": len(NODES),
                    "collection_sha256": parts.collection_digest(NODES), "files_sha256": parts.digest(files),
                    "tests": tests, "files": names}
        if tamper:
            tamper(index, manifest)
        directory = root / f"backend-test-evidence-{index}"
        directory.mkdir(parents=True)
        (directory / "part.json").write_text(json.dumps(manifest))
        failed = failures if index == 1 else 0
        cases = "".join("<testcase/>" for _ in range(tests))
        (directory / "junit.xml").write_text(
            f'<testsuites><testsuite name="pytest" errors="0" failures="{failed}" skipped="1" '
            f'tests="{tests}">{cases}</testsuite></testsuites>'
        )
    return root


def verdict(root, count=3, upstream="success"):
    return parts.main(["verify", "--parts", str(count), "--evidence", str(root), "--upstream", upstream])


def test_verdict_passes_only_when_every_test_ran_once_and_none_failed(tmp_path):
    assert verdict(evidence(tmp_path)) == 0


@pytest.mark.parametrize("case", ["missing-part", "failure", "upstream", "count", "other-collection", "file-dropped"])
def test_verdict_refuses_what_a_green_check_would_otherwise_hide(tmp_path, case):
    if case == "missing-part":
        root = evidence(tmp_path, skip_part=2)
    elif case == "failure":
        root = evidence(tmp_path, failures=1)
    elif case == "upstream":
        assert verdict(evidence(tmp_path), upstream="cancelled") == 1
        return
    elif case == "count":
        root = evidence(tmp_path, tamper=lambda i, m: m.update(tests=m["tests"] + 1) if i == 3 else None)
    elif case == "other-collection":
        root = evidence(tmp_path, tamper=lambda i, m: m.update(collection_sha256="0" * 64) if i == 2 else None)
    else:
        root = evidence(tmp_path, tamper=lambda i, m: m.update(files=m["files"][1:]) if i == 2 else None)
    assert verdict(root) == 1


def _workflow():
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / ".github" / "workflows" / "ci.yml"
        if candidate.is_file():
            return yaml.safe_load(candidate.read_text(encoding="utf-8"))
    pytest.skip(".github/workflows/ci.yml not in this checkout")


def test_ci_runs_every_part_and_the_backend_check_is_their_verdict():
    jobs = _workflow()["jobs"]
    tests, verdict_job = jobs["backend-tests"], jobs["backend"]
    command = next(s["run"] for s in tests["steps"] if "backend_test_parts.py run" in s.get("run", ""))
    count = int(re.search(r"--parts (\d+)", command).group(1))
    assert tests["strategy"]["matrix"]["part"] == list(range(1, count + 1))
    assert tests["strategy"]["fail-fast"] is False
    assert "-p tests.qualification_observer" in command and "python -m" in command
    assert verdict_job["name"] == "Backend" and verdict_job["needs"] == "backend-tests"
    assert verdict_job["if"] == "always()"
    check = next(s["run"] for s in verdict_job["steps"] if "backend_test_parts.py verify" in s.get("run", ""))
    assert f"--parts {count}" in check and "--upstream" in check
