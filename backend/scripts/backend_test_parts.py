#!/usr/bin/env python3
"""Run the backend suite as contiguous parts, and prove the parts add up.

Public CI ran the whole suite (about 20,000 tests) in one process for almost
five hours. That process's heap grows as it goes: a full garbage collection took
under 1.4 s in the first eighth of the run and 3 s by the end, long enough to
break tests with a short timing window. Each part is a contiguous slice of the
normal run order in its own process, so no process grows past the size of one
slice. Garbage collection itself is unchanged (tests/test_fixture_lifetime.py).

Slices are balanced by each file's recorded running time (tests/part_durations.json),
because test cost varies a thousandfold between areas. Stale or missing times only
unbalance the parts; they cannot drop a test, which ``verify`` would catch.

    run        collect the suite, run part K of N, and record its manifest
    verify     check that the N manifests describe one collection, cover every
               collected test exactly once in order, and that every part's JUnit
               report accounts for its tests with no failure or error
    durations  rewrite tests/part_durations.json from JUnit reports of a full run
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DURATIONS = ROOT / "tests" / "part_durations.json"


def digest(lines):
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def parse_collection(output):
    """Node ids from ``pytest --collect-only -q``, refused unless they match its own count."""
    lines = output.splitlines()
    nodes = []
    for line in lines:
        if not line.strip():
            break
        nodes.append(line.strip())
    counted = [int(m.group(1)) for m in map(re.compile(r"^(\d+) tests? collected").match, lines) if m]
    if not nodes or counted != [len(nodes)] or not all("::" in node for node in nodes):
        raise ValueError(f"unexpected collection output: {len(nodes)} node lines, summary {counted}")
    if len(set(nodes)) != len(nodes):
        raise ValueError("collection lists a test more than once")
    return nodes


def counts_by_file(nodes):
    counts = {}
    for node in nodes:
        name = node.split("::", 1)[0]
        counts[name] = counts.get(name, 0) + 1
    return counts


def collection_digest(nodes):
    """One collection, as parts compare it: every file in order with its test count.

    Test ids are not compared. Some are random per process (parametrize values
    made with uuid4()), and a part runs whole files, so the same files with the
    same counts already mean the parts split one collection.
    """
    return digest(f"{name} {count}" for name, count in counts_by_file(nodes).items())


def split(nodes, parts, seconds=None):
    """Contiguous parts of whole files, in run order, balanced by recorded time.

    A file without a recorded time weighs its test count times the mean time per
    test of the files that have one; with no times at all, every test weighs 1.
    """
    counts = counts_by_file(nodes)
    files = list(counts)
    if [node.split("::", 1)[0] for node in nodes] != [f for f in files for _ in range(counts[f])]:
        raise ValueError("a file's tests are not contiguous in the run order")
    known = {f: float(seconds[f]) for f in files if seconds and f in seconds}
    per_test = sum(known.values()) / sum(counts[f] for f in known) if known else 1.0
    weight = {f: known.get(f, counts[f] * per_test) for f in files}
    total, start, chosen = sum(weight.values()) or 1.0, 0.0, [[] for _ in range(parts)]
    for name in files:
        middle = start + weight[name] / 2
        chosen[min(parts - 1, int(middle * parts / total))].append(name)
        start += weight[name]
    if not all(chosen):
        raise ValueError(f"{parts} parts leave one empty")
    return files, [(names, sum(counts[n] for n in names)) for names in chosen]


def recorded_seconds():
    return json.loads(DURATIONS.read_text())["seconds"] if DURATIONS.is_file() else {}


def durations(args):
    """Sum each test file's JUnit times; a test's classname is its module path."""
    seconds = {}
    for report in args.junit:
        for case in ET.parse(report).getroot().iter("testcase"):
            dotted = case.get("classname", "").split(".")
            for n in range(len(dotted), 0, -1):
                name = "/".join(dotted[:n]) + ".py"
                if (ROOT / name).is_file():
                    seconds[name] = seconds.get(name, 0.0) + float(case.get("time") or 0)
                    break
    if not seconds:
        print("No test file found for any JUnit test case", file=sys.stderr)
        return 1
    DURATIONS.write_text(json.dumps({
        "about": "Seconds per test file from a full public CI run; only balances "
                 "scripts/backend_test_parts.py. Refresh with its `durations` command.",
        "source": args.source,
        "seconds": {name: round(value, 1) for name, value in sorted(seconds.items())},
    }, indent=1) + "\n")
    print(f"{len(seconds)} files, {sum(seconds.values()) / 60:.1f} min, written to {DURATIONS}")
    return 0


def run(args):
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"],
        cwd=ROOT, text=True, capture_output=True,
    )
    if collected.returncode != 0:
        sys.stderr.write(collected.stdout[-4000:] + collected.stderr[-4000:])
        print(f"Collection failed with exit code {collected.returncode}", file=sys.stderr)
        return 2
    nodes = parse_collection(collected.stdout)
    files, parts = split(nodes, args.parts, recorded_seconds())
    names, tests = parts[args.part - 1]
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "part.json").write_text(json.dumps({
        "part": args.part, "parts": args.parts, "collected": len(nodes),
        "collection_sha256": collection_digest(nodes), "files_sha256": digest(files),
        "tests": tests, "files": names,
    }, indent=1))
    print(f"Part {args.part}/{args.parts}: {tests} of {len(nodes)} tests in {len(names)} files, "
          f"{names[0]} .. {names[-1]}", flush=True)
    # The pytest command comes from the caller; this part's files and report are appended.
    command = args.pytest_command[1:] if args.pytest_command[:1] == ["--"] else list(args.pytest_command)
    if command[:1] == ["python"]:
        command[0] = sys.executable
    command += [*names, f"--junitxml={evidence / 'junit.xml'}"]
    return subprocess.run(command, cwd=ROOT).returncode


def junit_counts(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    total = {key: sum(int(s.get(key, 0)) for s in suites) for key in ("tests", "failures", "errors", "skipped")}
    total["cases"] = sum(len(s.findall("testcase")) for s in suites)
    return total


def verify(args):
    problems = []
    if args.upstream not in (None, "success"):
        problems.append(f"the test parts finished as '{args.upstream}', not 'success'")
    manifests = {}
    for path in sorted(Path(args.evidence).rglob("part.json")):
        manifest = json.loads(path.read_text())
        if manifest["part"] in manifests:
            problems.append(f"part {manifest['part']} reported twice")
        manifests[manifest["part"]] = (manifest, path.parent)
    missing = sorted(set(range(1, args.parts + 1)) - manifests.keys())
    extra = sorted(manifests.keys() - set(range(1, args.parts + 1)))
    if missing or extra:
        problems.append(f"expected parts 1..{args.parts}; missing {missing}, unexpected {extra}")
    present = [manifests[k] for k in sorted(manifests)]
    for key in ("parts", "collected", "collection_sha256", "files_sha256"):
        if len({m[key] for m, _ in present}) > 1:
            problems.append(f"the parts disagree on {key}: they did not run one collection")
    if present and not missing and not extra:
        first = present[0][0]
        files = [name for m, _ in present for name in m["files"]]
        if digest(files) != first["files_sha256"]:
            problems.append("the parts' files are not every collected file exactly once, in order")
        if sum(m["tests"] for m, _ in present) != first["collected"]:
            problems.append("the parts' test counts do not add up to the collection")
    passed = skipped = 0
    for manifest, directory in present:
        part = manifest["part"]
        report = directory / "junit.xml"
        if not report.is_file():
            problems.append(f"part {part} has no JUnit report")
            continue
        counts = junit_counts(report)
        if counts["tests"] != manifest["tests"] or counts["cases"] != manifest["tests"]:
            problems.append(f"part {part} reported {counts['tests']} tests "
                            f"({counts['cases']} cases) for {manifest['tests']} collected")
        if counts["failures"] or counts["errors"]:
            problems.append(f"part {part}: {counts['failures']} failed, {counts['errors']} errors")
        passed += counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
        skipped += counts["skipped"]
        print(f"part {part}/{manifest['parts']}: {counts['tests']} tests, {counts['failures']} failed, "
              f"{counts['errors']} errors, {counts['skipped']} skipped")
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"Backend: {passed} passed, {skipped} skipped, 0 failed, in {args.parts} parts "
          f"covering all {present[0][0]['collected']} collected tests")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("run")
    one.add_argument("--part", type=int, required=True)
    one.add_argument("--parts", type=int, required=True)
    one.add_argument("--evidence", required=True)
    one.add_argument("pytest_command", nargs=argparse.REMAINDER, help="-- python -m pytest [options]")
    check = sub.add_parser("verify")
    check.add_argument("--parts", type=int, required=True)
    check.add_argument("--evidence", required=True)
    check.add_argument("--upstream")
    times = sub.add_parser("durations")
    times.add_argument("--source", required=True, help="which run the reports came from")
    times.add_argument("junit", nargs="+")
    args = parser.parse_args(argv)
    if args.command == "run":
        if not 1 <= args.part <= args.parts:
            parser.error("--part must be between 1 and --parts")
        if not [a for a in args.pytest_command if a != "--"]:
            parser.error("give the pytest command after --")
        return run(args)
    if args.command == "durations":
        return durations(args)
    return verify(args)


if __name__ == "__main__":
    sys.exit(main())
