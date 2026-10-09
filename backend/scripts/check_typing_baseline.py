#!/usr/bin/env python3
"""Reject new mypy diagnostics without disguising existing typing debt.

Signatures include file, code and full message; counts detect duplicate new
instances. Line numbers are excluded so normal edits do not invalidate baseline.
No automatic baseline-update switch: reductions should be reviewed explicitly.
"""
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "typing-baseline.json"


def signature(item):
    return json.dumps([item["file"], item.get("code"), item["message"]], ensure_ascii=False)


def main():
    run = subprocess.run([sys.executable, "-m", "mypy", "app", "--output", "json"],
                         cwd=ROOT, text=True, capture_output=True)
    if run.returncode not in (0, 1):
        print(run.stderr, file=sys.stderr)
        return 2
    try:
        rows = [json.loads(line) for line in run.stdout.splitlines() if line.strip()]
        known = Counter(json.loads(BASELINE.read_text())["diagnostics"])
    except (ValueError, OSError) as error:
        print(f"Cannot validate typing baseline: {error}", file=sys.stderr)
        return 2
    current = Counter(signature(row) for row in rows if row["severity"] == "error")
    if run.returncode == 1 and not current:
        print("mypy failed without parseable diagnostics", file=sys.stderr)
        return 2
    added = current - known
    removed = known - current
    print(f"Typing debt: {sum(current.values())}; new: {sum(added.values())}; removed: {sum(removed.values())}")
    for key, count in added.items():
        print(f"NEW x{count}: {key}")
    if removed:
        print("Remove resolved signatures from typing-baseline.json to preserve the improvement.")
    return int(bool(added or removed))


if __name__ == "__main__":
    raise SystemExit(main())
