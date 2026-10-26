#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Gate a Trivy image inventory: fixable findings fail, unfixed ones need a review.

CI scans every application image with no ignore file and unfixed findings
included, so the uploaded inventory is complete. Until 26.10.3 that same scan
was also the gate, which made it impossible to pass: a Debian image carries
HIGH findings for which Debian has published no fix, and no change in this
repository can remove them. A gate that can never be green stops being read.

This splits the two jobs without hiding anything:

* A HIGH or CRITICAL finding WITH a fixed version always fails. There is no
  waiver for it here; rebuild, bump or patch.
* A HIGH or CRITICAL finding with NO fixed version fails unless the review file
  names it (id, package, component) with a review date that has not expired.
  Reviews may not be granted for more than ``MAX_REVIEW_DAYS``, so every
  accepted finding is looked at again by the next monthly security train.
* The moment upstream publishes a fix, the finding becomes fixable and fails,
  whatever the review file says.

Every finding is printed, accepted or not, so the job log is the report.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

GATED = ("CRITICAL", "HIGH")
MAX_REVIEW_DAYS = 62
REQUIRED = ("id", "packages", "components", "reason", "reviewed", "review_by")


class ReviewFileError(ValueError):
    """The review file is malformed; the gate must not guess what it meant."""


@dataclass(frozen=True)
class Finding:
    severity: str
    vuln_id: str
    package: str
    installed: str
    fixed: str
    kind: str

    @property
    def fixable(self) -> bool:
        return bool(self.fixed.strip())


@dataclass(frozen=True)
class Review:
    vuln_id: str
    packages: tuple[str, ...]
    components: tuple[str, ...]
    reason: str
    reviewed: date
    review_by: date

    def covers(self, finding: Finding, component: str) -> bool:
        return (
            self.vuln_id == finding.vuln_id
            and (finding.package in self.packages or "*" in self.packages)
            and (component in self.components or "*" in self.components)
        )


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "Results" not in data:
        raise ValueError(f"{path} is not a Trivy JSON report")
    findings = []
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity", "")).upper()
            if severity not in GATED:
                continue
            findings.append(
                Finding(
                    severity=severity,
                    vuln_id=str(vuln.get("VulnerabilityID", "")),
                    package=str(vuln.get("PkgName", "")),
                    installed=str(vuln.get("InstalledVersion", "")),
                    fixed=str(vuln.get("FixedVersion") or ""),
                    kind=str(result.get("Type", "")),
                )
            )
    return findings


def _day(entry: dict, key: str) -> date:
    value = entry[key]
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ReviewFileError(f"{entry.get('id')}: {key} is not an ISO date") from exc


def load_reviews(path: Path) -> list[Review]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    reviews = []
    for entry in raw.get("unfixed", []):
        missing = [key for key in REQUIRED if not entry.get(key)]
        if missing:
            raise ReviewFileError(f"{entry.get('id', '?')}: missing {', '.join(missing)}")
        reviewed, review_by = _day(entry, "reviewed"), _day(entry, "review_by")
        if (review_by - reviewed).days > MAX_REVIEW_DAYS:
            raise ReviewFileError(
                f"{entry['id']}: review_by is more than {MAX_REVIEW_DAYS} days after reviewed;"
                " an accepted finding must come back to the next monthly security train"
            )
        if len(str(entry["reason"]).strip()) < 40:
            raise ReviewFileError(f"{entry['id']}: reason is too short to be a review")
        reviews.append(
            Review(
                vuln_id=str(entry["id"]),
                packages=tuple(entry["packages"]),
                components=tuple(entry["components"]),
                reason=str(entry["reason"]).strip(),
                reviewed=reviewed,
                review_by=review_by,
            )
        )
    return reviews


def evaluate(
    findings: list[Finding], reviews: list[Review], component: str, today: date
) -> tuple[list[tuple[Finding, str]], list[tuple[Finding, str]]]:
    """Return (failures, accepted), each a list of (finding, explanation)."""
    failures, accepted = [], []
    for finding in findings:
        if finding.fixable:
            failures.append((finding, f"fixable: upgrade to {finding.fixed}"))
            continue
        match = next((r for r in reviews if r.covers(finding, component)), None)
        if match is None:
            failures.append((finding, "no fix upstream and no review entry"))
        elif match.review_by < today:
            failures.append((finding, f"review expired {match.review_by.isoformat()}"))
        else:
            accepted.append((finding, f"reviewed, until {match.review_by.isoformat()}"))
    return failures, accepted


def _row(finding: Finding, note: str) -> str:
    return (
        f"  {finding.severity:8} {finding.vuln_id:20} {finding.package[:28]:28} "
        f"{finding.installed[:24]:24} {finding.kind[:10]:10} {note}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = parser.parse_args(argv)

    try:
        findings = load_findings(args.findings)
        reviews = load_reviews(args.review)
    except (OSError, ValueError) as exc:
        print(f"image gate ({args.component}): cannot evaluate: {exc}", file=sys.stderr)
        return 2

    failures, accepted = evaluate(findings, reviews, args.component, args.today)
    print(
        f"image gate ({args.component}): {len(findings)} HIGH/CRITICAL findings,"
        f" {len(failures)} failing, {len(accepted)} accepted under review"
    )
    for finding, note in failures:
        print(_row(finding, "FAIL " + note))
    for finding, note in accepted:
        print(_row(finding, note))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
