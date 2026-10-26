"""The image gate must fail on anything fixable and accept only reviewed, current unfixed findings."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "check_image_findings.py"
REVIEW_FILE = Path(__file__).parents[2] / "security" / "image-cve-review.toml"
spec = importlib.util.spec_from_file_location("check_image_findings", SCRIPT)
gate = importlib.util.module_from_spec(spec)
# dataclasses resolve their module through sys.modules
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

REASON = "Debian has published no fixed package; the binary is never executed by the service."


def report(tmp_path, *vulns):
    path = tmp_path / "image-findings.json"
    path.write_text(
        json.dumps({"Results": [{"Type": "debian", "Vulnerabilities": list(vulns)}]}),
        encoding="utf-8",
    )
    return path


def vuln(vid="CVE-2026-0001", pkg="libxml2", severity="HIGH", fixed=""):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "FixedVersion": fixed,
        "Severity": severity,
    }


def review(tmp_path, *, vid="CVE-2026-0001", pkg="libxml2", component="postgres",
           reviewed="2026-10-26", review_by="2026-11-30", reason=REASON):
    path = tmp_path / "review.toml"
    path.write_text(
        "[[unfixed]]\n"
        f'id = "{vid}"\npackages = ["{pkg}"]\ncomponents = ["{component}"]\n'
        f'reason = "{reason}"\nreviewed = {reviewed}\nreview_by = {review_by}\n',
        encoding="utf-8",
    )
    return path


def run(findings, review_path, component="postgres", today="2026-10-27"):
    return gate.main([
        "--findings", str(findings), "--review", str(review_path),
        "--component", component, "--today", today,
    ])


def test_fixable_finding_fails_even_when_a_review_names_it(tmp_path, capsys):
    rc = run(report(tmp_path, vuln(fixed="2.0")), review(tmp_path))
    assert rc == 1
    assert "fixable: upgrade to 2.0" in capsys.readouterr().out


def test_unfixed_finding_without_review_fails(tmp_path):
    assert run(report(tmp_path, vuln()), review(tmp_path, vid="CVE-2026-9999")) == 1


def test_unfixed_finding_with_current_review_passes_and_is_still_printed(tmp_path, capsys):
    assert run(report(tmp_path, vuln()), review(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "CVE-2026-0001" in out and "reviewed, until 2026-11-30" in out


def test_expired_review_fails(tmp_path):
    assert run(report(tmp_path, vuln()), review(tmp_path), today="2026-12-01") == 1


def test_review_for_another_component_does_not_cover(tmp_path):
    assert run(report(tmp_path, vuln()), review(tmp_path), component="logdb") == 1


def test_review_longer_than_the_monthly_horizon_is_rejected(tmp_path):
    long = review(tmp_path, review_by="2027-03-01")
    assert run(report(tmp_path, vuln()), long) == 2


def test_placeholder_reason_is_rejected(tmp_path):
    assert run(report(tmp_path, vuln()), review(tmp_path, reason="accepted")) == 2


def test_medium_findings_are_outside_the_gate(tmp_path):
    rc = run(report(tmp_path, vuln(severity="MEDIUM", fixed="2.0")), review(tmp_path))
    assert rc == 0


def test_a_report_that_is_not_trivy_json_cannot_pass(tmp_path):
    bogus = tmp_path / "image-findings.json"
    bogus.write_text("{}", encoding="utf-8")
    assert run(bogus, review(tmp_path)) == 2


@pytest.mark.skipif(not REVIEW_FILE.exists(), reason="review file not present")
def test_the_shipped_review_file_is_valid():
    reviews = gate.load_reviews(REVIEW_FILE)
    assert reviews, "an empty review file should be deleted, not shipped"
    assert len({(r.vuln_id, r.packages, r.components) for r in reviews}) == len(reviews)
