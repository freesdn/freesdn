# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every blocking CI job must be able to stop a release.

GitHub Actions has no notion of "the workflow failed, so don't publish". A job
runs when its own ``needs`` are satisfied, regardless of a failing sibling. So a
job that is blocking (no ``continue-on-error``) but is NOT a transitive ancestor
of ``release`` cannot prevent anything: the run goes red only after the artifacts
are public.

``dependency-audit`` was in exactly that state. It runs pip-audit and
``npm audit --audit-level=high`` with no continue-on-error, and ``build-images``
did not depend on it -- so on a version tag, a red dependency audit still allowed
images to be built, pushed, SIGNED and attested, and ``release`` (which needs only
build-images) to create the GitHub release.

That happened while I was widening this exact graph: I added four jobs to
build-images.needs and reasoned explicitly about excluding the three advisory
``continue-on-error: true`` jobs -- and missed that dependency-audit is not one of
them. This test is the check I should have written then.
"""

from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

#: Jobs deliberately outside the release gate, each with a reason. An advisory
#: job reports success whatever happens, so listing it would be decoration.
_ADVISORY_BY_DESIGN = {
    "backend-integration-test",  # continue-on-error: testcontainers, run for visibility
    "mikrotik-chr-integration",  # continue-on-error: needs a CHR image
    "security-scan",  # continue-on-error: Trivy incl. unfixable base-image CVEs
}

#: Terminal jobs in the publish chain; gating them on themselves is meaningless.
_PUBLISH_CHAIN = {"build-images", "release", "deploy-staging", "deploy-production"}


def _workflow() -> dict:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / ".github" / "workflows" / "ci.yml"
        if candidate.is_file():
            return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    pytest.skip(".github/workflows/ci.yml not in this checkout")
    return {}


def _ancestors(jobs: dict, name: str, seen: set[str] | None = None) -> set[str]:
    seen = seen if seen is not None else set()
    for dep in jobs.get(name, {}).get("needs") or []:
        if dep not in seen:
            seen.add(dep)
            _ancestors(jobs, dep, seen)
    return seen


def _assert_source_only(workflow: dict) -> None:
    """A source-validation workflow must have no route to public promotion."""
    events = workflow.get("on", workflow.get(True, {}))
    assert "tags" not in events.get("push", {})
    assert workflow.get("permissions") == {"contents": "read"}
    jobs = workflow["jobs"]
    assert not (_PUBLISH_CHAIN & jobs.keys())
    for job in jobs.values():
        assert all(value != "write" for value in job.get("permissions", {}).values())
        for step in job.get("steps", []):
            action = step.get("uses", "").split("@", 1)[0]
            assert action not in {"softprops/action-gh-release", "ncipollo/release-action", "actions/attest-build-provenance"}
            if action == "docker/build-push-action":
                assert step.get("with", {}).get("push", False) in (False, "false")
            assert not re.search(r"\b(?:docker\s+(?:image\s+)?push|gh\s+release\s+create|cosign\s+(?:sign|attest))\b", step.get("run", ""))


def _source_only(workflow: dict) -> bool:
    if _PUBLISH_CHAIN & workflow["jobs"].keys():
        return False
    _assert_source_only(workflow)
    return True


def test_the_workflow_parses_and_has_the_jobs_this_test_checks() -> None:
    """Guard the guard: an empty parse would make the assertions below vacuous."""
    workflow = _workflow()
    jobs = workflow.get("jobs") or {}
    assert {"backend", "frontend", "dependency-audit", "secret-scan", "application-image-security"} <= set(jobs)
    if _source_only(workflow):
        return
    assert {"release", "build-images", "dependency-audit"} <= set(jobs), (
        f"expected the publish chain and the audit job; found {sorted(jobs)}"
    )


def test_every_blocking_job_can_stop_a_release() -> None:
    """The core regression. Fails before the fix, naming dependency-audit."""
    workflow = _workflow()
    if _source_only(workflow):
        return
    jobs = workflow["jobs"]
    gating = _ancestors(jobs, "release")

    ungated = sorted(
        name
        for name, job in jobs.items()
        if job.get("continue-on-error") is not True
        and name not in gating
        and name not in _PUBLISH_CHAIN
        and name not in _ADVISORY_BY_DESIGN
    )
    assert not ungated, (
        f"these jobs are BLOCKING but cannot stop a release: {ungated}. A tag "
        "would build, push, sign and publish while they are red, because a job "
        "runs whenever its own needs are satisfied regardless of a failing "
        "sibling. Add each to build-images.needs, or -- if it is genuinely "
        "advisory -- give it continue-on-error and a reason."
    )


def test_the_audit_gates_image_publication_not_merely_the_release() -> None:
    """Gate the push, not just the tag.

    Gating ``release`` alone would still let a vulnerable image reach ghcr and be
    cosign-signed; only the GitHub release would be withheld.
    """
    workflow = _workflow()
    if _source_only(workflow):
        return
    jobs = workflow["jobs"]
    assert "dependency-audit" in (jobs["build-images"].get("needs") or []), (
        "dependency-audit must gate build-images, so a vulnerable image is never "
        "pushed or signed at all"
    )


def test_the_advisory_exemptions_are_actually_advisory() -> None:
    """An exemption is only honest while the job really is continue-on-error.

    Otherwise this allow-list becomes the hiding place for the next instance.
    """
    jobs = _workflow().get("jobs") or {}
    wrong = sorted(
        name
        for name in _ADVISORY_BY_DESIGN
        if name in jobs and jobs[name].get("continue-on-error") is not True
    )
    assert not wrong, (
        f"{wrong} are exempted here as advisory but no longer set "
        "continue-on-error, so they are blocking jobs that cannot stop a release"
    )


@pytest.mark.parametrize("change", ["tag", "write", "push", "release", "attest", "publishing_action"])
def test_source_only_contract_refuses_publication_paths(change):
    workflow = {"on": {"push": {"branches": ["main"]}}, "permissions": {"contents": "read"}, "jobs": {"check": {"steps": []}}}
    if change == "tag":
        workflow["on"]["push"]["tags"] = ["v*"]
    elif change == "write":
        workflow["jobs"]["check"]["permissions"] = {"packages": "write"}
    elif change == "publishing_action":
        workflow["jobs"]["check"]["steps"] = [{"uses": "docker/build-push-action@pin", "with": {"push": True}}]
    else:
        command = {"push": "docker push candidate", "release": "gh release create v1", "attest": "cosign attest candidate"}[change]
        workflow["jobs"]["check"]["steps"] = [{"run": command}]
    with pytest.raises(AssertionError):
        _assert_source_only(workflow)
