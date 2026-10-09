# SPDX-License-Identifier: AGPL-3.0-only
"""Publishing must depend on an unsuppressed scan of the same local artifact."""

from pathlib import Path

import pytest
import yaml

APP = Path(__file__).resolve().parents[3]
PRIVATE = APP.parent / ".github/workflows/ci.yml"
PUBLIC = APP.parent / "launch-kit/.github/workflows/ci.yml"
if not PUBLIC.is_file():
    PUBLIC = APP / ".github/workflows/ci.yml"


@pytest.mark.parametrize("workflow", [PRIVATE, PUBLIC])
def test_application_images_have_blocking_full_inventory_gates(workflow):
    if not workflow.is_file():
        pytest.skip("requires private workflow source layout")
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    job = jobs["application-image-security"]
    assert not job.get("continue-on-error")
    matrix = job["strategy"]["matrix"]["include"]
    by_component = {entry["component"]: entry for entry in matrix}
    assert len(by_component) == len(matrix)
    assert set(by_component) == {
        "backend",
        "frontend",
        "nginx",
        "tailscale-access",
        "backup-metrics",
        "postgres",
        "valkey",
        "logdb",
        "ha-lb",
        "go2rtc",
        "pgbouncer",
        "rclone",
        "prometheus",
        "redis-exporter",
        "postgres-exporter",
    }
    for name, target in {
        "backend": "production",
        "frontend": "caddy",
        "nginx": "production",
        "tailscale-access": "tailscale-access",
    }.items():
        assert by_component[name]["target"] == target
    # Keep the production image contract in the gate, including optional profiles.
    for name, entry in by_component.items():
        if name == "redis-exporter":
            assert entry["image"] == "oliver006/redis_exporter:v1.91.1"
        else:
            assert "context" in entry and "dockerfile" in entry
            assert "image" not in entry
    exporter = next(entry for entry in matrix if entry["component"] == "backup-metrics")
    assert exporter["dockerfile"].endswith("docker/Dockerfile.backup-metrics")
    assert exporter["context"].endswith("docker")
    steps = job["steps"]
    build = next(s for s in steps if s.get("name") == "Build production image without stale layers")
    assert build["env"]["DOCKERFILE"] == "${{ matrix.dockerfile }}"
    assert build["env"]["BUILD_CONTEXT"] == "${{ matrix.context }}"
    assert build["env"]["BUILD_TARGET"] == "${{ matrix.target }}"
    assert '-f "$DOCKERFILE"' in build["run"]
    assert '"$BUILD_CONTEXT"' in build["run"]
    assert '--target "$BUILD_TARGET"' in build["run"]
    pull = next(s for s in steps if s.get("name") == "Pull the shipped optional-service image")
    assert "matrix.image" in pull["if"]
    assert 'docker pull "$UPSTREAM_IMAGE"' in pull["run"]
    assert 'docker tag "$UPSTREAM_IMAGE" "freesdn-${COMPONENT}:security"' in pull["run"]
    rules = next(s for s in steps if s.get("name") == "Validate backup alert behavior")
    assert rules["if"] == "matrix.component == 'backup-metrics'"
    assert "test rules backup-rules.test.yml" in rules["run"]
    assert not rules.get("continue-on-error")
    scan = next(s for s in steps if s.get("with", {}).get("scan-type") == "image")
    assert scan["with"]["exit-code"] == "1"
    assert not scan["with"]["ignore-unfixed"]
    assert scan["with"]["scanners"] == "vuln"
    assert scan["env"]["TRIVY_IGNOREFILE"] == "/dev/null"
    assert not scan.get("continue-on-error")
    artifact = next(s for s in steps if "upload-artifact@" in s.get("uses", ""))
    assert artifact["if"] == "always()"
    expected_paths = {scan["with"]["output"]}
    if any("check_native_media_security.py" in step.get("run", "") for step in steps):
        expected_paths.add("${{ runner.temp }}/native-media/*.json")
    artifact_paths = {line.strip() for line in artifact["with"]["path"].splitlines() if line.strip()}
    assert artifact_paths == expected_paths


def test_release_scans_locally_loaded_images_before_any_registry_push():
    if not PRIVATE.is_file():
        pytest.skip("private release workflow is not in flattened distribution")
    jobs = yaml.safe_load(PRIVATE.read_text())["jobs"]
    job = jobs["build-images"]
    assert "application-image-security" in job["needs"]
    assert "go-source-security" in job["needs"]
    steps = job["steps"]
    publisher = next(i for i, s in enumerate(steps) if s.get("id") == "publish-images")
    assert "docker push" in steps[publisher]["run"]
    for component in ["backend", "frontend"]:
        build = next(i for i, s in enumerate(steps) if s.get("id") == "build-" + component)
        settings = steps[build]["with"]
        assert not settings["push"] and settings["load"]
        ref = "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}/" + component + ":${{ github.sha }}"
        scan = next(i for i, s in enumerate(steps) if s.get("with", {}).get("image-ref") == ref)
        assert build < scan < publisher
        assert steps[scan]["with"]["exit-code"] == "1"
        assert not steps[scan].get("continue-on-error")
        # Both SHA and version tags originate in this same build, not a rebuild.
        assert ref in settings["tags"]
    for step in steps[publisher + 1 :]:
        if "cosign " in step.get("run", ""):
            assert "steps.publish-images.outputs." in step["env"]["DIGEST"]


@pytest.mark.parametrize("workflow", [PRIVATE, PUBLIC])
def test_reachable_vpn_and_edge_advisories_block_below_high_severity(workflow):
    if not workflow.is_file():
        pytest.skip("requires private workflow source layout")
    job = yaml.safe_load(workflow.read_text())["jobs"]["go-source-security"]
    assert not job.get("continue-on-error")
    matrix = job["strategy"]["matrix"]["include"]
    assert {entry["target"] for entry in matrix} == {
        "netbird-builder",
        "tailscale-builder",
        "caddy-builder",
    }
    steps = job["steps"]
    scan = next(s for s in steps if "govulncheck -show verbose" in s.get("run", ""))
    assert not scan.get("continue-on-error")
    assert "|| true" not in scan["run"]
    assert "-mode=binary" not in scan["run"]
    assert "-format=json" not in scan["run"]
    assert "--entrypoint sh" in scan["run"]
    assert "-ec" in scan["run"]
    artifact = next(s for s in steps if "upload-artifact@" in s.get("uses", ""))
    assert artifact["if"] == "always()"
