#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check the built HA image with isolated upstreams, no host ports or real API.

Build docker/Dockerfile.ha-lb first, then run this script. It exercises the exact
shipped nginx configuration, HTTP round-robin, WebSocket echo, and loss of one
upstream. It does not establish multi-host or database high availability.
Inputs are resolved to immutable local image IDs before container creation.
An absent fixture tag may be pulled; an absent image ID is refused.
"""

import argparse
import io
import json
import re
import subprocess
import tarfile
import time
from pathlib import Path
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="freesdn-ha-lb:ci")
    parser.add_argument("--fixture-image", default="python:3.14.8-slim-trixie")
    parser.add_argument("--docker-binary", default="docker")
    args = parser.parse_args()
    docker = args.docker_binary
    prefix = "freesdn-ha-check-" + uuid4().hex[:12]
    network = prefix + "-net"
    names = {role: prefix + "-" + role for role in ("api", "api-2", "lb")}
    created = []
    network_created = False
    script_dir = Path(__file__).resolve().parent

    def run(*command, input_bytes=None, check=True):
        result = subprocess.run(
            [docker, *command], input=input_bytes, capture_output=True, timeout=120, check=False
        )
        if check and result.returncode:
            raise RuntimeError(
                f"docker {' '.join(command)}: {result.stderr.decode(errors='replace')}"
            )
        return result.stdout.decode(errors="replace").strip()

    def copy_file(container, source, destination):
        archive = io.BytesIO()
        data = source.read_bytes()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo(Path(destination).name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
        run("cp", "-", f"{container}:{Path(destination).parent}", input_bytes=archive.getvalue())

    try:
        image_id = run("image", "inspect", "--format", "{{.Id}}", args.image)
        fixture_id = run("image", "inspect", "--format", "{{.Id}}", args.fixture_image, check=False)
        if not fixture_id:
            if re.fullmatch(r"(?:sha256:)?[0-9a-f]{12,64}", args.fixture_image):
                raise RuntimeError("The requested fixture image ID is not installed locally")
            run("pull", args.fixture_image)
            fixture_id = run("image", "inspect", "--format", "{{.Id}}", args.fixture_image)
        if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in [image_id, fixture_id]):
            raise RuntimeError("Docker did not resolve the requested images to immutable IDs")
        run("network", "create", "--internal", "--label", "freesdn.test=ha-lb", network)
        network_created = True
        for role in ("api", "api-2"):
            name = names[role]
            run(
                "create",
                "--name",
                name,
                "--network",
                network,
                "--network-alias",
                role,
                "--label",
                "freesdn.test=ha-lb",
                "--memory",
                "128m",
                "--cpus",
                "1",
                "--env",
                f"BACKEND_ID={role}",
                fixture_id,
                "python",
                "-u",
                "/tmp/ha_upstream.py",
                "serve",
            )
            created.append(name)
            copy_file(name, script_dir / "fixtures/ha_upstream.py", "/tmp/ha_upstream.py")
            run("start", name)
        run(
            "create",
            "--name",
            names["lb"],
            "--network",
            network,
            "--label",
            "freesdn.test=ha-lb",
            "--memory",
            "128m",
            "--cpus",
            "1",
            "--health-cmd",
            "wget -qO- http://127.0.0.1/health || exit 1",
            "--health-interval",
            "1s",
            "--health-timeout",
            "2s",
            image_id,
        )
        created.append(names["lb"])
        copy_file(
            names["lb"], script_dir.parent / "docker/ha-lb/nginx.conf", "/etc/nginx/nginx.conf"
        )
        run("start", names["lb"])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if run("inspect", "--format", "{{.State.Health.Status}}", names["lb"]) == "healthy":
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("HA image did not become healthy")
        run("exec", names["lb"], "nginx", "-t")
        before = json.loads(
            run(
                "exec",
                names["api-2"],
                "python",
                "/tmp/ha_upstream.py",
                "probe",
                names["lb"],
                "api",
                "api-2",
            )
        )
        run("stop", "--time", "2", names["api"])
        after = json.loads(
            run(
                "exec",
                names["api-2"],
                "python",
                "/tmp/ha_upstream.py",
                "probe",
                names["lb"],
                "api-2",
            )
        )
        print(
            json.dumps(
                {
                    "image_id": image_id,
                    "fixture_image_id": fixture_id,
                    "nginx_config": "passed",
                    "before_loss": before,
                    "after_one_upstream_stopped": after,
                    "host_ports_published": False,
                    "scope": "isolated proxy smoke test; not multi-host HA",
                },
                indent=2,
            )
        )
    except Exception:
        for name in created:
            print(f"{name} logs:\n{run('logs', '--tail', '40', name, check=False)}")
        raise
    finally:
        for name in reversed(created):
            run("rm", "-f", "-v", name, check=False)
        if network_created:
            run("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
