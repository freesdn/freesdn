#!/usr/bin/env python3
"""Exercise shipped Valkey HA in an isolated, disposable Compose project.

Never targets an existing installation. Uses synthetic data, an internal network,
no host ports, and only removes resources from its unique project. Requires the
production backend image for persistent sync/async application-client probes.
On Docker Desktop/WSL, put --source-root and --work-dir below /mnt/c.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

NODES = ["redis", "redis-replica", *[f"redis-sentinel-{i}" for i in range(1, 4)]]
PROBE = """
import asyncio, json, time
from app.core import redis_client as factory
from app.core.config import settings
from app.services.websocket_pubsub import WSCrossInstanceBus
async def main():
    sync = factory.get_sync_redis(decode_responses=True)
    asynchronous = factory.get_async_redis(decode_responses=True)
    successes = errors = 0
    maximum_duration = 0
    delivered = asyncio.Event()
    user = "qualification-" + __import__("uuid").uuid4().hex
    async def receive(user_id, payload):
        if user_id == user and payload.get("sequence") == successes:
            delivered.set()
    sender = WSCrossInstanceBus(str(settings.REDIS_URL))
    receiver = WSCrossInstanceBus(str(settings.REDIS_URL))
    await sender.connect(on_targeted=receive)
    await receiver.connect(on_targeted=receive)
    while True:
        started = time.monotonic()
        result = {}
        try:
            for label, client in [("sync", sync), ("async", asynchronous)]:
                if label == "sync":
                    assert client.get("qualification:seed") == "replicated"
                    assert client.set("qualification:" + label, str(successes))
                    assert client.get("qualification:" + label) == str(successes)
                    result[label + "_address"] = client.client_info()["laddr"].rsplit(":", 1)[0]
                else:
                    assert await client.get("qualification:seed") == "replicated"
                    assert await client.set("qualification:" + label, str(successes))
                    assert await client.get("qualification:" + label) == str(successes)
                    result[label + "_address"] = (await client.client_info())["laddr"].rsplit(":", 1)[0]
            delivered.clear()
            await sender.publish_to_user(user, {"sequence": successes})
            await asyncio.wait_for(delivered.wait(), timeout=2)
            result["ws_delivered"] = True
            successes += 1
            result["ok"] = True
        except Exception as exc:
            errors += 1
            result.update(ok=False, error=type(exc).__name__)
        duration = time.monotonic()-started
        maximum_duration = max(maximum_duration, duration)
        result.update(successes=successes, errors=errors, finished=time.time(), duration=duration, maximum_duration=maximum_duration)
        with open("/tmp/probe.json.tmp", "w") as f: json.dump(result, f)
        import os
        os.replace("/tmp/probe.json.tmp", "/tmp/probe.json")
        await asyncio.sleep(.2)
asyncio.run(main())
"""


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--valkey", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument(
        "--source-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--subnet", default="198.19.240.0/24")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    subnet = ipaddress.IPv4Network(args.subnet)
    if subnet.prefixlen != 24:
        parser.error("qualification requires a /24 subnet")
    prefix = "freesdn-valkey-" + uuid.uuid4().hex[:10]
    password, key, salt = [secrets.token_hex(32) for _ in range(3)]
    report = {
        "cases": [],
        "production_access": False,
        "published_ports": False,
        "passed": False,
    }
    started = False
    probe_created = False
    journal = []

    def host_path(path):
        value = str(path.resolve())
        if args.docker.endswith(".exe") and value.startswith("/mnt/c/"):
            return "C:/" + value[len("/mnt/c/") :]
        return value

    def clean(value):
        for secret in (password, key, salt):
            value = value.replace(secret, "[REDACTED]")
        return value

    def command(*argv, data=None, check=True, timeout=30):
        if "--force-recreate" in argv:
            # Keep fault history before Docker removes replaced containers.
            snapshot = subprocess.run(
                [args.docker, *compose, "logs", "--no-color", "--tail", "200"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            journal.append(clean(snapshot.stdout + snapshot.stderr))
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            raise AssertionError(clean(result.stdout + result.stderr)[-3000:])
        return result

    def wait_for(predicate, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.25)
        raise AssertionError(f"Qualification deadline exceeded ({seconds}s)")

    def case(message):
        report["cases"].append(message)
        print("PASS", message, flush=True)

    def cli(service, *argv):
        port = "26379" if "sentinel" in service else "6379"
        return command(
            "exec",
            "-e",
            "REDISCLI_AUTH=" + password,
            prefix + "-" + service,
            "valkey-cli",
            "--raw",
            "-p",
            port,
            *argv,
            check=False,
        ).stdout.strip()

    def replication(service):
        return cli(service, "INFO", "replication")

    with tempfile.TemporaryDirectory(prefix=prefix, dir=args.work_dir) as temporary:
        private = Path(temporary)
        os.chmod(private, 0o700)
        env = {}
        for line in (args.source_root / ".env.max.example").read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                env[name] = value
        addresses = {
            name: str(subnet[i])
            for name, i in zip(NODES, [210, 211, 221, 222, 223], strict=True)
        }
        env.update(
            COMPOSE_PROJECT_NAME=prefix,
            SECRET_KEY=key,
            ENCRYPTION_SALT=salt,
            POSTGRES_PASSWORD=password,
            LOGDB_PASSWORD=password,
            REDIS_PASSWORD=password,
            POSTGRES_REPL_PASSWORD=password,
            NETWORK_SUBNET=str(subnet),
            NETWORK_IP_RANGE=str(next(subnet.subnets(prefixlen_diff=1))),
            FORWARDED_ALLOW_IPS=str(subnet),
            HA_PRIMARY_IP=addresses["redis"],
            HA_REPLICA_IP=addresses["redis-replica"],
        )
        for i in range(1, 4):
            env[f"HA_SENTINEL_{i}_IP"] = addresses[f"redis-sentinel-{i}"]
        envfile = private / "qualification.env"
        envfile.write_text(
            "".join(name + "=" + value + "\n" for name, value in env.items())
        )
        envfile.chmod(0o600)
        config = json.loads(
            command(
                "compose",
                "--project-directory",
                host_path(args.source_root),
                "--env-file",
                host_path(envfile),
                "-f",
                host_path(args.source_root / "docker-compose.yml"),
                "-f",
                host_path(args.source_root / "docker-compose.ha.yml"),
                "config",
                "--format",
                "json",
            ).stdout
        )
        backend_environments = [
            service["environment"]
            for service in config["services"].values()
            if service.get("environment", {}).get("REDIS_SENTINELS")
        ]
        # Use actual rendered definitions; isolate identity, network and image only.
        config["services"] = {name: config["services"][name] for name in NODES}
        used_volumes = set()
        for name, service in config["services"].items():
            service.update(
                image=args.valkey,
                container_name=prefix + "-" + name,
                labels={"freesdn.qualification": prefix},
                pull_policy="never",
                restart="no",
            )
            for field in ("build", "depends_on", "profiles", "ports"):
                service.pop(field, None)
            for volume in service.get("volumes", []):
                if volume["type"] == "volume":
                    used_volumes.add(volume["source"])
        config["volumes"] = {
            name: {
                "name": prefix + "_" + name,
                "labels": {"freesdn.qualification": prefix},
            }
            for name in used_volumes
        }
        config["networks"]["default"].update(internal=True, name=prefix + "_default")
        assert len(used_volumes) == 5, (
            "each node must have a separate persistent named volume"
        )
        composefile = private / "compose.json"
        composefile.write_text(json.dumps(config))
        composefile.chmod(0o600)
        compose = ["compose", "--project-name", prefix, "-f", host_path(composefile)]
        probe = prefix + "-probe"
        try:
            assert backend_environments, "no Sentinel-aware backend services found"
            for environment in backend_environments:
                for setting, database in [
                    ("CELERY_BROKER_URL", "/1"),
                    ("CELERY_RESULT_BACKEND", "/2"),
                ]:
                    endpoints = environment[setting].split(";")
                    assert len(endpoints) == 3
                    assert all(
                        urlsplit(endpoint).scheme == "sentinel"
                        and urlsplit(endpoint).path == database
                        for endpoint in endpoints
                    ), setting + " changes database on endpoint failover"
            case(
                "every backend broker/result Sentinel endpoint retains its database number"
            )
            started = True
            command(
                *compose,
                "up",
                "-d",
                "--no-build",
                "--wait",
                "--wait-timeout",
                "80",
                timeout=100,
            )
            report["image_ids"] = {
                name: json.loads(command("inspect", prefix + "-" + name).stdout)[0][
                    "Image"
                ]
                for name in NODES
            }
            wait_for(lambda: "master_link_status:up" in replication("redis-replica"))
            wait_for(
                lambda: all(
                    "3 usable Sentinels"
                    in cli(n, "SENTINEL", "CKQUORUM", "freesdn-master")
                    for n in NODES[2:]
                )
            )
            assert cli("redis", "SET", "qualification:seed", "replicated") == "OK"
            wait_for(
                lambda: (
                    cli("redis-replica", "GET", "qualification:seed") == "replicated"
                )
            )
            case(
                "shipped configuration starts with authenticated quorum and replicated synthetic data"
            )
            probe_env = {
                "SECRET_KEY": key,
                "ENCRYPTION_SALT": salt,
                "POSTGRES_PASSWORD": password,
                "PYTHONPATH": "/app",
                "ENVIRONMENT": "development",
                "ADAPTER_READ_ONLY": "true",
                "REDIS_PASSWORD": password,
                "REDIS_SENTINELS": ",".join(addresses[n] + ":26379" for n in NODES[2:]),
                "REDIS_MASTER_NAME": "freesdn-master",
                "CELERY_BROKER_URL": backend_environments[0]["CELERY_BROKER_URL"],
                "CELERY_RESULT_BACKEND": backend_environments[0][
                    "CELERY_RESULT_BACKEND"
                ],
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            command(
                "run",
                "-d",
                "--name",
                probe,
                "--label",
                "freesdn.qualification=" + prefix,
                "--network",
                prefix + "_default",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--tmpfs",
                "/tmp",
                "--entrypoint",
                "sleep",
                *[item for k, v in probe_env.items() for item in ("-e", k + "=" + v)],
                args.backend,
                "infinity",
            )
            probe_created = True
            report["backend_image"] = json.loads(command("inspect", probe).stdout)[0][
                "Image"
            ]
            command(
                "exec",
                probe,
                "python",
                "-c",
                "from app.core.celery_app import celery_app; "
                "connection=celery_app.connection(); channel=connection.channel(); "
                "broker=channel.client.connection_pool.connection_kwargs; "
                "result=celery_app.backend.client.connection_pool.connection_kwargs; "
                "assert broker['socket_connect_timeout']==5 and broker['socket_timeout']==5; "
                "assert result['socket_connect_timeout']==5 and result['socket_timeout']==5; "
                "assert broker['db']==1 and result['db']==2; "
                "channel.close(); connection.close()",
            )
            case(
                "actual Celery broker/result clients use bounded sockets and the intended databases"
            )
            source = (args.source_root / "backend/app/core/redis_client.py").read_text()
            report["client_source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
            image_hash = command(
                "exec",
                probe,
                "python",
                "-c",
                "import hashlib; from app.core import redis_client; "
                "print(hashlib.sha256(open(redis_client.__file__, 'rb').read()).hexdigest())",
            ).stdout.strip()
            assert image_hash == report["client_source_sha256"], (
                "backend image has stale application client code"
            )
            command("exec", "-i", probe, "sh", "-c", "cat > /tmp/probe.py", data=PROBE)
            command(
                "exec",
                "-d",
                probe,
                "sh",
                "-c",
                "python /tmp/probe.py > /tmp/probe.log 2>&1",
            )

            def probe_status():
                output = command(
                    "exec", probe, "cat", "/tmp/probe.json", check=False
                ).stdout
                return json.loads(output) if output.strip() else {}

            def follows(service, after):
                status = probe_status()
                return (
                    status.get("ok")
                    and status.get("ws_delivered")
                    and status.get("finished", 0) > after
                    and status.get("sync_address") == addresses[service]
                    and status.get("async_address") == addresses[service]
                )

            wait_for(lambda: follows("redis", 0))
            case(
                "persistent application clients and cross-instance WebSocket bus read, write and deliver before faults"
            )
            command(*compose, "stop", "-t", "2", "redis")
            fault = time.time()
            wait_for(lambda: follows("redis-replica", fault))
            report["stop_recovery_seconds"] = round(time.time() - fault, 2)
            # No Docker DNS record for a stopped node: exactly the former failure.
            absent = command(
                "exec",
                probe,
                "python",
                "-c",
                "import socket; socket.getaddrinfo('redis',6379)",
                check=False,
            )
            assert absent.returncode != 0
            case(
                "actual primary stop removes its DNS name; existing clients and WebSocket bus recover through promoted replica"
            )
            wait_for(
                lambda: all(
                    cli(
                        n, "SENTINEL", "GET-MASTER-ADDR-BY-NAME", "freesdn-master"
                    ).splitlines()[0]
                    == addresses["redis-replica"]
                    for n in NODES[2:]
                )
            )
            # Recreate all Sentinels together while the old master is unavailable.
            command(
                *compose,
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                *NODES[2:],
                timeout=60,
            )
            wait_for(
                lambda: all(
                    "3 usable Sentinels"
                    in cli(n, "SENTINEL", "CKQUORUM", "freesdn-master")
                    for n in NODES[2:]
                )
            )
            wait_for(lambda: follows("redis-replica", time.time() - 1))
            case(
                "all Sentinel containers recreate from persisted election state while old primary remains stopped"
            )
            command(
                *compose,
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "redis-replica",
                timeout=60,
            )
            wait_for(lambda: "role:master" in replication("redis-replica"))
            wait_for(lambda: follows("redis-replica", time.time() - 1))
            case(
                "promoted data node recreates on its named volume without reverting to bootstrap replica role"
            )
            command(
                *compose,
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "redis",
                timeout=60,
            )
            wait_for(
                lambda: (
                    "role:slave" in replication("redis")
                    and "master_link_status:up" in replication("redis")
                )
            )
            assert (
                cli("redis-replica", "SET", "qualification:rejoin", "new-primary-write")
                == "OK"
            )
            wait_for(
                lambda: (
                    cli("redis", "GET", "qualification:rejoin") == "new-primary-write"
                )
            )
            case(
                "old primary recreates at its stable address and rejoins as a synchronized replica"
            )
            command(*compose, "stop", "-t", "2", "redis-sentinel-3")
            command(*compose, "kill", "-s", "SIGKILL", "redis-replica")
            fault = time.time()
            wait_for(lambda: follows("redis", fault))
            report["kill_with_one_sentinel_down_seconds"] = round(
                time.time() - fault, 2
            )
            case(
                "reverse failover survives SIGKILL with one Sentinel down; persistent clients follow again"
            )
            command(*compose, "start", "redis-replica", "redis-sentinel-3")
            wait_for(
                lambda: (
                    "role:slave" in replication("redis-replica")
                    and "master_link_status:up" in replication("redis-replica")
                )
            )
            case(
                "killed node and missing Sentinel rejoin without discarding current master"
            )
            for name in NODES[:2]:
                command(
                    *compose,
                    "up",
                    "-d",
                    "--no-deps",
                    "--force-recreate",
                    name,
                    timeout=60,
                )
            wait_for(lambda: follows("redis", time.time() - 1))
            wait_for(lambda: "master_link_status:up" in replication("redis-replica"))
            case(
                "both data containers recreate again with roles and replicated data preserved"
            )
            command(*compose, "stop", "-t", "2", "redis-sentinel-2", "redis-sentinel-3")
            command(*compose, "stop", "-t", "2", "redis")
            fault = time.time()
            while time.time() - fault < 12:
                assert "role:slave" in replication("redis-replica"), (
                    "minority quorum promoted a node"
                )
                time.sleep(0.5)
            assert not probe_status().get("ok"), (
                "writes succeeded without a reachable primary"
            )
            case(
                "loss of Sentinel majority refuses promotion rather than inventing a master"
            )
            command(*compose, "start", "redis-sentinel-2", "redis-sentinel-3")
            wait_for(lambda: follows("redis-replica", fault))
            command(*compose, "start", "redis")
            wait_for(
                lambda: (
                    "role:slave" in replication("redis")
                    and "master_link_status:up" in replication("redis")
                )
            )
            case(
                "restoring quorum permits promotion and both clients recover; old primary rejoins"
            )
            assert probe_status()["maximum_duration"] < 20, (
                "client operation stalled too long"
            )
            logs = command(*compose, "logs", "--no-color", *NODES[2:]).stdout
            assert "+tilt" not in ("\n".join(journal) + logs).lower()
            report["last_probe"] = probe_status()
            command(*compose, "stop", "-t", "2", *NODES)
            entrypoint = (
                args.source_root / "docker/redis/ha-entrypoint.sh"
            ).read_text()
            guard_args = [
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--name",
                prefix + "-guard",
                "--label",
                "freesdn.qualification=" + prefix,
                "-v",
                prefix + "_redis_data:/data",
                "--entrypoint",
                "sh",
            ]

            def refusal(
                expected, *, credential=password, address=addresses["redis"], setup=""
            ):
                output = command(
                    *guard_args,
                    "-e",
                    "REDIS_PASSWORD=" + credential,
                    "-e",
                    "HA_NODE_IP=" + address,
                    "-e",
                    "HA_PRIMARY_IP=" + addresses["redis"],
                    args.valkey,
                    "-s",
                    "primary",
                    data=setup + entrypoint,
                    check=False,
                )
                assert output.returncode != 0 and expected in output.stderr, clean(
                    output.stderr
                )

            refusal("credential changed", credential="different-synthetic-credential")
            refusal("node identity changed", address=str(subnet[212]))
            refusal(
                "password must not contain CR or LF", credential="synthetic\ninvalid"
            )
            case(
                "startup refuses uncoordinated credential rotation, identity change and config injection"
            )
            refusal("unmarked existing data", setup="mv /data/ha /data/ha.saved\n")
            case("startup refuses existing AOF/RDB without marked HA state")
            # Restore the original private directory in the owned fixture.
            command(
                *guard_args,
                args.valkey,
                "-c",
                "rmdir /data/ha && mv /data/ha.saved /data/ha",
            )
            report["passed"] = True
        except Exception as exc:
            report["failure"] = clean(str(exc))
            if probe_created:
                report["probe_log"] = clean(
                    command("exec", probe, "cat", "/tmp/probe.log", check=False).stdout
                )[-2000:]
            raise
        finally:
            if started:
                logs = command(
                    *compose, "logs", "--no-color", "--tail", "200", check=False
                )
                args.report.with_suffix(".log").write_text(
                    clean(logs.stdout + logs.stderr)
                )
            command("rm", "-fv", prefix + "-guard", check=False)
            if probe_created:
                command("rm", "-fv", probe, check=False)
            if started:
                command(*compose, "down", "--volumes", "--remove-orphans", timeout=90)
            args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
