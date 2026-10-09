#!/usr/bin/env python3
"""Pressure-test shipped Valkey tier budgets in disposable, isolated containers.

Requires existing Valkey and backend images. Never connects to an installation.
No published ports; synthetic cache/queue data; unique owned volumes only.
On WSL/Docker Desktop put --source-root and --work-dir under /mnt/c.
This tests one data node, not replication backlog sizing or sustained capacity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import uuid
from pathlib import Path

PROBE = r"""
import hashlib, json, os, sys, threading, time
import redis

r = redis.Redis(host="redis", password=os.environ["REDIS_PASSWORD"], socket_timeout=10)
queue = redis.Redis(host="redis", password=os.environ["REDIS_PASSWORD"], db=1, socket_timeout=10)
state_path = "/tmp/memory-state.json"
def digest_queue():
    digest = hashlib.sha256()
    for start in range(0, queue.llen("qualification:queue"), 64):
        for value in queue.lrange("qualification:queue", start, start+63):
            digest.update(value)
    return digest.hexdigest()

if sys.argv[1] == "verify":
    state = json.load(open(state_path))
    assert queue.get("qualification:marker") == b"persistent"
    assert queue.llen("qualification:queue") == state["acknowledged_queue_items"]
    assert digest_queue() == state["queue_sha256"]
    # Draining a full queue restores producer progress.
    while queue.lpop("qualification:queue", 64): pass
    assert queue.rpush("qualification:queue", b"after-drain") == 1
    assert queue.lpop("qualification:queue") == b"after-drain"
    print(json.dumps({"restored_queue_items":state["acknowledged_queue_items"], "drain_and_resume":True}))
    sys.exit(0)

budget = int(r.config_get("maxmemory")["maxmemory"])
limit = int(os.environ["CONTAINER_MEMORY_LIMIT"])
assert 0 < budget < limit, "maxmemory must leave headroom below the container limit"
assert r.config_get("maxmemory-policy")["maxmemory-policy"] == "volatile-lru"
assert r.config_get("appendonly")["appendonly"] == "yes"
queue.set("qualification:marker", "persistent")
payload = os.urandom(16384)  # incompressible RDB/AOF contents
for i in range(100): queue.rpush("qualification:queue", str(i).encode()+payload[:1024])
initial_digest = digest_queue()
cache_writes = max(512, int(budget*2.5)//len(payload))
for start in range(0, cache_writes, 32):
    with r.pipeline(transaction=False) as p:
        for i in range(start, start+32): p.set("qualification:cache:"+str(i), payload, ex=3600)
        assert all(p.execute())
assert r.info("stats")["evicted_keys"] > 0, "cache pressure never reached eviction"
assert queue.llen("qualification:queue") == 100 and digest_queue() == initial_digest
assert queue.get("qualification:marker") == b"persistent"

def wait_idle():
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        info = r.info("persistence")
        if not info["aof_rewrite_in_progress"] and not info["rdb_bgsave_in_progress"]: return
        time.sleep(.05)
    raise AssertionError("persistence did not finish within 60 seconds")

forks = []
for operation, active, status in [(r.bgrewriteaof,"aof_rewrite_in_progress","aof_last_bgrewrite_status"),
                                 (r.bgsave,"rdb_bgsave_in_progress","rdb_last_bgsave_status")]:
    wait_idle()
    stop = threading.Event()
    faults = []
    writes = [0]
    def churn():
        client = redis.Redis(host="redis", password=os.environ["REDIS_PASSWORD"], socket_timeout=10)
        try:
            while not stop.is_set():
                with client.pipeline(transaction=False) as p:
                    for i in range(32):
                        p.set("qualification:cache:"+str((writes[0]+i)%cache_writes),payload,ex=3600)
                    p.execute()
                    writes[0] += 32
        except Exception as exc: faults.append(type(exc).__name__)
        finally: client.close()
    thread = threading.Thread(target=churn)
    thread.start()
    try:
        operation()
        wait_idle()
    finally:
        stop.set(); thread.join(timeout=15)
    assert not thread.is_alive() and not faults, faults
    info = r.info("persistence")
    assert info[status] == "ok", info
    assert writes[0] > 0
    forks.append({"operation":active,"concurrent_cache_writes":writes[0],"status":info[status],
                  "aof_last_cow_size":info.get("aof_last_cow_size"),"rdb_last_cow_size":info.get("rdb_last_cow_size")})

# Remove TTL data, then exhaust non-evictable broker storage. A controlled OOM
# reply is required; a process restart, connection reset or missing item fails.
for keys in iter(lambda:list(r.scan_iter("qualification:cache:*",count=1000)), []):
    for start in range(0,len(keys),128): r.delete(*keys[start:start+128])
acknowledged = 100
rejected = 0
for start in range(0, int(budget*2)//len(payload), 32):
    with queue.pipeline(transaction=False) as p:
        for i in range(start,start+32): p.rpush("qualification:queue",str(i).encode()+payload)
        responses = p.execute(raise_on_error=False)
    for response in responses:
        if isinstance(response, redis.exceptions.OutOfMemoryError): rejected += 1
        else:
            assert isinstance(response,int), type(response).__name__
            acknowledged += 1
    if rejected: break
assert rejected > 0, "non-TTL queue did not reach a controlled OOM response"
assert queue.llen("qualification:queue") == acknowledged
assert queue.get("qualification:marker") == b"persistent"
wait_idle()
# Ensure a complete persisted checkpoint for deterministic recreation checks.
# This does NOT assert preservation of writes not fsynced before a crash.
r.bgrewriteaof(); wait_idle()
assert r.info("persistence")["aof_last_bgrewrite_status"] == "ok"
state = {"maxmemory":budget,"container_limit":limit,"evicted_keys":r.info("stats")["evicted_keys"],
         "acknowledged_queue_items":acknowledged,"rejected_queue_writes":rejected,
         "queue_sha256":digest_queue(),"forks":forks,
         "used_memory_peak":r.info("memory")["used_memory_peak"],
         "used_memory_rss":r.info("memory")["used_memory_rss"]}
with open(state_path,"w") as f: json.dump(state,f)
print(json.dumps(state))
"""


def main():
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--valkey", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument(
        "--tiers",
        nargs="+",
        choices=["lite", "pro", "max"],
        default=["lite", "pro", "max"],
    )
    parser.add_argument(
        "--source-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "passed": False,
        "production_access": False,
        "published_ports": False,
        "tiers": {},
    }

    def host_path(path):
        value = str(path.resolve())
        return (
            "C:/" + value[7:]
            if args.docker.endswith(".exe") and value.startswith("/mnt/c/")
            else value
        )

    password = secrets.token_hex(32)

    def command(*argv, data=None, check=True, timeout=120):
        result = subprocess.run(
            [args.docker, *argv],
            input=data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            raise AssertionError(
                (result.stdout + result.stderr).replace(password, "[REDACTED]")[-3500:]
            )
        return result

    try:
        for tier in args.tiers:
            prefix = "freesdn-memory-" + uuid.uuid4().hex[:10]
            result = report["tiers"][tier] = {"cases": []}
            started = probe_created = False
            with tempfile.TemporaryDirectory(
                prefix=prefix, dir=args.work_dir
            ) as temporary:
                private = Path(temporary)
                os.chmod(private, 0o700)
                env = {}
                for line in (
                    (args.source_root / f".env.{tier}.example").read_text().splitlines()
                ):
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        env[key] = value
                env.update(
                    {
                        key: password
                        for key in [
                            "SECRET_KEY",
                            "ENCRYPTION_SALT",
                            "POSTGRES_PASSWORD",
                            "LOGDB_PASSWORD",
                            "REDIS_PASSWORD",
                        ]
                    }
                )
                env.update(COMPOSE_PROJECT_NAME=prefix, COMPOSE_PROFILES="")
                ef = private / "test.env"
                ef.write_text("".join(k + "=" + v + "\n" for k, v in env.items()))
                ef.chmod(0o600)
                config = json.loads(
                    command(
                        "compose",
                        "--project-directory",
                        host_path(args.source_root),
                        "--env-file",
                        host_path(ef),
                        "-f",
                        host_path(args.source_root / "docker-compose.yml"),
                        "config",
                        "--format",
                        "json",
                    ).stdout
                )
                service = config["services"]["redis"]
                limit = int(service["deploy"]["resources"]["limits"]["memory"])
                service.update(
                    image=args.valkey,
                    container_name=prefix + "-redis",
                    restart="no",
                    pull_policy="never",
                    labels={"freesdn.qualification": prefix},
                )
                for field in ("build", "depends_on", "ports"):
                    service.pop(field, None)
                volumes = {
                    v["source"]: {
                        "name": prefix + "_" + v["source"],
                        "labels": {"freesdn.qualification": prefix},
                    }
                    for v in service["volumes"]
                    if v["type"] == "volume"
                }
                sources = [
                    Path(v["source"].replace("\\", "/").replace("C:/", "/mnt/c/"))
                    for v in service["volumes"]
                    if v["type"] == "bind"
                ]
                result["configuration_sha256"] = {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
                }
                config = {
                    "services": {"redis": service},
                    "volumes": volumes,
                    "networks": {
                        "default": {"internal": True, "name": prefix + "_default"}
                    },
                }
                cf = private / "compose.json"
                cf.write_text(json.dumps(config))
                cf.chmod(0o600)
                compose = ["compose", "--project-name", prefix, "-f", host_path(cf)]
                probe = prefix + "-probe"

                def case(message, result=result, tier=tier):
                    result["cases"].append(message)
                    print(tier, "PASS", message, flush=True)

                try:
                    started = True
                    command(
                        *compose,
                        "up",
                        "-d",
                        "--no-build",
                        "--wait",
                        "--wait-timeout",
                        "60",
                    )
                    inspected = json.loads(
                        command("inspect", prefix + "-redis").stdout
                    )[0]
                    assert inspected["HostConfig"]["Memory"] == limit
                    assert inspected["HostConfig"]["MemorySwap"] == limit, (
                        "container must not rely on swap beyond its memory budget"
                    )
                    assert not inspected["HostConfig"]["PortBindings"]
                    result["valkey_image_id"] = inspected["Image"]
                    case(
                        "actual tier container limit and shipped command/config; no host ports"
                    )
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
                        "--tmpfs",
                        "/tmp:uid=1001,gid=1001",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges",
                        "--env-file",
                        host_path(ef),
                        "-e",
                        "CONTAINER_MEMORY_LIMIT=" + str(limit),
                        "--entrypoint",
                        "sleep",
                        args.backend,
                        "infinity",
                    )
                    probe_created = True
                    result["backend_image_id"] = json.loads(
                        command("inspect", probe).stdout
                    )[0]["Image"]
                    measured = command(
                        "exec",
                        "-i",
                        probe,
                        "python",
                        "-",
                        "pressure",
                        data=PROBE,
                        timeout=300,
                    )
                    result["pressure"] = json.loads(measured.stdout)
                    case("TTL eviction preserves non-TTL queue contents")
                    case(
                        "AOF rewrite and RDB snapshot succeed with concurrent cache writes"
                    )
                    case(
                        "full non-TTL queue returns OOM replies and retains every accepted item"
                    )
                    # cgroup v2 includes all parent/child memory and OOM events.
                    peak = command(
                        "exec", prefix + "-redis", "cat", "/sys/fs/cgroup/memory.peak"
                    ).stdout.strip()
                    events = command(
                        "exec", prefix + "-redis", "cat", "/sys/fs/cgroup/memory.events"
                    ).stdout
                    result["cgroup_peak_bytes"] = int(peak)
                    result["swap_peak_bytes"] = int(
                        command(
                            "exec",
                            prefix + "-redis",
                            "cat",
                            "/sys/fs/cgroup/memory.swap.peak",
                        ).stdout.strip()
                    )
                    assert result["swap_peak_bytes"] == 0
                    result["cgroup_events"] = {
                        k: int(v)
                        for k, v in (line.split() for line in events.splitlines())
                    }
                    assert (
                        result["cgroup_events"]["oom_kill"] == 0
                        and result["cgroup_events"]["oom"] == 0
                    )
                    inspected = json.loads(
                        command("inspect", prefix + "-redis").stdout
                    )[0]
                    assert (
                        not inspected["State"]["OOMKilled"]
                        and inspected["RestartCount"] == 0
                    )
                    case("no cgroup OOM events, OOM kill or container restart")
                    command(
                        *compose,
                        "up",
                        "-d",
                        "--no-build",
                        "--force-recreate",
                        "--wait",
                        "--wait-timeout",
                        "60",
                    )
                    result["recovery"] = json.loads(
                        command(
                            "exec", "-i", probe, "python", "-", "verify", data=PROBE
                        ).stdout
                    )
                    case(
                        "container recreation restores queue digest/order; drain restores writes"
                    )
                    result["passed"] = True
                finally:
                    if started:
                        observed = command("inspect", prefix + "-redis", check=False)
                        if observed.returncode == 0:
                            observed = json.loads(observed.stdout)[0]
                            result["final_container_state"] = {
                                key: observed["State"].get(key)
                                for key in ("Status", "ExitCode", "OOMKilled")
                            }
                        log = command(
                            *compose, "logs", "--no-color", check=False
                        ).stdout.replace(password, "[REDACTED]")
                        args.report.with_suffix("." + tier + ".log").write_text(log)
                    if probe_created:
                        command("rm", "-fv", probe, check=False)
                    if started:
                        command(*compose, "down", "--volumes", "--remove-orphans")
        report["passed"] = True
    except BaseException as exc:
        report["failure"] = str(exc).replace(password, "[REDACTED]")
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
