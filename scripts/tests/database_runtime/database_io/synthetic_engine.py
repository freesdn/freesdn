"""Native controlled catalogue peer; never contacts a Docker daemon."""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

root = Path(os.environ["ENGINE_CASE_ROOT"])
mode = os.environ["ENGINE_CASE_MODE"]
args = sys.argv[1:]
state_path = root / "catalogue.json"
state = (
    json.loads(state_path.read_bytes())
    if state_path.exists()
    else {"volume": None, "container": None, "removed": []}
)


def save():
    temporary = root / "catalogue.pending"
    with temporary.open("w") as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    temporary.replace(state_path)


def journal(kind, **extra):
    with (root / "calls.jsonl").open("a") as f:
        json.dump(
            {
                "kind": kind,
                "pid": os.getpid(),
                "pgid": os.getpgrp(),
                "pgid_starttime": Path(f"/proc/{os.getpgrp()}/stat")
                .read_text()
                .rsplit(")", 1)[1]
                .split()[19],
                "starttime": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
                **extra,
            },
            f,
        )
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def stall(stage):
    journal("waiting", stage=stage)
    (root / "ready").write_text(stage)
    # Independent native-peer lifeline. This is not a checker timeout.
    time.sleep(4)
    sys.exit(49)


if args[:2] == ["image", "inspect"]:
    reference = args[2]
    row = {
        "Id": "sha256:" + hashlib.sha256(reference.encode()).hexdigest(),
        "Os": "linux",
        "Architecture": "amd64",
    }
    if mode == "image-os":
        row["Os"] = "windows"
    if mode == "image-arch" and reference == "target-logdb":
        row["Architecture"] = "arm64"
    if mode == "image-id":
        row["Id"] = "sha256:not-an-id"
    if mode == "image-alias":
        row["Id"] = "sha256:" + "a" * 64
    if mode == "image-missing":
        del row["Id"]
    journal("image", reference=reference)
    if mode == "image-stall":
        stall("image")
    if mode == "image-json":
        print("{invalid")
        sys.exit(0)
    if mode == "image-oversize":
        row["unexpected"] = "x" * 65537
    print(json.dumps([row, row] if mode == "image-many" else [row]))
    sys.exit(0)
if args[:2] == ["volume", "create"]:
    owner = args[args.index("--label") + 1].split("=", 1)[1]
    state["volume"] = {"Name": args[-1], "Labels": {"freesdn.qualification": owner}}
    save()
    journal("volume-create", name=args[-1])
    if mode == "volume-stall":
        stall("volume")
    if mode == "volume-lost-ack":
        sys.exit(42)
    print(args[-1])
    sys.exit(0)
if args[:2] == ["volume", "inspect"]:
    journal("volume-inspect", target=args[-1])
    if state["volume"] is None:
        sys.exit(44)
    print(json.dumps([state["volume"]]))
    sys.exit(0)
if args and args[0] == "run":
    name = args[args.index("--name") + 1]
    owner = args[args.index("--label") + 1].split("=", 1)[1]
    identity = hashlib.sha256(name.encode()).hexdigest()
    password = next(x.split("=", 1)[1] for x in args if x.startswith("POSTGRES_PASSWORD="))
    state["container"] = {
        "Id": identity,
        "Name": "/" + name,
        "Config": {"Labels": {"freesdn.qualification": owner}},
        "State": {"Status": "running", "Running": True, "OOMKilled": False, "ExitCode": 0},
        "RestartCount": 0,
    }
    state["password"] = password
    save()
    journal(
        "container-create",
        name=name,
        identity=identity,
        argv_without_password=[
            "POSTGRES_PASSWORD=[REDACTED]" if x.startswith("POSTGRES_PASSWORD=") else x
            for x in args
        ],
    )
    if mode == "container-stall":
        stall("container")
    if mode == "container-lost-ack":
        sys.exit(42)
    print(identity)
    sys.exit(0)
if args[:2] == ["inspect", "--type=container"]:
    target = args[-1]
    journal("container-inspect", target=target)
    if state["container"] is None:
        sys.exit(44)
    row = json.loads(json.dumps(state["container"]))
    if mode == "wrong-label":
        row["Config"]["Labels"]["freesdn.qualification"] = "unrelated"
    if mode == "wrong-name":
        row["Name"] = "/unrelated"
    if mode == "wrong-id":
        row["Id"] = "b" * 64
    print(json.dumps([row]))
    sys.exit(0)
if args and args[0] == "exec":
    if mode == "database-stall":
        if args[-2:] == ["cat", "/proc/1/comm"]:
            journal("readiness-probe")
            print("postgres")
            sys.exit(0)
        assert "psql" in args and args[1] == "-i"
        assert sys.stdin.buffer.read(4097) == b"SELECT 1"
        worker = os.getppid()
        worker_command = Path(f"/proc/{worker}/cmdline").read_bytes().split(b"\0")
        assert worker == os.getpgrp() and worker != os.getpid()
        assert any(
            value.endswith(b"/qualification/migration_io_worker.py") for value in worker_command
        )
        journal(
            "database-worker-boundary",
            worker_pid=worker,
            worker_starttime=Path(f"/proc/{worker}/stat").read_text().rsplit(")", 1)[1].split()[19],
            worker_command=[value.decode() for value in worker_command if value],
        )
        stall("database-command")
    journal("work-refusal")
    # Actual metadata output overflow stops the checker before SQL. A nonzero
    # /proc probe alone is intentionally retried by the real readiness loop.
    sys.stdout.buffer.write(b"x" * (4 * 1024**2 + 1))
    sys.stdout.buffer.flush()
    sys.exit(45)
if args and args[0] == "logs":
    journal("logs", target=args[-1])
    if mode == "log-error":
        sys.exit(46)
    if mode == "oversized-logs":
        print("x" * (1024**2 + 1))
        sys.exit(0)
    print("owned log " + state["password"])
    sys.exit(0)
if args and args[0] == "rm":
    journal("container-remove", target=args[-1])
    if mode == "cleanup-stall":
        stall("cleanup")
    if mode == "remove-failure":
        sys.exit(47)
    if state["container"] is None or args[-1] != state["container"]["Id"]:
        sys.exit(48)
    state["removed"].append({"kind": "container", "identity": args[-1]})
    state["container"] = None
    save()
    sys.exit(0)
if args[:2] == ["volume", "rm"]:
    journal("volume-remove", target=args[-1])
    if state["volume"] is None or args[-1] != state["volume"]["Name"]:
        sys.exit(48)
    if state["container"] is not None:
        sys.exit(50)
    state["removed"].append({"kind": "volume", "identity": args[-1]})
    state["volume"] = None
    save()
    sys.exit(0)
journal("unexpected", arguments=args)
sys.exit(51)
