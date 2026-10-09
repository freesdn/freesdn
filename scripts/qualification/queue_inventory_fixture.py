"""Synthetic Celery fixtures ONLY, used inside containers by check_queue_inventory.py.

This script deliberately writes/pops fixture data. Never run against an installation.
It accepts no remote address: loopback in a freshly owned network=none namespace.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import os
import runpy
import sys
import time
from pathlib import Path

import redis
from celery import Celery
from kombu import Connection, Exchange, Queue
from kombu.transport.redis import Channel

QUEUES = ("default", "discovery", "sync", "priority", "metrics")
SEP = "\x06\x16"


def main(options):
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")
    clients = [
        redis.Redis(host="127.0.0.1", db=db, password=options["password"])
        for db in range(16)
    ]
    r = clients[0]
    for _ in range(100):
        try:
            r.ping()
            break
        except redis.ConnectionError:
            time.sleep(0.1)
    assert Channel.priority_steps == [0, 3, 6, 9] and Channel.sep == SEP
    mode = options["mode"]
    if mode in ("enable-persistence", "disable-persistence"):
        r.config_set("save", "3600 1" if mode == "enable-persistence" else "")
        return {"configured": mode}
    if mode == "snapshot":
        items = []
        for db, client in enumerate(clients):
            for key in sorted(client.scan_iter()):
                items.append(
                    [
                        db,
                        base64.b64encode(key).decode(),
                        hashlib.sha256(client.dump(key)).hexdigest(),
                        client.pexpiretime(key),
                    ]
                )
        return {
            "dataset_sha256": hashlib.sha256(
                json.dumps(items, sort_keys=True).encode()
            ).hexdigest(),
            "keys": len(items),
        }
    if mode == "change-during-probe":
        probe_path = Path("/tmp/queue_inventory_probe.py")
        probe_path.write_text(options["probe_script"])
        namespace = runpy.run_path(str(probe_path), run_name="fixture_import")
        reader = namespace["Reader"]
        original = reader.snapshot
        snapshots = 0

        def change_after_first(self, count):
            nonlocal snapshots
            snapshot = original(self, count)
            snapshots += 1
            if snapshots == 1:
                # Actual write-and-delete: final bytes match, counters must detect it.
                r.set("fixture-concurrent-write", "synthetic")
                r.delete("fixture-concurrent-write")
                r.close()
            return snapshot

        reader.snapshot = change_after_first
        # Close fixture clients before the probe's initial clients/fence observation.
        for client in clients:
            client.close()
        result = namespace["run"](
            {
                "password": options["password"],
                "max_keys": 10000,
                "max_records": 10000,
                "max_value_bytes": 4 * 1024 * 1024,
                "max_total_bytes": 64 * 1024 * 1024,
            }
        )
        return result
    # Only the just-created fixture is cleared, never a user-provided source.
    r.flushall()
    expected = {}
    if mode == "empty":
        return {"expected_fifo": expected}
    for db in range(3):
        url = f"redis://:{options['password']}@127.0.0.1:6379/{db}"
        app = Celery("inventory-fixture", broker=url)
        queues = [
            Queue(
                q,
                Exchange("default" if q == "metrics" else q, type="direct"),
                routing_key=q,
            )
            for q in QUEUES
        ]
        app.conf.update(
            task_queues=queues,
            task_default_queue="default",
            task_default_exchange="default",
            task_default_routing_key="default",
            task_serializer="json",
            task_protocol=2,
            broker_connection_retry_on_startup=False,
        )
        with Connection(url) as connection:
            for q in queues:
                q(connection).declare()
            for q in QUEUES:
                for priority in (0, 3, 6, 9):
                    ids = []
                    for position in range(2):
                        identifier = f"fixture-{db}-{q}-{priority}-{position}"
                        app.send_task(
                            "synthetic.never_execute",
                            args=[options["argument_secret"], position],
                            task_id=identifier,
                            queue=q,
                            priority=priority,
                            connection=connection,
                        )
                        ids.append(identifier)
                    expected[f"{db}/{q}/{priority}"] = ids
        app.close()
    # Reserve a genuine Kombu message, then emulate abrupt worker death. Closing a
    # normal consumer would restore it at shutdown and would not test unacked state.
    pid = os.fork()
    if pid == 0:
        connection = Connection(f"redis://:{options['password']}@127.0.0.1:6379/1")
        queue = Queue(
            "default", Exchange("default", type="direct"), routing_key="default"
        )(connection)
        message = queue.get(no_ack=False)
        assert message is not None
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert status == 0
    expected["1/default/0"].pop(0)
    assert clients[1].hlen("unacked") == 1 and clients[1].zcard("unacked_index") == 1
    reserved = json.loads(next(iter(clients[1].hgetall("unacked").values())))
    reserved_id = reserved[0]["headers"]["id"]
    if mode == "ambiguous":
        raw = clients[0].lindex("default", -1)
        clients[2].lpush("default", raw)
        changed = json.loads(raw)
        changed["body"] = base64.b64encode(
            json.dumps([["different-argument"], {}, {}]).encode()
        ).decode()
        clients[1].lpush("default", json.dumps(changed))
        clients[0].lpush("default", json.dumps(reserved[0]))
        clients[2].set(
            "celery-task-meta-" + reserved_id,
            json.dumps(
                {
                    "task_id": reserved_id,
                    "status": "SUCCESS",
                    "result": options["result_secret"],
                }
            ),
            ex=86400,
        )
        for db, outcome in ((0, "FAILURE"), (2, "SUCCESS")):
            clients[db].set(
                "celery-task-meta-" + changed["headers"]["id"],
                json.dumps(
                    {
                        "task_id": changed["headers"]["id"],
                        "status": outcome,
                        "result": options["result_secret"],
                    }
                ),
                ex=86400,
            )
    elif mode == "expired-result":
        clients[2].set(
            "celery-task-meta-" + reserved_id,
            json.dumps(
                {
                    "task_id": reserved_id,
                    "status": "SUCCESS",
                    "result": options["result_secret"],
                }
            ),
            px=1,
        )
        time.sleep(0.02)
        assert clients[2].get("celery-task-meta-" + reserved_id) is None
    elif mode == "orphans":
        clients[1].zrem("unacked_index", next(iter(clients[1].hgetall("unacked"))))
        clients[2].zadd("unacked_index", {"orphan-index": time.time()})
    elif mode == "unsupported":
        clients[0].lpush("tenant:default", clients[0].lindex("default", 0))
        clients[2].lpush("custom-queue", b"not-json")
        clients[3].set("hidden-custom-database", options["argument_secret"])
        clients[0].lpush("default", b'{"headers":{},"headers":{"id":"duplicate"}}')
        clients[0].lpush("default", b'{"id":"protocol-one","task":"v1","args":[]}')
        malicious = json.loads(clients[1].lindex("default", 0))
        malicious["content-type"] = "application/x-python-serialize"
        # If deserialized this pickle creates a marker; neither the inventory nor
        # the test loader should ever unpickle it.
        malicious["body"] = base64.b64encode(
            b"cos\nsystem\n(S'touch /tmp/forbidden-unpickle'\ntR."
        ).decode()
        clients[0].lpush("default", json.dumps(malicious))
        clients[2].set("celery-task-meta-invalid", b"not-json")
    elif mode == "oversized":
        clients[0].lpush("default", b"x" * (1024 * 1024))
    return {
        "expected_fifo": expected,
        "reserved_id": reserved_id,
        "versions": {
            p: importlib.metadata.version(p) for p in ("celery", "kombu", "redis")
        },
    }


if __name__ == "__main__":
    print(json.dumps(main(json.load(sys.stdin)), sort_keys=True))
