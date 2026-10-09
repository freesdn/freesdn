"""Synthetic-only backup rehearsal client. Never use against an installation.

The host runner owns the network=none namespace and supplies a fresh password.
No FreeSDN application or hardware task modules are imported here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import redis
from celery import Celery
from celery.contrib.testing.worker import start_worker
from kombu import Exchange, Queue

QUEUES = ("default", "discovery", "sync", "priority", "metrics")
STEPS = (0, 3, 6, 9)
SEP = "\x06\x16"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def b64(value):
    return base64.b64encode(value).decode()


def snapshot(clients):
    """Hash logical values, not DUMP encoding (unordered values can re-encode)."""
    rows = []
    for db, client in enumerate(clients):
        for key in sorted(client.scan_iter()):
            kind = client.type(key).decode()
            if kind == "string":
                value = b64(client.get(key))
            elif kind == "list":
                value = list(map(b64, client.lrange(key, 0, -1)))
            elif kind == "set":
                value = sorted(map(b64, client.smembers(key)))
            elif kind == "hash":
                value = sorted((b64(k), b64(v)) for k, v in client.hgetall(key).items())
            elif kind == "zset":
                value = [
                    (b64(k), score)
                    for k, score in client.zrange(key, 0, -1, withscores=True)
                ]
            else:
                raise AssertionError("Unsupported synthetic fixture type")
            rows.append(
                {
                    "db": db,
                    "key_b64": b64(key),
                    "type": kind,
                    "value_sha256": hashlib.sha256(
                        canonical(value).encode()
                    ).hexdigest(),
                    "expires_at_ms": client.pexpiretime(key),
                }
            )
    return {
        "rows": rows,
        "keys": len(rows),
        "dataset_sha256": hashlib.sha256(canonical(rows).encode()).hexdigest(),
    }


def app_for(password):
    app = Celery(
        "backup-synthetic-only",
        broker=f"redis://:{password}@127.0.0.1:6379/1",
        backend=f"redis://:{password}@127.0.0.1:6379/2",
    )
    app.conf.update(
        task_queues=[
            Queue(
                q,
                Exchange("default" if q == "metrics" else q, type="direct"),
                routing_key=q,
            )
            for q in QUEUES
        ],
        task_default_queue="default",
        task_default_exchange="default",
        task_default_routing_key="default",
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_protocol=2,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=False,
        worker_enable_remote_control=False,
        task_ignore_result=False,
    )
    return app


def main(options):
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")
    clients = [
        redis.Redis(
            host="127.0.0.1",
            db=db,
            password=options["password"],
            socket_connect_timeout=1,
            socket_timeout=2,
        )
        for db in range(16)
    ]
    r = clients[0]
    ready = False
    for _ in range(50):
        try:
            ready = r.ping()
            if ready:
                break
        except (redis.ConnectionError, redis.BusyLoadingError):
            time.sleep(0.1)
    if not ready:
        return {"ready": False}
    mode = options["mode"]
    if mode == "ready":
        info = r.info("persistence")
        return {
            "ready": True,
            "aof_enabled": info["aof_enabled"],
            "loading": info["loading"],
        }
    if mode == "snapshot":
        return snapshot(clients)
    if mode == "prepare-rdb":
        # A real terminal result and an expiring result exercise TTL/result fidelity.
        for identifier in ("retained-result", "expiring-result"):
            clients[2].set(
                "celery-task-meta-" + identifier,
                canonical(
                    {
                        "task_id": identifier,
                        "status": "SUCCESS",
                        "result": options["result_secret"],
                    }
                ),
                px=86400000,
            )
        r.save()
        return snapshot(clients)
    if mode == "expire-result-and-save":
        assert clients[2].pexpire("celery-task-meta-expiring-result", 1500)
        before = snapshot(clients)
        r.save()
        return before
    if mode == "prepare-aof":
        r.config_set("appendonly", "yes")
        for _ in range(100):
            info = r.info("persistence")
            if (
                not info["aof_rewrite_in_progress"]
                and not info["aof_rewrite_scheduled"]
                and info["aof_last_bgrewrite_status"] == "ok"
            ):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("AOF rewrite did not complete")
        app = app_for(options["password"])
        app.send_task(
            "synthetic.never_execute",
            args=[options["argument_secret"], 7],
            task_id="fixture-aof-tail",
            queue="metrics",
            priority=9,
        )
        app.close()
        # This complete command must live in an incremental segment after the base.
        r.execute_command("WAITAOF", 1, 0, 5000)
        return snapshot(clients)
    if mode == "disable-persistence":
        r.config_set("appendonly", "no")
        r.config_set("save", "")
        return snapshot(clients)
    if mode == "review":
        decisions = []
        reserved_ids = set()
        for client in clients[:3]:
            for raw in client.hvals("unacked"):
                reserved_ids.add(json.loads(raw)[0]["headers"]["id"])
        for q in QUEUES:
            for priority in STEPS:
                key = q if priority == 0 else q + SEP + str(priority)
                # Cross-DB ordering is an explicit fixture decision, not a deduced
                # global ordering or a policy for customer jobs.
                for db in range(3):
                    for raw in reversed(clients[db].lrange(key, 0, -1)):
                        message = json.loads(raw)
                        identifier = message["headers"]["id"]
                        assert message["headers"]["task"] == "synthetic.never_execute"
                        assert (
                            identifier.startswith("fixture-")
                            and identifier not in reserved_ids
                        )
                        body = json.loads(base64.b64decode(message["body"]))
                        assert body[0][0] == options["argument_secret"]
                        decisions.append(
                            {
                                "source_db": db,
                                "key": key,
                                "task_id": identifier,
                                "envelope_b64": b64(raw),
                                "decision": "approve_synthetic_only",
                            }
                        )
        assert len({row["task_id"] for row in decisions}) == len(decisions)
        return {"decisions": decisions, "quarantined_reserved": sorted(reserved_ids)}
    if mode == "consume-reviewed":
        assert all(c.dbsize() == 0 for c in clients), "Target must start empty"
        decisions = options["review"]["decisions"]
        assert len({row["task_id"] for row in decisions}) == len(decisions)
        expected = {}
        for row in decisions:
            assert row["decision"] == "approve_synthetic_only"
            raw = base64.b64decode(row["envelope_b64"], validate=True)
            message = json.loads(raw)
            assert message["headers"]["id"] == row["task_id"]
            assert message["headers"]["task"] == "synthetic.never_execute"
            assert row["task_id"] not in options["review"]["quarantined_reserved"]
            expected.setdefault(row["key"], []).append(row["task_id"])
            clients[1].lpush(row["key"], raw)
        for key, identifiers in expected.items():
            assert [
                json.loads(v)["headers"]["id"]
                for v in reversed(clients[1].lrange(key, 0, -1))
            ] == identifiers
        app = app_for(options["password"])

        @app.task(bind=True, name="synthetic.never_execute")
        def synthetic(task, argument, position):
            assert argument == options["argument_secret"]
            event = {
                "id": task.request.id,
                "queue": task.request.delivery_info["routing_key"],
                "priority": task.request.delivery_info.get("priority", 0),
            }
            clients[4].rpush("fixture-executions", canonical(event))
            return {"fixture_only": True, "position": position}

        with start_worker(
            app,
            pool="solo",
            concurrency=1,
            perform_ping_check=False,
            loglevel="ERROR",
        ):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if clients[4].llen("fixture-executions") == len(decisions) and all(
                    app.AsyncResult(row["task_id"]).successful() for row in decisions
                ):
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Synthetic worker did not finish")
        events = [
            json.loads(raw) for raw in clients[4].lrange("fixture-executions", 0, -1)
        ]
        assert len(events) == len(decisions) and len({e["id"] for e in events}) == len(
            decisions
        )
        observed = {}
        for event in events:
            priority = max(p for p in STEPS if p <= event["priority"])
            key = (
                event["queue"]
                if priority == 0
                else event["queue"] + SEP + str(priority)
            )
            observed.setdefault(key, []).append(event["id"])
        assert observed == expected, "FIFO differs from reviewed per-queue order"
        assert (
            clients[1].hlen("unacked") == 0 and clients[1].zcard("unacked_index") == 0
        )
        assert all(clients[1].llen(key) == 0 for key in expected)
        app.close()
        return {
            "executed": len(events),
            "physical_queues": len(expected),
            "fifo_verified": True,
            "quarantined_reserved": len(options["review"]["quarantined_reserved"]),
            "hardware_tasks_imported": False,
        }
    raise AssertionError("Unknown fixture mode")
