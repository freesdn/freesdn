"""Read-only bounded Redis/Kombu inventory. Invoked by inventory_legacy_queues.py.

Never imports tasks, decodes task bodies into objects, or invokes Kombu consumers.
Only the envelope/result metadata is parsed as strict JSON. Output is PRIVATE.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections import Counter, defaultdict

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

QUEUES = ("default", "discovery", "sync", "priority", "metrics")
STEPS = (0, 3, 6, 9)
SEP = "\x06\x16"
PHYSICAL = {
    (q if p == 0 else q + SEP + str(p)).encode(): (q, p) for q in QUEUES for p in STEPS
}
EXCHANGES = {
    "default": {"default", "metrics"},
    "discovery": {"discovery"},
    "sync": {"sync"},
    "priority": {"priority"},
}
STATES = {"PENDING", "RECEIVED", "STARTED", "SUCCESS", "FAILURE", "RETRY", "REVOKED"}
TERMINAL = {"SUCCESS", "FAILURE", "REVOKED"}
READ_COMMANDS = {
    "PING",
    "INFO",
    "CONFIG",
    "SELECT",
    "DBSIZE",
    "SCAN",
    "TYPE",
    "DUMP",
    "PEXPIRETIME",
    "LLEN",
    "LRANGE",
    "HLEN",
    "HSCAN",
    "ZCARD",
    "ZRANGE",
    "SCARD",
    "SMEMBERS",
    "GET",
}


class Refusal(Exception):
    """A fixed, non-sensitive reason code, never an exception from input data."""


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def bounded_text(value, maximum=512):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("unsupported identifier")
    return value


class Reader:
    def __init__(self, options):
        self.options = options
        self.client = redis.Redis(
            host="127.0.0.1",
            port=6379,
            username=options.get("username"),
            password=options.get("password"),
            single_connection_client=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry=Retry(NoBackoff(), 0),
            health_check_interval=0,
        )
        self.commands = 0
        self.bytes = 0
        self.records = 0
        self.observations = []

    def call(self, command, *args):
        if command not in READ_COMMANDS or (command == "CONFIG" and args[0] != "GET"):
            raise Refusal("non_read_command_refused")
        self.commands += 1
        return self.client.execute_command(command, *args)

    def budget(self, raw, *, record=False):
        if not isinstance(raw, bytes):
            raise Refusal("source_changed_or_wrong_type")
        if len(raw) > self.options["max_value_bytes"]:
            raise Refusal("value_byte_limit")
        self.bytes += len(raw)
        self.records += int(record)
        if self.bytes > self.options["max_total_bytes"]:
            raise Refusal("total_byte_limit")
        if self.records > self.options["max_records"]:
            raise Refusal("record_limit")
        return raw

    def snapshot(self, database_count):
        self.bytes = self.records = 0
        snapshot = {
            "keys": [],
            "messages": [],
            "results": [],
            "bindings": [],
            "issues": [],
            "databases": [],
            "reserved_index": [],
        }
        self.observations.append(snapshot)
        seen_keys = 0

        def issue(code, db, key, **details):
            snapshot["issues"].append(
                {
                    "code": code,
                    "db": db,
                    "key_b64": base64.b64encode(key).decode(),
                    **details,
                }
            )

        def envelope(raw, db, key, location, **position):
            self.budget(raw, record=True)
            try:
                obj = strict_json(raw)
                reserved_route = None
                if location == "reserved":
                    if not isinstance(obj, list) or len(obj) != 3:
                        raise ValueError("unsupported reserved envelope")
                    obj, exchange, route = obj
                    reserved_route = (exchange, route)
                if not isinstance(obj, dict):
                    raise TypeError("unsupported envelope")
                headers, props = obj["headers"], obj["properties"]
                task_id = bounded_text(headers["id"], 256)
                task = bounded_text(headers["task"])
                delivery_tag = bounded_text(props["delivery_tag"], 256)
                if (
                    location == "reserved"
                    and base64.b64encode(delivery_tag.encode()).decode()
                    != position["delivery_tag_b64"]
                ):
                    raise ValueError("inconsistent reservation tag")
                if (
                    obj["content-type"] != "application/json"
                    or obj["content-encoding"].lower() != "utf-8"
                    or props["body_encoding"] != "base64"
                    or props["correlation_id"] != task_id
                ):
                    raise ValueError("unsupported protocol")
                body = base64.b64decode(obj["body"], validate=True)
                priority = props.get("priority", 0)
                if type(priority) is not int or not 0 <= priority <= 9:
                    raise ValueError("unsupported priority")
                bucket = max(p for p in STEPS if p <= priority)
                delivery = props["delivery_info"]
                route = (delivery["exchange"], delivery["routing_key"])
                exchange, routing_key = route
                # The default exchange ('') routes directly to the named queue.
                if not (
                    (exchange == "" and routing_key in QUEUES)
                    or routing_key in EXCHANGES.get(exchange, set())
                ):
                    raise ValueError("unsupported routing")
                if reserved_route is not None and reserved_route != route:
                    raise ValueError("inconsistent reserved routing")
                if location == "queued" and PHYSICAL[key] != (routing_key, bucket):
                    raise ValueError("queue/priority mismatch")
                snapshot["messages"].append(
                    {
                        "db": db,
                        "key_b64": base64.b64encode(key).decode(),
                        "location": location,
                        "task_id": task_id,
                        "task": task,
                        "queue": routing_key,
                        "exchange": exchange,
                        "priority_bucket": bucket,
                        "envelope_sha256": digest(raw),
                        "body_sha256": digest(body),
                        # Deliberately conservative: header changes (ETA/retries etc.)
                        # are conflicts. Delivery tags/redelivered flags are not bodies.
                        "execution_sha256": digest(
                            canonical(
                                {
                                    "headers": headers,
                                    "body_sha256": digest(body),
                                    "exchange": exchange,
                                    "routing_key": routing_key,
                                    "priority": priority,
                                }
                            )
                        ),
                        **position,
                    }
                )
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
                issue(
                    "unsupported_or_malformed_envelope",
                    db,
                    key,
                    envelope_sha256=digest(raw),
                    **position,
                )

        for db in range(database_count):
            self.call("SELECT", db)
            count = self.call("DBSIZE")
            snapshot["databases"].append({"db": db, "keys": count})
            if seen_keys + count > self.options["max_keys"]:
                raise Refusal("key_limit")
            if db > 2 and count:
                issue("unsupported_database", db, b"")
            cursor, found, scans = 0, set(), 0
            while True:
                cursor, keys = self.call("SCAN", cursor, "COUNT", 100)
                found.update(keys)
                scans += 1
                if (
                    len(found) + seen_keys > self.options["max_keys"]
                    or scans > self.options["max_keys"] + 1
                ):
                    raise Refusal("key_or_scan_limit")
                if not cursor:
                    break
            if len(found) != count:
                raise Refusal("source_changed_during_scan")
            seen_keys += len(found)
            hash_tags, index_tags = set(), set()
            for key in sorted(found):
                self.budget(key)
                typ = self.call("TYPE", key)
                dumped = self.budget(self.call("DUMP", key))
                expiry = self.call("PEXPIRETIME", key)
                if expiry == -2:
                    raise Refusal("source_changed_during_scan")
                snapshot["keys"].append(
                    {
                        "db": db,
                        "key_b64": base64.b64encode(key).decode(),
                        "type": typ.decode("ascii"),
                        "dump_sha256": digest(dumped),
                        "dump_bytes": len(dumped),
                        "expires_at_ms": expiry,
                    }
                )
                if key in PHYSICAL and typ == b"list":
                    length = self.call("LLEN", key)
                    if self.records + length > self.options["max_records"]:
                        raise Refusal("record_limit")
                    for start in range(0, length, 100):
                        rows = self.call(
                            "LRANGE", key, start, min(start + 99, length - 1)
                        )
                        if len(rows) != min(100, length - start):
                            raise Refusal("source_changed_during_scan")
                        for offset, raw in enumerate(rows):
                            left = start + offset
                            envelope(
                                raw,
                                db,
                                key,
                                "queued",
                                list_index=left,
                                fifo_index=length - 1 - left,
                            )
                elif key == b"unacked" and typ == b"hash":
                    length = self.call("HLEN", key)
                    if self.records + length > self.options["max_records"]:
                        raise Refusal("record_limit")
                    cur, rounds = 0, 0
                    while True:
                        cur, entries = self.call("HSCAN", key, cur, "COUNT", 100)
                        rounds += 1
                        if rounds > self.options["max_records"] + 1:
                            raise Refusal("record_or_scan_limit")
                        for tag, raw in entries.items():
                            if tag in hash_tags:
                                continue
                            self.budget(tag)
                            hash_tags.add(tag)
                            envelope(
                                raw,
                                db,
                                key,
                                "reserved",
                                delivery_tag_b64=base64.b64encode(tag).decode(),
                            )
                        if not cur:
                            break
                    if len(hash_tags) != length:
                        raise Refusal("source_changed_during_scan")
                elif key == b"unacked_index" and typ == b"zset":
                    length = self.call("ZCARD", key)
                    if self.records + length > self.options["max_records"]:
                        raise Refusal("record_limit")
                    for start in range(0, length, 100):
                        # Use the redis-py parser's WITHSCORES option explicitly.
                        rows = self.client.zrange(
                            key, start, min(start + 99, length - 1), withscores=True
                        )
                        self.commands += 1
                        if len(rows) != min(100, length - start):
                            raise Refusal("source_changed_during_scan")
                        for tag, score in rows:
                            self.budget(tag, record=True)
                            if not math.isfinite(score) or score < 0:
                                issue("invalid_reserved_timestamp", db, key)
                            index_tags.add(tag)
                            snapshot["reserved_index"].append(
                                {
                                    "db": db,
                                    "delivery_tag_b64": base64.b64encode(tag).decode(),
                                    "timestamp": score
                                    if math.isfinite(score)
                                    else None,
                                }
                            )
                elif key.startswith(b"_kombu.binding.") and typ == b"set":
                    length = self.call("SCARD", key)
                    if self.records + length > self.options["max_records"]:
                        raise Refusal("record_limit")
                    rows = self.call("SMEMBERS", key)
                    if len(rows) != length:
                        raise Refusal("source_changed_during_scan")
                    exchange = key[len(b"_kombu.binding.") :].decode(
                        "utf-8", errors="replace"
                    )
                    for raw in sorted(rows):
                        self.budget(raw, record=True)
                        parts = raw.decode("utf-8", errors="replace").split(SEP)
                        valid = (
                            len(parts) == 3
                            and parts[1] == ""
                            and parts[0] == parts[2]
                            and parts[2] in EXCHANGES.get(exchange, set())
                        )
                        snapshot["bindings"].append(
                            {
                                "db": db,
                                "exchange": exchange,
                                "member_b64": base64.b64encode(raw).decode(),
                                "supported": valid,
                            }
                        )
                        if not valid:
                            issue("unsupported_binding", db, key)
                elif key.startswith(b"celery-task-meta-") and typ == b"string":
                    raw = self.budget(self.call("GET", key), record=True)
                    try:
                        obj = strict_json(raw)
                        task_id = bounded_text(
                            key[len(b"celery-task-meta-") :].decode(), 256
                        )
                        if obj["task_id"] != task_id or obj["status"] not in STATES:
                            raise ValueError("unsupported result")
                        snapshot["results"].append(
                            {
                                "db": db,
                                "task_id": task_id,
                                "status": obj["status"],
                                "expires_at_ms": expiry,
                                "metadata_sha256": digest(raw),
                            }
                        )
                    except (ValueError, KeyError, TypeError, RecursionError):
                        issue("unsupported_or_malformed_result", db, key)
                else:
                    issue("unsupported_key_or_type", db, key)
            for tag in sorted(hash_tags - index_tags):
                issue(
                    "reserved_hash_without_index",
                    db,
                    b"unacked",
                    delivery_tag_b64=base64.b64encode(tag).decode(),
                )
            for tag in sorted(index_tags - hash_tags):
                issue(
                    "reserved_index_without_hash",
                    db,
                    b"unacked_index",
                    delivery_tag_b64=base64.b64encode(tag).decode(),
                )
        snapshot["bytes_examined"] = self.bytes
        snapshot["records_examined"] = self.records
        return snapshot


def reconcile(snapshot):
    messages, results = defaultdict(list), defaultdict(list)
    for item in snapshot["messages"]:
        messages[item["task_id"]].append(item)
    for item in snapshot["results"]:
        results[item["task_id"]].append(item)
    reviews = []
    for task_id in sorted(messages.keys() | results.keys()):
        jobs, outcomes = messages[task_id], results[task_id]
        reasons = []
        if len(jobs) > 1:
            reasons.append("duplicate_task_id")
        if len({j["db"] for j in jobs}) > 1:
            reasons.append("cross_database_duplicate")
        if len({j["execution_sha256"] for j in jobs}) > 1:
            reasons.append("conflicting_execution_payload")
        if {j["location"] for j in jobs} == {"queued", "reserved"}:
            reasons.append("queued_reserved_overlap")
        if len({r["metadata_sha256"] for r in outcomes}) > 1:
            reasons.append("conflicting_result_metadata")
        if jobs:
            reasons.append(
                "terminal_result_present"
                if any(r["status"] in TERMINAL for r in outcomes)
                else "completion_unknown"
            )
            reasons.append("manual_replay_decision_required")
        if reasons:
            reviews.append(
                {
                    "task_id": task_id,
                    "reasons": reasons,
                    "message_copies": len(jobs),
                    "result_copies": len(outcomes),
                }
            )
    return reviews


def run(options):
    result = {
        "receipt": {
            "schema_version": 1,
            "inventory_complete": False,
            "source_unchanged": False,
            "replay_authorized": False,
            "cutover_qualified": False,
            "failure_code": None,
        },
        "private": {},
    }
    reader = None
    try:
        reader = Reader(options)
        reader.call("PING")  # Complete connection/handshake before accounting.
        before = reader.call("INFO")
        initial_commands = reader.commands
        result["private"]["source_before"] = {
            k: before.get(k)
            for k in (
                "run_id",
                "redis_version",
                "valkey_version",
                "role",
                "master_replid",
                "master_replid2",
                "master_repl_offset",
                "second_repl_offset",
                "slave_repl_offset",
                "master_link_status",
                "connected_clients",
            )
        }
        if before.get("connected_clients") != 1 or before.get("cluster_enabled") != 0:
            raise Refusal("source_has_clients_or_cluster")
        config = reader.call("CONFIG", "GET", "databases", "save", "appendonly")
        if isinstance(config, list):
            config = dict(zip(config[::2], config[1::2]))
        # CONFIG returns byte pairs with execute_command, depending on client version.
        config = {
            k.decode() if isinstance(k, bytes) else k: v.decode()
            if isinstance(v, bytes)
            else v
            for k, v in config.items()
        }
        if config.get("appendonly") != "no" or config.get("save") != "":
            raise Refusal("source_persistence_enabled")
        databases = int(config["databases"])
        if not 3 <= databases <= 64:
            raise Refusal("unsupported_database_count")
        first = reader.snapshot(databases)
        second = reader.snapshot(databases)
        after = reader.call("INFO")
        counters = (
            "run_id",
            "role",
            "master_replid",
            "master_replid2",
            "master_repl_offset",
            "slave_repl_offset",
            "rdb_changes_since_last_save",
            "expired_keys",
            "evicted_keys",
            "total_connections_received",
        )
        unchanged = (
            first["keys"] == second["keys"]
            and all(before.get(k) == after.get(k) for k in counters)
            and after.get("connected_clients") == 1
            and after["total_commands_processed"] - before["total_commands_processed"]
            == reader.commands - initial_commands
        )
        result["private"]["consistency"] = {
            "expected_commands": reader.commands - initial_commands,
            "observed_commands": after["total_commands_processed"]
            - before["total_commands_processed"],
            "changed_counters": [k for k in counters if before.get(k) != after.get(k)],
        }
        if not unchanged:
            raise Refusal("source_changed_during_inventory")
        reviews = reconcile(second)
        result["private"]["inventory"] = second
        result["private"]["reconciliation"] = reviews
        result["receipt"].update(
            {
                "inventory_complete": not second["issues"],
                "source_unchanged": True,
                "databases_examined": databases,
                "keys": len(second["keys"]),
                "messages": len(second["messages"]),
                "queued": sum(m["location"] == "queued" for m in second["messages"]),
                "reserved": sum(
                    m["location"] == "reserved" for m in second["messages"]
                ),
                "results": len(second["results"]),
                "issue_counts": dict(
                    sorted(Counter(i["code"] for i in second["issues"]).items())
                ),
                "review_counts": dict(
                    sorted(
                        Counter(
                            reason for r in reviews for reason in r["reasons"]
                        ).items()
                    )
                ),
                "disposition": "quarantine_pending_operator_review",
                "dataset_sha256": digest(canonical(second["keys"])),
            }
        )
        if second["issues"]:
            result["receipt"]["failure_code"] = "unsupported_or_inconsistent_records"
    except Refusal as exc:
        result["receipt"]["failure_code"] = str(exc)
    except (
        redis.RedisError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
    ):
        # Redis/JSON exceptions can echo a credential, task body or key. Never relay.
        result["receipt"]["failure_code"] = "probe_failed"
    finally:
        if reader is not None:
            result["private"]["partial_snapshots"] = (
                reader.observations
                if not result["receipt"]["inventory_complete"]
                else []
            )
            reader.client.close()
    return result


if __name__ == "__main__":
    print(
        json.dumps(run(globals()["OPTIONS"]), sort_keys=True, allow_nan=False)
    )  # supplied via private stdin
