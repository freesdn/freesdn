# SPDX-License-Identifier: AGPL-3.0-only
"""Reconcile disposable qualification resources inside a trusted engine.

A lost CLI acknowledgement is not proof that creation failed. Inspect planned
names with this fixture's random ownership label; once known, retain immutable
container/network IDs. Volumes have names, not immutable IDs. These checks do
not protect against a privileged engine administrator concurrently replacing a
volume or forging labels. Failed inspection is uncertainty, never absence.
"""
import json
import re


def plan_resource(resources, kind, name, owner):
    """Register intent before issuing the command that may create a resource."""
    if kind not in {"container", "network", "volume"}:
        raise ValueError("Unsupported qualification resource kind")
    if any(row["kind"] == kind and row["planned_name"] == name for row in resources):
        raise ValueError("Qualification resource was already planned")
    resource = {"kind": kind, "planned_name": name, "owner": owner, "identity": None}
    resources.append(resource)
    return resource


def remember_identity(resource, output):
    """Only detached create/run and network-create commands return an ID."""
    identity = output.decode("ascii").strip()
    if resource["kind"] == "volume" or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise RuntimeError("Invalid created qualification resource identity")
    resource["identity"] = identity
    return identity


def inspect_owned(resource, command):
    kind = resource["kind"]
    target = resource["identity"] or resource["planned_name"]
    args = ("inspect", "--type=container", target) if kind == "container" else (kind, "inspect", target)
    raw = command(*args).stdout
    if len(raw) > 65536:
        raise RuntimeError("Owned resource inspection exceeds its parse budget")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("Ambiguous owned resource inspection")
    row = rows[0]
    config = row.get("Config")
    labels = config.get("Labels") if kind == "container" and isinstance(config, dict) else row.get("Labels") if kind != "container" else None
    if not isinstance(labels, dict) or labels.get("freesdn.qualification") != resource["owner"]:
        raise RuntimeError("Refusing resource without this fixture ownership label")
    name = row.get("Name")
    if kind == "container" and isinstance(name, str):
        name = name.removeprefix("/")
    if name != resource["planned_name"]:
        raise RuntimeError("Owned resource name differs from the planned name")
    identity = name if kind == "volume" else row.get("Id")
    if kind != "volume" and (not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None):
        raise RuntimeError("Invalid inspected qualification resource identity")
    if resource["identity"] is not None and identity != resource["identity"]:
        raise RuntimeError("Qualification resource identity changed")
    resource["identity"] = identity
    return row


def cleanup_resources(resources, command, failures, *, anonymous_volumes=False):
    """Attempt every planned resource independently, retaining original errors."""
    cleanup = []
    # Containers must be considered before any volumes or networks they use.
    for kind in ("container", "volume", "network"):
        for resource in reversed(resources):
            if resource["kind"] != kind:
                continue
            entry = {"kind": kind, "planned_name": resource["planned_name"], "removed": False}
            try:
                inspect_owned(resource, command)
                identity = resource["identity"]
                entry["inspected_identity"] = identity
                if kind == "container":
                    args = ("rm", "-f", "-v", identity) if anonymous_volumes else ("rm", "-f", identity)
                else:
                    args = (kind, "rm", identity)
                if command(*args, check=False).returncode:
                    raise RuntimeError("Owned qualification resource removal failed")
                entry["removed"] = True
            except BaseException as error:
                failures.append(error)
                entry["error_type"] = type(error).__name__
            cleanup.append(entry)
    return cleanup
