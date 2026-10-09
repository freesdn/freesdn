# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse any pressure target that could escape the disposable tmpfs fixture."""

import argparse
import importlib.util
import sys
from copy import deepcopy
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "postgres_pressure",
    Path(__file__).parents[1] / "check_postgres_pressure.py",
)
pressure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pressure)


def volume():
    return {
        "Name": "owned-data",
        "Driver": "local",
        "Options": {"type": "tmpfs", "device": "tmpfs", "o": "size=512m,mode=1777"},
        "Labels": {"freesdn.qualification": "owned"},
    }


def container():
    return {
        "Config": {"Labels": {"freesdn.qualification": "owned"}},
        "HostConfig": {"NetworkMode": "none", "PortBindings": {}},
        "Mounts": [
            {
                "Type": "volume",
                "Name": "owned-data",
                "Destination": pressure.MOUNT,
                "RW": True,
            }
        ],
    }


@pytest.mark.parametrize(
    "value", ["0", "-1", "511", "1025", "65536", "1.5", "unbounded"]
)
def test_refuses_unbounded_or_invalid_sizes(value):
    with pytest.raises(argparse.ArgumentTypeError):
        pressure.bounded_size(value)


@pytest.mark.parametrize("value", ["512", "1024"])
def test_accepts_documented_bounds(value):
    assert pressure.bounded_size(value) == int(value)


@pytest.mark.parametrize(
    "change",
    [
        {"Name": "customer-data"},
        {"Driver": "nfs"},
        {"Labels": {}},
        {"Labels": {"freesdn.qualification": "someone-else"}},
        {"Options": {"type": "none", "device": "/var/lib/postgresql", "o": "bind"}},
        {"Options": {"type": "tmpfs", "device": "tmpfs", "o": "size=8g,mode=1777"}},
    ],
)
def test_refuses_foreign_or_unbounded_volume(change):
    info = volume()
    info.update(change)
    with pytest.raises(RuntimeError):
        pressure.validate_volume(info, "owned-data", "owned", 512)


def test_requires_both_owned_metadata_and_actual_bounded_mount():
    pressure.validate_volume(volume(), "owned-data", "owned", 512)
    pressure.validate_container(container(), "owned-data", "owned")
    assert (
        pressure.validate_filesystem(
            "tmpfs /var/lib/postgresql tmpfs rw,size=524288k 0 0",
            "4096 131072 1",
            512,
        )
        == 4096
    )


@pytest.mark.parametrize(
    "kind", ["foreign", "bind", "wrong_path", "readonly", "extra", "network", "ports"]
)
def test_refuses_unexpected_container_mounts_or_exposure(kind):
    info = deepcopy(container())
    if kind == "foreign":
        info["Mounts"][0]["Name"] = "customer-data"
    elif kind == "bind":
        info["Mounts"][0]["Type"] = "bind"
    elif kind == "wrong_path":
        info["Mounts"][0]["Destination"] = "/customer"
    elif kind == "readonly":
        info["Mounts"][0]["RW"] = False
    elif kind == "extra":
        info["Mounts"].append({"Type": "volume", "Name": "customer-data"})
    elif kind == "network":
        info["HostConfig"]["NetworkMode"] = "host"
    else:
        info["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostPort": "5432"}]}
    with pytest.raises(RuntimeError):
        pressure.validate_container(info, "owned-data", "owned")


@pytest.mark.parametrize(
    "mounts,stats",
    [
        ("/dev/sda /var/lib/postgresql ext4 rw 0 0", "4096 131072 0"),
        ("tmpfs /var/lib/postgresql tmpfs ro 0 0", "4096 131072 0"),
        ("tmpfs /somewhere-else tmpfs rw 0 0", "4096 131072 0"),
        ("tmpfs /var/lib/postgresql tmpfs rw 0 0", "4096 262144 0"),
        ("tmpfs /var/lib/postgresql tmpfs rw 0 0", "4096 131072 -1"),
        ("tmpfs /var/lib/postgresql tmpfs rw 0 0", "4096 131072 131073"),
        ("tmpfs /var/lib/postgresql tmpfs rw 0 0", "unknown"),
    ],
)
def test_refuses_actual_filesystem_mismatch(mounts, stats):
    with pytest.raises(RuntimeError):
        pressure.validate_filesystem(mounts, stats, 512)


@pytest.mark.parametrize("symlink", [False, True])
def test_existing_work_cannot_be_overwritten_or_trigger_docker(
    tmp_path, monkeypatch, symlink
):
    target = tmp_path / "protected"
    target.mkdir()
    marker = target / "retained"
    marker.write_text("keep")
    work = target
    if symlink:
        work = tmp_path / "link"
        work.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(
        sys, "argv", ["pressure", "--postgres", "unused", "--work-dir", str(work)]
    )

    def refused(*args, **kwargs):
        raise AssertionError("Docker must not be called")

    monkeypatch.setattr(pressure.subprocess, "run", refused)
    with pytest.raises(SystemExit) as exc:
        pressure.main()
    assert exc.value.code == 2 and marker.read_text() == "keep"
