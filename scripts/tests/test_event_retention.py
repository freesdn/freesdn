"""Reject unsafe qualification work directories before any Docker operation."""

import importlib.util
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "kind", ["relative", "existing", "file", "symlink", "dangling"]
)
def test_unsafe_work_directory_never_reaches_docker(monkeypatch, tmp_path, kind):
    spec = importlib.util.spec_from_file_location(
        "event_retention_check", Path(__file__).parents[1] / "check_event_retention.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    work = tmp_path / "work"
    if kind == "relative":
        work = Path("relative-fixture")
    elif kind == "existing":
        work.mkdir()
    elif kind == "file":
        work.write_text("existing data")
    else:
        target = tmp_path / "target"
        if kind == "symlink":
            target.mkdir()
        work.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_event_retention",
            "--backend",
            "fixture",
            "--logdb",
            "fixture",
            "--work-dir",
            str(work),
        ],
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Docker was invoked for an unsafe work directory")

    monkeypatch.setattr(module.subprocess, "run", forbidden)
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2
    if kind == "file":
        assert work.read_text() == "existing data"
