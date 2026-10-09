"""Resolve the checkout under test without external qualification configuration."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def local_checker_source(monkeypatch):
    scripts = Path(__file__).resolve().parents[2]
    checker = scripts / "check_database_runtime.py"
    assert checker.is_file()
    monkeypatch.setenv("FREESDN_CHECKER_SOURCE", str(checker))
    monkeypatch.syspath_prepend(str(scripts))
    # Wrapper children must import from this same checkout. Restore any caller
    # environment after each test; never choose a source from inherited input.
    monkeypatch.setenv(
        "PYTHONPATH", os.pathsep.join((str(scripts), str(scripts / "qualification")))
    )
