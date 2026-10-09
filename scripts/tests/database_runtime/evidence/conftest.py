"""Load the immutable candidate; keep OS/clock injection local to that module."""

import importlib.util
import os
from pathlib import Path

import pytest


@pytest.fixture
def evidence():
    path = Path(os.environ["FREESDN_CHECKER_SOURCE"]).parent / "qualification/fixture_evidence.py"
    spec = importlib.util.spec_from_file_location("owned_evidence_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def attempt(evidence, tmp_path):
    instance = evidence.FixtureAttempt(tmp_path / "result.json", work_seconds=30)
    try:
        yield instance
    finally:
        instance.close()


class OSProxy:
    def __init__(self, **overrides):
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides.get(name, getattr(os, name))


@pytest.fixture
def replace_os(evidence, monkeypatch):
    def install(**overrides):
        monkeypatch.setattr(evidence, "os", OSProxy(**overrides))

    return install
