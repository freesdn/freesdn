# SPDX-License-Identifier: AGPL-3.0-only
"""Run plugin filesystem contracts with the shipped bytecode-write policy."""

import sys

import pytest


@pytest.fixture(autouse=True)
def packaged_bytecode_policy(monkeypatch):
    # The production image sets PYTHONDONTWRITEBYTECODE=1. Keep exact archive
    # and rollback comparisons (including unexpected files) without introducing
    # interpreter cache writes that the shipped runtime does not perform.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
