# SPDX-License-Identifier: AGPL-3.0-only
"""Maintenance receipts must stay resumable and never expose database parameters."""

import argparse
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from scripts import encrypt_vpn_site_configs as command


@pytest.fixture
def runner(monkeypatch):
    @asynccontextmanager
    async def transaction():
        yield

    @asynccontextmanager
    async def factory():
        yield SimpleNamespace(begin=transaction)

    monkeypatch.setattr(command, "async_session_factory", factory)
    return argparse.Namespace(apply=False, after_id=None, batch_size=1, max_batches=2)


async def test_audit_is_readonly_and_reports_plaintext_without_echoing_it(runner, monkeypatch, capsys):
    helper = AsyncMock(return_value={"examined": 1, "plaintext": 1, "already_encrypted": 0,
                                    "updated": 0, "last_id": str(uuid4())})
    runner.batch_size = 2
    monkeypatch.setattr(command, "encrypt_legacy_profile_batch", helper)
    assert await command.run(runner) == 0
    assert helper.await_args.kwargs["apply"] is False
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "audit" and report["plaintext"] == 1
    assert report["updated"] == 0 and report["complete"] is True


async def test_failure_reports_only_committed_progress_without_secret_parameters(runner, monkeypatch, capsys):
    cursor = str(uuid4())
    secret = "synthetic-profile-content-that-must-not-be-logged"
    helper = AsyncMock(side_effect=[
        {"examined": 1, "plaintext": 1, "already_encrypted": 0, "updated": 1, "last_id": cursor},
        SQLAlchemyError("parameters: " + secret),
    ])
    runner.apply = True
    monkeypatch.setattr(command, "encrypt_legacy_profile_batch", helper)
    assert await command.run(runner) == 1
    output = capsys.readouterr().out
    assert secret not in output
    report = json.loads(output)
    assert report["last_id"] == cursor and report["updated"] == 1
    assert report["batches"] == 1 and report["complete"] is False
    assert report["error_type"] == "SQLAlchemyError"


async def test_batch_limit_requires_resume_instead_of_claiming_completion(runner, monkeypatch, capsys):
    cursor = str(uuid4())
    runner.max_batches = 1
    helper = AsyncMock(return_value={"examined": 1, "plaintext": 0, "already_encrypted": 1,
                                    "updated": 0, "last_id": cursor})
    monkeypatch.setattr(command, "encrypt_legacy_profile_batch", helper)
    assert await command.run(runner) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["last_id"] == cursor and report["complete"] is False
