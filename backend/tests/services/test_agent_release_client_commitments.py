# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Same frozen wire documents consumed by the planned browser codec suite."""

import json
from pathlib import Path

import pytest

from app.schemas.agent_release_operations import decode_release_command


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5, 6, 7])
def test_browser_commitment_vector_matches_real_service_codec(index):
    path = Path(__file__).resolve().parents[3] / "frontend/src/lib/api/__tests__/releaseCommitmentVectors.json"
    vector = json.loads(path.read_text())[index]
    command = decode_release_command(vector["raw"].encode("utf-8"))
    assert command.request_sha256() == vector["intent_sha256"]
