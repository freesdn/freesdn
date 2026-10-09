# SPDX-License-Identifier: AGPL-3.0-only
"""The opt-in origin must reach API, beat and both worker pools consistently."""

from pathlib import Path

import yaml


def test_report_origin_is_shared_by_all_backend_services():
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    services = compose["services"]
    relevant = [s for s in services.values() if s.get("image", "").startswith("${BACKEND_IMAGE")]
    assert len(relevant) >= 4
    for service in relevant:
        assert service["environment"]["FRONTEND_URL"] == "${FRONTEND_URL:-}"
        assert (
            service["environment"]["SLA_REPORT_DELIVERY_EPOCH"] == "${SLA_REPORT_DELIVERY_EPOCH:-}"
        )
    for preset in ("", ".lite", ".pro", ".max", ".dev"):
        lines = (root / f".env{preset}.example").read_text().splitlines()
        assert [line for line in lines if line.startswith("FRONTEND_URL=")] == ["FRONTEND_URL="]
        assert [line for line in lines if line.startswith("SLA_REPORT_DELIVERY_EPOCH=")] == [
            "SLA_REPORT_DELIVERY_EPOCH="
        ]
