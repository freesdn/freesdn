"""A bounded inventory must not present contradictory coverage metadata."""

import pytest

from app.adapters.base import AdapterResult
from app.modules.firewall.gateway_live_reads import aggregate_payload


def payload(total=75):
    count = min(total, 50)
    return {
        "crowdsec": {
            "running": True,
            "alerts": [{"id": i} for i in range(count)],
            "decisions": [],
            "alert_count": count,
            "decision_count": 0,
            "alert_total": total,
            "decision_total": 0,
            "alert_truncated": total > count,
            "decision_truncated": False,
        }
    }


@pytest.mark.parametrize("total", [0, 1, 50, 75])
def test_valid_bounded_inventory_preserves_totals(total):
    body = payload(total)
    assert aggregate_payload(AdapterResult.ok(body), "crowdsec", vendor="opnsense") == body


@pytest.mark.parametrize("prefix", ["alert", "decision"])
@pytest.mark.parametrize(
    "total,truncated",
    [
        (-1, False),
        (1.5, False),
        ("75", True),
        (float("inf"), True),
        (49, False),
        (75, False),
        (75, "true"),
        (None, True),
    ],
)
def test_invalid_bounded_inventory_is_not_success(prefix, total, truncated):
    body = payload()
    body["crowdsec"][prefix + "_total"] = total
    body["crowdsec"][prefix + "_truncated"] = truncated
    with pytest.raises(ValueError):
        aggregate_payload(AdapterResult.ok(body), "crowdsec", vendor="opnsense")


def test_legacy_normalized_adapter_without_window_metadata_is_preserved():
    body = {
        "crowdsec": {
            "running": True,
            "alerts": [],
            "decisions": [],
            "alert_count": 0,
            "decision_count": 0,
        }
    }
    assert aggregate_payload(AdapterResult.ok(body), "crowdsec", vendor="opnsense") == body
