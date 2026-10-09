"""Native controlled creation/ownership/cleanup/report behavior after work refusal."""

import json

import pytest


@pytest.mark.parametrize(
    "mode",
    [
        "volume-lost-ack",
        "container-lost-ack",
        "wrong-label",
        "wrong-name",
        "wrong-id",
        "remove-failure",
        "log-error",
        "oversized-logs",
    ],
)
def test_owned_resource_reconciliation_keeps_failure_and_identity(native_case, mode):
    result = native_case(mode)
    state = result["report"]
    calls = result["calls"]
    catalogue = result["catalogue"]
    assert result["snapshot"]["exit"] != 0 and state is not None
    assert (
        not state["passed"]
        and not state["qualification_complete"]
        and not state["checks_completed"]
    )
    assert result["snapshot"]["live_native_cli_before_fixture_cleanup"] == []
    plans = [
        json.loads(p.read_bytes())
        for p in sorted((result["artifact_path"] / "events").glob("*-plan.json"))
    ]
    assert plans and plans[0]["resource"]["kind"] == "volume"
    created = [r for r in calls if r["kind"] == "container-create"]
    if mode == "volume-lost-ack":
        assert not created
    else:
        assert len(created) == 1
        args = created[0]["argv_without_password"]
        for option, value in (
            ("--network", "none"),
            ("--pull", "never"),
            ("--restart", "no"),
            ("--memory", "768m"),
            ("--memory-swap", "768m"),
            ("--cpus", "2"),
            ("--pids-limit", "128"),
            ("--log-driver", "local"),
        ):
            assert args[args.index(option) + 1] == value
        assert "-p" not in args and "--publish" not in args
        assert any(
            r["resource"]["kind"] == "container"
            and r["resource"]["planned_name"] == created[0]["name"]
            for r in plans
        )
    refused = mode in {"wrong-label", "wrong-name", "wrong-id", "remove-failure"}
    removals = [r for r in calls if r["kind"] == "container-remove"]
    if mode in {"wrong-label", "wrong-name", "wrong-id"}:
        assert removals == []
    elif created:
        assert len(removals) == 1 and removals[0]["target"] == created[0]["identity"]
    assert bool(catalogue["container"]) is refused
    assert bool(catalogue["volume"]) is refused
    assert state["owned_resources_removed"] is (not refused)
    assert (result["artifact_path"] / "outcome.json").read_bytes() == (
        result["artifact_path"].parent / "report.json"
    ).read_bytes()
    if created and mode not in {
        "wrong-label",
        "wrong-name",
        "wrong-id",
        "log-error",
        "oversized-logs",
    }:
        assert len(state["private_logs"]) == 1
        content = (result["artifact_path"] / state["private_logs"][0]["path"]).read_bytes()
        assert catalogue["password"].encode() not in content and b"[REDACTED]" in content
