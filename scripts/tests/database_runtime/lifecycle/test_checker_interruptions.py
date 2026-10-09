"""Real monotonic deadline and OS-signal boundaries in the checker process."""

import signal

import pytest


def complete_failed(result):
    assert result["snapshot"]["exit"] != 0
    assert result["report"] is not None
    assert not result["report"]["passed"] and not result["report"]["qualification_complete"]
    assert result["snapshot"]["live_native_cli_before_fixture_cleanup"] == []
    catalogue = result["catalogue"]
    assert catalogue is None or catalogue["container"] is None and catalogue["volume"] is None


@pytest.mark.parametrize("mode", ["image-stall", "volume-stall", "container-stall"])
def test_native_work_deadline_preserves_outcome_and_reconciles_plans(native_case, mode):
    result = native_case(mode, work_seconds=1)
    assert any(c["kind"] == "waiting" for c in result["calls"])
    complete_failed(result)
    assert result["snapshot"]["elapsed_seconds"] < 3.5


@pytest.mark.parametrize(
    "mode", ["image-stall", "volume-stall", "container-stall", "cleanup-stall"]
)
def test_sigterm_retains_a_failed_outcome_and_no_live_native_cli(native_case, mode):
    result = native_case(mode, interrupt=signal.SIGTERM)
    assert any(c["kind"] == "waiting" for c in result["calls"])
    assert result["snapshot"]["exit"] != 0
    assert result["report"] is not None
    assert not result["report"]["passed"] and not result["report"]["qualification_complete"]
    assert result["snapshot"]["live_native_cli_before_fixture_cleanup"] == []
    if mode != "cleanup-stall":
        assert (
            result["catalogue"] is None
            or result["catalogue"]["container"] is None
            and result["catalogue"]["volume"] is None
        )
    else:
        assert not result["report"]["owned_resources_removed"]


@pytest.mark.parametrize("mode", ["volume-stall", "container-stall"])
def test_sigint_control_retains_a_failed_outcome_and_reconciles(native_case, mode):
    complete_failed(native_case(mode, interrupt=signal.SIGINT))
