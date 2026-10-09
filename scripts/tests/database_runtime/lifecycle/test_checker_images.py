"""Native image-admission refusal controls, with no daemon or SQL fixture."""

import pytest


@pytest.mark.parametrize(
    "mode",
    [
        "image-os",
        "image-arch",
        "image-id",
        "image-alias",
        "image-missing",
        "image-json",
        "image-oversize",
        "image-many",
    ],
)
def test_invalid_image_identity_refuses_before_resource_intent(native_case, mode):
    result = native_case(mode)
    state = result["report"]
    assert result["snapshot"]["exit"] != 0 and state is not None
    assert not state["passed"] and not state["qualification_complete"]
    assert result["calls"] and all(row["kind"] == "image" for row in result["calls"])
    assert result["catalogue"] is None
    assert not list((result["artifact_path"] / "events").glob("*-plan.json"))
    assert result["snapshot"]["live_native_cli_before_fixture_cleanup"] == []
