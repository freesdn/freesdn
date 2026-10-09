"""An empty selection must not hide a malformed required target field."""

import pytest

from tests.adapters import test_opnsense_plugin_read_contracts as helpers

wire = helpers.wire


@pytest.mark.parametrize("targets", [None, {}, [], True, 23])
async def test_empty_interface_selection_still_validates_required_targets(wire, targets):
    _, state = wire
    helpers.configure(state, "netflow")
    capture = state["wire"]["/api/diagnostics/netflow/getconfig"]["netflow"]["capture"]
    capture["interfaces"] = {}
    capture["targets"] = targets
    result = await helpers.call(wire, "netflow")
    assert result.success is False and result.data is None
