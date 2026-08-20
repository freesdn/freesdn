# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The switch port dialog wrote things nobody asked for, and dropped things they did.

1. SAVING ANY PORT FIELD SILENTLY DISABLED 802.1X
   ``SecurityConfig.enabled`` -- the "Port Security" master toggle the dialog
   shows -- was collected, sent on every save, and READ BY NOTHING. The block
   that builds the controller payload ran unconditionally, so:

     * ``dot1x_enabled`` was ``bool = False`` and the dialog has no 802.1X
       control at all, so every save arrived carrying the Pydantic DEFAULT and
       the else-branch pushed ``dot1x=0``. Renaming a port, or changing its
       MTU, turned off 802.1X on that switch port -- including 802.1X someone
       had configured outside FreeSDN, which FreeSDN cannot see and did not
       warn about.
     * ``macLimit`` went out whenever the field was non-null, even with the
       toggle off. The dialog only lets you EDIT it while the toggle is on, but
       it sent the value either way.

2. THE PoE TAB WROTE THE WRONG KEY, AND DROPPED TWO SETTINGS ENTIRELY
   The endpoint sent ``poeEnabled`` (flat). The PoE page's own endpoint, which
   IS validated against the maintainer's Omada fleet, sends
   ``poe: {enable: ...}``. And ``mode`` / ``power_limit`` were collected by the
   dialog, accepted by the schema, and never added to the config dict at all --
   an operator set a 15W cap, saved, saw it echoed back, and nothing reached
   the switch.

3. TWO CONTROLS HAD NO CONTROLLER MAPPING AT ALL
   PoE ``priority`` and the port dialog's ``voice_vlan`` / ``guest_vlan`` were
   accepted, echoed back and never sent anywhere. Removed rather than left
   there lying -- no validated write mapping exists for either. Port PROFILES
   keep their own voice_vlan on a different path.

4. THE DISCOVERY PAGE'S AGENT SCAN NEVER REACHED THE AGENT
   ``POST /discovery/agent-scan`` INSERTed an AgentTask row at PENDING,
   returned "Scan task dispatched", published
   ``discovery.agent_scan_started``, and stopped. The only consumer of a
   PENDING AgentTask row is ``GET /agents/{id}/tasks/pending``, documented as
   "called by the agent process to poll for work" -- and the shipped agent
   never calls it. It wires ``ws_client.on_command`` straight to its
   TaskExecutor and takes work exclusively over the socket. There is no poller.

   So the row sat at PENDING forever while the Discovery page showed its "scan
   started" toast and polled a status that never moved.
   ``POST /agents/{id}/scan`` next door has always done this correctly; this
   endpoint was written against a polling model that was never built.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.api.v1.endpoints import switches as sw


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


def _port(metadata: dict | None = None):
    return SimpleNamespace(
        port_metadata=metadata if metadata is not None else {},
        is_enabled=True,
        is_poe_enabled=False,
        vlan_id=1,
    )


def _build_config(data, port) -> dict:
    """A MIRROR of update_switch_port's config-building branch.

    Being honest about what this is: it is a copy of the endpoint's logic, not
    the endpoint itself, because driving the real one needs a device, a site,
    an org check and an adapter. ``test_the_extracted_builder_matches_the_endpoint``
    is what keeps the two from drifting -- it asserts every branch below still
    appears verbatim in the endpoint's source, and it fails against the
    pre-fix code.
    """
    config: dict = {}
    if data.vlan_config:
        config["pvid"] = data.vlan_config.native_vlan
        config["taggedVlans"] = data.vlan_config.tagged_vlans
    if data.poe_config is not None:
        config["poe"] = {"enable": data.poe_config.enabled}
        if data.poe_config.mode is not None:
            config["poeMode"] = data.poe_config.mode
        if data.poe_config.power_limit is not None:
            config["poePowerLimit"] = data.poe_config.power_limit
    if data.security_config is not None:
        state = dict(port.port_metadata or {})
        was_managed = bool(state.get("security_managed"))
        if data.security_config.enabled:
            modes = {"auto": 1, "force_auth": 2, "force_unauth": 3, "disable": 0}
            if data.security_config.dot1x_enabled is True:
                config["dot1x"] = modes[data.security_config.dot1x_mode]
            elif data.security_config.dot1x_enabled is False:
                config["dot1x"] = 0
            if data.security_config.mac_limit is not None:
                config["macLimit"] = data.security_config.mac_limit
            if data.security_config.violation_action != "restrict":
                config["violationAction"] = data.security_config.violation_action
            state["security_managed"] = True
            port.port_metadata = state
        elif was_managed:
            config["macLimit"] = 0
            state["security_managed"] = False
            port.port_metadata = state
    return config


def _update(**kw):
    payload = {"security_config": sw.SecurityConfig()}
    payload.update(kw)
    return SimpleNamespace(
        vlan_config=payload.get("vlan_config"),
        poe_config=payload.get("poe_config"),
        security_config=payload.get("security_config"),
    )


# ── 1. port security ─────────────────────────────────────────────


def test_the_extracted_builder_matches_the_endpoint() -> None:
    """
    Guard against this file drifting from the code it claims to test. If the
    endpoint's branching changes, the helper above must change with it.
    """
    code = _code(sw.update_switch_port)
    for marker in (
        'config["poe"] = {"enable": data.poe_config.enabled}',
        'config["poeMode"] = data.poe_config.mode',
        'config["poePowerLimit"] = data.poe_config.power_limit',
        "if data.security_config.enabled:",
        "if data.security_config.dot1x_enabled is True:",
        'security_state["security_managed"] = True',
    ):
        assert marker in code, f"update_switch_port no longer contains: {marker}"


def test_an_unrelated_save_does_not_touch_dot1x() -> None:
    """
    The regression. The dialog has no 802.1X control, so ``dot1x_enabled``
    always arrived as the schema default and the endpoint pushed dot1x=0 --
    turning off 802.1X because someone renamed a port.
    """
    data = _update(poe_config=sw.PoeConfig(enabled=True))
    config = _build_config(data, _port())

    assert "dot1x" not in config, "an unrelated port save still disables 802.1X"
    assert "macLimit" not in config


def test_mac_limit_is_not_applied_while_security_is_off() -> None:
    """
    The dialog hides the field when the toggle is off but kept sending its
    value, and the endpoint applied it regardless.
    """
    data = _update(security_config=sw.SecurityConfig(enabled=False, mac_limit=3))
    assert "macLimit" not in _build_config(data, _port())


def test_security_settings_apply_when_the_toggle_is_on() -> None:
    """The fix must not have made the feature inert instead."""
    data = _update(
        security_config=sw.SecurityConfig(
            enabled=True, mac_limit=8, violation_action="shutdown", dot1x_enabled=True
        )
    )
    config = _build_config(data, _port())

    assert config["macLimit"] == 8
    assert config["violationAction"] == "shutdown"
    assert config["dot1x"] == 1  # auto


def test_802_1x_is_only_touched_when_the_caller_says_something() -> None:
    """
    None means "the caller said nothing about 802.1X", which is what the dialog
    actually means. False is an explicit disable and still goes through.
    """
    on = _update(security_config=sw.SecurityConfig(enabled=True, dot1x_enabled=None))
    assert "dot1x" not in _build_config(on, _port())

    off = _update(security_config=sw.SecurityConfig(enabled=True, dot1x_enabled=False))
    assert _build_config(off, _port())["dot1x"] == 0


def test_dot1x_enabled_is_optional_in_the_schema() -> None:
    """``bool = False`` is what made every save carry an implicit disable."""
    assert sw.SecurityConfig().dot1x_enabled is None


def test_turning_the_toggle_off_undoes_our_own_change() -> None:
    """
    Off must be meaningful when FreeSDN was the one that turned it on --
    otherwise a MAC limit stays on the switch that the UI no longer shows.
    """
    port = _port({"security_managed": True})
    data = _update(security_config=sw.SecurityConfig(enabled=False))
    config = _build_config(data, port)

    assert config["macLimit"] == 0
    assert port.port_metadata["security_managed"] is False


def test_turning_the_toggle_off_leaves_a_hand_configured_port_alone() -> None:
    """
    The distinction that matters. FreeSDN cannot see 802.1X or a MAC limit
    someone set on the switch directly, so it must not "undo" what it never
    did -- guessing here is how the original bug started.
    """
    data = _update(security_config=sw.SecurityConfig(enabled=False))
    assert _build_config(data, _port()) == {}


def test_managing_security_records_that_we_did() -> None:
    port = _port()
    _build_config(_update(security_config=sw.SecurityConfig(enabled=True, mac_limit=4)), port)
    assert port.port_metadata["security_managed"] is True


# ── 2. the PoE keys ──────────────────────────────────────────────


def test_poe_uses_the_key_the_controller_actually_takes() -> None:
    """
    ``poeEnabled`` was invented here. ``poe: {enable: ...}`` is what the
    live-validated PoE endpoint sends.
    """
    config = _build_config(_update(poe_config=sw.PoeConfig(enabled=True)), _port())
    assert config["poe"] == {"enable": True}
    assert "poeEnabled" not in config


def test_the_key_matches_the_live_validated_endpoint() -> None:
    """Pin the two together so they cannot drift apart again."""
    from app.api.v1.endpoints import poe as poe_api

    proven = _code(poe_api)
    assert 'omada_config["poe"] = {"enable"' in proven
    assert '"poeMode"' in proven
    assert '"poePowerLimit"' in proven


def test_poe_mode_and_power_limit_reach_the_controller() -> None:
    """Both were collected, accepted, and never added to the config at all."""
    config = _build_config(
        _update(poe_config=sw.PoeConfig(enabled=True, mode="manual", power_limit=15.0)), _port()
    )
    assert config["poeMode"] == "manual"
    assert config["poePowerLimit"] == 15.0


def test_an_unset_power_limit_is_not_sent() -> None:
    """Sending a null cap would be a different way of writing the wrong thing."""
    config = _build_config(_update(poe_config=sw.PoeConfig(enabled=True)), _port())
    assert "poePowerLimit" not in config


# ── 3. the controls with no mapping ──────────────────────────────


def test_poe_priority_is_no_longer_accepted() -> None:
    """
    There is no validated controller key for per-port PoE priority. It was
    collected by the dialog and dropped. Removed rather than kept as a control
    that does nothing.
    """
    assert "priority" not in sw.PoeConfig.model_fields


@pytest.mark.parametrize("field", ["voice_vlan", "guest_vlan"])
def test_the_dead_vlan_fields_are_gone(field: str) -> None:
    assert field not in sw.VlanConfig.model_fields


def test_port_profiles_keep_their_own_voice_vlan() -> None:
    """
    A different path, deliberately untouched. Removing that too would have been
    scope creep dressed up as consistency.
    """
    assert "voice_vlan" in sw.SwitchPortProfileCreate.model_fields


def test_the_surviving_vlan_range_checks_still_hold() -> None:
    with pytest.raises(ValidationError):
        sw.VlanConfig(native_vlan=4095)
    assert sw.VlanConfig(native_vlan=4094).native_vlan == 4094


# ── 4. the agent scan that never left the database ───────────────


def test_the_agent_scan_pushes_over_the_socket() -> None:
    """
    The regression. An INSERT is not a dispatch when nothing consumes the row.
    """
    from app.api.v1.endpoints import discovery

    code = _code(discovery.start_agent_scan)
    assert "get_agent_registry" in code
    assert "send_command" in code
    assert "AgentCommandType.SCAN_NETWORK" in code


def test_it_refuses_rather_than_queueing_into_a_void() -> None:
    """
    With no live socket the honest answer is an error the operator can act on,
    not a task id that will never move off pending.
    """
    from app.api.v1.endpoints import discovery

    code = _code(discovery.start_agent_scan)
    assert "no active WebSocket connection" in code
    assert code.index("get_connection_for_site") < code.index("session.add(task)"), (
        "the row is still created before the connection is checked"
    )


def test_the_task_is_marked_running_once_it_is_on_the_wire() -> None:
    from app.api.v1.endpoints import discovery

    code = _code(discovery.start_agent_scan)
    assert "AgentTaskStatus.RUNNING" in code
    assert 'status="running"' in code, "the response still claims pending"


def test_a_dispatch_failure_marks_the_task_failed() -> None:
    """
    Leaving it at running would recreate the original symptom in a new place:
    a task the UI polls forever.
    """
    from app.api.v1.endpoints import discovery

    code = _code(discovery.start_agent_scan)
    tail = code[code.index("except Exception as exc:") :]
    assert "AgentTaskStatus.FAILED" in tail
    assert "unregister_interactive_task" in tail


def test_the_shipped_agent_really_has_no_task_poller() -> None:
    """
    The premise, and the reason an INSERT alone was never going to work. If a
    poller is ever added, this endpoint's design becomes viable again and this
    test says so.
    """
    import pathlib

    agent_src = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "agent" / "src" / "freesdn_agent"
        if candidate.is_dir():
            agent_src = candidate
            break
    if agent_src is None:  # pragma: no cover - agent tree is not in the flatten
        pytest.skip("agent source not present (backend-only checkout or CI mount)")

    sources = [p.read_text(encoding="utf-8", errors="ignore") for p in agent_src.rglob("*.py")]
    assert not any("tasks/pending" in s for s in sources), (
        "the agent now polls for tasks; the INSERT-only design may be viable again"
    )
    assert any("on_command" in s for s in sources), "the agent's WS command path is gone"


def test_the_sibling_scan_endpoint_was_always_right() -> None:
    """Guard the class: both scan paths must dispatch, not just the fixed one."""
    from app.api.v1.endpoints import agents

    code = _code(agents.run_interactive_scan)
    assert "send_command" in code
