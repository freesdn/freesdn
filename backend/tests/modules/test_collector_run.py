# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unit tests for the dedicated collector runner (app/modules/collector/run.py).

The runner was previously untested — which is how the reload-rebind race and the
no-retry behaviour slipped through. These lock the pure logic: change detection,
env-port single-source, the bind-verification that drives the self-healing retry,
and the per-org merge (incl. the soft-delete-filtered org query path).
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.modules.collector import run as collector_run


def _cfg(**kw: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "snmp_enabled": False,
        "snmp_port": 162,
        "snmp_community": "public",
        "syslog_enabled": False,
        "syslog_port": 514,
        "netflow_enabled": False,
        "netflow_port": 2055,
        "allowed_source_ips": [],
    }
    base.update(kw)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# _profile_key — change detection
# --------------------------------------------------------------------------- #
def test_profile_key_none_is_empty() -> None:
    assert collector_run._profile_key(None) == ()


def test_profile_key_changes_with_allowlist() -> None:
    a = _cfg(syslog_enabled=True, allowed_source_ips=["10.0.0.0/8"])
    b = _cfg(syslog_enabled=True, allowed_source_ips=["10.0.0.0/8", "192.168.0.0/16"])
    assert collector_run._profile_key(a) != collector_run._profile_key(b)


def test_profile_key_stable_for_same_profile() -> None:
    a = _cfg(syslog_enabled=True, allowed_source_ips=["10.0.0.0/8"])
    b = _cfg(syslog_enabled=True, allowed_source_ips=["10.0.0.0/8"])
    assert collector_run._profile_key(a) == collector_run._profile_key(b)


# --------------------------------------------------------------------------- #
# _port_from_env — deployment owns the listen port
# --------------------------------------------------------------------------- #
def test_port_from_env_default_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("COLLECTOR_SYSLOG_PORT", raising=False)
    assert collector_run._port_from_env("COLLECTOR_SYSLOG_PORT", 514) == 514


def test_port_from_env_override(monkeypatch) -> None:
    monkeypatch.setenv("COLLECTOR_SYSLOG_PORT", "5514")
    assert collector_run._port_from_env("COLLECTOR_SYSLOG_PORT", 514) == 5514


def test_port_from_env_invalid_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("COLLECTOR_SYSLOG_PORT", "not-a-port")
    assert collector_run._port_from_env("COLLECTOR_SYSLOG_PORT", 514) == 514


# --------------------------------------------------------------------------- #
# _all_receivers_bound — the bind check that makes a failed rebind self-heal
# --------------------------------------------------------------------------- #
def _mgr(status: dict) -> SimpleNamespace:
    return SimpleNamespace(status=lambda: status)


def test_all_bound_true_when_enabled_running() -> None:
    mgr = _mgr({"syslog": {"running": True}, "snmp_trap": {"running": False}})
    assert collector_run._all_receivers_bound(mgr, _cfg(syslog_enabled=True)) is True


def test_all_bound_false_when_enabled_not_running() -> None:
    mgr = _mgr({"syslog": {"running": False}})
    assert collector_run._all_receivers_bound(mgr, _cfg(syslog_enabled=True)) is False


def test_all_bound_ignores_disabled_protocols() -> None:
    # snmp not running, but it is also not enabled → still "all bound".
    mgr = _mgr({"syslog": {"running": True}, "snmp_trap": {"running": False}})
    assert collector_run._all_receivers_bound(mgr, _cfg(syslog_enabled=True)) is True


# --------------------------------------------------------------------------- #
# _load_merged_config — merge + env-port single-source + idle cases
# --------------------------------------------------------------------------- #
class _Scalars:
    def __init__(self, items: list) -> None:
        self._items = items

    def all(self) -> list:
        return self._items


class _Res:
    def __init__(self, rows: list | None = None, scalar_list: list | None = None) -> None:
        self._rows = rows or []
        self._scalars = scalar_list or []

    def all(self) -> list:
        return self._rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._scalars)


class _FakeDB:
    """Returns canned results for the 3 selects in _load_merged_config (orgs,
    modules, configs) — the actual select() objects are ignored."""

    def __init__(self, results: list) -> None:
        self._results = results
        self._i = 0

    async def execute(self, *_a: object, **_k: object) -> _Res:
        r = self._results[self._i]
        self._i += 1
        return r


async def test_merged_config_merges_and_unions(monkeypatch) -> None:
    monkeypatch.delenv("COLLECTOR_SYSLOG_PORT", raising=False)
    org = uuid4()
    cfg = _cfg(organization_id=org, syslog_enabled=True, allowed_source_ips=["10.0.0.0/8"])
    db = _FakeDB([_Res(rows=[(org,)]), _Res(rows=[(org,)]), _Res(scalar_list=[cfg])])
    merged = await collector_run._load_merged_config(db)
    assert merged is not None
    assert merged.syslog_enabled is True
    assert merged.syslog_port == 514
    assert merged.allowed_source_ips == ["10.0.0.0/8"]


async def test_merged_config_env_port_wins(monkeypatch) -> None:
    monkeypatch.setenv("COLLECTOR_SYSLOG_PORT", "5514")
    org = uuid4()
    cfg = _cfg(organization_id=org, syslog_enabled=True, syslog_port=514)
    db = _FakeDB([_Res(rows=[(org,)]), _Res(rows=[(org,)]), _Res(scalar_list=[cfg])])
    merged = await collector_run._load_merged_config(db)
    assert merged is not None
    assert merged.syslog_port == 5514  # deployment env overrides the DB port


async def test_merged_config_none_when_no_eligible_org() -> None:
    db = _FakeDB([_Res(rows=[]), _Res(rows=[]), _Res(scalar_list=[])])
    assert await collector_run._load_merged_config(db) is None


async def test_merged_config_none_when_all_protocols_disabled() -> None:
    org = uuid4()
    cfg = _cfg(organization_id=org)  # eligible org, but nothing enabled
    db = _FakeDB([_Res(rows=[(org,)]), _Res(rows=[(org,)]), _Res(scalar_list=[cfg])])
    assert await collector_run._load_merged_config(db) is None
