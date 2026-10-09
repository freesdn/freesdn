# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual Settings parsing and immutable deployment policy, no startup I/O."""

from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from app.core.agent_release_runtime_policy import ReleaseRuntimePolicy

LIMITS = (
    "FREESDN_AGENT_RELEASE_GLOBAL_HISTORY_LIMIT", "FREESDN_AGENT_RELEASE_ORG_HISTORY_LIMIT",
    "FREESDN_AGENT_RELEASE_GLOBAL_BYTE_LIMIT", "FREESDN_AGENT_RELEASE_ORG_BYTE_LIMIT",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in (*LIMITS, "FREESDN_AGENT_RELEASE_DIR", "FREESDN_AGENT_MANAGED_RELEASE_DIR"):
        monkeypatch.delenv(name, raising=False)


def configuration(**overrides):
    from app.core.config import Settings

    values = {
        "SECRET_KEY": "owned-runtime-policy-synthetic-credential",
        "ENCRYPTION_SALT": "owned-runtime-policy-synthetic-salt",
        "POSTGRES_PASSWORD": "owned-runtime-policy-synthetic-db-password",
        "ENVIRONMENT": "development", "LOGDB_URL": "postgresql+asyncpg://unused:unused@127.0.0.1/unused",
    }
    return Settings(_env_file=None, **(values | overrides))


def test_defaults_separate_existing_flat_files_and_bound_resources():
    policy = ReleaseRuntimePolicy.from_settings(configuration())
    assert policy.legacy_root == "/var/lib/freesdn/agent-releases"
    assert policy.managed_root == policy.legacy_root + "/.managed-v1"
    assert (policy.global_history, policy.organization_history) == (10000, 2000)
    assert (policy.global_owned_bytes, policy.organization_owned_bytes) == (50 * 1024**3, 10 * 1024**3)
    with pytest.raises(FrozenInstanceError):
        policy.global_history = 1


def test_actual_environment_names_and_explicit_shared_volume_parent(monkeypatch):
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", "/data/legacy")
    monkeypatch.setenv("FREESDN_AGENT_MANAGED_RELEASE_DIR", "/data/managed/store")
    for name in LIMITS:
        monkeypatch.setenv(name, "500")
    policy = ReleaseRuntimePolicy.from_settings(configuration())
    assert policy.legacy_root == "/data/legacy" and policy.managed_root == "/data/managed/store"
    assert (policy.global_history, policy.organization_history,
            policy.global_owned_bytes, policy.organization_owned_bytes) == (500,) * 4


@pytest.mark.parametrize("name", LIMITS)
@pytest.mark.parametrize("value", (True, False, 1.5, 0, -1, "01", "1.0", "+1", "1e2", "١", "", str(2**63)))
def test_settings_do_not_coerce_invalid_budgets(name, value):
    with pytest.raises(ValidationError):
        configuration(**{name: value})


@pytest.mark.parametrize("pair", ((LIMITS[0], LIMITS[1]), (LIMITS[2], LIMITS[3])))
def test_organization_limit_cannot_exceed_shared_deployment_limit(pair):
    with pytest.raises(ValidationError, match="Organization release budgets"):
        configuration(**{pair[0]: 100, pair[1]: 101})


@pytest.mark.parametrize("root", ("relative", "/data//managed", "/data/../managed", "/", "/data/managed/", "/data/nul\0"))
def test_invalid_explicit_root_refuses_configuration_without_access(root):
    with pytest.raises(ValidationError):
        configuration(FREESDN_AGENT_MANAGED_RELEASE_DIR=root)


@pytest.mark.parametrize("managed", ("/data/legacy", "/data"))
def test_managed_root_cannot_relabel_legacy_root_or_its_parent(managed):
    with pytest.raises(ValidationError, match="must not contain or replace"):
        configuration(FREESDN_AGENT_RELEASE_DIR="/data/legacy", FREESDN_AGENT_MANAGED_RELEASE_DIR=managed)


def test_retained_configuration_does_not_follow_later_environment_changes(monkeypatch):
    original = configuration(FREESDN_AGENT_RELEASE_DIR="/data/initial")
    captured = ReleaseRuntimePolicy.from_settings(original)
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", "/data/changed")
    monkeypatch.setenv(LIMITS[0], "20000")
    assert ReleaseRuntimePolicy.from_settings(original) == captured
    successor = ReleaseRuntimePolicy.from_settings(configuration())
    assert successor.managed_root == "/data/changed/.managed-v1" and successor.global_history == 20000


def test_explicit_empty_managed_root_uses_private_child_and_not_current_directory():
    policy = ReleaseRuntimePolicy.from_settings(configuration(
        FREESDN_AGENT_RELEASE_DIR="/data/releases", FREESDN_AGENT_MANAGED_RELEASE_DIR="",
    ))
    assert policy.managed_root == "/data/releases/.managed-v1"
