# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unrun management null/omission contracts with durable recovery observations.

Actual JWT/API-key HTTP, independently committed PostgreSQL and sealed vault
collection. A failed response alone does not establish a persisted bad provider.
No IdP exchange, connection test, hardware or production service is contacted.
"""

import json
from copy import deepcopy
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sso import SSOProvider
from app.services.backup import BackupRecoveryError
from tests.security.test_sso_provider_mfa_trust_types import (
    actor_headers,
    provider_body,
    transport,
)
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

MANDATORY_FIELDS = [
    "name", "status", "display_order", "ldap_use_tls", "attribute_mapping",
    "role_mapping", "jit_provisioning", "default_role", "extra_settings",
]
VALID_PATCHES = {
    "omitted": {},
    "zero_order": {"display_order": 0},
    "false_jit": {"jit_provisioning": False},
    "false_tls": {"ldap_use_tls": False},
    "empty_attributes": {"attribute_mapping": {}},
    "empty_roles": {"role_mapping": {}},
    "empty_settings": {"extra_settings": {}},
    "clear_description": {"description": None},
    "clear_icon": {"icon_url": None},
}


def typed_equal(left, right):
    # Preserve distinctions that ordinary Python equality erases (False/0).
    return json.dumps(left, sort_keys=True, default=str) == json.dumps(right, sort_keys=True, default=str)


async def provider_state(f, provider_id):
    async with AsyncSession(f.db.bind) as observer:
        row = (await observer.execute(select(*SSOProvider.__table__.columns).where(
            SSOProvider.id == provider_id,
        ))).mappings().one()
        return deepcopy(dict(row))


async def owned_provider(f, client, headers):
    slug = uuid4().hex
    body = provider_body(f, slug, {"trust_idp_mfa": False})
    body.update(description="Owned optional description", icon_url="https://owned.example.invalid/icon.svg",
                display_order=7, ldap_use_tls=True, attribute_mapping={"email": "mail"},
                role_mapping={"viewer": "owned-readers"})
    response = await client.post("/api/v1/auth/sso/providers", headers=headers, json=body)
    assert response.status_code == 201, response.text
    async with AsyncSession(f.db.bind) as observer:
        provider_id = await observer.scalar(select(SSOProvider.id).where(SSOProvider.slug == slug))
    assert provider_id is not None
    return provider_id


async def observe_collection(f, provider_id):
    try:
        archive = await export_vault(f)
    except BackupRecoveryError:
        # Record a controlled collection refusal, never swallow setup or
        # decryption/assertion errors as an expected product observation.
        return None, "controlled_refusal"
    rows = [p for p in archive.contributors["core"]["sso_providers"] if p["id"] == str(provider_id)]
    assert len(rows) == 1
    return rows[0], "completed_and_decrypted"


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("field", MANDATORY_FIELDS)
async def test_provider_patch_refuses_explicit_null_required_fields(
    vault_db, tmp_path, monkeypatch, request, credential, field,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    headers = await actor_headers(f, credential)
    async with httpx.AsyncClient(transport=transport(), base_url="http://test") as client:
        provider_id = await owned_provider(f, client, headers)
        before = await provider_state(f, provider_id)
        response = await client.patch(f"/api/v1/auth/sso/providers/{provider_id}",
                                      headers=headers, json={field: None})
        after = await provider_state(f, provider_id)
        archived, collection = await observe_collection(f, provider_id)
        after_collection = await provider_state(f, provider_id)
        request.node.user_properties.extend([
            ("management_HTTP_status", response.status_code),
            ("durable_provider_unchanged", typed_equal(before, after)),
            ("durable_requested_field_is_null", after[field] is None),
            ("actual_vault_collection", collection),
            ("collection_preserved_provider", typed_equal(after, after_collection)),
        ])
        # These observations all precede the proposed response-contract check.
        # A 500 with rollback is not the same outcome as an accepted JSON null.
        assert response.status_code in {400, 422}
        assert typed_equal(before, after)
        assert collection == "completed_and_decrypted" and archived is not None
        assert typed_equal(archived[field], before[field])
        assert typed_equal(after, after_collection)


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("case", list(VALID_PATCHES))
async def test_provider_patch_keeps_omitted_false_zero_empty_and_optional_null_usable(
    vault_db, tmp_path, monkeypatch, request, credential, case,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    headers = await actor_headers(f, credential)
    patch = deepcopy(VALID_PATCHES[case])
    async with httpx.AsyncClient(transport=transport(), base_url="http://test") as client:
        provider_id = await owned_provider(f, client, headers)
        before = await provider_state(f, provider_id)
        response = await client.patch(f"/api/v1/auth/sso/providers/{provider_id}",
                                      headers=headers, json=patch)
        after = await provider_state(f, provider_id)
        archived, collection = await observe_collection(f, provider_id)
        after_collection = await provider_state(f, provider_id)
        changed = {key for key in before if not typed_equal(before[key], after[key])}
        requested_exact = all(typed_equal(after[key], value) for key, value in patch.items())
        archive_exact = archived is not None and all(
            typed_equal(archived[key], after[key]) for key in MANDATORY_FIELDS + ["description", "icon_url"]
        )
        request.node.user_properties.extend([
            ("management_HTTP_status", response.status_code),
            ("durable_requested_values_and_types_exact", requested_exact),
            ("only_requested_and_audit_columns_changed", changed <= set(patch) | {"updated_at", "updated_by"}),
            ("actual_vault_collection", collection),
            ("archived_provider_values_and_types_exact", archive_exact),
            ("collection_preserved_provider", typed_equal(after, after_collection)),
        ])
        assert response.status_code == 200
        assert requested_exact
        assert changed <= set(patch) | {"updated_at", "updated_by"}
        assert collection == "completed_and_decrypted" and archive_exact
        assert typed_equal(after, after_collection)
