"""Real PostgreSQL response budget; no archive, factor, or storage acceptance."""

import pytest
from sqlalchemy import Text, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_keys import APIKey
from app.models.core import Controller, User
from app.models.sso import SSOProvider
from app.modules.backup.models import Backup, StorageLocation
from app.services import vault_export_operation_state as operation
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_operation_state import call
from tests.security.test_vault_export_operation_state import operations as operations

LIMIT = 4 * 1024 * 1024
FIELDS = {
    'account-codes': (User, 'mfa_backup_codes', 'user', 'authority', False),
    'account-pending-codes': (User, 'mfa_pending_backup_codes', 'user', 'authority', False),
    'key-scopes': (APIKey, 'scopes', 'key_id', 'authority', True),
    'provider-extra': (SSOProvider, 'extra_settings', 'provider', 'authority', True),
    'provider-role-map': (SSOProvider, 'role_mapping', 'provider', 'authority', True),
    'provider-attributes': (SSOProvider, 'attribute_mapping', 'provider', 'authority', True),
    'provider-certificate': (SSOProvider, 'saml_certificate', 'provider', 'authority', False),
    'provider-signing': (SSOProvider, 'saml_signing_key', 'provider', 'authority', False),
    'provider-ca': (SSOProvider, 'ldap_tls_ca_cert', 'provider', 'authority', False),
    'backup-metadata': (Backup, 'metadata_json', 'backup', 'operation', True),
    'storage-config': (StorageLocation, 'config', 'location', 'operation', True),
    'storage-credentials': (StorageLocation, 'encrypted_credentials', 'location', 'operation', False),
    'controller-config': (Controller, 'config', 'controller', 'operation', True),
}


async def initial(f, kind='key'):
    response = await call(f, kind, 'download_recorded')
    assert response.status_code == 200, response.text
    return f.last


def statement(state, scope):
    if scope == 'authority':
        return state.authority._statement()
    return operation._statement(state.authority, state.intent, None)


async def put(f, name, raw):
    model, field, identifier, _, as_json = FIELDS[name]
    value = {'padding': raw} if as_json else raw
    if name == 'key-scopes':
        value = [raw]
    if name == 'storage-config':
        value['controller_id'] = str(f.controller)
        value['dataset_path'] = 'tank/backup'
    async with AsyncSession(f.engine) as db:
        if model is SSOProvider:
            await db.execute(update(User).where(User.id == f.user).values(sso_provider_id=f.provider))
        await db.execute(update(model).where(model.id == getattr(f, identifier)).values({field: value}))
        await db.commit()
        return await db.scalar(select(func.octet_length(cast(getattr(model, field), Text))).where(
            model.id == getattr(f, identifier)))


async def returned(f, state, scope):
    async with AsyncSession(f.engine) as db:
        row = (await db.execute(statement(state, scope))).mappings().one_or_none()
        # Do not include synthetic multi-megabyte payloads in assertion/log output.
        return row is not None


@pytest.mark.parametrize('name', list(FIELDS))
async def test_oversized_selected_value_never_returns_to_driver(operations, name, record_property):
    f = operations
    state = await initial(f)
    size = await put(f, name, 'x' * (LIMIT + 1))
    assert size > LIMIT
    result = await returned(f, state, FIELDS[name][3])
    record_property('stored_octets', size)
    record_property('over_budget_row_returned', result)
    assert not result, 'SQL returned a selected row larger than the response value budget'


@pytest.mark.parametrize('kind', ['jwt', 'key'])
@pytest.mark.parametrize('scope', ['authority', 'operation'])
async def test_normal_typed_snapshot_remains_available(operations, kind, scope):
    f = operations
    state = await initial(f, kind)
    async with AsyncSession(f.engine) as db:
        row = (await db.execute(statement(state, scope))).mappings().one()
    assert row['a_id'] == f.user
    assert row['a_token_version'] == 17
    assert row['a_is_active'] is True
    if scope == 'operation':
        assert row['b_id'] == f.backup
        assert row['s_config']['controller_id'] == str(f.controller)


@pytest.mark.parametrize('scope', ['authority', 'operation'])
async def test_combined_selected_values_share_one_budget(operations, scope, record_property):
    f = operations
    state = await initial(f)
    names = ('account-codes', 'account-pending-codes') if scope == 'authority' else (
        'storage-credentials', 'controller-config')
    sizes = [await put(f, name, 'x' * (LIMIT // 2)) for name in names]
    assert all(size < LIMIT for size in sizes)
    result = await returned(f, state, scope)
    record_property('over_budget_row_returned', result)
    assert not result, 'Individually bounded fields exceeded the aggregate response budget'


async def test_snapshot_budget_counts_utf8_bytes_not_characters(operations, record_property):
    f = operations
    state = await initial(f)
    value = '\U0001f642' * (LIMIT // 4)
    assert len(value) < LIMIT
    size = await put(f, 'controller-config', value)
    assert size > LIMIT
    result = await returned(f, state, 'operation')
    record_property('stored_octets', size)
    record_property('over_budget_row_returned', result)
    assert not result, 'UTF-8 byte overflow was returned from PostgreSQL'
