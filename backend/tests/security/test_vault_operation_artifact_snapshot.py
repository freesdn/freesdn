"""Current SQL identity carried to the already prepared archive consumer."""

import json

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.backup.models import Backup
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_operation_state import call
from tests.security.test_vault_export_operation_state import operations as operations


@pytest.mark.parametrize('kind', ['jwt', 'key'])
@pytest.mark.parametrize('action', ['create', 'download_recorded', 'observe_legacy', 'download_legacy'])
async def test_snapshot_carries_only_the_same_read_recorded_identity(operations, kind, action):
    f = operations
    if action in {'observe_legacy', 'download_legacy'}:
        async with AsyncSession(f.engine) as db:
            await db.execute(update(Backup).where(Backup.id == f.backup).values(metadata_json={}))
            await db.commit()
    response = await call(f, kind, action)
    assert response.status_code == 200, response.text
    value = f.last.artifact_identity_json
    if action == 'download_recorded':
        assert json.loads(value) == f.observed
    else:
        assert value is None
    # The later consumer must verify actual bytes against this copied identity;
    # it cannot treat a legacy observation as an authored catalogue anchor.
    async with AsyncSession(f.engine) as db:
        row = await db.get(Backup, f.backup)
        assert row.metadata_json == ({} if action in {'observe_legacy', 'download_legacy'}
                                     else {'artifact_identity': f.observed})
