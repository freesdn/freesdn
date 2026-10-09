"""Explicit unit-only boundaries; no account, signing identity or SQL proof.

The endpoint-contract modules already replace authentication and persistence.
Native service/public-router cases cover the actual authority, signing and row
locks separately. This helper is never an app or integration-test dependency.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services import release_signing_async
from app.services.agent_release_authority import ReleaseMutationAuthority


def isolate_release_unit_boundaries(monkeypatch, endpoint):
    identity = object()
    fence = SimpleNamespace(recheck=AsyncMock())

    def require_scope(organization_id):
        # Existing publication unit fixtures represent an unrestricted global
        # administrator. Do not silently let a changed target contract pass.
        assert organization_id is None

    authority = SimpleNamespace(lock=AsyncMock(return_value=fence), require_scope=require_scope)
    monkeypatch.setattr(ReleaseMutationAuthority, 'capture', AsyncMock(return_value=authority))
    monkeypatch.setattr(release_signing_async, 'sign_manifest_async', AsyncMock(return_value='unit-test-signature'))
    monkeypatch.setattr(release_signing_async, 'verify_manifest_async', AsyncMock(return_value=identity))

    async def lock_identity(session, actual_identity):
        assert actual_identity is identity
        assert hasattr(session, 'added') and hasattr(session, 'commits')

    monkeypatch.setattr(endpoint, 'lock_verified_identity', lock_identity)
