# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test audit log tenant isolation.

These signature-level smoke tests verify that the audit service cannot be
invoked without an ``organization_id`` and that the HTTP endpoints always
pass the caller's own ``organization_id`` rather than a user-supplied
value. Cross-org DB-integration coverage lives in the integration suite.
"""

from __future__ import annotations

import inspect


def test_get_by_resource_requires_organization_id() -> None:
    """Signature check: organization_id must be a required parameter."""
    from app.services.audit import AuditService

    sig = inspect.signature(AuditService.get_by_resource)
    params = sig.parameters

    assert "organization_id" in params, "organization_id must be a parameter"
    # It should not have a default (required)
    assert (
        params["organization_id"].default is params["organization_id"].empty
    ), "organization_id must be required (no default)"


def test_get_by_actor_requires_organization_id() -> None:
    """Signature check: organization_id must be a required parameter."""
    from app.services.audit import AuditService

    sig = inspect.signature(AuditService.get_by_actor)
    params = sig.parameters

    assert "organization_id" in params
    assert (
        params["organization_id"].default is params["organization_id"].empty
    )


def test_resource_endpoint_scopes_to_caller_org() -> None:
    """Smoke test: ensure the endpoint passes current_user.organization_id,
    not a user-supplied value."""
    from app.api.v1.endpoints import audit as audit_endpoint

    source = inspect.getsource(audit_endpoint.get_resource_audit_logs)
    # The endpoint should call get_by_resource with current_user.organization_id
    assert "current_user.organization_id" in source, (
        "Endpoint must pass current_user.organization_id, not a user-supplied value"
    )
    assert "organization_id=current_user.organization_id" in source, (
        "get_by_resource call must pass organization_id kwarg from current_user"
    )


def test_user_endpoint_scopes_to_caller_org() -> None:
    """Smoke test: user-log endpoint must scope to caller's org and verify
    target user's org before serving rows."""
    from app.api.v1.endpoints import audit as audit_endpoint

    source = inspect.getsource(audit_endpoint.get_user_audit_logs)

    assert "current_user.organization_id" in source, (
        "Endpoint must pass current_user.organization_id, not a user-supplied value"
    )
    assert "organization_id=current_user.organization_id" in source, (
        "get_by_actor call must pass organization_id kwarg from current_user"
    )
    # Must verify target user belongs to caller's org
    assert "target_user" in source or "session.get(User" in source, (
        "Endpoint must look up target user before serving audit rows"
    )
    assert "404" in source or "HTTP_404_NOT_FOUND" in source, (
        "Cross-org access must return 404 (not 403) to avoid leaking existence"
    )
