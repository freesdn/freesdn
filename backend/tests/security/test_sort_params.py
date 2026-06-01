# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test that SortParams default-denies when no allowlist is provided.

``SortParams.apply`` used to sort by ANY model attribute
when ``allowed_fields`` was ``None`` (the default). That allowed a
blind side-channel: an attacker could observe pagination order to
extract secret column values (``hashed_password``, ``mfa_secret``,
``api_key``, ...). These tests lock in the default-deny behaviour.
"""
from unittest.mock import MagicMock

from app.core.query import SortParams


def test_sort_params_default_denies() -> None:
    """SortParams.apply must not sort when allowed_fields is None or empty."""
    params = SortParams(sort_by="hashed_password", sort_order="asc")

    # Mock query and model
    mock_query = MagicMock()
    mock_query.order_by = MagicMock(return_value=mock_query)
    mock_model = MagicMock()
    mock_model.hashed_password = MagicMock()

    # None case
    params.apply(mock_query, mock_model, allowed_fields=None)
    assert not mock_query.order_by.called, (
        "SortParams must not sort when allowed_fields is None"
    )

    # Empty list case
    mock_query.order_by.reset_mock()
    params.apply(mock_query, mock_model, allowed_fields=[])
    assert not mock_query.order_by.called, (
        "SortParams must not sort when allowed_fields is empty"
    )


def test_sort_params_respects_allowlist() -> None:
    """SortParams.apply must only sort by fields in the allowlist."""
    # Use a real SA model + Select so that asc()/desc() actually bind
    # to a column (MagicMock doesn't satisfy SQLAlchemy coercions).
    from sqlalchemy import Column, Integer, String, select
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()

    class _Widget(Base):  # type: ignore[misc, valid-type]
        __tablename__ = "_widget_sort_test"
        id = Column(Integer, primary_key=True)
        name = Column(String)
        hashed_password = Column(String)

    query = select(_Widget)
    params = SortParams(sort_by="name", sort_order="asc")

    # Allowed field — sort applied, ORDER BY present
    sorted_query = params.apply(
        query, _Widget, allowed_fields=["name", "created_at"]
    )
    sql = str(sorted_query)
    assert "ORDER BY" in sql
    assert "name" in sql


def test_sort_params_blocks_non_allowlisted() -> None:
    """SortParams must not sort by fields not in the allowlist."""
    params = SortParams(sort_by="hashed_password", sort_order="asc")

    mock_query = MagicMock()
    mock_query.order_by = MagicMock(return_value=mock_query)
    mock_model = MagicMock()
    mock_model.hashed_password = MagicMock()

    # Sensitive field NOT in allowlist — must not sort
    params.apply(mock_query, mock_model, allowed_fields=["name"])
    assert not mock_query.order_by.called


def test_sort_params_blocks_secret_columns_when_allowlist_is_none() -> None:
    """Regression for secret columns must never leak.

    Even if an attacker supplies a known secret column name
    (``hashed_password``, ``mfa_secret``, ``api_key``, ``token``,
    ``password``), the default-deny behaviour blocks sorting.
    """
    secret_fields = [
        "hashed_password",
        "mfa_secret",
        "api_key",
        "token",
        "password",
        "oidc_client_secret",
    ]

    for field_name in secret_fields:
        params = SortParams(sort_by=field_name, sort_order="desc")
        mock_query = MagicMock()
        mock_query.order_by = MagicMock(return_value=mock_query)
        mock_model = MagicMock()
        setattr(mock_model, field_name, MagicMock())

        # No allowlist — must not sort
        params.apply(mock_query, mock_model, allowed_fields=None)
        assert not mock_query.order_by.called, (
            f"SortParams must not sort on secret column {field_name!r} "
            "when allowed_fields is None"
        )


def test_sort_params_noop_when_sort_by_missing() -> None:
    """When sort_by is None, apply must be a no-op regardless of allowlist."""
    params = SortParams(sort_by=None, sort_order="asc")
    mock_query = MagicMock()
    mock_query.order_by = MagicMock(return_value=mock_query)
    mock_model = MagicMock()

    params.apply(mock_query, mock_model, allowed_fields=["name"])
    assert not mock_query.order_by.called
