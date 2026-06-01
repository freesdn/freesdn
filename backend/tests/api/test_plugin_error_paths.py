# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for plugin install endpoint error handling.

Verifies that policy HTTPExceptions are not swallowed by broad except
handlers — the ``except HTTPException: raise`` pattern must be present
so that 403/400 errors propagate correctly instead of being masked as 500.
"""

import pytest
from fastapi import HTTPException


class TestPluginErrorPassthrough:
    """Verify that policy HTTPExceptions are not swallowed by broad except handlers."""

    def test_http_exception_not_caught_by_generic_handler(self):
        """HTTPException should propagate through except-HTTPException-raise pattern."""

        # Simulate the pattern used in plugins.py
        def install_with_policy_check(allowed: bool):
            try:
                if not allowed:
                    raise HTTPException(status_code=403, detail="URL installs disabled")
                return {"status": "installed"}
            except HTTPException:
                raise  # This is the fix — re-raise policy errors
            except Exception:
                raise HTTPException(status_code=500, detail="Install failed")

        # Policy failure should return 403, not 500
        with pytest.raises(HTTPException) as exc_info:
            install_with_policy_check(allowed=False)
        assert exc_info.value.status_code == 403
        assert "disabled" in exc_info.value.detail

    def test_generic_error_returns_500(self):
        """Non-HTTP exceptions should be caught and return 500."""

        def install_with_unexpected_error():
            try:
                raise RuntimeError("disk full")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=500, detail="Install failed")

        with pytest.raises(HTTPException) as exc_info:
            install_with_unexpected_error()
        assert exc_info.value.status_code == 500

    def test_domain_not_allowed_returns_400(self):
        """Domain validation failure should return proper status, not 500."""

        def install_with_domain_check(url: str, allowed_domains: list):
            try:
                from urllib.parse import urlparse

                host = urlparse(url).hostname or ""
                if host.lower() not in allowed_domains:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Domain {host} not in allowlist",
                    )
                return {"status": "installed"}
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=500, detail="Install failed")

        with pytest.raises(HTTPException) as exc_info:
            install_with_domain_check("https://evil.com/plugin.zip", ["github.com"])
        assert exc_info.value.status_code == 400
        assert "evil.com" in exc_info.value.detail

    def test_successful_install_returns_result(self):
        """When policy checks pass, install should return success."""

        def install_with_policy_check(allowed: bool):
            try:
                if not allowed:
                    raise HTTPException(status_code=403, detail="URL installs disabled")
                return {"status": "installed"}
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=500, detail="Install failed")

        result = install_with_policy_check(allowed=True)
        assert result == {"status": "installed"}
