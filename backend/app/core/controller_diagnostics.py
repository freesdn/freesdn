# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fixed public controller diagnostics; never infer safety from redaction patterns."""

import re
from datetime import datetime

CONTROLLER_ERROR = "Controller operation failed. Check connectivity, credentials and configuration."
CONNECTION_FAILED = "Connection failed"
CONNECTION_SUCCEEDED = "Connection successful"

_SAFE_ERRORS = frozenset(
    {
        CONTROLLER_ERROR,
        CONNECTION_FAILED,
        "Connection test failed",
        "Discovery failed; verify controller connectivity and configuration.",
        "Previous discovery failure",
        "Authentication failed with the cloud API. "
        "Verify your Client ID, Client Secret, and Omada Controller ID are correct.",
        "Authentication failed. "
        "Verify your username and password are correct and the account has admin privileges.",
        "Cannot reach the cloud endpoint. "
        "Check the cloud region and ensure outbound HTTPS (port 443) is not blocked.",
        "Cannot reach the controller. "
        "Verify the host address, port, network access and the trusted TLS certificate configuration.",
        "Connection timed out. The controller may be overloaded or unreachable.",
        "Proxmox authentication failed. "
        "If using API Token, verify the Token ID (user@realm!token-name) and Token Secret. "
        "If using username/password, check credentials and realm (pam/pve).",
        "Proxmox access denied. "
        "The user or API token lacks the required privileges. "
        "Ensure PVEAuditor or higher role is assigned.",
        "Proxmox API request failed.",
        "An unexpected error occurred. Check server logs for details.",
    }
)


def public_controller_error(value: object) -> str | None:
    """Preserve fixed local categories, not arbitrary historical/provider text."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        if value in _SAFE_ERRORS:
            return value
        if re.fullmatch(r"Proxmox API request failed \(HTTP [1-5][0-9]{2}\)\.", value):
            return value
    return CONTROLLER_ERROR


def public_controller_history(value: object) -> list[dict[str, str]]:
    """Copy at most ten valid timestamp/error projections without mutating storage."""
    if not isinstance(value, list):
        return []
    result = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        stamp = item.get("timestamp")
        if not isinstance(stamp, str) or len(stamp) > 40:
            continue
        try:
            timestamp = datetime.fromisoformat(stamp).isoformat()
        except ValueError:
            continue
        result.append(
            {
                "timestamp": timestamp,
                "error": public_controller_error(item.get("error")) or CONTROLLER_ERROR,
            }
        )
    return result
