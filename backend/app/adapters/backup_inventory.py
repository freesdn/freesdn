"""Validate metadata only; configuration contents never belong in an inventory."""

import re
from typing import Any


def validate_backup_metadata(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError("Invalid backup inventory")
    backups = []
    filenames = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid backup inventory")
        filename = row.get("filename")
        timestamp = row.get("timestamp")
        size = row.get("size_bytes")
        description = row.get("description")
        if (
            not isinstance(filename, str)
            or re.fullmatch(r"[a-zA-Z0-9_.-]{1,255}", filename) is None
            or ".." in filename
            or filename == "."
            or filename in filenames
            or not isinstance(timestamp, str)
            or type(size) is not int
            or size < 0
            or not isinstance(description, str)
        ):
            raise ValueError("Invalid backup inventory")
        filenames.add(filename)
        backups.append(
            {
                "filename": filename,
                "timestamp": timestamp,
                "size_bytes": size,
                "description": description,
            }
        )
    return backups
