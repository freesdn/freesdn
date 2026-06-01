# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Backup Module
====================

Backup and restore functionality including:
- Full system backups
- Device configuration backups
- Scheduled backups
- Multiple storage backends (local, S3, SFTP, FTP, WebDAV, etc.)
- Encrypted backups
- Restore with validation

Production service: app.services.backup.BackupService
Production endpoints: app.api.v1.endpoints.backups
Production tasks: app.tasks.backup
"""

from app.modules.backup.module import BackupModule

__all__ = [
    "BackupModule",
]
