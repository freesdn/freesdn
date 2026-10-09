"""The backup client must not inherit an unused PostgreSQL data volume."""

from pathlib import Path

import yaml


def test_backup_client_masks_image_database_volume_without_masking_backups():
    root = Path(__file__).resolve().parents[3]
    service = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]["pg-backup"]
    temporary = {entry.split(":", 1)[0] for entry in service["tmpfs"]}
    assert "/var/lib/postgresql" in temporary
    assert "/backups" not in temporary
    assert "pg_backups:/backups" in service["volumes"]
