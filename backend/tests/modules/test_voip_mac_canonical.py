# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
One phone, one MAC spelling, one provisioning file.

Provisioning finds a phone, and names its config file, by the lowercase colon
form of its MAC (``00:0b:82:12:34:56`` -> ``cfg000b82123456.xml``). The phone
API stored the MAC exactly as typed, so:

* a phone saved as ``00:0B:82:12:34:56`` or ``000b82123456`` was never served
  its config, because the lookup compares the stored string;
* the unique index on ``mac_address`` compared raw strings too, so two spellings
  of one MAC could both exist, in different sites;
* provisioning either of them wrote the SAME file, and the file is served to
  the phone stored in the canonical form. Provisioning the misspelled phone
  replaced the other phone's configuration (SIP server, account, admin
  password) without any access to that phone's site.

The schema now stores the canonical spelling, and the file writer refuses a
phone whose stored MAC is not canonical (legacy rows, or any path around the
schema), rather than overwrite somebody else's file.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.modules.voip.schemas import PhoneCreate, PhoneUpdate

CANONICAL = "00:0b:82:12:34:56"
CFG_NAME = "cfg000b82123456.xml"
SPELLINGS = ["00:0B:82:12:34:56", "00-0b-82-12-34-56", "000B82123456", CANONICAL]


@pytest.mark.parametrize("typed", SPELLINGS)
def test_phone_create_stores_the_canonical_mac(typed: str) -> None:
    assert PhoneCreate(name="desk", mac_address=typed).mac_address == CANONICAL


@pytest.mark.parametrize("typed", SPELLINGS)
def test_phone_update_stores_the_canonical_mac(typed: str) -> None:
    assert PhoneUpdate(mac_address=typed).mac_address == CANONICAL


@pytest.mark.parametrize("bad", ["00:0b:82:12:34", "zz:0b:82:12:34:56", "00:0b:82:12:34:56\n"])
def test_phone_schema_still_refuses_non_macs(bad: str) -> None:
    with pytest.raises(ValueError):
        PhoneCreate(name="desk", mac_address=bad)


def _service(provision_dir: Path):
    from app.modules.voip.provisioning import ProvisioningService

    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    return ProvisioningService(db, provision_dir=provision_dir)


@pytest.mark.parametrize("stored", ["00:0B:82:12:34:56", "000b82123456", "00-0b-82-12-34-56"])
async def test_a_non_canonical_phone_cannot_replace_the_canonical_phones_file(
    tmp_path: Path, stored: str
) -> None:
    from app.modules.voip.provisioning import ProvisioningError

    svc = _service(tmp_path / "voip")
    owner_path = await svc._write_config_file(CANONICAL, "grandstream", "<owner/>")
    assert Path(owner_path).name == CFG_NAME

    with pytest.raises(ProvisioningError):
        await svc._write_config_file(stored, "grandstream", "<other-site/>")

    assert Path(owner_path).read_text(encoding="utf-8") == "<owner/>"
