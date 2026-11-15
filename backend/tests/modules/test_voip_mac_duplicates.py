# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Two live phones that share a MAC are refused, never served, and never added.

Migration 032 canonicalises phone MACs. Where two live phones turn out to be
one MAC spelled two ways it keeps both and flags them (``mac_review``). From
then on:

* provisioning either phone is refused, naming the other, because both would
  be served the same cfg<mac>.xml and one could get the other's SIP account;
* the unauthenticated config pull answers "no config" instead of crashing on
  two matches;
* deleting one clears the survivor's flag and provisioning works again;
* the API refuses to create or re-address a phone onto a MAC another live phone
  already holds (409, naming it when it is in the caller's organization).
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser
from app.models.core import Organization, Site, User
from app.modules.voip import api as voip_api
from app.modules.voip.models import MAC_REVIEW_DUPLICATE, Phone
from app.modules.voip.provisioning import ProvisioningService, SharedPhoneMACError
from app.modules.voip.schemas import PhoneCreate, PhoneUpdate
from app.modules.voip.service import DuplicatePhoneMACError, VoIPService

MAC = "00:0b:82:12:34:56"


async def _org_site(db: AsyncSession) -> tuple[Organization, Site]:
    org = Organization(name="MAC dup", slug=f"mac-dup-{uuid4().hex[:8]}")
    db.add(org)
    await db.flush()
    site = Site(organization_id=org.id, name="Main", slug=f"main-{uuid4().hex[:6]}")
    db.add(site)
    await db.flush()
    return org, site


async def _phone(db: AsyncSession, site: Site, name: str, mac: str, review: str | None) -> Phone:
    phone = Phone(
        site_id=site.id,
        name=name,
        mac_address=mac,
        mac_review=review,
        status="offline",
        lifecycle_state="discovered",
        sip_registered=False,
        settings={},
        tags=[],
    )
    db.add(phone)
    await db.flush()
    return phone


def _user(org: Organization) -> CurrentUser:
    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        username=uuid4().hex[:8],
        organization_id=org.id,
        role="site_admin",
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=["voip.view", "voip.manage_phones"])


async def _flagged_pair(db: AsyncSession):
    org, site = await _org_site(db)
    a = await _phone(db, site, "desk A", MAC, MAC_REVIEW_DUPLICATE)
    b = await _phone(db, site, "desk B", MAC, MAC_REVIEW_DUPLICATE)
    return org, site, a, b


async def test_provisioning_a_flagged_phone_is_refused_naming_its_twin(
    db_session: AsyncSession,
) -> None:
    org, _, a, b = await _flagged_pair(db_session)
    prov = ProvisioningService(db_session, organization_id=org.id)

    with pytest.raises(SharedPhoneMACError) as exc:
        await prov.generate_phone_config(a.id, write_file=False)

    assert str(b.id) in str(exc.value) and "desk B" in str(exc.value)


async def test_the_provision_endpoint_answers_409_with_the_twin(db_session: AsyncSession) -> None:
    org, _, a, b = await _flagged_pair(db_session)

    with pytest.raises(HTTPException) as exc:
        await voip_api.provision_phone(
            a.id,
            voip_api.PhoneProvisionRequest(),
            current_user=_user(org),
            session=db_session,
        )

    assert exc.value.status_code == 409
    assert str(b.id) in exc.value.detail


async def test_the_unauthenticated_pull_does_not_serve_a_shared_mac(
    db_session: AsyncSession,
) -> None:
    await _flagged_pair(db_session)
    prov = ProvisioningService(db_session)

    assert await prov.get_config_for_mac(MAC) is None


async def test_deleting_one_twin_clears_the_other(db_session: AsyncSession) -> None:
    org, _, a, b = await _flagged_pair(db_session)
    svc = VoIPService(db=db_session, organization_id=org.id)

    await svc.delete_phone(b.id)

    await db_session.refresh(a)
    assert a.mac_review is None
    prov = ProvisioningService(db_session, organization_id=org.id)
    await prov._refuse_shared_mac(a)  # no twin left: does not raise


async def test_a_new_phone_cannot_take_a_mac_already_in_use(db_session: AsyncSession) -> None:
    org, site = await _org_site(db_session)
    await _phone(db_session, site, "existing", MAC, None)
    svc = VoIPService(db=db_session, organization_id=org.id)

    with pytest.raises(DuplicatePhoneMACError) as exc:
        await svc.create_phone({"site_id": site.id, "name": "new", "mac_address": "000B82123456"})

    assert "existing" in str(exc.value)


async def test_the_create_endpoint_answers_409(db_session: AsyncSession) -> None:
    org, site = await _org_site(db_session)
    await _phone(db_session, site, "existing", MAC, None)
    user = _user(org)

    with pytest.raises(HTTPException) as exc:
        await voip_api.create_phone(
            PhoneCreate(site_id=site.id, name="new", mac_address="00-0B-82-12-34-56"),
            current_user=user,
            service=VoIPService(db=db_session),
        )

    assert exc.value.status_code == 409


async def test_a_phone_cannot_be_readdressed_onto_a_mac_in_use(db_session: AsyncSession) -> None:
    org, site = await _org_site(db_session)
    await _phone(db_session, site, "existing", MAC, None)
    other = await _phone(db_session, site, "other", "00:11:22:33:44:55", None)
    user = _user(org)

    with pytest.raises(HTTPException) as exc:
        await voip_api.update_phone(
            other.id,
            PhoneUpdate(mac_address=MAC.upper()),
            current_user=user,
            service=VoIPService(db=db_session),
        )

    assert exc.value.status_code == 409


async def test_resending_a_phones_own_mac_is_not_a_conflict(db_session: AsyncSession) -> None:
    org, _, a, _ = await _flagged_pair(db_session)
    svc = VoIPService(db=db_session, organization_id=org.id)

    updated = await svc.update_phone(a.id, {"name": "renamed", "mac_address": MAC.upper()})

    assert updated.name == "renamed"
    assert updated.mac_review == MAC_REVIEW_DUPLICATE
