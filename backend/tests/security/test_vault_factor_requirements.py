"""Planned actual application/PG hint tests; no remote IdP or lifespan proof."""
import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import User
from app.models.sso import SSOProvider
from app.services.vault_export_authority import VaultExportAuthority
from tests.security.test_vault_confirmation_registration import registered_actor
from tests.security.test_vault_public_creation_lifecycle import rows

CALLBACK = "https://owned-ui.example/vault/callback"


@asynccontextmanager
async def actor(monkeypatch, tmp_path, credential, method="local", mfa=False, callback=CALLBACK):
    async with registered_actor(monkeypatch, tmp_path, credential, callback=callback) as f:
        provider = uuid4() if method != "local" else None
        async with AsyncSession(f.engine) as db:
            if provider:
                db.add(SSOProvider(id=provider, organization_id=f.org_id, name="Owned hint provider",
                                   slug=uuid4().hex, protocol=method, status="active",
                                   oidc_issuer="https://owned-idp.example.invalid", oidc_client_id="owned-client"))
                await db.flush()
            await db.execute(update(User).where(User.id == f.actor_id).values(
                auth_provider=method, sso_provider_id=provider, external_id="owned-subject" if provider else None,
                mfa_enabled=mfa, hashed_password="!SSO_MANAGED" if provider else f.password_hash))
            await db.commit()
        f.provider = provider
        try:
            yield f
        finally:
            async with AsyncSession(f.engine) as db:
                await db.execute(update(User).where(User.id == f.actor_id).values(
                    auth_provider="local", sso_provider_id=None, external_id=None,
                    mfa_enabled=False, hashed_password=f.password_hash))
                if provider:
                    await db.execute(delete(SSOProvider).where(SSOProvider.id == provider))
                await db.commit()


def headers(f):
    return {"X-FreeSDN-Vault-Actor": str(f.actor_id), "X-FreeSDN-Vault-Organization": str(f.org_id)}


async def security_state(f):
    async with AsyncSession(f.engine) as db:
        row = (await db.execute(select(User.token_version, User.hashed_password, User.mfa_enabled,
                                      User.mfa_secret, User.mfa_backup_codes, User.mfa_last_totp_step,
                                      User.failed_login_attempts).where(User.id == f.actor_id))).one()
        return tuple(row)


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
@pytest.mark.parametrize("method", ["local", "ldap", "oidc"])
@pytest.mark.parametrize("mfa", [False, True])
async def test_current_factor_hint_discloses_only_method_and_requirement(monkeypatch, tmp_path, request, credential, method, mfa):
    async with actor(monkeypatch, tmp_path, credential, method, mfa) as f:
        before = await security_state(f)
        got = await f.client.get(f.confirmation_prefix + "/requirements?action=create", headers=headers(f))
        request.node.user_properties.append(("hint_status", got.status_code))
        assert got.status_code == 200, got.text
        assert got.json() == {"method": method, "mfa_required": mfa,
                              "oidc_redirect_uri": CALLBACK if method == "oidc" else None}
        assert "no-store" in got.headers["cache-control"]
        assert await security_state(f) == before
        assert await rows(f) == [] and not list(f.root.rglob("*.fsdnvault"))
        assert not f.claim_hashes


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
async def test_missing_callback_is_visible_without_deriving_a_host(monkeypatch, tmp_path, credential):
    async with actor(monkeypatch, tmp_path, credential, "oidc", callback="") as f:
        got = await f.client.get(f.confirmation_prefix + "/requirements?action=download",
                                 headers={**headers(f), "Host": "untrusted.example"})
        assert got.status_code == 200, got.text
        assert got.json() == {"method": "oidc", "mfa_required": False, "oidc_redirect_uri": None}
        assert "untrusted" not in got.text and "no-store" in got.headers["cache-control"]


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
async def test_hint_does_not_admit_anonymous_or_changed_browser_actor(monkeypatch, tmp_path, credential):
    async with actor(monkeypatch, tmp_path, credential) as f:
        got = await f.client.get(f.confirmation_prefix + "/requirements", headers={**headers(f), "X-FreeSDN-Vault-Actor": str(uuid4())})
        assert got.status_code == 409 and "no-store" in got.headers["cache-control"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=f.application, raise_app_exceptions=False), base_url="http://test") as anonymous:
            got = await anonymous.get(f.confirmation_prefix + "/requirements")
        assert got.status_code == 401 and "no-store" in got.headers["cache-control"]
        assert "method" not in got.json()


@pytest.mark.parametrize("credential", ["jwt", "key", "cookie"])
@pytest.mark.parametrize("change", ["inactive", "counter", "provider-disabled", "provider-deleted"])
async def test_hint_revalidates_real_committed_changes_after_controlled_wait(monkeypatch, tmp_path, request, credential, change):
    async with actor(monkeypatch, tmp_path, credential, "oidc") as f:
        captured, proceed = asyncio.Event(), asyncio.Event()
        original = VaultExportAuthority.confirmation_requirements

        async def wait(self):
            captured.set()
            await proceed.wait()
            return await original(self)

        monkeypatch.setattr(VaultExportAuthority, "confirmation_requirements", wait)
        task = asyncio.create_task(f.client.get(f.confirmation_prefix + "/requirements", headers=headers(f)))
        try:
            await asyncio.wait_for(captured.wait(), 10)
            async with AsyncSession(f.engine) as db:
                if change == "inactive":
                    await db.execute(update(User).where(User.id == f.actor_id).values(is_active=False))
                elif change == "counter":
                    await db.execute(update(User).where(User.id == f.actor_id).values(token_version=User.token_version + 1))
                elif change == "provider-disabled":
                    await db.execute(update(SSOProvider).where(SSOProvider.id == f.provider).values(status="inactive"))
                else:
                    await db.execute(update(SSOProvider).where(SSOProvider.id == f.provider).values(deleted_at=datetime.now(UTC)))
                await db.commit()
            proceed.set()
            got = await asyncio.wait_for(task, 10)
        finally:
            proceed.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        request.node.user_properties.extend([("hint_status", got.status_code), ("controlled_wait_not_pg_lock_claim", True)])
        assert got.status_code == 401, got.text
        assert "method" not in got.json() and "no-store" in got.headers["cache-control"]
