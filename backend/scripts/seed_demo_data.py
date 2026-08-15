# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Seed Demo Data
============================

Creates a default admin user, organization, and enables all modules.
Run after `alembic upgrade head` on a fresh database.

Usage:
    cd freesdn/backend
    python -m scripts.seed_demo_data
"""

import asyncio
import logging
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.db.session import async_session_factory
from app.models.core import Organization, User, UserRole
from app.modules.loader import BUILTIN_MODULES
from app.modules.models import OrganizationModule

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Default credentials ──────────────────────────────────────────
ADMIN_EMAIL = "admin@example.com"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "demo"
ADMIN_FIRST_NAME = "Demo"
ADMIN_LAST_NAME = "Admin"

ORG_NAME = "Demo Organization"
ORG_SLUG = "demo"


async def seed(db: AsyncSession) -> None:
    """Create org, admin user, and enable all modules."""

    # 1. Organization
    org = Organization(
        id=uuid4(),
        name=ORG_NAME,
        slug=ORG_SLUG,
        description="Default development organization",
        is_active=True,
        settings={
            "setup_completed": True,
            "setup_completed_at": datetime.now(UTC).isoformat(),
        },
    )
    db.add(org)
    await db.flush()
    logger.info("Created organization: %s (id=%s)", org.name, org.id)

    # 2. Admin user (bypass password-policy validation for dev convenience)
    user = User(
        id=uuid4(),
        email=ADMIN_EMAIL,
        username=ADMIN_USERNAME,
        full_name=f"{ADMIN_FIRST_NAME} {ADMIN_LAST_NAME}".strip() or ADMIN_USERNAME,
        hashed_password=get_password_hash(ADMIN_PASSWORD),
        role=UserRole.SUPER_ADMIN,
        is_active=True,
        is_verified=True,
        organization_id=org.id,
        preferences={"theme": "dark", "notifications": True},
    )
    db.add(user)
    await db.flush()
    logger.info("Created admin user: %s (id=%s)", user.email, user.id)

    # 3. Enable all built-in modules for the org
    for module_id in BUILTIN_MODULES:
        om = OrganizationModule(
            id=uuid4(),
            organization_id=org.id,
            module_id=module_id,
            is_enabled=True,
            settings={},
        )
        db.add(om)
    await db.flush()
    logger.info("Enabled %d modules: %s", len(BUILTIN_MODULES), ", ".join(BUILTIN_MODULES))

    await db.commit()
    logger.info("Seed complete! Login with %s / %s", ADMIN_EMAIL, ADMIN_PASSWORD)


async def main() -> None:
    # This helper writes well-known demo credentials (admin@example.com / "demo")
    # and is meant for local development only. Refuse to run against a production
    # deployment — production instances are provisioned through the first-run
    # setup wizard, which forces a real administrator password.
    from app.core.config import settings

    if settings.ENVIRONMENT == "production":
        raise SystemExit(
            "Refusing to seed demo data in a production environment. "
            "Use the first-run setup wizard to create the administrator account."
        )

    async with async_session_factory() as db:
        await seed(db)


if __name__ == "__main__":
    asyncio.run(main())
