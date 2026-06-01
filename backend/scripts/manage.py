# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Account Management CLI.

Secure CLI tool for superuser account operations. Requires direct
server/container access — no HTTP endpoints exposed.

Usage (inside Docker container):
    docker compose exec api python scripts/manage.py unlock-user --email user@example.com
    docker compose exec api python scripts/manage.py reset-password --email user@example.com
    docker compose exec api python scripts/manage.py create-user --email user@example.com --username user
    docker compose exec api python scripts/manage.py list-users
    docker compose exec api python scripts/manage.py disable-user --email user@example.com
    docker compose exec api python scripts/manage.py enable-user --email user@example.com
"""

import argparse
import getpass
import json
import os
import re
import sys
import traceback
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text


def _get_sync_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        from app.core.config import settings
        url = str(settings.DATABASE_URL)
    url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg://", url)
    return url


def _get_engine():
    return create_engine(_get_sync_url())


def _audit_log(engine, action: str, target_email: str, details: str = ""):
    """Write an audit record for management operations."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit.audit_logs "
                "(id, action, resource_type, resource_id, actor_type, actor_name, "
                "ip_address, status, timestamp, metadata) "
                "VALUES (gen_random_uuid(), :action, 'user', :email, 'system', 'manage.py', "
                "'127.0.0.1', 'success', NOW(), :meta)"
            ),
            {"action": action, "email": target_email, "meta": json.dumps({"details": details})},
        )


def cmd_unlock_user(args):
    """Unlock a locked user account."""
    engine = _get_engine()
    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("SELECT id, username, email, failed_login_attempts, locked_until FROM core.users WHERE email = :email"),
                {"email": args.email},
            )
            row = result.fetchone()
            if not row:
                print(f"Error: No user found with email '{args.email}'")
                sys.exit(1)

            uid, username, email, attempts, locked_until = row
            print(f"User: {username} ({email})")
            print(f"  Failed attempts: {attempts}")
            print(f"  Locked until:    {locked_until or 'Not locked'}")

            if attempts == 0 and locked_until is None:
                print("Account is not locked. Nothing to do.")
                return

            conn.execute(
                text("UPDATE core.users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id"),
                {"id": uid},
            )
            print("Account unlocked successfully.")
            _audit_log(engine, "manage.unlock_user", email, f"Unlocked by CLI (was: {attempts} attempts, locked_until={locked_until})")
    finally:
        engine.dispose()


def cmd_reset_password(args):
    """Reset a user's password."""
    from app.core.security import get_password_hash

    engine = _get_engine()
    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("SELECT id, username, email FROM core.users WHERE email = :email"),
                {"email": args.email},
            )
            row = result.fetchone()
            if not row:
                print(f"Error: No user found with email '{args.email}'")
                sys.exit(1)

            uid, username, email = row
            print(f"User: {username} ({email})")

            if args.password:
                password = args.password
            else:
                password = getpass.getpass("New password: ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Error: Passwords do not match")
                    sys.exit(1)

            if not password:
                print("Error: Password cannot be empty")
                sys.exit(1)

            hashed = get_password_hash(password)
            conn.execute(
                text(
                    "UPDATE core.users SET hashed_password = :pw, "
                    "failed_login_attempts = 0, locked_until = NULL "
                    "WHERE id = :id"
                ),
                {"pw": hashed, "id": uid},
            )
            print("Password reset successfully. Account also unlocked.")
            _audit_log(engine, "manage.reset_password", email, "Password reset by CLI")
    finally:
        engine.dispose()


def cmd_create_user(args):
    """Create a new user account (dev / admin bootstrap).

    Builds the row via the ORM (same path as ``scripts/seed_demo_data``) so all
    model defaults apply and the account is immediately usable. Attaches it to
    the org from ``--org-slug``, else the first existing org, else a fresh
    ``default`` org. Like the seed, this bypasses the HTTP password-policy
    (it's a local bootstrap tool) — choose a strong password for anything real.
    """
    import asyncio

    asyncio.run(_create_user_async(args))
    engine = _get_engine()
    try:
        _audit_log(
            engine, "manage.create_user", args.email, f"Created by CLI (role={args.role})"
        )
    finally:
        engine.dispose()


async def _create_user_async(args) -> None:
    from uuid import uuid4

    from sqlalchemy import or_, select

    from app.core.security import get_password_hash
    from app.db.session import async_session_factory
    from app.models.core import Organization, User, UserRole

    try:
        role = UserRole(args.role)
    except ValueError:
        valid = ", ".join(r.value for r in UserRole)
        print(f"Error: invalid --role {args.role!r}; choose one of: {valid}")
        sys.exit(1)

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("New password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match")
            sys.exit(1)
    if not password:
        print("Error: Password cannot be empty")
        sys.exit(1)

    async with async_session_factory() as db:
        dupe = (
            await db.execute(
                select(User).where(
                    or_(User.email == args.email, User.username == args.username)
                )
            )
        ).scalar_one_or_none()
        if dupe is not None:
            print(
                f"Error: a user with email {args.email!r} or username "
                f"{args.username!r} already exists (id={dupe.id}). "
                "Use reset-password to change its password instead."
            )
            sys.exit(1)

        org = None
        if args.org_slug:
            org = (
                await db.execute(
                    select(Organization).where(Organization.slug == args.org_slug)
                )
            ).scalar_one_or_none()
            if org is None:
                print(f"Error: no organization with slug {args.org_slug!r}")
                sys.exit(1)
        if org is None:
            org = (await db.execute(select(Organization).limit(1))).scalar_one_or_none()
        if org is None:
            org = Organization(
                id=uuid4(),
                name="Default Organization",
                slug="default",
                description="Created by manage.py create-user",
                is_active=True,
                settings={"setup_completed": True},
            )
            db.add(org)
            await db.flush()
            print(f"Created organization: {org.name} (slug={org.slug}, id={org.id})")

        user = User(
            id=uuid4(),
            email=args.email,
            username=args.username,
            full_name=args.full_name or args.username,
            hashed_password=get_password_hash(password),
            role=role,
            is_active=True,
            is_verified=True,
            organization_id=org.id,
        )
        db.add(user)
        await db.commit()
        print(
            f"Created user: {user.email} (username={user.username}, "
            f"role={role.value}, org={org.slug}, id={user.id})"
        )


def cmd_list_users(args):
    """List all users with their status."""
    engine = _get_engine()
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    "SELECT username, email, is_active, role, "
                    "failed_login_attempts, locked_until, last_login "
                    "FROM core.users ORDER BY username"
                )
            )
            rows = result.fetchall()
            if not rows:
                print("No users found.")
                return

            print(f"{'Username':<20} {'Email':<30} {'Active':<8} {'Role':<12} {'Attempts':<10} {'Locked Until':<22} {'Last Login'}")
            print("-" * 130)
            now = datetime.now(UTC)
            for username, email, active, role, attempts, locked_until, last_login in rows:
                locked_str = ""
                if locked_until:
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=UTC)
                    if locked_until > now:
                        locked_str = str(locked_until.strftime("%Y-%m-%d %H:%M:%S"))
                    else:
                        locked_str = "(expired)"
                else:
                    locked_str = "-"
                login_str = last_login.strftime("%Y-%m-%d %H:%M:%S") if last_login else "Never"
                print(f"{username:<20} {email:<30} {'Yes' if active else 'No':<8} {role or 'N/A':<12} {attempts or 0:<10} {locked_str:<22} {login_str}")
    finally:
        engine.dispose()


def cmd_disable_user(args):
    """Disable a user account."""
    engine = _get_engine()
    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("SELECT id, username, email, is_active FROM core.users WHERE email = :email"),
                {"email": args.email},
            )
            row = result.fetchone()
            if not row:
                print(f"Error: No user found with email '{args.email}'")
                sys.exit(1)

            uid, username, email, is_active = row
            if not is_active:
                print(f"User {username} ({email}) is already disabled.")
                return

            conn.execute(text("UPDATE core.users SET is_active = false WHERE id = :id"), {"id": uid})
            print(f"User {username} ({email}) has been disabled.")
            _audit_log(engine, "manage.disable_user", email, "Disabled by CLI")
    finally:
        engine.dispose()


def cmd_enable_user(args):
    """Enable a disabled user account."""
    engine = _get_engine()
    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("SELECT id, username, email, is_active FROM core.users WHERE email = :email"),
                {"email": args.email},
            )
            row = result.fetchone()
            if not row:
                print(f"Error: No user found with email '{args.email}'")
                sys.exit(1)

            uid, username, email, is_active = row
            if is_active:
                print(f"User {username} ({email}) is already active.")
                return

            conn.execute(text("UPDATE core.users SET is_active = true WHERE id = :id"), {"id": uid})
            print(f"User {username} ({email}) has been enabled.")
            _audit_log(engine, "manage.enable_user", email, "Enabled by CLI")
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="FreeSDN Account Management CLI — requires server/container access",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # unlock-user
    p_unlock = subparsers.add_parser("unlock-user", help="Unlock a locked user account")
    p_unlock.add_argument("--email", required=True, help="User email address")
    p_unlock.set_defaults(func=cmd_unlock_user)

    # reset-password
    p_reset = subparsers.add_parser("reset-password", help="Reset a user's password")
    p_reset.add_argument("--email", required=True, help="User email address")
    p_reset.add_argument("--password", default=None, help="New password (omit for interactive prompt)")
    p_reset.set_defaults(func=cmd_reset_password)

    # create-user
    p_create = subparsers.add_parser("create-user", help="Create a new user account")
    p_create.add_argument("--email", required=True, help="User email address")
    p_create.add_argument("--username", required=True, help="Login username")
    p_create.add_argument(
        "--password", default=None, help="Password (omit for interactive prompt)"
    )
    p_create.add_argument(
        "--role", default="super_admin",
        help="Role: super_admin | org_admin | site_admin | operator | viewer",
    )
    p_create.add_argument("--full-name", default=None, dest="full_name", help="Display name")
    p_create.add_argument(
        "--org-slug", default=None, dest="org_slug",
        help="Attach to this org slug (default: first existing org, else create 'default')",
    )
    p_create.set_defaults(func=cmd_create_user)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List all users with status")
    p_list.set_defaults(func=cmd_list_users)

    # disable-user
    p_disable = subparsers.add_parser("disable-user", help="Disable a user account")
    p_disable.add_argument("--email", required=True, help="User email address")
    p_disable.set_defaults(func=cmd_disable_user)

    # enable-user
    p_enable = subparsers.add_parser("enable-user", help="Enable a disabled user account")
    p_enable.add_argument("--email", required=True, help="User email address")
    p_enable.set_defaults(func=cmd_enable_user)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(f"Command failed: {e}", file=sys.stderr)
        sys.exit(1)
