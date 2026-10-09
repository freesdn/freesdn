# SPDX-License-Identifier: AGPL-3.0-only
"""Audit legacy site OpenVPN profiles; --apply explicitly enables encryption.

Run inside the upgraded application environment with its existing vault keys.
Output contains counts and a pagination cursor, never profile content. Read
docker/VPN-PROFILE-MAINTENANCE before applying this to an existing installation.
"""

import argparse
import asyncio
import json
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from app.db.session import async_session_factory
from app.services.vpn_profile_storage import encrypt_legacy_profile_batch


def bounded_batch(value: str) -> int:
    size = int(value)
    if not 1 <= size <= 1000:
        raise argparse.ArgumentTypeError("Batch size must be 1..1000")
    return size


async def run(args: argparse.Namespace) -> int:
    report = {
        "mode": "apply" if args.apply else "audit",
        "examined": 0, "plaintext": 0, "already_encrypted": 0, "updated": 0,
        "batches": 0, "last_id": str(args.after_id) if args.after_id else None,
        "complete": False,
    }
    cursor = args.after_id
    try:
        for _ in range(args.max_batches):
            async with async_session_factory() as session, session.begin():
                batch = await encrypt_legacy_profile_batch(
                    session, apply=args.apply, after_id=cursor, limit=args.batch_size,
                )
            # Count only successfully committed batches. A later failure keeps
            # the prior cursor so a review/resume does not skip the failed page.
            for key in ["examined", "plaintext", "already_encrypted", "updated"]:
                report[key] += batch[key]
            report["batches"] += 1
            report["last_id"] = batch["last_id"]
            cursor = UUID(batch["last_id"]) if batch["last_id"] else None
            if batch["examined"] < args.batch_size:
                report["complete"] = True
                break
    except (SQLAlchemyError, ValueError, UnicodeError, OSError) as exc:
        # Exception strings can carry bound SQL parameters, including secrets.
        report["error_type"] = type(exc).__name__
        print(json.dumps(report))
        return 1
    print(json.dumps(report))
    return 0 if report["complete"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Encrypt plaintext; default only audits")
    parser.add_argument("--batch-size", type=bounded_batch, default=100)
    parser.add_argument("--max-batches", type=bounded_batch, default=100)
    parser.add_argument("--after-id", type=UUID, help="Resume after the last successful receipt cursor")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
