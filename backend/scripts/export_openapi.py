#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Export the FreeSDN backend's OpenAPI spec to a static JSON file the
frontend can consume for type generation.

Run this whenever a backend endpoint signature changes::

    python backend/scripts/export_openapi.py \\
        --output frontend/openapi.json

The frontend's ``npm run gen:api`` reads that file and produces
``frontend/src/lib/api/generated/openapi.d.ts`` with typed paths +
schemas. The hand-written API clients can then ``import type`` from
the generated file instead of redeclaring shapes that drift.

NOTE ON MODULE ROUTES: importing ``app.main`` does NOT give you the whole
API. The 10 loadable modules (voip, cameras, firewall, hypervisor, ...)
mount their routers from ``ModuleLoader`` inside the lifespan, which never
runs on a bare import -- and ``register_routes()`` walks the loader's
REGISTRY, so discovery alone registers nothing. Exporting without loading
them silently dropped ~500 paths: every module endpoint was missing from the
generated contract, so drift in the majority of the API went unchecked. We
therefore run the loader here explicitly. It needs no database.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Allow ``python backend/scripts/export_openapi.py`` from the repo
# root or ``python scripts/export_openapi.py`` from the backend dir.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("openapi.json"),
        help="Path to write the OpenAPI JSON to (default: ./openapi.json)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON (default: compact)",
    )
    args = parser.parse_args()

    from app.core.config import settings
    from app.main import app
    from app.modules.loader import ModuleLoader

    # Mount the module routers the lifespan would mount, so the exported
    # spec matches what /api/v1/openapi.json returns at runtime rather
    # than just the statically-included core routes.
    async def _mount_modules() -> None:
        loader = ModuleLoader()
        loader.discover_modules()
        await loader.load_all_modules()
        loader.register_routes(app, prefix=settings.API_V1_PREFIX)

    asyncio.run(_mount_modules())
    app.openapi_schema = None  # drop anything cached before the modules mounted

    spec = app.openapi()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        if args.pretty:
            json.dump(spec, f, indent=2, sort_keys=True)
        else:
            json.dump(spec, f, separators=(",", ":"), sort_keys=True)
    paths = len(spec.get("paths", {}))
    schemas = len(spec.get("components", {}).get("schemas", {}))
    print(
        f"Wrote {args.output} ({paths} paths, {schemas} schemas)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
