# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The marketplace was permanently empty on every deployment, and nothing said why.

`POST /marketplace/plugins/sync` fetches a remote catalogue and falls back to a
first-party seed file bundled with the app when the registry is unreachable.
That fallback was unreachable in practice:

  * the configured registry was https://registry.freesdn.org, a domain that
    has never been attached (the default now points at a registry that really
    resolves, but an offline or air-gapped install still needs this path);
  * the SSRF-safe fetcher reports an unresolvable host by raising HTTPException;
  * sync wrapped fetch AND signature verification in one try, with a single
    ``except HTTPException: raise`` arm.

That arm was added for a good reason -- a SIGNATURE failure must never degrade
to the local seed -- but it also caught the FETCH failure, which is exactly the
case the seed exists for. So every sync returned 400 and the catalogue stayed
at zero plugins.

The two failures need opposite behaviour, so they now sit in separate steps:

    fetch fails      -> fall back to the bundled first-party seed
    signature fails  -> refuse outright, never fall back

Verified live: sync went from HTTP 400 with an empty catalogue to HTTP 200
synchronising the seeded entries.

The seed itself was a second bug and is fixed separately. It used to be three
hand-written samples with all-zero checksums pointing at that dead domain, so
nothing in it could ever be installed -- and one of them squatted the slug
"hello-world", which is unique, so any instance that fell back to the seed could
never afterwards ingest the real hello-world from a registry. It is now
generated from the signed catalogue by registry/build.py.
"""

from __future__ import annotations

import inspect
import json
import pathlib

import pytest


def _sync_source() -> str:
    from app.api.v1.endpoints.marketplace import sync_marketplace

    return inspect.getsource(sync_marketplace)


async def test_an_unreachable_registry_falls_back_to_the_seed(monkeypatch):
    """
    Behavioural, not structural. My first version of this test asserted that an
    `except Exception` appeared between the fetch and the seed load -- which was
    true of the BROKEN code too, because the broad arm sat right after the
    `except HTTPException: raise` that swallowed the case. It passed against the
    bug it was written for. This drives the real thing instead: make the fetch
    fail exactly the way an unresolvable registry does, and require the seed.
    """
    from fastapi import HTTPException

    from app.api.v1.endpoints import marketplace as mp

    async def _unresolvable(_url):
        # Precisely how the SSRF-safe fetcher reports an unresolvable host.
        raise HTTPException(
            status_code=400,
            detail="SSRF blocked: Cannot resolve hostname: registry.invalid",
        )

    monkeypatch.setattr(mp, "_fetch_registry_catalog", _unresolvable)

    seen: dict = {}

    def _record(catalog):
        seen["verified"] = True

    monkeypatch.setattr(mp, "_verify_catalog_signature", _record)

    captured: dict = {}

    class _FakeSession:
        async def execute(self, *a, **k):
            class _R:
                def scalar_one_or_none(self):
                    return None

                def scalars(self):
                    class _S:
                        def all(self_inner):
                            return []

                    return _S()

            return _R()

        def add(self, obj):
            captured.setdefault("added", []).append(obj)

        async def commit(self):
            captured["committed"] = True

        async def flush(self):
            pass

        async def rollback(self):
            pass

        def begin_nested(self):
            # Each entry is ingested inside a SAVEPOINT so one bad row cannot
            # abort the batch; the double has to model that or the loop dies on
            # the first entry.
            class _Savepoint:
                async def __aenter__(self_inner):
                    return self_inner

                async def __aexit__(self_inner, *exc):
                    return False

            return _Savepoint()

    class _User:
        id = None
        organization_id = None
        role = "super_admin"
        is_superuser = True

        def has_permission(self, _p):
            return True

    monkeypatch.setattr(mp, "is_unscoped_superuser", lambda _u: True)

    out = await mp.sync_marketplace(current_user=_User(), session=_FakeSession())

    assert out["synced"] > 0, f"the seed fallback produced nothing: {out}"
    # A seeded catalogue is first-party and must NOT be signature-checked.
    assert "verified" not in seen, "the bundled seed was signature-checked"


def test_a_signature_failure_still_refuses_outright():
    """
    The half that must not regress. A remote catalogue that fails verification
    must never silently degrade to the bundled seed, because that would let a
    MITM suppress a signed catalogue by breaking its signature.
    """
    src = _sync_source()
    assert "used_seed" in src, "no flag distinguishing a seeded catalogue from a fetched one"
    verify_idx = src.index("_verify_catalog_signature(")
    seed_idx = src.index("marketplace_seed.json")
    assert seed_idx < verify_idx, "verification no longer runs after the fallback decision"
    assert "if not used_seed:" in src, "the seed is being signature-checked, or the remote is not"


def test_the_seed_file_exists_and_carries_entries():
    """Premise: a fallback to a missing or empty file fixes nothing."""
    seed = pathlib.Path(__file__).resolve().parents[2] / "app" / "data" / "marketplace_seed.json"
    assert seed.is_file(), "the bundled seed catalogue is gone"
    data = json.loads(seed.read_text(encoding="utf-8"))
    assert data.get("plugins"), "the seed catalogue lists no plugins"


def test_the_unsigned_posture_is_still_fail_closed():
    """
    With no publisher key pinned and no explicit opt-out, a REMOTE catalogue is
    refused rather than trusted. Unchanged by the fallback fix, and worth
    pinning: it is the property the fallback separation exists to protect.
    """
    from fastapi import HTTPException

    from app.api.v1.endpoints import marketplace as mp

    if mp.MARKETPLACE_PUBLISHER_PUBLIC_KEY or mp.MARKETPLACE_ALLOW_UNSIGNED:
        pytest.skip("this instance pins a key or opts out; posture tested elsewhere")

    with pytest.raises(HTTPException) as exc:
        mp._verify_catalog_signature({"plugins": []})
    assert exc.value.status_code == 403


def test_a_tampered_signature_is_rejected():
    """Ed25519 verification actually verifies, with a real keypair."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi import HTTPException

    from app.api.v1.endpoints import marketplace as mp

    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    catalog = {"plugins": [{"plugin_id": "x"}], "version": 1}
    good_sig = priv.sign(mp._canonical_catalog_bytes(catalog)).hex()

    original = mp.MARKETPLACE_PUBLISHER_PUBLIC_KEY
    try:
        mp.MARKETPLACE_PUBLISHER_PUBLIC_KEY = pub_hex

        # A correctly signed catalogue passes.
        mp._verify_catalog_signature({**catalog, "signature": good_sig})

        # Tampering with the payload invalidates it, which is the whole point:
        # the signature covers the canonicalised body, not just the envelope.
        tampered = {**catalog, "plugins": [{"plugin_id": "evil"}], "signature": good_sig}
        with pytest.raises(HTTPException) as exc:
            mp._verify_catalog_signature(tampered)
        assert exc.value.status_code == 403

        # A missing signature is refused when a key is pinned.
        with pytest.raises(HTTPException) as exc:
            mp._verify_catalog_signature(catalog)
        assert exc.value.status_code == 403
    finally:
        mp.MARKETPLACE_PUBLISHER_PUBLIC_KEY = original


def test_the_seed_file_exists_where_the_fallback_looks_for_it():
    """
    The fallback resolves the seed relative to marketplace.py. If that path is
    wrong, or the file is missing from the distribution, sync answers 503 on
    exactly the offline installs the seed exists for.
    """
    import app.api.v1.endpoints.marketplace as mp

    seed = pathlib.Path(mp.__file__).parent.parent.parent.parent / "data" / "marketplace_seed.json"
    assert seed.is_file(), f"the bundled seed is missing at {seed}"

    catalog = json.loads(seed.read_text(encoding="utf-8"))
    assert catalog.get("plugins"), "the bundled seed carries no plugins"


def test_the_seed_file_is_not_gitignored():
    """
    It was, and that is why the fallback had never worked anywhere but a
    developer's own machine.

    ``backend/app/data/`` is application source, but a broad ``data/`` rule in
    freesdn/.gitignore swallowed the whole directory, so the seed was never
    committed. Every fresh clone and every release flatten shipped without it.
    The file being present locally proves nothing, which is why this asks git
    rather than the filesystem.
    """
    import shutil
    import subprocess

    import app.api.v1.endpoints.marketplace as mp

    if shutil.which("git") is None:  # pragma: no cover - slim CI image
        pytest.skip("git is not available in this environment")

    seed = pathlib.Path(mp.__file__).parent.parent.parent.parent / "data" / "marketplace_seed.json"
    result = subprocess.run(
        ["git", "check-ignore", "-q", str(seed)],
        capture_output=True,
        cwd=str(seed.parent),
        check=False,
    )
    # 0 = ignored, 1 = not ignored, 128 = not a git work tree (a released
    # tarball, where the question does not apply).
    if result.returncode == 128:  # pragma: no cover - non-git checkout
        pytest.skip("not a git work tree")
    assert result.returncode == 1, (
        "marketplace_seed.json is gitignored, so it will not be committed and "
        "will not ship. Check the data/ rules in freesdn/.gitignore."
    )


def test_the_seed_entries_are_actually_installable():
    """
    The seed used to hold three samples with all-zero checksums pointing at a
    domain that has never resolved, so nothing in it could be installed. It was
    decoration that made the marketplace look populated.

    Worse, one squatted the slug "hello-world", and slug is unique: any instance
    that fell back to the seed could never afterwards ingest the real
    hello-world from a registry. The sync reported "1 skipped" and no reason.
    """
    import app.api.v1.endpoints.marketplace as mp

    seed = pathlib.Path(mp.__file__).parent.parent.parent.parent / "data" / "marketplace_seed.json"
    catalog = json.loads(seed.read_text(encoding="utf-8"))

    for entry in catalog["plugins"]:
        pid = entry.get("plugin_id", "?")
        checksum = entry.get("checksum_sha256", "")
        assert len(checksum) == 64, f"{pid}: not a SHA-256 digest"
        assert set(checksum) != {"0"}, f"{pid}: placeholder all-zero checksum"
        assert entry.get("download_url", "").startswith("https://"), f"{pid}: no https download"

    slugs = [e.get("slug") for e in catalog["plugins"]]
    assert len(slugs) == len(set(slugs)), f"the seed collides with itself on slug: {slugs}"
