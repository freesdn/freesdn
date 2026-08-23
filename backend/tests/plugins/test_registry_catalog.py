# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The publisher and the consumer must canonicalise a catalogue identically.

``registry/build.py`` signs the bytes it derives; ``marketplace.py`` verifies
the bytes IT derives. Nothing forces the two derivations to agree, and they
live in different trees on purpose: the publisher runs outside the app, and
importing the app's helper into it would be a lie about the coupling.

The failure mode if they drift is nasty and quiet in the wrong direction: every
catalogue the project publishes is refused by every instance, with a message
that reads like a security incident ("signature verification failed") rather
than like a build bug. So the agreement is pinned here, in the consumer's own
test suite, against the real publisher source.

These tests skip in a backend-only checkout, where registry/ is absent.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest


def _load_builder():
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "build.py"
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("_registry_build", candidate)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules["_registry_build"] = module
            spec.loader.exec_module(module)
            return module
    return None


def _catalog_path() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "registry" / "public" / "plugins.json"
        if candidate.is_file():
            return candidate
    return None


builder = _load_builder()
pytestmark = pytest.mark.skipif(builder is None, reason="registry/ not present in this checkout")


CASES = [
    pytest.param({"plugins": []}, id="empty"),
    pytest.param(
        {"plugins": [{"plugin_id": "a"}], "signature": "deadbeef"}, id="signature-stripped"
    ),
    pytest.param({"b": 2, "a": 1, "plugins": []}, id="key-order"),
    pytest.param({"plugins": [{"name": "Café Ünïcode ✓"}]}, id="non-ascii"),
    pytest.param({"plugins": [{"n": 1, "f": 1.5, "t": True, "z": None}]}, id="json-scalars"),
    pytest.param({"plugins": [{"nested": {"z": 1, "a": {"y": 2, "b": 3}}}]}, id="nested-ordering"),
    pytest.param(
        {"plugins": [{"q": 'he said "hi"', "b": "a\\b", "t": "a\tb", "n": "a\nb"}]},
        id="escapes",
    ),
]


@pytest.mark.parametrize("catalog", CASES)
def test_publisher_and_consumer_canonicalise_identically(catalog):
    from app.api.v1.endpoints.marketplace import _canonical_catalog_bytes

    assert builder.canonical_bytes(catalog) == _canonical_catalog_bytes(catalog)


def test_the_signature_field_is_excluded_not_merely_emptied():
    """
    Signing over a catalogue that still carries a ``signature`` key would be
    unverifiable by construction: the value cannot be known before it is
    computed. Both sides must drop the key entirely.
    """
    from app.api.v1.endpoints.marketplace import _canonical_catalog_bytes

    without = {"plugins": [{"plugin_id": "x"}]}
    with_sig = {**without, "signature": "00" * 64}

    assert builder.canonical_bytes(with_sig) == builder.canonical_bytes(without)
    assert _canonical_catalog_bytes(with_sig) == _canonical_catalog_bytes(without)
    assert b"signature" not in builder.canonical_bytes(with_sig)


def test_the_published_catalogue_verifies_against_its_own_signature():
    """
    End-to-end on the real artefact: the checked-in catalogue must verify with
    the key it was signed by. This is what an operator's first sync does.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    path = _catalog_path()
    if path is None:  # pragma: no cover - registry present but not yet built
        pytest.skip("registry/public/plugins.json has not been built")

    catalog = json.loads(path.read_text(encoding="utf-8"))
    signature = catalog.get("signature")
    if not signature:  # pragma: no cover - unsigned local preview build
        pytest.skip("catalogue is an unsigned local preview")

    # The key the shipped compose pins. If the registry is ever re-keyed, this
    # and docker-compose.yml move together or deployments break.
    compose = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "docker-compose.yml"
        if candidate.is_file():
            compose = candidate.read_text(encoding="utf-8")
            break
    assert compose is not None, "docker-compose.yml not found"

    marker = "MARKETPLACE_PUBLISHER_PUBLIC_KEY:-"
    assert marker in compose, "compose no longer pins a publisher key"
    pinned = compose.split(marker, 1)[1].split("}", 1)[0].strip()
    assert len(pinned) == 64, f"pinned key is not a 32-byte hex Ed25519 key: {pinned!r}"

    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned))
    try:
        public.verify(bytes.fromhex(signature), builder.canonical_bytes(catalog))
    except InvalidSignature:  # pragma: no cover - the failure this test exists for
        pytest.fail(
            "the published catalogue does not verify against the key pinned in "
            "docker-compose.yml. Re-run registry/build.py and update the pin."
        )


def test_the_catalogue_only_carries_fields_the_ingest_accepts():
    """
    A registry must not be able to set a trust marker. ``is_verified``,
    ``is_featured``, ``status`` and ``download_count`` are decided by the
    instance; the ingest allowlist strips them, and the publisher must not emit
    them either, so the two never appear to disagree about who decides.
    """
    from app.api.v1.endpoints.marketplace import _CATALOG_ALLOWED_FIELDS

    path = _catalog_path()
    if path is None:  # pragma: no cover
        pytest.skip("registry/public/plugins.json has not been built")

    catalog = json.loads(path.read_text(encoding="utf-8"))
    for entry in catalog.get("plugins", []):
        extra = sorted(set(entry) - set(_CATALOG_ALLOWED_FIELDS))
        assert not extra, f"catalogue entry carries fields the ingest drops: {extra}"

    assert set(builder.ALLOWED_FIELDS) <= set(_CATALOG_ALLOWED_FIELDS), (
        "the publisher emits fields the consumer does not accept"
    )


def test_every_catalogue_entry_carries_a_checksum_and_a_download():
    """
    Without both, an entry is un-installable: the install path refuses to
    fetch without a URL and refuses to unpack without a matching SHA-256.
    """
    path = _catalog_path()
    if path is None:  # pragma: no cover
        pytest.skip("registry/public/plugins.json has not been built")

    catalog = json.loads(path.read_text(encoding="utf-8"))
    assert catalog.get("plugins"), "the published catalogue is empty"

    for entry in catalog["plugins"]:
        pid = entry.get("plugin_id")
        assert pid, f"entry with no plugin_id: {entry}"
        checksum = entry.get("checksum_sha256", "")
        assert len(checksum) == 64, f"{pid}: checksum is not a SHA-256 hex digest"
        assert int(checksum, 16) >= 0, f"{pid}: checksum is not hex"
        url = entry.get("download_url", "")
        assert url.startswith("https://"), f"{pid}: download_url is not https"
