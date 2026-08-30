# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A signed catalogue must say WHEN it was signed, not only WHO signed it.

The signed object used to be {catalog_version, generated_by, plugins}, and
``catalog_version`` is a constant SCHEMA number, not a sequence. So two builds
months apart over unchanged plugins produced byte-identical signed bytes: a
valid signature proved provenance and nothing about currency. Anyone able to
serve stale bytes -- a stuck CDN edge, an intermediate cache, a MITM against a
client that skips TLS verification -- could replay an old catalogue whose
signature still verifies perfectly.

The damage is not a stale index. ``marketplace.py`` upserts every catalogue
entry unconditionally and, on finding a row it had marked ``withdrawn``, sets it
back to ``published``. Replaying a catalogue from before a withdrawal therefore
RE-PUBLISHES the plugin the project decided nobody should install any more.

``registry/build.py`` now stamps ``generated_at``, a monotonic ``serial`` and
``expires_at`` INSIDE the payload it signs. These tests pin that: the fields
exist, the serial advances build over build, and all three are covered by the
signature rather than bolted onto the file afterwards.

The VERIFYING half -- a persisted serial floor and an expiry refusal in
marketplace.py -- is deliberately not covered here, because it is deliberately
not implemented: it needs a schema addition and a rollback story and is tracked
separately. Emitting the signed data first is what lets that land later without
another republish of the catalogue.

These tests skip in a backend-only checkout, where registry/ is absent.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types
from datetime import UTC, datetime

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

FRESHNESS_FIELDS = ("generated_at", "serial", "expires_at")

#: A frozen instant, so a test asserting on the emitted strings is not a
#: coin-flip against the wall clock.
_NOON = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)


def _catalog(previous_serial: int = 0, now: datetime = _NOON, valid_days: int = 90) -> dict:
    """A catalogue shaped exactly like the one build.py signs."""
    return {
        "catalog_version": 1,
        "generated_by": "freesdn registry build.py",
        **builder.freshness_fields(previous_serial, valid_days, now),
        "plugins": [{"plugin_id": "hello-world", "version": "1.2.0"}],
    }


# ---------------------------------------------------------------------------
# The fields exist and mean something
# ---------------------------------------------------------------------------


def test_the_signed_payload_carries_a_freshness_binding() -> None:
    catalog = _catalog()
    missing = [f for f in FRESHNESS_FIELDS if f not in catalog]
    assert not missing, (
        f"the catalogue build.py signs is missing {missing}. Without them the signed "
        "bytes cannot distinguish today's catalogue from one signed months ago."
    )

    assert catalog["generated_at"] == "2026-08-26T12:00:00Z"
    assert catalog["expires_at"] == "2026-11-24T12:00:00Z"
    assert catalog["serial"] == 1


def test_generated_at_and_expires_at_are_parseable_utc_instants() -> None:
    """A consumer has to be able to compare them without guessing a format."""
    catalog = _catalog()
    generated = datetime.fromisoformat(catalog["generated_at"])
    expires = datetime.fromisoformat(catalog["expires_at"])

    assert generated.tzinfo is not None and generated.utcoffset().total_seconds() == 0
    assert expires.tzinfo is not None and expires.utcoffset().total_seconds() == 0
    assert expires > generated, "a catalogue cannot expire before it was generated"


def test_a_catalogue_cannot_be_stamped_already_expired() -> None:
    with pytest.raises(ValueError):
        builder.freshness_fields(0, valid_days=0)
    with pytest.raises(ValueError):
        builder.freshness_fields(0, valid_days=-1)


# ---------------------------------------------------------------------------
# The serial advances
# ---------------------------------------------------------------------------


def test_the_serial_increments_across_builds() -> None:
    """Each build reads the previous catalogue back and continues the count.

    The serial is the only field that ORDERS two catalogues carrying identical
    plugin content, which is the case a replay exploits.
    """
    first = _catalog(builder.read_serial(None))
    second = _catalog(builder.read_serial(first))
    third = _catalog(builder.read_serial(second))

    assert [first["serial"], second["serial"], third["serial"]] == [1, 2, 3]


def test_a_catalogue_published_before_freshness_fields_starts_the_count_at_one() -> None:
    """The migration case: the live catalogue carries no serial at all.

    If this returned anything but 0 the first republish could not happen, so it
    is pinned rather than left to read as an accident.
    """
    legacy = {"catalog_version": 1, "generated_by": "freesdn registry build.py", "plugins": []}
    assert builder.read_serial(legacy) == 0
    assert _catalog(builder.read_serial(legacy))["serial"] == 1


@pytest.mark.parametrize("bad", [True, False, "7", 7.0, -1, [7]])
def test_a_serial_that_is_not_a_counter_is_refused_not_coerced(bad) -> None:
    """Guessing the next serial is not free.

    Restarting at 1 either re-issues a serial that a different set of signed
    bytes already used -- the exact ambiguity a monotonic counter removes -- or,
    against a consumer holding a floor, locks the registry out of publishing for
    ever. ``True`` is called out because bool is an int subclass, so an
    unguarded isinstance() would read a hand-edited ``true`` as serial 1.
    """
    with pytest.raises(ValueError):
        builder.read_serial({"serial": bad, "plugins": []})


# ---------------------------------------------------------------------------
# The fields are INSIDE the signature, not alongside it
# ---------------------------------------------------------------------------


def test_the_freshness_fields_land_in_the_bytes_that_get_signed() -> None:
    signed_bytes = builder.canonical_bytes(_catalog())
    for field in FRESHNESS_FIELDS:
        assert f'"{field}"'.encode() in signed_bytes, (
            f"{field} is not in the canonical bytes, so it is decoration on the file "
            "rather than a claim the signature makes"
        )


def test_rolling_back_a_freshness_field_invalidates_the_signature(tmp_path) -> None:
    """The property that actually matters, proved by signing and then tampering.

    A field merged onto the JSON after signing would survive every mutation
    below. Each of these must break verification instead.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key_path = tmp_path / "throwaway.key"
    builder._generate_key(key_path)
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(builder._public_hex(key_path)))

    # Serial 5, so rolling it back to 1 is a genuine change rather than a no-op.
    catalog = _catalog(previous_serial=4)
    catalog["signature"] = builder._sign(catalog, key_path)
    public.verify(bytes.fromhex(catalog["signature"]), builder.canonical_bytes(catalog))

    rollbacks = {
        "serial": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    for field, stale in rollbacks.items():
        tampered = {**catalog, field: stale}
        with pytest.raises(InvalidSignature):
            public.verify(bytes.fromhex(tampered["signature"]), builder.canonical_bytes(tampered))

    for field in FRESHNESS_FIELDS:
        stripped = {k: v for k, v in catalog.items() if k != field}
        with pytest.raises(InvalidSignature):
            public.verify(bytes.fromhex(stripped["signature"]), builder.canonical_bytes(stripped))


def test_two_builds_over_identical_plugins_no_longer_produce_identical_bytes() -> None:
    """The replay this whole change exists to stop, stated directly."""
    january = _catalog(previous_serial=0, now=datetime(2026, 1, 1, tzinfo=UTC))
    august = _catalog(previous_serial=1, now=datetime(2026, 8, 1, tzinfo=UTC))

    assert january["plugins"] == august["plugins"]
    assert builder.canonical_bytes(january) != builder.canonical_bytes(august)


def test_canonical_bytes_stays_deterministic_with_the_new_fields() -> None:
    """Ordering must come from sort_keys, never from insertion order.

    The publisher builds the dict one way and a verifier reconstructs it from
    parsed JSON another; if the bytes depended on insertion order, every
    catalogue would be refused with "signature verification failed".
    """
    catalog = _catalog()
    reversed_insertion = {k: catalog[k] for k in reversed(list(catalog))}

    assert builder.canonical_bytes(reversed_insertion) == builder.canonical_bytes(catalog)
    assert builder.canonical_bytes(catalog) == builder.canonical_bytes(dict(catalog))


# ---------------------------------------------------------------------------
# End to end, through main(), against a throwaway registry
# ---------------------------------------------------------------------------


def _throwaway_registry(monkeypatch, tmp_path) -> pathlib.Path:
    """Point build.py at a scratch tree and stub the site renderer.

    Never at registry/public: a test that regenerated the committed catalogue
    would overwrite a signed artefact with one signed by a throwaway key, which
    is a defect this suite already has a test for.
    """
    src = tmp_path / "plugins" / "freshness-probe"
    src.mkdir(parents=True)
    (src / "plugin.yaml").write_text(
        "id: freshness-probe\nversion: 1.0.0\nname: Freshness Probe\n"
        "description: Fixture plugin for the catalogue freshness tests.\n",
        encoding="utf-8",
    )
    (src / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")

    public = tmp_path / "public"
    monkeypatch.setattr(builder, "PLUGIN_SRC", tmp_path / "plugins")
    monkeypatch.setattr(builder, "PUBLIC", public)
    monkeypatch.setattr(builder, "DOWNLOADS", public / "dl")

    stub = types.ModuleType("site_render")
    stub.render = lambda *_args, **_kwargs: 0
    monkeypatch.setitem(sys.modules, "site_render", stub)
    return public


def test_build_signs_the_freshness_fields_and_advances_them_run_over_run(
    monkeypatch, tmp_path
) -> None:
    """The wiring test: correct helpers are worth nothing if main() drops them.

    Runs the real entry point twice with a generated key, then verifies each
    published catalogue against that key's public half -- which is exactly what
    an instance does on sync.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_dir = _throwaway_registry(monkeypatch, tmp_path)
    key_path = tmp_path / "publisher.key"
    argv = [
        "build.py",
        "--generate-key",
        "--key-file",
        str(key_path),
        "--seed-out",
        "",  # never rewrite the app's bundled seed from a test
    ]

    serials = []
    for _ in range(2):
        monkeypatch.setattr(sys, "argv", list(argv))
        assert builder.main() == 0

        catalog = json.loads((public_dir / "plugins.json").read_text(encoding="utf-8"))
        for field in FRESHNESS_FIELDS:
            assert field in catalog, f"main() published a catalogue with no {field}"

        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(builder._public_hex(key_path)))
        # Does not raise => the freshness fields were signed, not appended after.
        verifier.verify(bytes.fromhex(catalog["signature"]), builder.canonical_bytes(catalog))
        serials.append(catalog["serial"])

    assert serials == [1, 2], (
        f"serial did not advance across builds: {serials}. A repeated serial cannot "
        "order two catalogues, which is the whole point of carrying one."
    )


def test_build_refuses_to_guess_a_serial_from_an_unreadable_catalogue(
    monkeypatch, tmp_path
) -> None:
    """Failing loudly beats silently rewinding the counter to 1.

    The catalogue is committed, so the recovery is a `git checkout` -- cheap,
    and only available if the build says so instead of republishing serial 1.
    """
    public_dir = _throwaway_registry(monkeypatch, tmp_path)
    public_dir.mkdir(parents=True, exist_ok=True)

    for corrupt in ("{not json", json.dumps({"serial": "seven", "plugins": []})):
        (public_dir / "plugins.json").write_text(corrupt, encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["build.py", "--unsigned", "--seed-out", ""])
        assert builder.main() == 1, (
            f"build accepted a catalogue it cannot read a serial from: {corrupt!r}"
        )


# ---------------------------------------------------------------------------
# The published artefact
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "The live catalogue was signed before freshness fields existed and cannot "
        "gain them without being re-signed, which needs the publisher key. It goes "
        "green with the republish already required for the archive-determinism fix "
        "(docs/agents/REGISTRY-REPUBLISH.md); remove this marker then."
    ),
    strict=False,
)
def test_the_published_catalogue_carries_a_freshness_binding() -> None:
    """The end state: what registry.freesdn.org serves says how old it is."""
    path = _catalog_path()
    if path is None:  # pragma: no cover - registry present but not yet built
        pytest.skip("registry/public/plugins.json has not been built")

    catalog = json.loads(path.read_text(encoding="utf-8"))
    missing = [f for f in FRESHNESS_FIELDS if f not in catalog]
    assert not missing, (
        f"the published catalogue is missing {missing}, so a months-old copy of it "
        "replays with a signature that verifies. Republish with registry/build.py."
    )
    assert catalog["serial"] >= 1
    assert datetime.fromisoformat(catalog["expires_at"]) > datetime.fromisoformat(
        catalog["generated_at"]
    )
