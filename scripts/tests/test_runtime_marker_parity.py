"""The database runtime marker must mean the same thing everywhere it appears.

The marker in PGDATA is what the entrypoint compares an existing cluster
against, so a deployment starts, is adopted, or is refused on the strength of
this one string. It is written by two Dockerfiles and asserted by two scripts,
and nothing kept the four in step.

They fell out of step. The Debian revert changed what the images write and left
both scripts demanding "postgresql-18-alpine-3.24-v1", a marker no shipped
image produces. scripts/check_database_ha.py asserts it directly, so its
qualification failed outright; scripts/migrate_database_runtime.py refused the
shipped image as "not the qualified FreeSDN database runtime", which disabled
the entire exceptional migration path -- the path the entrypoint's own refusal
message tells operators to use. Both run in blocking CI jobs.

This runs without Docker: it reads the files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Both shipped database images write the marker during initdb.
IMAGE_SOURCES = (
    Path("docker/Dockerfile.postgres"),
    Path("docker/Dockerfile.logdb"),
)
# Scripts that compare an image's marker against what they expect to find.
SCRIPT_SOURCES = (
    Path("scripts/check_database_ha.py"),
    Path("scripts/migrate_database_runtime.py"),
)

_WRITES_MARKER = re.compile(
    r"printf\s+'%s\\n'\s+'(?P<marker>[^']+)'\s*>\s*"
    r"/usr/local/share/freesdn-database-runtime"
)
_CONSTANT = re.compile(r'^EXPECTED_DATABASE_RUNTIME\s*=\s*"(?P<marker>[^"]+)"', re.MULTILINE)


def _read(rel: Path) -> str:
    path = ROOT / rel
    assert path.is_file(), f"{rel} is missing; update this test with it"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", IMAGE_SOURCES, ids=lambda p: p.name)
def test_image_writes_a_marker(rel: Path) -> None:
    found = _WRITES_MARKER.search(_read(rel))
    assert found, (
        f"{rel} no longer writes /usr/local/share/freesdn-database-runtime in a "
        "form this test recognises. The marker is what decides whether an "
        "operator's existing cluster is adopted or refused; if the write moved, "
        "move this test with it rather than deleting it."
    )


@pytest.mark.parametrize("rel", SCRIPT_SOURCES, ids=lambda p: p.name)
def test_script_declares_the_constant(rel: Path) -> None:
    assert _CONSTANT.search(_read(rel)), (
        f"{rel} must declare EXPECTED_DATABASE_RUNTIME rather than comparing "
        "against an inline marker literal. Inline literals are how two scripts "
        "came to demand an Alpine marker no shipped image writes."
    )


def test_every_marker_agrees() -> None:
    markers: dict[str, str] = {}
    for rel in IMAGE_SOURCES:
        found = _WRITES_MARKER.search(_read(rel))
        if found:
            markers[str(rel)] = found.group("marker")
    for rel in SCRIPT_SOURCES:
        found = _CONSTANT.search(_read(rel))
        if found:
            markers[str(rel)] = found.group("marker")

    assert len(markers) == len(IMAGE_SOURCES) + len(SCRIPT_SOURCES)
    distinct = sorted(set(markers.values()))
    assert len(distinct) == 1, (
        "The database runtime marker disagrees across the tree. An image that "
        "writes one value and a script that expects another is not a cosmetic "
        "mismatch: it fails qualification and disables the documented migration "
        f"path. Found {distinct} in {markers}"
    )


def test_marker_names_the_runtime_the_images_are_actually_built_on() -> None:
    """A marker saying 'debian-trixie' on a musl base would be a lie in PGDATA.

    The marker is trusted later, by a different image, to decide whether a
    cluster is safe to serve. It must therefore describe the base the image was
    really built from -- so the base and the marker are checked against each
    other here, not just the marker against itself.
    """
    postgres = _read(Path("docker/Dockerfile.postgres"))
    marker = _WRITES_MARKER.search(postgres)
    assert marker, "Dockerfile.postgres must write a marker"
    name = marker.group("marker")

    arg = re.search(r"^ARG POSTGRES_VERSION=(?P<tag>\S+)", postgres, re.MULTILINE)
    assert arg, "Dockerfile.postgres must pin a default POSTGRES_VERSION"
    tag = arg.group("tag")

    if "debian" in name:
        assert "alpine" not in tag, (
            f"the marker claims Debian ({name}) but the default base is {tag}"
        )
        codename = name.rsplit("-", 1)[0].split("-")[-1]
        assert codename in tag, f"the marker names '{codename}' but the default base tag is {tag}"
        assert re.search(r'test\s+"\$VERSION_CODENAME"\s*=\s*' + re.escape(codename), postgres), (
            f"Dockerfile.postgres must assert VERSION_CODENAME={codename} so a "
            "mismatched POSTGRES_VERSION build argument fails loudly instead of "
            "producing an image whose marker misdescribes it. The shipped compose "
            "files passed an Alpine tag here."
        )
    elif "alpine" in name:
        assert "alpine" in tag, f"the marker claims Alpine ({name}) but the default base is {tag}"
    else:
        pytest.fail(f"marker {name!r} names no recognised base runtime")


def test_compose_build_args_match_the_dockerfile_base() -> None:
    """Compose build args override the Dockerfile's ARG default.

    This is the defect that motivated the test: the shipped compose files passed
    POSTGRES_VERSION=18.6-alpine3.24 into a Dockerfile that requires trixie, so
    `docker compose build postgres` failed for every from-source deployment
    while the Dockerfile alone looked correct.
    """
    postgres = _read(Path("docker/Dockerfile.postgres"))
    arg = re.search(r"^ARG POSTGRES_VERSION=(?P<tag>\S+)", postgres, re.MULTILINE)
    assert arg
    expected = arg.group("tag")

    seen = 0
    for rel in (Path("docker-compose.yml"), Path("docker-compose.ha.yml")):
        for found in re.finditer(
            r"POSTGRES_VERSION:\s*\$\{POSTGRES_VERSION:-(?P<tag>[^}]+)\}",
            _read(rel),
        ):
            seen += 1
            assert found.group("tag") == expected, (
                f"{rel} defaults the postgres build to {found.group('tag')!r} but "
                f"Dockerfile.postgres expects {expected!r}. A build argument wins "
                "over the Dockerfile's own default."
            )
    assert seen >= 2, (
        "expected a POSTGRES_VERSION build-arg default in both compose files; "
        f"found {seen}. If the arg moved, move this check with it."
    )
