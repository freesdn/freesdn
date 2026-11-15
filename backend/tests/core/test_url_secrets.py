# SPDX-License-Identifier: AGPL-3.0-only
"""Free text that may carry a credential is hidden whole.

An earlier masker hid only the credential inside a URL. Each review of 26.11.1
found inputs where it misjudged where the credential ended; two whole-module
reviews then listed dozens. These are every input those reviews reported:
each is now hidden whole. Ordinary values stay readable, and every scan is
linear.
"""

from __future__ import annotations

import time

import pytest

from app.core.url_secrets import mask_url_credentials, mask_url_credentials_in

REVIEW_INPUTS = [
    # Rounds before the whole-value rule.
    "https://example.test/update?password=%26SECRET",
    "https://example.test/update?password=prefix%26SECRET",
    "https://example.test/update?x=1%26password=pre%2526y=https://SECRET.example/x",
    "https://example.test/u?x=1%26password=pre%26next=https://SECRET.example/x",
    "https://example.test/update?password=prefix/https://SECRET.example/x",
    "https://example.test/update?password=https://a.test/https://SECRET.example/x",
    "host=example.test&pwd=prefix/https://SECRET.example/x",
    # Whole-module review, revision 10.
    "https://h/?password%3DSECRET=x",
    "https://h/?x=1%26password%3DSECRET=x",
    "https://h/?password%253DSECRET",
    "x=1 password%253DSECRET",
    "https://h/?x=1%25%32%36password=SECRET",
    "https://h/?x=1&password%25%33%44SECRET",
    "https://h%3Fpassword=SECRET",
    "https://u%3ASECRET%40h/?x=1",
    "https%3A%2F%2Fu%3ASECRET%40h/?x=1",
    "https://h/?password=pre?SECRET",
    "https://h/?password=pre;SECRET",
    "password=pre#SECRET",
    "https://h/?password=pre'SECRET",
    "https://u:SEC'RET@h/",
    "https://h/?pass\tword=SECRET",
    "https://u:SEC\nRET@h/",
    "//u:SECRET@h/?next=https://x/",
    "url=//u:SECRET@h/",
    "-https://u:SECRET@h/",
    "password:x=SECRET",
    "//password=SECRET",
    "https://h/?password%3DSECRET=",
    "https://h/%25%33%46password=SECRET",
    "https://h/?password='SECRET",
    "https://u:SECRET'@h/",
    "https://u:SE\tCRET@h/",
    "https://h/?p%09assword=SECRET",
    "https://u:SECRET%40h/?x=1",
    "https%3A%2F%2Fu:SECRET@h/",
    "https://h/?next=//u:SECRET@h/",
    "https:u:SECRET@h/",
    "https:/u:SECRET@h/",
    "https:///u:SECRET@h/",
    r"https:\u:SECRET@h/",
    "sip:u:SECRET@h",
    # Whole-module review, revision 11 (the residue check).
    "https://h/?password= SECRET",
    "https://h/?password=A SECRET",
    "https://u:SECRET'=@h/",
    "https:u:SECRET=x@h/",
    "https://u:SEC\tRET&x@h/",
    "https://h/?password%3D%3DSECRET=x",
    "https://h/?password%3D%3ASECRET=x",
    "https://x%3Fpassword=A@h/SECRET",
    "https://h/?password%25252525%33%44SECRET",
    "https://h/?password'=SECRET",
    "password:=SECRET",
    "https://h%3Fpassword==SECRET",
    "url=//u:SECRET=@h/",
    "https://u:SECRET+tail%40h/",
    "https://h%3Fpassword%3D+SECRET",
    "https://u:SECRET%2525252540h/",
    "https://h/?password=pre SECRET",
    # Whole-module review, revision 12 (the whole-value rule).
    "https://u: SECRET@h/",
    "https://u:pre SECRET@h/",
    "https://h/?%7\t0assword=SECRET",
    "https://h/?pass%\t77ord=SECRET",
    "https://h/?pass%7\n7ord=SECRET",
    "https://h/?pass%\r77ord=SECRET",
    "https://h/?password[0]=SECRET",
    "\\\\SECRET@h/",
    # Whole-module review, revision 13.
    "https://h/?password/foo=SECRET",
    "https://h/?password?x=SECRET",
    "https://h/?password;x=SECRET",
    "https://h/?pa%73sword%2Ffoo=SECRET",
    "password#x=SECRET",
    "https:u: SECRET@h/",
    "https:/u:pre SECRET@h/",
    "https:u:pre SECRET@h/",
    "ws:/u: SECRET@h/",
    # Final reviews, revision 14 (rated unlikely or contrived by both).
    "https://h/?%70assword%26x=SECRET",
    "https: SECRET@h/",
    "https:pre SECRET@h/",
    "https://h/?mfa_backup_codes=SECRET",
    "https://h/?mfa-backup-codes=SECRET",
]
SHOWN = ("SECRET", "SEC'RET", "SE\tCRET", "SEC\nRET", "SEC\tRET")


def _mask(text: str) -> str:
    from app.services.device_config_render import name_is_secret

    return mask_url_credentials(text, lambda _value: "***", name_is_secret)


@pytest.mark.parametrize("text", REVIEW_INPUTS)
def test_no_reported_input_shows_its_credential(text: str) -> None:
    masked = _mask(text)
    assert not any(shown in masked for shown in SHOWN), masked
    assert masked == "***"


@pytest.mark.parametrize(
    "text",
    [
        "mode=wpa2",
        "admin@example.com",
        "git@github.com:org/repo",
        "Uplink: port 24",
        "12:03 UTC",
        "fe80::1",
        "https://example.test/u?h%6Fst=gw&a=1",
        "https://downloads.example.invalid/x",
        "url=https://a.test/?x=1",
        "https://pkg.opnsense.org/FreeBSD:14:amd64/24.7",
        "Interface: igb0 mtu=1500",
        "Contact: admin@example.com",
        "see https://docs.example.com/x for details",
        "long note without secrets",
    ],
)
def test_ordinary_values_stay_readable(text: str) -> None:
    assert _mask(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "https://example.test/" + "a" * 200_000 + "?url=https://target.test/x",
        "x" + "=https://a.test/" * 20_000,
        "a:" * 100_000,
        "a@" * 100_000,
        "%25" * 100_000,
        "-" * 200_000 + "=",
        "x " * 100_000 + "@",
    ],
)
def test_long_inputs_are_read_in_linear_time(text: str) -> None:
    started = time.perf_counter()
    _mask(text)
    assert time.perf_counter() - started < 2.0


def test_decoding_that_does_not_settle_is_hidden() -> None:
    # Each decoding round removes one "25": eleven rounds, past the bound.
    text = "x=%" + "25" * 10 + "41"
    assert _mask(text) == "***"
    assert _mask("x=%" + "25" * 3 + "41") == "x=%" + "25" * 3 + "41"


def test_nested_payloads_mask_keys_and_do_not_skip_deep_values() -> None:
    deep: object = "https://u:SECRET@h/"
    for _ in range(40):
        deep = [deep]
    payload = {"https://u:SECRET@h/": "x", "deep": deep, "name": "edge-1"}
    masked = mask_url_credentials_in(payload, lambda _value: "***", lambda _name: False)
    assert "SECRET" not in repr(masked)
    assert masked["name"] == "edge-1"


def test_public_keys_in_remembered_answers_stay_readable() -> None:
    """A WireGuard public key is base64 ending in "=" that can spell a secret
    fragment ("otp" here); it is never a URL, so it is kept."""
    from app.services.device_live_read import _for_cache

    public = "ngV6yNm9otpa6ZR7OJuMn5slMsBUwWnNQK3aZO5cl2s="
    stored = _for_cache({"peers": [{"public_key": public, "note": "https://u:SECRET@h/"}]})
    assert stored["peers"][0]["public_key"] == public
    assert "SECRET" not in repr(stored)


def test_a_public_key_name_does_not_protect_a_url() -> None:
    """Only a value shaped like a base64 key is kept under a public-key name."""
    from app.services.device_live_read import _for_cache

    stored = _for_cache({"public_key": "https://u:SECRET@h/"})
    assert "SECRET" not in repr(stored)


def test_a_short_value_under_a_public_key_name_is_not_kept_unread() -> None:
    """Base64-shaped but no key: "password==" is a name and a value to a form
    parser. Only a value as long as a real key (40+ characters) is kept."""
    from app.services.device_live_read import _for_cache

    assert _for_cache({"public_key": "password=="}) == {"public_key": "***"}


def test_masked_keys_do_not_overwrite_each_other() -> None:
    masked = mask_url_credentials_in(
        {"https://a/?token=ONE": {"status": "down"}, "https://b/?token=TWO": {"status": "up"}},
        lambda _value: "***",
        lambda _name: False,
    )
    assert sorted(masked.values(), key=repr) == [{"status": "down"}, {"status": "up"}]
    assert "ONE" not in repr(masked) and "TWO" not in repr(masked)


def test_a_literal_masked_looking_key_does_not_overwrite_a_masked_one() -> None:
    masked = mask_url_credentials_in(
        {"https://a/?token=ONE": {"status": "down"}, "***": {"status": "up"}},
        lambda _value: "***",
        lambda _name: False,
    )
    assert len(masked) == 2 and masked["***"] == {"status": "up"}


def test_many_keys_masked_alike_are_numbered_in_linear_time() -> None:
    payload = {f"https://h/{index}?token=X": index for index in range(20_000)}
    started = time.perf_counter()
    masked = mask_url_credentials_in(payload, lambda _value: "***", lambda _name: False)
    assert time.perf_counter() - started < 2.0
    assert len(masked) == 20_000
