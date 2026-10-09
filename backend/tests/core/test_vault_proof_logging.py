"""Real formatter disclosure probes with synthetic values, not observed production leaks."""

import json
import logging
import sys
from uuid import uuid4

import jwt
import pytest

from app.core.logging import ColoredFormatter, JSONLogFormatter


def record(**values):
    output = logging.LogRecord("owned.vault", logging.ERROR, "owned.py", 7, "Owned failure", (), None)
    for key, value in values.items():
        setattr(output, key, value)
    return output


def proof():
    return jwt.encode({"purpose": "owned-vault-test", "nonce": uuid4().hex}, uuid4().hex + uuid4().hex, algorithm="HS256")


@pytest.mark.parametrize("key", ["proof", "vault_proof", "X-FreeSDN-Vault-Proof"])
@pytest.mark.parametrize("shape", ["top", "nested", "list"])
def test_opaque_proof_named_fields_are_redacted(key, shape):
    token = "owned-opaque-permission-" + uuid4().hex
    if shape == "top":
        row = record(**{key: token})
    elif shape == "nested":
        row = record(extra_fields={"response": {key: token}})
    else:
        row = record(extra_fields={"responses": [{key: token}]})
    rendered = JSONLogFormatter().format(row)
    payload = json.loads(rendered)
    assert token not in rendered
    assert "[REDACTED]" in rendered and payload["message"] == "Owned failure"


@pytest.mark.parametrize("style", ["extra_fields", "standard"])
@pytest.mark.parametrize("shape", ["string", "nested", "list", "object"])
def test_jwt_values_are_redacted_even_under_unrelated_keys(style, shape):
    token = proof()

    class OpaqueValue:
        def __str__(self):
            return "owned " + token

    value = {"string": token, "nested": {"payload": token}, "list": [token], "object": OpaqueValue()}[shape]
    row = record(**({"extra_fields": {"response": value}} if style == "extra_fields" else {"response": value}))
    rendered = JSONLogFormatter().format(row)
    payload = json.loads(rendered)
    assert token not in rendered and "[REDACTED]" in rendered
    assert payload["message"] == "Owned failure"


@pytest.mark.parametrize("formatter", [JSONLogFormatter, ColoredFormatter])
@pytest.mark.parametrize("chained", [False, True])
def test_exception_rendering_does_not_disclose_signed_proof(formatter, chained):
    token = proof()
    try:
        try:
            raise ValueError("Owned provider rejected " + token)
        except ValueError as error:
            if chained:
                raise RuntimeError("Owned export failed") from error
            raise
    except (ValueError, RuntimeError):
        row = record(exc_info=sys.exc_info())
    rendered = formatter().format(row)
    if formatter is JSONLogFormatter:
        json.loads(rendered)
    assert token not in rendered and "[REDACTED]" in rendered
    assert "ValueError" in rendered and "Owned failure" in rendered


@pytest.mark.parametrize("formatter", [JSONLogFormatter, ColoredFormatter])
def test_existing_message_redaction_positive_control(formatter):
    token = proof()
    rendered = formatter().format(record(msg="Owned proof %s", args=(token,)))
    assert token not in rendered and "[REDACTED]" in rendered


@pytest.mark.parametrize("formatter", [JSONLogFormatter, ColoredFormatter])
def test_normal_diagnostics_are_preserved(formatter):
    row = record(msg="Owned archive id=%s failed after %d bytes", args=("ordinary-id", 812))
    rendered = formatter().format(row)
    assert "Owned archive id=ordinary-id failed after 812 bytes" in rendered
    if formatter is JSONLogFormatter:
        payload = json.loads(rendered)
        assert payload["logger"] == "owned.vault" and payload["level"] == "ERROR"
