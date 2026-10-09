"""Raw OPNsense configuration downloads retain XML and reject unsafe payloads.

These are actual HTTPX/client/adapter parser checks with a synthetic transport.
They do not prove backup storage, restoration or hardware compatibility.
"""

import asyncio
import io
import logging

import httpx
import pytest
import pytest_asyncio

from app.adapters.exceptions import AdapterAuthenticationError, AdapterConnectionError
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.adapters.opnsense.client import OPNsenseAPIError

SECRET = "owned-configuration-private-material"
INVALID_MESSAGE = "OPNsense returned an invalid configuration document"
VALID = [
    "<opnsense><system><hostname>owned</hostname></system></opnsense>",
    '<?xml version="1.0"?><opnsense>\n<secret>' + SECRET + "</secret>\n</opnsense>",
    '<?xml version="1.0" encoding="UTF-8"?><opnsense><name>café &amp; 東京</name></opnsense>',
    "<opnsense><!-- retained --><description><![CDATA[<owned>&value]]></description></opnsense>",
]
INVALID = [
    "",
    "   ",
    '{"result":"ok","secret":"' + SECRET + '"}',
    '["' + SECRET + '"]',
    "<opnsense>" + SECRET,
    "<html><body>" + SECRET + "</body></html>",
    "<pfsense><secret>" + SECRET + "</secret></pfsense>",
    "<!DOCTYPE opnsense><opnsense><secret>" + SECRET + "</secret></opnsense>",
    '<!DOCTYPE opnsense [<!ENTITY x "' + SECRET + '">]><opnsense>&x;</opnsense>',
]


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.55", username="owned-key", password="owned-secret", verify_ssl=True
    )
    client = adapter._api
    client.max_retries = 1
    state = {"body": VALID[0], "status": 200, "error": None, "requests": []}

    async def response(request):
        state["requests"].append(request)
        assert request.method == "GET"
        assert request.url.path == "/api/core/backup/download/this"
        if state["error"]:
            raise state["error"]
        return httpx.Response(
            state["status"],
            content=state["body"].encode(),
            headers={"Content-Type": "application/octet-stream"},
        )

    client._client = httpx.AsyncClient(
        base_url=client.base_url, transport=httpx.MockTransport(response)
    )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    log = logging.getLogger("app.adapters.opnsense.adapter")
    log.addHandler(handler)
    try:
        yield adapter, client, state, stream
    finally:
        log.removeHandler(handler)
        await adapter.disconnect()


@pytest.mark.parametrize("entry", ["client", "adapter"])
@pytest.mark.parametrize("body", VALID)
async def test_valid_xml_is_preserved_without_json_parsing(wire, entry, body):
    adapter, client, state, logs = wire
    state["body"] = body
    result = await (client if entry == "client" else adapter).download_config()
    if entry == "adapter":
        assert result.success is True
        result = result.data
    assert result == {"config_xml": body}
    assert len(state["requests"]) == 1
    assert SECRET not in logs.getvalue()


@pytest.mark.parametrize("entry", ["client", "adapter"])
@pytest.mark.parametrize("body", INVALID)
async def test_non_configuration_documents_are_refused_without_body_diagnostics(wire, entry, body):
    adapter, client, state, logs = wire
    state["body"] = body
    if entry == "client":
        with pytest.raises(OPNsenseAPIError, match="^" + INVALID_MESSAGE + "$"):
            await client.download_config()
    else:
        result = await adapter.download_config()
        assert result.success is False and result.data is None
        assert result.error == "Configuration download failed"
        assert result.error_code == "DOWNLOAD_FAILED"
    assert len(state["requests"]) == 1
    assert SECRET not in logs.getvalue() and "Traceback" not in logs.getvalue()


@pytest.mark.parametrize("entry", ["client", "adapter"])
@pytest.mark.parametrize("failure", [401, 403, 500, "connection", "timeout"])
async def test_transport_failure_remains_failure_with_safe_adapter_diagnostics(
    wire, entry, failure
):
    adapter, client, state, logs = wire
    state["body"] = '{"message":"' + SECRET + '"}'
    if isinstance(failure, int):
        state["status"] = failure
        expected = AdapterAuthenticationError if failure == 401 else OPNsenseAPIError
    else:
        state["error"] = (httpx.ConnectError if failure == "connection" else httpx.ReadTimeout)(
            SECRET
        )
        expected = AdapterConnectionError
    if entry == "client":
        with pytest.raises(expected):
            await client.download_config()
    else:
        result = await adapter.download_config()
        assert result.success is False and result.data is None
        assert result.error == "Configuration download failed"
        assert result.error_code == "DOWNLOAD_FAILED"
        assert SECRET not in logs.getvalue() and "Traceback" not in logs.getvalue()


@pytest.mark.parametrize("entry", ["client", "adapter"])
async def test_cancellation_propagates(wire, entry):
    adapter, client, state, _ = wire
    state["error"] = asyncio.CancelledError("owned-cancellation")
    with pytest.raises(asyncio.CancelledError):
        await (client if entry == "client" else adapter).download_config()


@pytest.mark.parametrize("entry", ["client", "adapter"])
async def test_parser_limit_rejects_large_xml(wire, entry):
    adapter, client, state, logs = wire
    state["body"] = (
        "<opnsense><secret>" + SECRET + ("x" * (16 * 1024 * 1024)) + "</secret></opnsense>"
    )
    if entry == "client":
        with pytest.raises(OPNsenseAPIError, match="^" + INVALID_MESSAGE + "$"):
            await client.download_config()
    else:
        result = await adapter.download_config()
        assert result.success is False and result.data is None
        assert result.error == "Configuration download failed"
    assert SECRET not in logs.getvalue() and "Traceback" not in logs.getvalue()
