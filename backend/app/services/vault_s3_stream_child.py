"""Fixed read-only S3 worker: bounded secret stdin, bounded archive stdout."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import resource
import signal
import sys
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from botocore.awsrequest import AWSPreparedRequest, AWSRequest, AWSResponse

    class _URLLib3Session:
        """The installed botocore session surface; botocore supplies no inline types."""

        def __init__(self, **kwargs: Any) -> None: ...
        def _get_pool_manager_kwargs(self, **extra: Any) -> dict[str, Any]: ...
        def send(self, request: AWSPreparedRequest) -> AWSResponse: ...


REQUEST_BYTES = 65536
CHUNK_BYTES = 65536
MAX_BYTES = 200 * 1024 * 1024


def limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    signal.alarm(61)
    limit(resource.RLIMIT_CORE, 0)
    limit(resource.RLIMIT_AS, 256 * 1024 * 1024)
    limit(resource.RLIMIT_CPU, 20)
    limit(resource.RLIMIT_NOFILE, 64)
    limit(resource.RLIMIT_FSIZE, 0)
    raw = sys.stdin.buffer.read(REQUEST_BYTES + 1)
    if len(raw) > REQUEST_BYTES:
        return 2
    value = json.loads(raw)
    fields = {
        "bucket",
        "key",
        "limit",
        "scheme",
        "hostname",
        "pin",
        "port",
        "basepath",
        "region",
        "access",
        "secret",
        "token",
        "expires",
        "verify",
        "client_cert",
        "options",
        "proxies",
        "proxies_config",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return 2
    for name in ("bucket", "key", "hostname", "pin", "region", "access", "secret"):
        if not isinstance(value[name], str) or not value[name] or len(value[name]) > REQUEST_BYTES:
            return 2
    if value["token"] is not None and not isinstance(value["token"], str):
        return 2
    if (
        value["scheme"] not in {"http", "https"}
        or type(value["port"]) is not int
        or not 1 <= value["port"] <= 65535
    ):
        return 2
    if type(value["limit"]) is not int or not 1 <= value["limit"] <= MAX_BYTES:
        return 2
    expiry = value["expires"]
    if expiry is not None and (
        type(expiry) not in (int, float) or not math.isfinite(expiry) or time.time() >= expiry
    ):
        return 2
    pin = str(ipaddress.ip_address(value["pin"]))
    host = "[" + pin + "]" if ":" in pin else pin
    endpoint = urlunsplit(
        (value["scheme"], host + ":" + str(value["port"]), value["basepath"], "", "")
    )
    parsed = urlsplit(endpoint)
    route = (value["scheme"], pin, value["port"])
    if (
        (parsed.scheme, parsed.hostname, parsed.port) != route
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        return 2
    if (
        value["scheme"] == "https"
        and value["verify"] is not True
        and not isinstance(value["verify"], str)
    ):
        return 2
    options = value["options"]
    if not isinstance(options, dict) or set(options) != {
        "signature_version",
        "connect_timeout",
        "read_timeout",
        "retries",
        "s3",
        "request_checksum_calculation",
        "response_checksum_validation",
    }:
        return 2
    if (
        options["signature_version"] != "s3v4"
        or not isinstance(options["s3"], dict)
        or options["s3"].get("addressing_style") != "path"
    ):
        return 2
    for field in ("proxies", "proxies_config"):
        if not isinstance(value[field], dict):
            return 2
    # Imports occur only after resource and control-input limits. Explicit
    # credentials prevent a profile, IMDS or credential_process in this worker.
    import boto3
    from botocore.config import Config

    if not TYPE_CHECKING:
        from botocore.httpsession import URLLib3Session as _URLLib3Session

    def check_route(url: str) -> None:
        target = urlsplit(url)
        if (
            target.username
            or target.password
            or (
                target.scheme,
                target.hostname,
                target.port or (443 if target.scheme == "https" else 80),
            )
            != route
        ):
            raise ValueError("Destination changed")

    hostname = value["hostname"]
    header = "[" + hostname + "]" if ":" in hostname else hostname
    if value["port"] != (443 if value["scheme"] == "https" else 80):
        header += ":" + str(value["port"])

    class PinnedSession(_URLLib3Session):
        def _get_pool_manager_kwargs(self, **extra: Any) -> dict[str, Any]:
            if value["scheme"] == "https":
                extra.update(assert_hostname=hostname, server_hostname=hostname)
            return super()._get_pool_manager_kwargs(**extra)

        def send(self, request: AWSPreparedRequest) -> AWSResponse:
            check_route(request.url)
            return super().send(request)

    def before_sign(request: AWSRequest, **_kwargs: Any) -> None:
        check_route(request.url)
        request.headers["Host"] = header

    client = body = original = None
    try:
        client = boto3.session.Session().client(
            "s3",
            endpoint_url=endpoint,
            region_name=value["region"],
            aws_access_key_id=value["access"],
            aws_secret_access_key=value["secret"],
            aws_session_token=value["token"],
            verify=value["verify"],
            config=Config(
                **options,
                proxies=value["proxies"],
                proxies_config=value["proxies_config"],
                client_cert=tuple(value["client_cert"])
                if isinstance(value["client_cert"], list)
                else value["client_cert"],
            ),
        )
        original = client._endpoint.http_session
        cert = (
            tuple(value["client_cert"])
            if isinstance(value["client_cert"], list)
            else value["client_cert"]
        )
        client._endpoint.http_session = PinnedSession(
            verify=value["verify"],
            proxies=value["proxies"],
            proxies_config=value["proxies_config"],
            timeout=(options["connect_timeout"], options["read_timeout"]),
            client_cert=cert,
            max_pool_connections=1,
        )
        original.close()
        client.meta.events.register("before-sign.s3", before_sign)
        response = client.get_object(Bucket=value["bucket"], Key=value["key"])
        body = response["Body"]
        length = response.get("ContentLength")
        if length is not None and (type(length) is not int or not 1 <= length <= value["limit"]):
            return 2
        count = 0
        while chunk := body.read(min(CHUNK_BYTES, value["limit"] - count + 1)):
            if (
                not isinstance(chunk, bytes)
                or len(chunk) > CHUNK_BYTES
                or len(chunk) > value["limit"] - count
            ):
                return 2
            count += len(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if (
            not count
            or (length is not None and count != length)
            or (expiry is not None and time.time() >= expiry)
        ):
            return 2
    finally:
        try:
            if body is not None:
                body.close()
        finally:
            try:
                if original is not None:
                    original.close()
            finally:
                if client is not None:
                    client.close()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2
    os._exit(code)
