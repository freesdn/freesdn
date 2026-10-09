# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual app timeout error contract with an owned file; no authentication claim."""

import asyncio
import json
import re
from uuid import UUID

import httpx
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.main import create_application
from tests.services.test_backup_download_response_lifetime import fixture, opened

MESSAGE = 'Backup download preparation exceeded its deadline.'
SECURITY_HEADERS = (
    'x-content-type-options', 'x-frame-options', 'x-xss-protection',
    'referrer-policy', 'permissions-policy', 'cache-control', 'pragma',
    'content-security-policy', 'strict-transport-security',
)


@pytest.mark.parametrize('request_id_kind', ['valid', 'invalid', 'absent'])
@pytest.mark.parametrize('allowed_origin', [False, True])
@pytest.mark.parametrize('https', [False, True])
async def test_actual_app_preheader_timeout_retains_standard_error_and_headers(
    tmp_path, request, request_id_kind, allowed_origin, https,
):
    response, _, _ = fixture(tmp_path, size=127, verified=True, seconds=.2)
    entered = asyncio.Event()

    async def hold_authority():
        entered.set()
        await asyncio.Event().wait()

    response.authorize = hold_authority
    application = create_application()

    @application.get('/owned-deadline-contract')
    async def deadline_route():
        return response

    @application.get('/owned-reference-contract')
    async def reference_route():
        raise HTTPException(504, MESSAGE)

    origin = settings.CORS_ORIGINS[0] if allowed_origin else 'https://untrusted-ui.invalid'
    headers = {'Origin': origin}
    if request_id_kind != 'absent':
        headers['X-Request-ID'] = 'owned-correlation-12' if request_id_kind == 'valid' else 'owned invalid request id'
    base = ('https' if https else 'http') + '://owned-app.test'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url=base) as client:
        reference = await client.get('/owned-reference-contract', headers=headers)
        result = await asyncio.wait_for(client.get('/owned-deadline-contract', headers=headers), 5)
    no_descriptors = not opened(tmp_path / 'spool')
    response.pool.acquire().close()
    actual, expected = result.json(), reference.json()
    request.node.user_properties.extend([
        ('authority_entered', entered.is_set()), ('HTTP_status', result.status_code),
        ('reference_status', reference.status_code), ('actual_body', json.dumps(actual, sort_keys=True)),
        ('reference_body', json.dumps(expected, sort_keys=True)),
        ('actual_headers', json.dumps(dict(result.headers), sort_keys=True)),
        ('reference_headers', json.dumps(dict(reference.headers), sort_keys=True)),
        ('no_snapshot_descriptors', no_descriptors), ('slot_reusable_after_cleanup', True),
        ('source', 'actual create_application middleware and real owned file; no auth/proxy/deployment claim'),
    ])
    assert reference.status_code == result.status_code == 504 and entered.is_set() and no_descriptors
    assert set(expected) == {'error'} and set(expected['error']) == {'code', 'message', 'request_id'}
    assert set(actual) == {'error'} and set(actual['error']) == {'code', 'message', 'request_id'}
    assert actual['error']['code'] == expected['error']['code'] == 504
    assert actual['error']['message'] == expected['error']['message'] == MESSAGE
    for current in (reference, result):
        correlation = current.json()['error']['request_id']
        assert correlation == current.headers['x-request-id']
        if request_id_kind == 'valid':
            assert correlation == 'ext-owned-correlation-12'
        else:
            assert str(UUID(correlation)) == correlation and not correlation.startswith('ext-')
        assert re.fullmatch(r'\d+\.\d{2}ms', current.headers['x-response-time'])
        assert current.headers.get('access-control-allow-origin') == (origin if allowed_origin else None)
    for name in SECURITY_HEADERS:
        assert result.headers.get(name) == reference.headers.get(name), name
    assert ('strict-transport-security' in result.headers) is https
    assert int(result.headers['content-length']) == len(result.content)
