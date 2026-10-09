# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Finished ASGI fixtures must not survive through dependency classifier caches."""

import os
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path


def test_completed_dependency_fixtures_are_collectable(tmp_path):
    cases = tmp_path / "test_owned_fixture_cases.py"
    cases.write_text(textwrap.dedent("""\
        import asyncio
        import gc
        import weakref
        from typing import Annotated

        import pytest
        from fastapi import Depends, FastAPI
        from httpx import ASGITransport, AsyncClient

        retained = []
        closed = []
        original_thresholds = gc.get_threshold()

        class OwnedResource:
            pass

        async def original_dependency():
            raise AssertionError('The owned override must handle this request')

        @pytest.fixture
        def owned_application():
            resource = OwnedResource()
            retained.append(weakref.ref(resource))
            app = FastAPI()
            async def override():
                yield resource
            @app.get('/owned')
            async def endpoint(value: Annotated[OwnedResource, Depends(original_dependency)]):
                assert value is resource
                return {'ok': True}
            app.dependency_overrides[original_dependency] = override
            yield app
            app.dependency_overrides.clear()
            closed.append(True)

        @pytest.mark.parametrize('case', range(3))
        def test_01_owned_request(owned_application, case):
            async def execute():
                async with AsyncClient(transport=ASGITransport(app=owned_application), base_url='http://test') as client:
                    response = await client.get('/owned')
                assert response.status_code == 200 and response.json() == {'ok': True}
            asyncio.run(execute())

        def test_02_finished_fixtures_are_released():
            gc.collect()
            assert closed == [True, True, True]
            assert all(ref() is None for ref in retained), 'Finished dependency closures are retained by callable classification caches'
            assert gc.isenabled() and gc.get_threshold() == original_thresholds
    """))
    junit = tmp_path / "junit.xml"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "tests.conftest",
         "-p", "no:cacheprovider", "-c", os.devnull, "--confcutdir", str(tmp_path),
         "--rootdir", str(tmp_path), "--junitxml", str(junit), "-q", "--tb=short", str(cases)],
        cwd=tmp_path,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "",
             "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    suite = ET.parse(junit).getroot().find("testsuite")
    assert suite is not None
    assert (suite.get("tests"), suite.get("failures"), suite.get("errors")) == ("4", "0", "0")
