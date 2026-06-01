<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Third-Party Licenses — FreeSDN Backend

FreeSDN is licensed under the GNU AGPL-3.0 (see ../LICENSE). The backend
bundles the third-party Python packages listed below, each under its own
license (all OSI-approved and AGPL-compatible). This file provides the
required attribution; the full license text for each package ships inside its
distribution on PyPI, and `poetry.lock` pins the exact versions and hashes.

_Auto-generated from the production dependency set (the `poetry.lock` main
group). Regenerate after dependency changes:_

```
poetry install --only main --no-root && pip install pip-licenses
pip-licenses --from=mixed --with-urls --format=markdown --order=name
```

| Package | Version | License | Source |
|---|---|---|---|
| aiohappyeyeballs | 2.6.2 | Python Software Foundation License | https://github.com/aio-libs/aiohappyeyeballs |
| aiohttp | 3.14.1 | Apache-2.0 AND MIT | https://github.com/aio-libs/aiohttp |
| aiosignal | 1.4.0 | Apache Software License | https://github.com/aio-libs/aiosignal |
| alembic | 1.18.4 | MIT | https://alembic.sqlalchemy.org |
| amqp | 5.3.1 | BSD License | http://github.com/celery/py-amqp |
| annotated-doc | 0.0.4 | MIT | https://github.com/fastapi/annotated-doc |
| annotated-types | 0.7.0 | MIT License | https://github.com/annotated-types/annotated-types |
| anyio | 4.14.0 | MIT | https://anyio.readthedocs.io/en/stable/versionhistory.html |
| argon2-cffi | 25.1.0 | MIT | https://github.com/hynek/argon2-cffi/blob/main/CHANGELOG.md |
| argon2-cffi-bindings | 25.1.0 | MIT | https://github.com/hynek/argon2-cffi-bindings/blob/main/CHANGELOG.md |
| asyncpg | 0.31.0 | Apache-2.0 |  |
| attrs | 26.1.0 | MIT | https://www.attrs.org/en/stable/changelog.html |
| babel | 2.18.0 | BSD License | https://babel.pocoo.org/ |
| billiard | 4.2.4 | BSD License | https://github.com/celery/billiard |
| celery | 5.6.3 | BSD-3-Clause | https://docs.celeryq.dev/ |
| certifi | 2026.5.20 | Mozilla Public License 2.0 (MPL 2.0) | https://github.com/certifi/python-certifi |
| cffi | 2.0.0 | MIT | https://cffi.readthedocs.io/en/latest/whatsnew.html |
| charset-normalizer | 3.4.7 | MIT | https://github.com/jawah/charset_normalizer/blob/master/CHANGELOG.md |
| click | 8.4.1 | BSD-3-Clause | https://github.com/pallets/click/ |
| click-didyoumean | 0.3.1 | MIT License | https://github.com/click-contrib/click-didyoumean |
| click-plugins | 1.1.1.2 | BSD License | https://github.com/click-contrib/click-plugins |
| click-repl | 0.3.0 | MIT | https://github.com/untitaker/click-repl |
| cryptography | 49.0.0 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| defusedxml | 0.7.1 | Python Software Foundation License | https://github.com/tiran/defusedxml |
| dnspython | 2.8.0 | ISC License (ISCL) | https://www.dnspython.org |
| email-validator | 2.3.0 | The Unlicense (Unlicense) | https://github.com/JoshData/python-email-validator |
| fastapi | 0.136.3 | MIT | https://github.com/fastapi/fastapi |
| flower | 2.0.1 | BSD License | https://github.com/mher/flower |
| frozenlist | 1.8.0 | Apache-2.0 | https://github.com/aio-libs/frozenlist |
| greenlet | 3.5.1 | MIT AND PSF-2.0 | https://greenlet.readthedocs.io |
| gunicorn | 26.0.0 | MIT | https://gunicorn.org |
| h11 | 0.16.0 | MIT License | https://github.com/python-hyper/h11 |
| hiredis | 3.4.0 | MIT License | https://github.com/redis/hiredis-py |
| http_ece | 1.2.1 | MIT License | https://github.com/martinthomson/encrypted-content-encoding |
| httpcore | 1.0.9 | BSD-3-Clause | https://www.encode.io/httpcore/ |
| httptools | 0.8.0 | MIT | https://github.com/MagicStack/httptools |
| httpx | 0.28.1 | BSD License | https://github.com/encode/httpx |
| humanize | 4.15.0 | MIT | https://github.com/python-humanize/humanize |
| idna | 3.18 | BSD-3-Clause | https://github.com/kjd/idna |
| isodate | 0.7.2 | BSD License | https://github.com/gweis/isodate/ |
| Jinja2 | 3.1.6 | BSD License | https://github.com/pallets/jinja/ |
| kombu | 5.6.2 | BSD-3-Clause | https://kombu.readthedocs.io |
| lxml | 6.1.1 | BSD-3-Clause | https://lxml.de/ |
| Mako | 1.3.12 | MIT License | https://www.makotemplates.org/ |
| MarkupSafe | 3.0.3 | BSD-3-Clause | https://github.com/pallets/markupsafe/ |
| multidict | 6.7.1 | Apache License 2.0 | https://github.com/aio-libs/multidict |
| onvif_zeep | 0.2.12 | MIT | http://github.com/quatanium/python-onvif |
| orjson | 3.11.9 | MPL-2.0 AND (Apache-2.0 OR MIT) | https://github.com/ijl/orjson |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| pillow | 12.2.0 | MIT-CMU | https://python-pillow.github.io |
| platformdirs | 4.10.0 | MIT | https://github.com/tox-dev/platformdirs |
| prometheus-fastapi-instrumentator | 7.1.0 | ISC | https://github.com/trallnag/prometheus-fastapi-instrumentator |
| prometheus_client | 0.25.0 | Apache-2.0 AND BSD-2-Clause | https://github.com/prometheus/client_python |
| prompt_toolkit | 3.0.52 | BSD License | https://github.com/prompt-toolkit/python-prompt-toolkit |
| propcache | 0.5.2 | Apache Software License | https://github.com/aio-libs/propcache |
| psycopg | 3.3.4 | LGPL-3.0-only | https://psycopg.org/ |
| psycopg-binary | 3.3.4 | LGPL-3.0-only | https://psycopg.org/ |
| py-vapid | 1.9.4 | MPL-2.0 | https://github.com/mozilla-services/vapid |
| pycparser | 3.0 | BSD-3-Clause | https://github.com/eliben/pycparser |
| pydantic | 2.13.4 | MIT | https://github.com/pydantic/pydantic |
| pydantic-settings | 2.14.1 | MIT | https://github.com/pydantic/pydantic-settings |
| pydantic_core | 2.46.4 | MIT | https://github.com/pydantic |
| Pygments | 2.20.0 | BSD-2-Clause | https://pygments.org |
| PyJWT | 2.13.0 | MIT | https://github.com/jpadilla/pyjwt |
| PyOTP | 2.10.0 | MIT | https://github.com/pyauth/pyotp |
| python-dateutil | 2.9.0.post0 | Apache Software License; BSD License | https://github.com/dateutil/dateutil |
| python-dotenv | 1.2.2 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| python-multipart | 0.0.32 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| pytz | 2026.2 | MIT License | http://pythonhosted.org/pytz |
| pywebpush | 2.3.0 | MPL-2.0 | https://github.com/web-push-libs/pywebpush |
| PyYAML | 6.0.3 | MIT License | https://pyyaml.org/ |
| qrcode | 8.2 | BSD-3-Clause | https://github.com/lincolnloop/python-qrcode |
| redis | 6.4.0 | MIT | https://github.com/redis/redis-py |
| requests | 2.34.2 | Apache Software License | https://github.com/psf/requests |
| requests-file | 3.0.1 | Apache Software License | https://codeberg.org/dashea/requests-file |
| requests-toolbelt | 1.0.0 | Apache Software License | https://toolbelt.readthedocs.io/ |
| six | 1.17.0 | MIT License | https://github.com/benjaminp/six |
| SQLAlchemy | 2.0.51 | MIT | https://www.sqlalchemy.org |
| starlette | 0.52.1 | BSD-3-Clause | https://github.com/Kludex/starlette |
| tornado | 6.5.7 | Apache Software License | http://www.tornadoweb.org/ |
| typing-inspection | 0.4.2 | MIT | https://github.com/pydantic/typing-inspection |
| typing_extensions | 4.15.0 | PSF-2.0 | https://github.com/python/typing_extensions |
| tzdata | 2026.2 | Apache-2.0 | https://github.com/python/tzdata |
| tzlocal | 5.4 | MIT | https://github.com/regebro/tzlocal/blob/master/CHANGES.txt |
| urllib3 | 2.7.0 | MIT | https://github.com/urllib3/urllib3/blob/main/CHANGES.rst |
| uvicorn | 0.49.0 | BSD-3-Clause | https://uvicorn.dev/ |
| uvloop | 0.22.1 | Apache Software License; MIT License |  |
| vine | 5.1.0 | BSD License | https://github.com/celery/vine |
| watchfiles | 1.2.0 | MIT License | https://github.com/samuelcolvin/watchfiles |
| websockets | 16.0 | BSD-3-Clause | https://github.com/python-websockets/websockets |
| yarl | 1.24.2 | Apache-2.0 | https://github.com/aio-libs/yarl |
| zeep | 4.3.2 | MIT License | https://github.com/mvantellingen/python-zeep |
