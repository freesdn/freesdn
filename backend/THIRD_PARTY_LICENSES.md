<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Third-Party Licenses — FreeSDN Backend

This inventory matches the locked main dependency group on 2026-09-22.
Development tools are excluded; platform markers determine what is installed.
Version and license metadata were read from the matching installed distributions,
with the conditional Windows-only package read from its exact PyPI version.
Full license texts are supplied in the package distributions. Regenerate after
dependency changes; this inventory does not cover OS packages or bundled VPN tools.
VPN source licenses and modification notices are included in the image under
`/usr/share/licenses/{tailscale,netbird}` and in their build directories.

| Package | Version | License | Source |
|---|---|---|---|
| aiohappyeyeballs | 2.7.1 | Python Software Foundation License | https://github.com/aio-libs/aiohappyeyeballs |
| aiohttp | 3.14.3 | Apache-2.0 AND MIT | https://github.com/aio-libs/aiohttp |
| aiosignal | 1.4.0 | Apache Software License | https://github.com/aio-libs/aiosignal |
| alembic | 1.20.0 | MIT | https://alembic.sqlalchemy.org |
| amqp | 5.4.0 | BSD License | http://github.com/celery/py-amqp |
| annotated-doc | 0.0.5 | MIT | https://github.com/fastapi/annotated-doc |
| annotated-types | 0.8.0 | MIT | https://github.com/annotated-types/annotated-types |
| anyio | 4.15.1 | MIT | https://pypi.org/project/anyio/ |
| argon2-cffi | 25.1.0 | MIT | https://pypi.org/project/argon2-cffi/ |
| argon2-cffi-bindings | 26.1.0 | MIT | https://pypi.org/project/argon2-cffi-bindings/ |
| asyncpg | 0.31.0 | Apache-2.0 | https://pypi.org/project/asyncpg/ |
| attrs | 26.1.0 | MIT | https://pypi.org/project/attrs/ |
| babel | 2.18.0 | BSD License | https://github.com/python-babel/babel |
| bcrypt | 5.0.0 | Apache Software License | https://github.com/pyca/bcrypt/ |
| billiard | 4.3.0 | BSD License | https://github.com/celery/billiard |
| boto3 | 1.43.99 | Apache-2.0 | https://github.com/boto/boto3 |
| botocore | 1.43.99 | Apache-2.0 | https://github.com/boto/botocore |
| celery | 5.6.3 | BSD-3-Clause | https://docs.celeryq.dev/ |
| certifi | 2026.7.22 | Mozilla Public License 2.0 (MPL 2.0) | https://github.com/certifi/python-certifi |
| cffi | 2.1.1 | MIT-0 | https://pypi.org/project/cffi/ |
| charset-normalizer | 3.5.1 | MIT | https://pypi.org/project/charset-normalizer/ |
| click | 8.5.0 | BSD-3-Clause | https://github.com/pallets/click/ |
| click-didyoumean | 0.3.1 | MIT License | https://github.com/click-contrib/click-didyoumean |
| click-plugins | 1.1.1.2 | BSD License | https://github.com/click-contrib/click-plugins |
| click-repl | 0.4.0 | MIT | https://github.com/click-contrib/click-repl |
| colorama | 0.4.6 | See distribution license | https://pypi.org/project/colorama/0.4.6/ |
| croniter | 6.2.4 | MIT | https://github.com/pallets-eco/croniter |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| defusedxml | 0.7.1 | Python Software Foundation License | https://github.com/tiran/defusedxml |
| dnspython | 2.8.0 | ISC License (ISCL) | https://www.dnspython.org |
| dropbox | 12.2.1 | MIT | http://www.dropbox.com/developers |
| email-validator | 2.3.0 | The Unlicense (Unlicense) | https://github.com/JoshData/python-email-validator |
| fastapi | 0.141.1 | MIT | https://github.com/fastapi/fastapi |
| flower | 2.1.0 | BSD License | https://github.com/mher/flower |
| frozenlist | 1.8.0 | Apache-2.0 | https://github.com/aio-libs/frozenlist |
| google-api-core | 2.38.0 | Apache Software License | https://github.com/googleapis/google-cloud-python/tree/main/packages/google-api-core |
| google-api-python-client | 2.200.0 | Apache Software License | https://github.com/googleapis/google-api-python-client/ |
| google-auth | 2.58.0 | Apache Software License | https://github.com/googleapis/google-cloud-python/tree/main/packages/google-auth |
| google-auth-httplib2 | 0.4.2 | Apache Software License | https://github.com/googleapis/google-cloud-python/packages/google-auth-httplib2 |
| googleapis-common-protos | 1.75.3 | Apache-2.0 | https://github.com/googleapis/google-cloud-python/tree/main/packages/googleapis-common-protos |
| greenlet | 3.5.6 | MIT AND PSF-2.0 | https://greenlet.readthedocs.io |
| gunicorn | 26.2.0 | MIT | https://gunicorn.org |
| h11 | 0.16.0 | MIT License | https://github.com/python-hyper/h11 |
| hiredis | 3.4.1 | MIT License | https://github.com/redis/hiredis-py |
| http-ece | 1.2.1 | MIT License | https://github.com/martinthomson/encrypted-content-encoding |
| httpcore | 1.0.9 | BSD-3-Clause | https://www.encode.io/httpcore/ |
| httplib2 | 0.32.0 | MIT License | https://github.com/httplib2/httplib2 |
| httptools | 0.8.0 | MIT | https://github.com/MagicStack/httptools |
| httpx | 0.28.1 | BSD License | https://github.com/encode/httpx |
| humanize | 4.16.0 | MIT | https://github.com/python-humanize/humanize |
| idna | 3.20 | BSD-3-Clause | https://github.com/kjd/idna |
| invoke | 3.0.3 | BSD-2-Clause | https://github.com/pyinvoke/invoke |
| isodate | 0.7.2 | BSD License | https://github.com/gweis/isodate/ |
| jinja2 | 3.1.6 | BSD License | https://github.com/pallets/jinja/ |
| jmespath | 1.1.0 | MIT License | https://github.com/jmespath/jmespath.py |
| kombu | 5.6.2 | BSD-3-Clause | https://github.com/celery/kombu |
| lxml | 6.1.3 | BSD-3-Clause | https://github.com/lxml/lxml |
| mako | 1.4.1 | MIT | https://www.makotemplates.org/ |
| markupsafe | 3.0.3 | BSD-3-Clause | https://github.com/pallets/markupsafe/ |
| multidict | 6.9.1 | Apache License 2.0 | https://github.com/aio-libs/multidict |
| onvif-zeep | 0.2.12 | MIT | http://github.com/quatanium/python-onvif |
| opentelemetry-api | 1.44.0 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api |
| orjson | 3.12.0 | MPL-2.0 AND (Apache-2.0 OR MIT) | https://github.com/ijl/orjson |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| paramiko | 5.0.0 | LGPL-2.1 | https://github.com/paramiko/paramiko |
| pillow | 12.3.0 | MIT-CMU | https://python-pillow.github.io |
| platformdirs | 4.11.12 | MIT | https://github.com/tox-dev/platformdirs |
| prometheus-client | 0.26.0 | Apache-2.0 AND BSD-2-Clause | https://github.com/prometheus/client_python |
| prometheus-fastapi-instrumentator | 8.1.0 | ISC | https://github.com/trallnag/prometheus-fastapi-instrumentator |
| prompt-toolkit | 3.0.53 | BSD License | https://github.com/prompt-toolkit/python-prompt-toolkit |
| propcache | 0.5.4 | Apache-2.0 | https://github.com/aio-libs/propcache |
| proto-plus | 1.28.4 | Apache Software License | https://github.com/googleapis/google-cloud-python |
| protobuf | 7.36.2 | 3-Clause BSD License | https://developers.google.com/protocol-buffers/ |
| psycopg | 3.3.6 | LGPL-3.0-only | https://psycopg.org/ |
| psycopg-binary | 3.3.6 | LGPL-3.0-only | https://psycopg.org/ |
| py-vapid | 1.9.4 | MPL-2.0 | https://github.com/mozilla-services/vapid |
| pyasn1 | 0.6.4 | BSD-2-Clause | https://github.com/pyasn1/pyasn1 |
| pyasn1-modules | 0.4.2 | BSD License | https://github.com/pyasn1/pyasn1-modules |
| pycparser | 3.0 | BSD-3-Clause | https://github.com/eliben/pycparser |
| pydantic | 2.13.5 | MIT | https://github.com/pydantic/pydantic |
| pydantic-core | 2.46.5 | MIT | https://github.com/pydantic |
| pydantic-settings | 2.15.0 | MIT | https://github.com/pydantic/pydantic-settings |
| pygments | 2.21.0 | BSD-2-Clause | https://pygments.org |
| pyjwt | 2.14.0 | MIT | https://github.com/jpadilla/pyjwt |
| pynacl | 1.6.2 | Apache Software License | https://github.com/pyca/pynacl |
| pyotp | 2.10.0 | MIT | https://github.com/pyauth/pyotp |
| pyparsing | 3.3.3 | MIT | https://github.com/pyparsing/pyparsing/ |
| python-dateutil | 2.9.0.post0 | BSD License | https://github.com/dateutil/dateutil |
| python-dotenv | 1.2.3 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| python-multipart | 0.0.32 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| pytz | 2026.3.post1 | MIT License | https://github.com/stub42/pytz.git |
| pywebpush | 2.5.0 | MPL-2.0 | https://github.com/web-push-libs/pywebpush |
| pyyaml | 6.0.3 | MIT License | https://pyyaml.org/ |
| qrcode | 8.2 | BSD License | https://github.com/lincolnloop/python-qrcode |
| redis | 6.4.0 | MIT | https://github.com/redis/redis-py |
| reportlab | 5.0.1 | BSD License | https://www.reportlab.com/ |
| requests | 2.34.2 | Apache Software License | https://github.com/psf/requests |
| requests-file | 3.0.1 | Apache Software License | https://codeberg.org/dashea/requests-file |
| requests-toolbelt | 1.0.0 | Apache Software License | https://github.com/requests/toolbelt |
| s3transfer | 0.19.2 | Apache Software License | https://github.com/boto/s3transfer |
| six | 1.17.0 | MIT License | https://github.com/benjaminp/six |
| sqlalchemy | 2.0.54 | MIT | https://www.sqlalchemy.org |
| starlette | 1.6.0 | BSD-3-Clause | https://github.com/Kludex/starlette |
| stone | 3.5.4 | MIT | https://github.com/dropbox/stone |
| tornado | 6.5.10 | Apache Software License | https://github.com/tornadoweb/tornado |
| typing-extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions |
| typing-inspection | 0.4.4 | MIT | https://github.com/pydantic/typing-inspection |
| tzdata | 2026.4 | Apache-2.0 | https://github.com/python/tzdata |
| tzlocal | 5.4.4 | MIT | https://pypi.org/project/tzlocal/ |
| uritemplate | 4.2.0 | BSD 3-Clause OR Apache-2.0 | https://github.com/python-hyper/uritemplate |
| urllib3 | 2.8.0 | MIT | https://pypi.org/project/urllib3/ |
| uv | 0.12.17 | Apache-2.0 OR MIT | https://github.com/astral-sh/uv |
| uvicorn | 0.53.0 | BSD-3-Clause | https://uvicorn.dev/ |
| uvloop | 0.22.1 | Apache Software License | https://pypi.org/project/uvloop/ |
| vine | 5.1.0 | BSD License | https://github.com/celery/vine |
| watchfiles | 1.3.0 | MIT License | https://github.com/samuelcolvin/watchfiles |
| wcwidth | 0.8.4 | MIT | https://github.com/jquast/wcwidth |
| websockets | 17.1 | BSD-3-Clause | https://github.com/python-websockets/websockets |
| yarl | 1.25.1 | Apache-2.0 | https://github.com/aio-libs/yarl |
| zeep | 4.3.3 | MIT License | https://github.com/mvantellingen/python-zeep |
