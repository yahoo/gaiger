# Third-Party Notices

This file lists the third-party Python packages in Gaiger's runtime image
and their licenses: every package in `requirements.lock` (direct and
transitive), as installed on the image's Python 3.12.

Generated with `pip-licenses --with-urls --format=markdown` in a fresh
python:3.12-slim container holding only `pip install --require-hashes -r
requirements.lock` (pip-licenses excludes itself and its own dependencies).
Regenerate it the same way whenever `requirements.lock` changes.

## Python packages

| Name                                     | Version    | License                                             | URL                                                                                                                            |
|------------------------------------------|------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| PyGithub                                 | 2.10.0     | GNU Library or Lesser General Public License (LGPL) | https://github.com/pygithub/pygithub                                                                                           |
| PyJWT                                    | 2.15.1     | MIT                                                 | https://github.com/jpadilla/pyjwt                                                                                              |
| PyNaCl                                   | 1.6.2      | Apache Software License                             | https://github.com/pyca/pynacl                                                                                                 |
| PyYAML                                   | 6.0.3      | MIT License                                         | https://pyyaml.org/                                                                                                            |
| aiohappyeyeballs                         | 2.7.1      | Python Software Foundation License                  | https://github.com/aio-libs/aiohappyeyeballs                                                                                   |
| aiohttp                                  | 3.14.5     | Apache-2.0 AND MIT                                  | https://github.com/aio-libs/aiohttp                                                                                            |
| aiohttp-retry                            | 2.9.1      | MIT License                                         | https://github.com/inyutin/aiohttp_retry                                                                                       |
| aiosignal                                | 1.4.0      | Apache Software License                             | https://github.com/aio-libs/aiosignal                                                                                          |
| annotated-doc                            | 0.0.5      | MIT                                                 | https://github.com/fastapi/annotated-doc                                                                                       |
| annotated-types                          | 0.8.0      | MIT                                                 | https://github.com/annotated-types/annotated-types                                                                             |
| anthropic                                | 0.125.0    | MIT License                                         | https://github.com/anthropics/anthropic-sdk-python                                                                             |
| anyio                                    | 4.15.1     | MIT                                                 | https://anyio.readthedocs.io/en/stable/versionhistory.html                                                                     |
| asgiref                                  | 3.13.0     | BSD-3-Clause                                        | https://github.com/django/asgiref/                                                                                             |
| asyncpg                                  | 0.32.0     | Apache-2.0                                          | UNKNOWN                                                                                                                        |
| attrs                                    | 26.1.0     | MIT                                                 | https://www.attrs.org/en/stable/changelog.html                                                                                 |
| certifi                                  | 2026.10.23 | Mozilla Public License 2.0 (MPL 2.0)                | https://github.com/certifi/python-certifi                                                                                      |
| cffi                                     | 2.1.1      | MIT-0                                               | https://cffi.readthedocs.io/en/latest/whatsnew.html                                                                            |
| charset-normalizer                       | 3.5.2      | MIT                                                 | https://github.com/jawah/charset_normalizer/blob/master/CHANGELOG.md                                                           |
| click                                    | 8.5.0      | BSD-3-Clause                                        | https://github.com/pallets/click/                                                                                              |
| cryptography                             | 50.0.2     | Apache-2.0 OR BSD-3-Clause                          | https://github.com/pyca/cryptography                                                                                           |
| distro                                   | 1.9.0      | Apache Software License                             | https://github.com/python-distro/distro                                                                                        |
| docstring_parser                         | 0.18.0     | MIT License                                         | https://github.com/rr-/docstring_parser                                                                                        |
| durationpy                               | 0.11       | MIT                                                 | https://github.com/icholy/durationpy                                                                                           |
| fastapi                                  | 0.141.1    | MIT                                                 | https://github.com/fastapi/fastapi                                                                                             |
| frozenlist                               | 1.8.0      | Apache-2.0                                          | https://github.com/aio-libs/frozenlist                                                                                         |
| googleapis-common-protos                 | 1.76.0     | Apache-2.0                                          | https://github.com/googleapis/google-cloud-python/tree/main/packages/googleapis-common-protos                                  |
| grpcio                                   | 1.85.0     | Apache-2.0                                          | https://grpc.io                                                                                                                |
| h11                                      | 0.16.0     | MIT License                                         | https://github.com/python-hyper/h11                                                                                            |
| httpcore                                 | 1.0.9      | BSD-3-Clause                                        | https://www.encode.io/httpcore/                                                                                                |
| httpcore2                                | 2.16.0     | BSD-3-Clause                                        | https://github.com/pydantic/httpx2                                                                                             |
| httptools                                | 0.9.0      | MIT                                                 | https://github.com/MagicStack/httptools                                                                                        |
| httpx                                    | 0.28.1     | BSD License                                         | https://github.com/encode/httpx                                                                                                |
| httpx2                                   | 2.16.0     | BSD-3-Clause                                        | https://github.com/pydantic/httpx2                                                                                             |
| idna                                     | 3.20       | BSD-3-Clause                                        | https://github.com/kjd/idna                                                                                                    |
| importlib_metadata                       | 8.7.1      | Apache-2.0                                          | https://github.com/python/importlib_metadata                                                                                   |
| jiter                                    | 0.18.0     | MIT                                                 | https://github.com/pydantic/jiter/                                                                                             |
| jsonpatch                                | 1.38       | BSD-3-Clause                                        | https://github.com/stefankoegl/python-json-patch                                                                               |
| jsonpointer                              | 3.6        | BSD License                                         | https://github.com/stefankoegl/python-json-pointer                                                                             |
| kubernetes                               | 37.0.1     | Apache-2.0                                          | https://github.com/kubernetes-client/python                                                                                    |
| langchain-anthropic                      | 1.7.6      | MIT License                                         | https://docs.langchain.com/oss/python/integrations/providers/anthropic                                                         |
| langchain-core                           | 1.7.0      | MIT License                                         | https://docs.langchain.com/                                                                                                    |
| langchain-protocol                       | 0.0.20     | MIT License                                         | https://github.com/langchain-ai/agent-protocol/tree/main/streaming                                                             |
| langgraph                                | 1.2.18     | MIT                                                 | https://docs.langchain.com/oss/python/langgraph/overview                                                                       |
| langgraph-checkpoint                     | 4.3.1      | MIT                                                 | https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint                                                            |
| langgraph-prebuilt                       | 1.1.1      | MIT                                                 | https://github.com/langchain-ai/langgraph/tree/main/libs/prebuilt                                                              |
| langgraph-sdk                            | 0.4.10     | MIT                                                 | https://github.com/langchain-ai/langgraph/tree/main/libs/sdk-py                                                                |
| langsmith                                | 0.14.13    | MIT License                                         | https://github.com/langchain-ai/langsmith-python                                                                               |
| multidict                                | 7.2.1      | Apache-2.0                                          | https://github.com/aio-libs/multidict                                                                                          |
| oauthlib                                 | 4.0.1      | BSD-3-Clause                                        | https://github.com/oauthlib/oauthlib                                                                                           |
| openinference-instrumentation            | 0.1.72     | Apache-2.0                                          | https://github.com/Arize-ai/openinference/tree/main/python/openinference-instrumentation                                       |
| openinference-instrumentation-langchain  | 0.1.80     | Apache-2.0                                          | https://github.com/Arize-ai/openinference/tree/main/python/instrumentation/openinference-instrumentation-langchain             |
| openinference-semantic-conventions       | 0.1.42     | Apache-2.0                                          | https://github.com/Arize-ai/openinference/tree/main/python/openinference-semantic-conventions                                  |
| opentelemetry-api                        | 1.40.0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api                                             |
| opentelemetry-exporter-otlp-proto-common | 1.40.0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/exporter/opentelemetry-exporter-otlp-proto-common             |
| opentelemetry-exporter-otlp-proto-grpc   | 1.40.0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/exporter/opentelemetry-exporter-otlp-proto-grpc               |
| opentelemetry-instrumentation            | 0.61b0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/opentelemetry-instrumentation                         |
| opentelemetry-instrumentation-asgi       | 0.61b0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation/opentelemetry-instrumentation-asgi    |
| opentelemetry-instrumentation-fastapi    | 0.61b0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/instrumentation/opentelemetry-instrumentation-fastapi |
| opentelemetry-proto                      | 1.40.0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-proto                                           |
| opentelemetry-sdk                        | 1.40.0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-sdk                                             |
| opentelemetry-semantic-conventions       | 0.61b0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-semantic-conventions                            |
| opentelemetry-util-http                  | 0.61b0     | Apache-2.0                                          | https://github.com/open-telemetry/opentelemetry-python-contrib/tree/main/util/opentelemetry-util-http                          |
| orjson                                   | 3.13.0     | MPL-2.0 AND (Apache-2.0 OR MIT)                     | https://github.com/ijl/orjson                                                                                                  |
| ormsgpack                                | 1.13.0     | Apache-2.0 OR MIT                                   | https://github.com/ormsgpack/ormsgpack                                                                                         |
| packaging                                | 26.3       | Apache-2.0 OR BSD-2-Clause                          | https://github.com/pypa/packaging                                                                                              |
| propcache                                | 0.5.4      | Apache-2.0                                          | https://github.com/aio-libs/propcache                                                                                          |
| protobuf                                 | 6.33.6     | 3-Clause BSD License                                | https://developers.google.com/protocol-buffers/                                                                                |
| pycparser                                | 3.12       | BSD-3-Clause                                        | https://github.com/eliben/pycparser                                                                                            |
| pydantic                                 | 2.14.1     | MIT                                                 | https://github.com/pydantic/pydantic                                                                                           |
| pydantic_core                            | 2.50.1     | MIT                                                 | https://github.com/pydantic                                                                                                    |
| python-dateutil                          | 3.0.0      | Apache Software License; BSD License                | https://github.com/dateutil/dateutil                                                                                           |
| python-dotenv                            | 1.2.4      | BSD-3-Clause                                        | https://github.com/theskumar/python-dotenv                                                                                     |
| requests                                 | 2.34.2     | Apache Software License                             | https://github.com/psf/requests                                                                                                |
| requests-oauthlib                        | 2.0.0      | BSD License                                         | https://github.com/requests/requests-oauthlib                                                                                  |
| requests-toolbelt                        | 1.0.0      | Apache Software License                             | https://toolbelt.readthedocs.io/                                                                                               |
| six                                      | 1.17.0     | MIT License                                         | https://github.com/benjaminp/six                                                                                               |
| sniffio                                  | 1.3.1      | Apache Software License; MIT License                | https://github.com/python-trio/sniffio                                                                                         |
| starlette                                | 1.10.0     | BSD-3-Clause                                        | https://github.com/Kludex/starlette                                                                                            |
| tenacity                                 | 9.2.1      | Apache-2.0                                          | https://github.com/jd/tenacity                                                                                                 |
| truststore                               | 0.10.5     | MIT                                                 | https://github.com/sethmlarson/truststore                                                                                      |
| typing-inspection                        | 0.4.4      | MIT                                                 | https://github.com/pydantic/typing-inspection                                                                                  |
| typing_extensions                        | 4.16.0     | PSF-2.0                                             | https://github.com/python/typing_extensions                                                                                    |
| tzdata                                   | 2026.5     | Apache-2.0                                          | https://github.com/python/tzdata                                                                                               |
| urllib3                                  | 2.8.0      | MIT                                                 | https://github.com/urllib3/urllib3/blob/main/CHANGES.rst                                                                       |
| uuid_utils                               | 0.19.0     | BSD-3-Clause                                        | https://github.com/aminalaee/uuid-utils                                                                                        |
| uvicorn                                  | 0.54.0     | BSD-3-Clause                                        | https://uvicorn.dev/                                                                                                           |
| uvloop                                   | 0.23.0     | Apache Software License; MIT License                | UNKNOWN                                                                                                                        |
| watchfiles                               | 1.3.0      | MIT License                                         | https://github.com/samuelcolvin/watchfiles                                                                                     |
| websocket-client                         | 1.9.2      | Apache-2.0                                          | https://github.com/websocket-client/websocket-client                                                                           |
| websockets                               | 16.1.1     | BSD-3-Clause                                        | https://github.com/python-websockets/websockets                                                                                |
| wrapt                                    | 1.17.3     | BSD License                                         | https://github.com/GrahamDumpleton/wrapt                                                                                       |
| xxhash                                   | 4.0.2      | BSD-2-Clause                                        | https://github.com/ifduyue/python-xxhash                                                                                       |
| yarl                                     | 1.25.1     | Apache-2.0                                          | https://github.com/aio-libs/yarl                                                                                               |
| zipp                                     | 4.1.2      | MIT                                                 | https://github.com/jaraco/zipp                                                                                                 |
| zstandard                                | 0.25.0     | BSD-3-Clause                                        | https://github.com/indygreg/python-zstandard                                                                                   |

## Notes

- All packages except PyGithub, certifi and orjson are under permissive
  licenses (MIT, BSD, Apache-2.0, PSF and similar) compatible with this
  project's Apache-2.0 license.
- certifi (MPL-2.0) and the MPL-2.0 portion of orjson are file-level copyleft;
  both are installed unmodified from PyPI and no file of theirs is modified or
  vendored here.
- PyGithub is licensed under the GNU Lesser General Public License v3. It is
  consumed unmodified as a runtime library (dynamic import), which the LGPL
  permits without imposing its terms on this project; no PyGithub source is
  modified or vendored here.
- `UNKNOWN` in the URL column means the package metadata names no home page;
  the package is on PyPI under the listed name.
- For the canonical license text of each package, consult its project URL or
  the license file shipped in the installed distribution.
