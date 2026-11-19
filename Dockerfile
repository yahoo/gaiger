# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

# Base image pinned by digest (python:3.12-slim); Dependabot's docker entry keeps it current.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Fail the build if the interpreter is not the version the docs assert (3.12).
RUN python3.12 -c "import sys; assert sys.version_info[:2] == (3, 12), sys.version"

WORKDIR /app

# Non-root user. The numeric ids (uid=9999, gid=10952) are what the sample Kubernetes
# securityContext / fsGroup rely on — keep them in sync with k8s/ if you change them.
RUN groupadd -g 10952 app && \
    useradd -u 9999 -g app -m -s /bin/bash app

# requirements.lock is generated from requirements.txt with hashes for every
# package (scripts/compile-requirements.sh); --require-hashes refuses anything
# that is not in it byte for byte.
COPY requirements.lock .
# gcc is needed only to build the few native wheels (e.g. asyncpg) that have no binary
# wheel for this platform. It is installed AND removed inside this single RUN: an image
# layer is the filesystem diff of one instruction, so a compiler installed in an earlier
# RUN and removed later would still be present in that earlier layer. Installing and
# removing it in the same RUN keeps every published layer of the runtime image compiler-free.
# apt-get upgrade applies Debian security fixes not yet in the base image.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends gcc && \
    pip install --no-cache-dir --require-hashes -r requirements.lock && \
    apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/*

COPY app/ ./app/

RUN chown -R app:app /app

USER 9999:10952

EXPOSE 8765

# python:*-slim has no curl; probe the health endpoint with the stdlib instead.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=5).status == 200 else 1)"

CMD ["python", "-m", "app.main"]
