#!/usr/bin/env bash
# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.
#
# Regenerate requirements.lock (hash-pinned, what the image installs) from
# requirements.txt, on Linux under the image's Python, against public PyPI.
# Review the diff and commit both files. The OpenTelemetry upper bounds in
# requirements.txt are inputs and carry into the lock; do not drop them.
set -euo pipefail

cd "$(dirname "$0")/.."
base="$(sed -n 's/^FROM \(python:[^ ]*\).*/\1/p' Dockerfile | head -n 1)"
[[ -n "${base}" ]] || { echo "no python base image in Dockerfile" >&2; exit 1; }

docker run --rm --platform linux/amd64 -v "${PWD}:/w" -w /w "${base}" sh -c \
  "pip install -q 'pip-tools>=7.4' && pip-compile --quiet --generate-hashes --strip-extras --no-emit-index-url --output-file requirements.lock requirements.txt"

echo "requirements.lock regenerated from ${base}; review and commit requirements.txt and requirements.lock."
