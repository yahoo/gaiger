#!/usr/bin/env bash
# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.
#
# Build the public release commit: one parentless commit whose tree is REF's tree
# minus the paths in EXCLUDE. Prints the commit SHA; nothing is pushed.
#   scripts/publish-tree.sh [REF] [MESSAGE]
set -euo pipefail

# Internal-only workflows (self-hosted runners, internal actions).
EXCLUDE=(
  .github/workflows/internal-container-scan.yml
  .github/workflows/security-workflow.yml
)

ref="${1:-HEAD}"
msg="${2:-Gaiger release}"
cd "$(git rev-parse --show-toplevel)"

index="$(mktemp)"
trap 'rm -f "${index}"' EXIT
export GIT_INDEX_FILE="${index}"
git read-tree "${ref}^{tree}"
git rm --cached --quiet --ignore-unmatch -- "${EXCLUDE[@]}"
tree="$(git write-tree)"

for path in "${EXCLUDE[@]}"; do
  if git ls-tree -r --name-only "${tree}" | grep -qxF "${path}"; then
    echo "excluded path still in tree: ${path}" >&2
    exit 1
  fi
done

git commit-tree "${tree}" -m "${msg}"
