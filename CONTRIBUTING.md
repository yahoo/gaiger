# Contributing

Thanks for your interest in contributing to Gaiger.

## Filing issues

Please open an issue describing the bug, feature request, or question. Include:
- What you were trying to do
- What happened (logs, error messages)
- What you expected to happen
- Repro steps and environment (Python version, K8s version, Flink version)

## Pull requests

1. Fork the repo and create your branch from `main`.
2. Make your change. Keep PRs focused — one logical change per PR.
3. Add or update tests for any behavior change.
4. Run the test suite locally (see below).
5. Open a PR and fill out the PR template.

By submitting a PR you agree that your contribution is licensed under the
Apache License, Version 2.0 (see LICENSE).

## Developer Certificate of Origin (DCO)

This project requires every commit to be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). The
sign-off certifies that you wrote the change (or otherwise have the right to
submit it) under the project's license. Add the sign-off with

```
git commit -s
```

which appends a `Signed-off-by: Your Name <you@example.com>` trailer to the
commit message. PRs whose commits are missing the sign-off will not be merged;
use `git commit --amend -s` or `git rebase --signoff` to fix existing commits.

## Running the tests

The unit tests run without a live cluster or an LLM key:

```
pip install --require-hashes -r requirements.lock
pip install -r requirements-dev.txt
SECRET_PROVIDER=env ANTHROPIC_API_KEY=dummy python -m pytest tests/
```

CI runs the same commands on every PR. After changing `requirements.txt`, regenerate the
hash-pinned `requirements.lock` with `scripts/compile-requirements.sh` (needs Docker) and
commit both files.

Before each release, also run the planted-instruction check against the real model
(it is skipped without a real key, and calls the Anthropic API):

```
SECRET_PROVIDER=env ANTHROPIC_API_KEY=<non-production key> \
  python -m pytest tests/test_injection_eval.py -q
```

## Code style

- Python: follow the existing style in the codebase (PEP 8, type hints where
  they help).
- Keep functions small and focused. Prefer composition over inheritance.
- Don't add comments that just restate the code. Use comments for the
  non-obvious *why*.

## Commit messages

- Use the imperative mood in the subject line ("Add X", not "Added X").
- Keep the subject under 72 characters.
- Reference an issue number if applicable.

## Reporting security issues

Please do **not** file public issues for security vulnerabilities. See SECURITY.md.
