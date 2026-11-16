# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in this project, please report it
privately rather than opening a public issue or pull request.

Report it through GitHub's
[private vulnerability reporting](https://github.com/yahoo/gaiger/security/advisories/new)
for this repository ("Security" tab → "Report a vulnerability"). Please do not
open a public issue, pull request, or discussion.

Include in your report:

- A description of the vulnerability and its impact
- Steps to reproduce
- The version or commit affected
- Any proof-of-concept code or logs (if available)

We aim to acknowledge reports within five business days and will coordinate
a disclosure timeline with you once the issue is confirmed.

## Scope notes

Gaiger runs as a sidecar with access to the Kubernetes API and, when
`ENABLE_WRITE_TOOLS=true`, can mutate Flink deployments. Reports about
prompt-injection paths that lead to unintended cluster mutation, secret
exposure in logs or audit events, or bypasses of the write-tool gate are
especially welcome.

## Supported versions

Only the `main` branch is actively maintained. Security fixes are applied
to `main`; older versions are not patched.
