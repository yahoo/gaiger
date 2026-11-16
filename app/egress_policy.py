"""Startup validation of every outbound (egress) destination.

Every outbound destination this service talks to (Flink REST, GitHub API,
Grafana, the OTLP collector, Slack webhooks, the Anthropic API endpoint, the
Postgres host) is configurable via an environment variable, and several of
those connections carry live credentials. This module is the single
chokepoint that decides whether a configured destination is acceptable —
bespoke per-client checks would drift.

Fails closed: a destination that violates the policy raises EgressPolicyError
at CLIENT CONSTRUCTION time, so a misconfigured deployment refuses to start
rather than starting silently and shipping a credential (or cleartext
telemetry) somewhere new on every subsequent action.

Policy:
- The URL must be http(s) with a non-empty host.
- Loopback hosts (localhost / 127.0.0.0/8 / ::1) may use plaintext, but only
  for destinations that declare a legitimate intra-pod hop
  (``allow_loopback=True``).
- Every non-loopback destination must use https when ``require_https`` is set
  (it is, for every credential-bearing client in this app).
- When EGRESS_ALLOWED_HOSTS is set (comma-separated hostnames), every
  non-loopback destination host must appear in it. When unset, a destination
  that declares a built-in set of known hosts (``default_allowed_hosts``, e.g.
  the GitHub API hosts) is checked against that set instead; destinations
  without one skip the allowlist check — the https/loopback rules above still
  apply.
"""

import ipaddress
import os
from typing import Optional
from urllib.parse import urlparse


class EgressPolicyError(ValueError):
    """An outbound destination violates the deployment's egress policy."""


def _allowed_hosts() -> frozenset:
    """The EGRESS_ALLOWED_HOSTS allowlist, read at call time (not import time)
    so tests and re-validation always see the current environment."""
    return frozenset(
        h.strip().lower()
        for h in os.getenv("EGRESS_ALLOWED_HOSTS", "").split(",")
        if h.strip()
    )


def is_loopback(host: str) -> bool:
    """True when ``host`` is a loopback name or address (intra-pod hop)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_destination(
    url: str,
    *,
    name: str,
    require_https: bool = True,
    allow_loopback: bool = False,
    default_allowed_hosts: Optional[frozenset] = None,
) -> str:
    """Validate one outbound destination URL against the egress policy.

    Returns the URL unchanged when acceptable; raises EgressPolicyError
    otherwise. ``name`` identifies the configuration knob (e.g. the env var)
    in the error so an operator can see exactly what was rejected and why.

    ``default_allowed_hosts`` is the destination's built-in set of known hosts.
    It applies only when EGRESS_ALLOWED_HOSTS is unset (the operator's list,
    when present, is authoritative for every destination), so a destination
    with a known, small set of legitimate hosts is never accepted at an
    arbitrary https host merely because no deployment-wide allowlist was
    configured.
    """
    parsed = urlparse(url or "")
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not host:
        raise EgressPolicyError(
            f"{name}: {url!r} is not a valid http(s) URL with a host"
        )
    if allow_loopback and is_loopback(host):
        # Intra-pod hop (shared network namespace): plaintext is defensible
        # there, and the allowlist does not apply to the pod's own loopback.
        return url
    if require_https and parsed.scheme != "https":
        raise EgressPolicyError(
            f"{name}: {parsed.scheme}:// is not permitted for destination host "
            f"{host!r} — non-loopback destinations must use https://"
        )
    allowed = _allowed_hosts()
    if allowed:
        if host.lower() not in allowed:
            raise EgressPolicyError(
                f"{name}: host {host!r} is not in EGRESS_ALLOWED_HOSTS"
            )
    elif default_allowed_hosts is not None and host.lower() not in default_allowed_hosts:
        raise EgressPolicyError(
            f"{name}: host {host!r} is not a known host for this destination "
            f"({', '.join(sorted(default_allowed_hosts))}); set EGRESS_ALLOWED_HOSTS "
            f"to permit it explicitly"
        )
    return url


# GitHub API hosts this service is known to talk to. GITHUB_API_BASE carries
# the repo-scoped PAT on every call, so with no operator allowlist it may only
# point at one of these (public GitHub or a GitHub Enterprise instance).
GITHUB_DEFAULT_ALLOWED_HOSTS = frozenset({"api.github.com"})


# The Anthropic SDK / langchain-anthropic default endpoint. Kept here so the
# DEFAULT is validated too: an EGRESS_ALLOWED_HOSTS list that omits
# api.anthropic.com pins the deployment to a gateway, as intended.
ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com"

# Precedence mirrors langchain_anthropic.ChatAnthropic._resolve_gateway
# (base_url_env=["ANTHROPIC_API_URL", "ANTHROPIC_BASE_URL"]): the FIRST set
# variable wins. Validating only ANTHROPIC_BASE_URL would let
# ANTHROPIC_API_URL=http://attacker bypass the policy, and when both are set
# the validated one would be the one the library ignores.
ANTHROPIC_BASE_URL_ENV_VARS = ("ANTHROPIC_API_URL", "ANTHROPIC_BASE_URL")


def resolve_anthropic_base_url() -> "tuple[str, str]":
    """Return ``(url, source)`` for the Anthropic endpoint the client WOULD use,
    resolved exactly as langchain-anthropic does. ``source`` is the env var
    name, or ``"default"``."""
    for var in ANTHROPIC_BASE_URL_ENV_VARS:
        value = os.getenv(var)
        if value:
            return value, var
    return ANTHROPIC_DEFAULT_BASE_URL, "default"


def validated_anthropic_base_url() -> str:
    """Resolve the effective Anthropic base URL and validate it.

    Callers MUST pass the returned value explicitly to the model client
    (``base_url=``) so the URL that was validated is the URL that is used —
    never let the client re-read the environment on its own.
    """
    url, source = resolve_anthropic_base_url()
    name = source if source != "default" else "ANTHROPIC_BASE_URL (default)"
    return validate_destination(
        url, name=name, require_https=True, allow_loopback=True,
    )


def validate_host(
    host: str,
    *,
    name: str,
    allow_loopback: bool = True,
) -> str:
    """Validate a bare hostname (non-URL destination, e.g. POSTGRES_HOST)
    against the EGRESS_ALLOWED_HOSTS allowlist.

    Transport encryption is the caller's job (asyncpg ssl=...); this only
    answers "may a credential be sent to this host at all?". Returns the host
    unchanged when acceptable; raises EgressPolicyError otherwise.
    """
    host = (host or "").strip()
    if not host:
        raise EgressPolicyError(f"{name}: empty host")
    if allow_loopback and is_loopback(host):
        return host
    allowed = _allowed_hosts()
    if allowed and host.lower() not in allowed:
        raise EgressPolicyError(
            f"{name}: host {host!r} is not in EGRESS_ALLOWED_HOSTS"
        )
    return host
