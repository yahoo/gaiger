# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""
Loads secrets at startup and holds them in module-level memory only — they are never
written to disk, re-exported into the environment, or logged.

The only built-in backend reads environment variables (``SECRET_PROVIDER=env``, the
default). Secrets and the variables they are read from:

    fetch_key() / get_api_key()                          ANTHROPIC_API_KEY   required
    fetch_slack_token() / get_slack_token()              SLACK_BOT_TOKEN     optional -> None
    fetch_github_token() / get_github_token()            GITHUB_TOKEN        optional -> None
    fetch_postgres_password() / get_postgres_password()  POSTGRES_PASSWORD   required when called
    fetch_grafana_sa_token() / get_grafana_sa_token()    GRAFANA_SA_TOKEN    optional -> None

Blank / whitespace-only values are treated as missing. Optional secrets resolve to None
and the feature that needs them is disabled; required ones raise RuntimeError so a
misconfigured deployment fails at startup rather than at first use.

Cached values have a bounded lifetime (SECRET_CACHE_TTL_SECONDS, default 3600
seconds): the get_* accessors transparently re-fetch once the TTL expires. With a
backend that serves live values, a rotation or revocation there takes effect
without a pod restart. With the built-in SECRET_PROVIDER=env, values come from
container environment variables, which do not change until the pod restarts:
restart the pod after rotating a Secret.
Each secret can also be invalidated explicitly (invalidate_*) from an
authentication-failure handler to force an immediate re-fetch on the next access;
an invalidated secret is never served stale (fail closed).

Plugging in a secrets backend (HashiCorp Vault, AWS Secrets Manager, GCP Secret
Manager, a KMS-backed store, ...):

  * Keep the public functions above and their signatures — the rest of the app calls
    only these, so nothing else has to change.
  * Replace the ``env`` branch of ``_fetch_secret`` with a lookup against your backend,
    using whatever identity your pod already has (workload identity, mounted client
    certificate, IAM role, ...). Do the network call inside fetch_*; callers run the
    get_* accessors via ``asyncio.to_thread`` because a re-fetch may block.
  * Validate every environment-derived value that becomes an argument to an external
    command or path before using it (anchored allowlist, not a denylist).
  * If you add a new provider name, register it in ``_SUPPORTED_PROVIDERS``. Any value of
    ``SECRET_PROVIDER`` that is not registered fails closed at the first fetch.
  * Never fall back to a weaker source (e.g. a mounted file) silently — raise instead.
  * Build error messages from the variable NAME or a label, never the value.
"""

import logging
import math
import os
import threading
import time
from typing import Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)

_SUPPORTED_PROVIDERS = ("env",)

_api_key: Optional[str] = None
_slack_token: Optional[str] = None
_github_token: Optional[str] = None
_postgres_password: Optional[str] = None
_grafana_sa_token: Optional[str] = None

# Bounded cache lifetime for every cached credential: getters re-fetch once the
# TTL expires so a rotation in the secret backend propagates without a pod restart. Read per call
# (not at import) so tests and deployments can override without a reload.
_DEFAULT_CACHE_TTL_SECONDS = 3600

# After a failed TTL re-fetch, don't retry on every access — a backend fetch
# may be a network round-trip with its own retry/backoff. The cached value keeps
# serving during this window; an explicitly invalidated secret instead fails
# closed (see _maybe_refetch).
_REFETCH_FAILURE_BACKOFF_SECONDS = 60

_fetched_at: Dict[str, float] = {}            # secret name -> monotonic fetch time
_last_refetch_attempt: Dict[str, float] = {}  # secret name -> monotonic attempt time
_invalidated: Set[str] = set()                # flagged bad by an auth-failure handler
# One lock PER secret: a backend round-trip for one credential (which may
# retry/back off for minutes in the worst case) must not stall the getters
# of the other four.
_refetch_locks: Dict[str, threading.Lock] = {}
_refetch_locks_guard = threading.Lock()


def _lock_for(name: str) -> threading.Lock:
    with _refetch_locks_guard:
        lock = _refetch_locks.get(name)
        if lock is None:
            lock = _refetch_locks[name] = threading.Lock()
        return lock


_MIN_CACHE_TTL_SECONDS = 60.0
_MAX_CACHE_TTL_SECONDS = 86400.0


def _cache_ttl_seconds() -> float:
    """Clamped to [60 s, 24 h]; inf / nan / non-numbers fall back to the default,
    so a typo can neither pin a secret forever nor hammer the backend."""
    try:
        ttl = float(os.getenv("SECRET_CACHE_TTL_SECONDS", str(_DEFAULT_CACHE_TTL_SECONDS)))
    except ValueError:
        logger.warning("SECRET_CACHE_TTL_SECONDS is not a number — using default %ds", _DEFAULT_CACHE_TTL_SECONDS)
        return float(_DEFAULT_CACHE_TTL_SECONDS)
    if not math.isfinite(ttl):
        return float(_DEFAULT_CACHE_TTL_SECONDS)
    return min(max(ttl, _MIN_CACHE_TTL_SECONDS), _MAX_CACHE_TTL_SECONDS)


_fetch_generation: Dict[str, int] = {}        # secret name -> count of recorded fetches


def _record_fetch(name: str) -> None:
    """Marks a successful fetch: restarts the TTL and clears any invalidation."""
    _fetched_at[name] = time.monotonic()
    _fetch_generation[name] = _fetch_generation.get(name, 0) + 1
    _invalidated.discard(name)


def _invalidate(name: str, label: str) -> None:
    """Flags the secret bad. Deliberately keeps _last_refetch_attempt: a
    credential revoked upstream but NOT rotated in the secret backend fails every call, and
    each failure invalidates again — without the back-off that is one backend
    round-trip per failing call. Inside the back-off window an invalidated
    secret fails closed instead (see _maybe_refetch)."""
    _fetched_at.pop(name, None)
    _invalidated.add(name)
    logger.info("%s cache invalidated — next access re-fetches from the secret provider", label)


def _fresh(name: str, now: float) -> bool:
    fetched = _fetched_at.get(name)
    return fetched is not None and (now - fetched) <= _cache_ttl_seconds()


def _backing_off(name: str, now: float) -> bool:
    last_attempt = _last_refetch_attempt.get(name)
    return last_attempt is not None and (now - last_attempt) < _REFETCH_FAILURE_BACKOFF_SECONDS


def _fail_closed(label: str) -> RuntimeError:
    return RuntimeError(
        f"{label} was invalidated after an authentication failure and its "
        f"re-fetch is backing off — refusing to serve the cached value"
    )


def _maybe_refetch(name: str, label: str, fetch_fn: Callable[[], object], current: object) -> None:
    """Re-fetches the named secret when its TTL expired or it was invalidated.

    TTL expiry is best-effort: if the re-fetch fails, a label-only warning is
    logged and the caller keeps serving the cached value (a hard failure here
    means the backend's own retry/backoff was already exhausted), with a
    back-off before the next attempt. Invalidation is fail-closed: a secret
    flagged bad by an authentication-failure handler is never served stale —
    the re-fetch must succeed or this raises.

    A fetch_* that returns without recording a value (provider reports the
    secret unconfigured) is a FAILED attempt, not a successful re-fetch. A
    re-fetch that returns the SAME value after an invalidation is served (a
    single spurious 401 must not take the integration down) but counts as a
    failed attempt for back-off purposes: repeat failures inside the window
    fail closed without another backend round-trip.

    The back-off is armed only by those two outcomes, and only AFTER the
    attempt finishes; a successful fetch clears it. Recording the attempt up
    front would make a routine successful TTL refresh arm the back-off, so a
    rotation right after it would fail closed for 60 s without a single backend
    call — and would make every caller arriving during a legitimate in-flight
    re-fetch fail closed instead of waiting on the lock for its result.
    """
    now = time.monotonic()
    if name not in _invalidated and _fresh(name, now):
        return
    if _backing_off(name, now):
        if name in _invalidated:
            raise _fail_closed(label)
        return

    lock = _lock_for(name)
    if name in _invalidated:
        lock.acquire()  # join the in-flight re-fetch: its result is re-checked below
    elif not lock.acquire(blocking=False):
        return  # another caller is already refreshing — serve the cached value
    try:
        # Re-check under the lock: a concurrent caller may have refreshed — or
        # tried and failed — while we waited. Queued waiters behind a failed
        # attempt must not each launch their own fetch.
        now = time.monotonic()
        if name not in _invalidated and _fresh(name, now):
            return
        if _backing_off(name, now):
            if name in _invalidated:
                raise _fail_closed(label)
            return
        was_invalidated = name in _invalidated
        before = _fetch_generation.get(name, 0)
        try:
            fetched = fetch_fn()  # on success the fetch_* function calls _record_fetch
            if _fetch_generation.get(name, 0) == before:
                raise RuntimeError(f"{label} re-fetch returned no value (provider reports it unconfigured)")
        except Exception as e:
            _last_refetch_attempt[name] = time.monotonic()  # failed attempt: arm the back-off
            # Label only — never the value. The env path raises before reading a
            # value, so `e` carries no secret; keep that property in any backend.
            if was_invalidated:
                _invalidated.add(name)  # a partial fetch_* must not have cleared it
                logger.error("%s re-fetch after invalidation failed — failing closed: %s", label, e)
                raise
            logger.warning("%s re-fetch failed — serving cached value until the next attempt: %s", label, e)
            return
        if was_invalidated and fetched is not None and fetched == current:
            _last_refetch_attempt[name] = time.monotonic()  # counts as a failed attempt
            logger.warning(
                "%s re-fetch after an authentication failure returned the unchanged value — "
                "the credential may be revoked upstream but not rotated in the secret backend; "
                "further auth failures fail closed for %ds before the next re-fetch",
                label, _REFETCH_FAILURE_BACKOFF_SECONDS,
            )
        else:
            _last_refetch_attempt.pop(name, None)  # success: a fresh value is in the cache, nothing to back off from
    finally:
        lock.release()



def fetch_key() -> str:
    """Called at startup and on cache expiry. Loads the Anthropic API key into memory."""
    global _api_key
    _api_key = _fetch_secret(label="Anthropic API key", env_var="ANTHROPIC_API_KEY")
    _record_fetch("api_key")
    return _api_key


def get_api_key() -> str:
    """Returns the in-memory Anthropic API key, re-fetching once the cache TTL
    expires or after invalidate_api_key(). Raises if fetch_key() was not called
    at startup or the initial fetch failed."""
    if _api_key is None:
        raise RuntimeError("API key not loaded — fetch_key() must be called at startup")
    _maybe_refetch("api_key", "Anthropic API key", fetch_key, _api_key)
    return _api_key


def invalidate_api_key() -> None:
    """Force the next get_api_key() to re-fetch. Call from a 401 /
    AuthenticationError handler (see langgraph_agent._is_anthropic_auth_error);
    not 403: a permission denial is permanent and not fixed by a re-fetch."""
    _invalidate("api_key", "Anthropic API key")


def fetch_slack_token() -> Optional[str]:
    """Called at startup and on cache expiry. Returns the Slack bot token, or None if unconfigured.

    Slack is optional — missing config silently disables it without blocking startup.
    """
    global _slack_token
    provider = _provider()
    if not _configured(provider, "SLACK_BOT_TOKEN"):
        logger.info("Slack credentials not configured — Slack integration disabled")
        return None
    _slack_token = _fetch_secret(label="Slack bot token", env_var="SLACK_BOT_TOKEN", provider=provider)
    _record_fetch("slack_token")
    return _slack_token


def get_slack_token() -> Optional[str]:
    """Returns the in-memory Slack bot token, re-fetching once the cache TTL
    expires or after invalidate_slack_token(). None if Slack is unconfigured."""
    if _slack_token is None:
        return None
    _maybe_refetch("slack_token", "Slack bot token", fetch_slack_token, _slack_token)
    return _slack_token


def invalidate_slack_token() -> None:
    """Force the next get_slack_token() to re-fetch. Call from an auth-failure handler."""
    _invalidate("slack_token", "Slack bot token")


def fetch_github_token() -> Optional[str]:
    """Called at startup and on cache expiry. Returns the GitHub token, or None if unconfigured.

    When unconfigured the GitHub tools are not registered on the agent.
    """
    global _github_token
    provider = _provider()
    if not _configured(provider, "GITHUB_TOKEN"):
        logger.info("GitHub credentials not configured — create_github_pr disabled")
        return None
    _github_token = _fetch_secret(label="GitHub token", env_var="GITHUB_TOKEN", provider=provider)
    _record_fetch("github_token")
    return _github_token


def get_github_token() -> Optional[str]:
    """Returns the in-memory GitHub token, re-fetching once the cache TTL expires
    or after invalidate_github_token(). None if GitHub is unconfigured."""
    if _github_token is None:
        return None
    _maybe_refetch("github_token", "GitHub token", fetch_github_token, _github_token)
    return _github_token


def invalidate_github_token() -> None:
    """Force the next get_github_token() to re-fetch. Call from a 401 handler."""
    _invalidate("github_token", "GitHub token")


def fetch_postgres_password() -> str:
    """Called at startup (only when PostgreSQL is enabled) and on cache expiry.
    Loads the password into memory."""
    global _postgres_password
    _postgres_password = _fetch_secret(label="PostgreSQL password", env_var="POSTGRES_PASSWORD")
    _record_fetch("postgres_password")
    return _postgres_password


def get_postgres_password() -> str:
    """Returns the in-memory PostgreSQL password, re-fetching once the cache TTL
    expires or after invalidate_postgres_password(). Raises if
    fetch_postgres_password() was not called at startup or the initial fetch failed."""
    if _postgres_password is None:
        raise RuntimeError(
            "PostgreSQL password not loaded — fetch_postgres_password() must be called at startup"
        )
    _maybe_refetch("postgres_password", "PostgreSQL password", fetch_postgres_password, _postgres_password)
    return _postgres_password


def peek_postgres_password() -> str:
    """Returns the cached PostgreSQL password WITHOUT a TTL re-fetch. For the
    asyncpg password callable, which runs inside Pool.acquire(timeout=5):
    a backend round-trip there would blow the acquire timeout, so the consumer
    refreshes via get_postgres_password() off the event loop BEFORE acquiring
    and this only reads the value that refresh produced. Fails closed on an
    invalidated (known-bad) value."""
    if _postgres_password is None:
        raise RuntimeError(
            "PostgreSQL password not loaded — fetch_postgres_password() must be called at startup"
        )
    if "postgres_password" in _invalidated:
        raise _fail_closed("PostgreSQL password")
    return _postgres_password


def invalidate_postgres_password() -> None:
    """Force the next get_postgres_password() to re-fetch. Call from an auth-failure handler."""
    _invalidate("postgres_password", "PostgreSQL password")


def fetch_grafana_sa_token() -> Optional[str]:
    """Called at startup and on cache expiry. Returns the Grafana service-account
    token, or None if unconfigured.

    The token is optional — missing config disables the Grafana alert poller.
    """
    global _grafana_sa_token
    provider = _provider()
    if not _configured(provider, "GRAFANA_SA_TOKEN"):
        logger.info("Grafana SA token not configured — alert poller disabled")
        return None
    _grafana_sa_token = _fetch_secret(label="Grafana SA token", env_var="GRAFANA_SA_TOKEN", provider=provider)
    _record_fetch("grafana_sa_token")
    return _grafana_sa_token


def get_grafana_sa_token() -> Optional[str]:
    """Returns the in-memory Grafana SA token, re-fetching once the cache TTL
    expires or after invalidate_grafana_sa_token(). None if not configured."""
    if _grafana_sa_token is None:
        return None
    _maybe_refetch("grafana_sa_token", "Grafana SA token", fetch_grafana_sa_token, _grafana_sa_token)
    return _grafana_sa_token


def invalidate_grafana_sa_token() -> None:
    """Force the next get_grafana_sa_token() to re-fetch. Call from a 401 handler
    (not 403: a permission denial is permanent and not fixed by a re-fetch)."""
    _invalidate("grafana_sa_token", "Grafana SA token")


# --- provider plumbing -------------------------------------------------------------


def _provider() -> str:
    """Returns the configured SECRET_PROVIDER, failing closed on anything not built in."""
    provider = os.getenv("SECRET_PROVIDER", "env").strip().lower() or "env"
    if provider not in _SUPPORTED_PROVIDERS:
        raise RuntimeError(
            f"Unknown SECRET_PROVIDER={provider!r}; only 'env' is built in — "
            "see module docstring to plug in a secrets backend"
        )
    return provider


def _read_env(name: str) -> str:
    """Raw read of one env var with surrounding whitespace stripped ('' when unset)."""
    return os.getenv(name, "").strip()


def _configured(provider: str, env_var: str) -> bool:
    """Whether an OPTIONAL secret is configured for the given provider. A backend
    plug-in extends this with its own 'is this secret wired up' test."""
    if provider == "env":
        return bool(_read_env(env_var))
    return False


def _fetch_secret(label: str, env_var: str, provider: Optional[str] = None) -> str:
    """Fetches a named secret using the configured SECRET_PROVIDER.

    In env mode: reads the value from the given environment variable. A backend
    plug-in adds its branch here (see module docstring). Error messages carry the
    variable NAME and the label only — never the value.
    """
    if provider is None:
        provider = _provider()
    elif provider not in _SUPPORTED_PROVIDERS:
        raise RuntimeError(
            f"Unknown SECRET_PROVIDER={provider!r}; only 'env' is built in — "
            "see module docstring to plug in a secrets backend"
        )
    logger.info("Secret provider: %s — fetching %s", provider, label)

    if provider == "env":
        fetched = _read_env(env_var)
        if not fetched:
            raise RuntimeError(
                f"{env_var} must be set to the {label} when SECRET_PROVIDER={provider}"
            )
    else:  # pragma: no cover — unreachable while _SUPPORTED_PROVIDERS == ("env",)
        raise RuntimeError(f"Unknown SECRET_PROVIDER={provider!r}")

    logger.info("%s loaded from %s into memory (provider=%s)", label, env_var, provider)
    return fetched
