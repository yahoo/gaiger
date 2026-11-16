"""Bounded credential-cache lifetime and invalidate-on-auth-failure.

Covers app/secret_provider.py's TTL cache (SECRET_CACHE_TTL_SECONDS), the
per-secret invalidate_* functions, the fail-closed semantics for invalidated
secrets, and the consumer wiring that makes rotation actually propagate:
the asyncpg callable password, the Slack per-call token resolution, the
GitHub client rebuild-on-rotation, the LangGraph agent rebuild-on-rotation,
and the Grafana poller's 401 invalidation.

All tests run with SECRET_PROVIDER=env (deterministic, no external backend, no network).
The properties the original module got right stay asserted here too: no
secret VALUE may ever appear in a log line (label-only logging).
"""
import asyncio
import logging
import time

import pytest

import app.secret_provider as sp

_REAL_TTL = sp._cache_ttl_seconds


SECRET_A = "test-secret-value-A"
SECRET_B = "test-secret-value-B"


@pytest.fixture(autouse=True)
def reset_secret_provider(monkeypatch):
    """env provider, default TTL, and a pristine module state per test."""
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.delenv("SECRET_CACHE_TTL_SECONDS", raising=False)

    def _reset():
        sp._api_key = None
        sp._slack_token = None
        sp._github_token = None
        sp._postgres_password = None
        sp._grafana_sa_token = None
        sp._fetched_at.clear()
        sp._last_refetch_attempt.clear()
        sp._fetch_generation.clear()
        sp._invalidated.clear()
        sp._refetch_locks.clear()

    _reset()
    yield
    _reset()


def _count_fetches(monkeypatch):
    calls = {"n": 0}
    real_fetch_secret = sp._fetch_secret

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real_fetch_secret(*args, **kwargs)

    monkeypatch.setattr(sp, "_fetch_secret", counting)
    return calls


# ── Core TTL semantics ────────────────────────────────────────────────────────

def test_get_before_fetch_raises():
    with pytest.raises(RuntimeError):
        sp.get_api_key()


def test_serves_cached_value_within_ttl(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    # default TTL (3600s) has not expired — the cached value is served
    assert sp.get_api_key() == SECRET_A


def test_refetches_after_ttl_expiry(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)  # everything is expired
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    assert sp.get_api_key() == SECRET_B


def test_invalidate_forces_immediate_refetch(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    assert sp.get_api_key() == SECRET_A  # within TTL: still cached
    sp.invalidate_api_key()
    assert sp.get_api_key() == SECRET_B  # invalidation bypasses the TTL


def test_ttl_refetch_failure_serves_cached_and_logs_label_only(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)
    monkeypatch.delenv("ANTHROPIC_API_KEY")  # the re-fetch will fail
    with caplog.at_level(logging.INFO):
        assert sp.get_api_key() == SECRET_A  # availability: stale-serve on TTL failure
    assert "re-fetch failed" in caplog.text
    # label-only logging: the secret value never appears in any log line
    assert SECRET_A not in caplog.text


def test_ttl_refetch_failure_backs_off(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)
    monkeypatch.delenv("ANTHROPIC_API_KEY")

    calls = _count_fetches(monkeypatch)
    assert sp.get_api_key() == SECRET_A  # attempt 1: fails, back-off recorded
    assert sp.get_api_key() == SECRET_A  # inside the back-off window: no new attempt
    assert calls["n"] == 1


def test_invalidated_refetch_failure_fails_closed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    monkeypatch.delenv("ANTHROPIC_API_KEY")  # the forced re-fetch will fail
    sp.invalidate_api_key()
    # A known-bad credential is never served stale — the getter raises
    with pytest.raises(RuntimeError):
        sp.get_api_key()
    # and keeps failing closed during the back-off window
    with pytest.raises(RuntimeError):
        sp.get_api_key()
    # once the provider recovers (back-off elapsed), the fresh value is served
    monkeypatch.setattr(sp, "_REFETCH_FAILURE_BACKOFF_SECONDS", 0)
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    assert sp.get_api_key() == SECRET_B


def test_repeated_invalidations_stay_inside_backoff(monkeypatch):
    """Revoked upstream but NOT rotated in the secret backend: every call fails and
    invalidates again. That must cost one backend round-trip per back-off window,
    not one per failing call; inside the window the getter fails closed."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    calls = _count_fetches(monkeypatch)

    sp.invalidate_api_key()
    assert sp.get_api_key() == SECRET_A  # re-fetch #1 (same value, served)
    for _ in range(4):
        sp.invalidate_api_key()
        with pytest.raises(RuntimeError):  # inside the back-off: fail closed, no subprocess
            sp.get_api_key()
    assert calls["n"] == 1

    # back-off elapsed: exactly one more attempt, and a rotated value is picked up
    monkeypatch.setattr(sp, "_REFETCH_FAILURE_BACKOFF_SECONDS", 0)
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    sp.invalidate_api_key()
    assert sp.get_api_key() == SECRET_B
    assert calls["n"] == 2


def test_same_value_refetch_after_invalidation_is_served_and_logged(monkeypatch, caplog):
    """A single spurious 401 must not take the integration down: the unchanged
    value is served, with a label-only warning, and the back-off is armed."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    sp.invalidate_api_key()
    with caplog.at_level(logging.INFO):
        assert sp.get_api_key() == SECRET_A
    assert "returned the unchanged value" in caplog.text
    assert SECRET_A not in caplog.text
    assert "api_key" in sp._last_refetch_attempt  # back-off armed


def test_unconfigured_refetch_is_a_failed_attempt_not_a_success(monkeypatch, caplog):
    """fetch_* returning None ("not configured") without recording a value is
    a FAILED re-fetch: stale-serve on TTL expiry, fail closed after invalidation."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_A)
    sp.fetch_slack_token()
    monkeypatch.delenv("SLACK_BOT_TOKEN")  # the provider now reports "unconfigured"

    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)
    with caplog.at_level(logging.WARNING):
        assert sp.get_slack_token() == SECRET_A  # TTL path: stale-serve + warning
    assert "re-fetch failed" in caplog.text
    assert SECRET_A not in caplog.text

    monkeypatch.setattr(sp, "_REFETCH_FAILURE_BACKOFF_SECONDS", 0)
    sp.invalidate_slack_token()
    with pytest.raises(RuntimeError):  # invalidated path: never served as "successfully re-fetched"
        sp.get_slack_token()
    assert "slack_token" in sp._invalidated


def test_refetch_locks_are_per_secret(monkeypatch):
    """A backend round-trip for one credential must not stall the other four."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_A)
    sp.fetch_key()
    sp.fetch_slack_token()
    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_B)

    api_lock = sp._lock_for("api_key")
    api_lock.acquire()  # an Anthropic-key re-fetch is "in flight"
    try:
        assert sp.get_slack_token() == SECRET_B  # Slack refreshes regardless
    finally:
        api_lock.release()


def test_queued_waiter_does_not_refetch_after_a_failed_attempt(monkeypatch):
    """Invalidated callers queue on the lock; once the first attempt fails,
    the waiters must fail closed on the recorded attempt, not each launch
    their own backend fetch."""
    import threading

    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    calls = _count_fetches(monkeypatch)
    sp.invalidate_api_key()

    lock = sp._lock_for("api_key")
    lock.acquire()  # simulate the first caller mid-fetch
    outcome = {}

    def waiter():
        try:
            sp.get_api_key()
            outcome["result"] = "served"
        except RuntimeError:
            outcome["result"] = "fail-closed"

    t = threading.Thread(target=waiter)
    t.start()
    # The first caller's attempt fails: it records the attempt and leaves the
    # secret invalidated, then releases the lock. Whether the waiter is already
    # blocked on the lock (re-check under the lock) or has not reached it yet
    # (pre-lock check), it must see the recorded attempt and fail closed.
    sp._last_refetch_attempt["api_key"] = time.monotonic()
    lock.release()
    t.join(timeout=5)

    assert outcome["result"] == "fail-closed"
    assert calls["n"] == 0


def test_successful_ttl_refresh_does_not_arm_the_backoff(monkeypatch):
    """Round 3: a SUCCESSFUL TTL refresh (still-current value) must not arm
    the 60 s back-off. Otherwise: refresh -> the backend rotates -> consumer 401s ->
    invalidate -> the getter fails closed with zero backend calls. Postgres
    refreshes before every acquire, so it hit this on every rotation."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()
    calls = _count_fetches(monkeypatch)

    monkeypatch.setattr(sp, "_cache_ttl_seconds", lambda: 0.0)
    assert sp.get_api_key() == SECRET_A  # TTL refresh succeeds, value unchanged
    assert calls["n"] == 1
    assert "api_key" not in sp._last_refetch_attempt  # success: nothing to back off from
    monkeypatch.setattr(sp, "_cache_ttl_seconds", _REAL_TTL)  # back to the default TTL: cache is fresh

    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)  # the backend rotates...
    sp.invalidate_api_key()  # ...the consumer 401s
    assert sp.get_api_key() == SECRET_B  # a backend call happens, the rotated value is served
    assert calls["n"] == 2


def test_concurrent_callers_join_the_in_flight_refetch(monkeypatch):
    """Round 3: a caller arriving while an invalidated re-fetch is in flight
    must wait on the lock and receive that fetch's result — not fail closed on
    an attempt timestamp recorded before the fetch finished. One backend call."""
    import threading

    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_A)
    sp.fetch_key()

    entered = threading.Event()
    release = threading.Event()
    calls = {"n": 0}
    real_fetch_secret = sp._fetch_secret

    def blocking(*args, **kwargs):
        calls["n"] += 1
        entered.set()
        assert release.wait(5), "test harness never released the in-flight fetch"
        return real_fetch_secret(*args, **kwargs)

    monkeypatch.setattr(sp, "_fetch_secret", blocking)
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_B)
    sp.invalidate_api_key()

    results = {}

    def caller(tag):
        try:
            results[tag] = sp.get_api_key()
        except RuntimeError as e:
            results[tag] = e

    first = threading.Thread(target=caller, args=("first",))
    first.start()
    assert entered.wait(5)  # the first caller is mid-fetch
    second = threading.Thread(target=caller, args=("second",))
    second.start()
    second.join(timeout=0.5)
    assert second.is_alive(), f"second caller did not wait for the in-flight fetch: {results.get('second')!r}"

    release.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert results == {"first": SECRET_B, "second": SECRET_B}
    assert calls["n"] == 1


def test_optional_getters_return_none_when_unconfigured():
    assert sp.get_slack_token() is None
    assert sp.get_github_token() is None
    assert sp.get_grafana_sa_token() is None


def test_slack_token_ttl_and_invalidate(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_A)
    sp.fetch_slack_token()
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_B)
    assert sp.get_slack_token() == SECRET_A
    sp.invalidate_slack_token()
    assert sp.get_slack_token() == SECRET_B


def test_grafana_token_ttl_and_invalidate(monkeypatch):
    monkeypatch.setenv("GRAFANA_SA_TOKEN", SECRET_A)
    sp.fetch_grafana_sa_token()
    monkeypatch.setenv("GRAFANA_SA_TOKEN", SECRET_B)
    assert sp.get_grafana_sa_token() == SECRET_A
    sp.invalidate_grafana_sa_token()
    assert sp.get_grafana_sa_token() == SECRET_B


def test_postgres_password_ttl_and_invalidate(monkeypatch):
    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_A)
    sp.fetch_postgres_password()
    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_B)
    assert sp.get_postgres_password() == SECRET_A
    sp.invalidate_postgres_password()
    assert sp.get_postgres_password() == SECRET_B


# ── Consumer wiring: rotation must reach the actual API calls ─────────────────

def test_postgres_connect_passes_password_callable(monkeypatch):
    """asyncpg must receive a CALLABLE password so pool-spawned connections
    re-read the (TTL-refreshed) provider value instead of a startup copy."""
    import app.postgres_client as pc

    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_A)
    sp.fetch_postgres_password()

    captured = {}

    async def fake_create_pool(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(pc.asyncpg, "create_pool", fake_create_pool)
    reader = pc.PostgresStateReader()
    asyncio.run(reader.connect())

    password = captured["password"]
    assert callable(password)
    assert not asyncio.iscoroutinefunction(password)  # a peek: no backend round-trip inside acquire(timeout=5)
    assert password() == SECRET_A
    # rotation propagates to the next pool connection without reconnecting:
    # the refresh (off the event loop, before acquire) produces the new value...
    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_B)
    sp.invalidate_postgres_password()
    with pytest.raises(RuntimeError):
        password()  # ...and until it has run, the known-bad value is never handed to asyncpg
    asyncio.run(reader._refresh_password())
    assert password() == SECRET_B


@pytest.mark.parametrize("auth_error", [
    "InvalidPasswordError",                      # 28P01
    "InvalidAuthorizationSpecificationError",    # 28000, the parent class
])
def test_postgres_runtime_invalid_password_invalidates_and_retries(monkeypatch, auth_error):
    """A rotation while the service runs: the pool spawns a connection with
    the stale password, the server rejects it — the reader must invalidate,
    re-fetch and retry once, not fail every new connection until the TTL.
    Both SQLSTATE 28P01 and its class parent 28000 are authentication rejections."""
    import app.postgres_client as pc

    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_A)
    sp.fetch_postgres_password()
    error_cls = getattr(pc.asyncpg.exceptions, auth_error)

    class FakeConn:
        async def fetch(self, *args):
            return []

    class FakePool:
        def __init__(self):
            self.acquire_calls = 0
            self.released = []

        async def acquire(self, timeout=None):
            self.acquire_calls += 1
            assert timeout == pc.POOL_ACQUIRE_TIMEOUT_SECONDS
            if sp.peek_postgres_password() == SECRET_A:
                raise error_cls("authentication rejected")
            return FakeConn()

        async def release(self, conn):
            self.released.append(conn)

    reader = pc.PostgresStateReader()
    reader.pool = FakePool()
    monkeypatch.setenv("POSTGRES_PASSWORD", SECRET_B)  # rotated in the backend after startup

    result = asyncio.run(reader.get_autoscaler_state("job"))
    assert result == {"state": None, "message": "No autoscaler state found"}
    assert reader.pool.acquire_calls == 2  # rejected once, retried with the fresh value
    assert len(reader.pool.released) == 1
    assert sp.peek_postgres_password() == SECRET_B


def test_slack_client_resolves_token_per_call(monkeypatch):
    from app.slack_client import SlackClient

    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_A)
    sp.fetch_slack_token()
    client = SlackClient(bot_token=SECRET_A)
    monkeypatch.setenv("SLACK_BOT_TOKEN", SECRET_B)
    sp.invalidate_slack_token()
    # the constructor copy is stale; the per-call resolution is fresh
    assert asyncio.run(client._current_token()) == SECRET_B


def test_slack_client_falls_back_to_constructor_token(monkeypatch):
    from app.slack_client import SlackClient

    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    client = SlackClient(bot_token="local-dev-token")
    assert asyncio.run(client._current_token()) == "local-dev-token"


def test_github_client_rebuilds_on_rotated_pat(monkeypatch):
    from app.github_client import GitHubClient

    monkeypatch.setenv("GITHUB_TOKEN", SECRET_A)
    sp.fetch_github_token()
    client = GitHubClient(token=SECRET_A)
    gh_before = client._gh
    monkeypatch.setenv("GITHUB_TOKEN", SECRET_B)
    sp.invalidate_github_token()
    client._refresh_token_if_rotated()
    assert client.token == SECRET_B
    assert client._gh is not gh_before


def test_github_client_invalidates_on_401():
    from github import GithubException
    from app.github_client import GitHubClient

    sp._github_token = SECRET_A
    sp._fetched_at["github_token"] = 10**9  # pretend-fresh
    GitHubClient._note_auth_failure(GithubException(401, {"message": "Bad credentials"}, None))
    assert "github_token" in sp._invalidated
    sp._invalidated.clear()
    GitHubClient._note_auth_failure(GithubException(404, {"message": "Not Found"}, None))
    assert "github_token" not in sp._invalidated


def test_github_client_fails_closed_when_invalidated_refetch_fails(monkeypatch):
    """After a 401 the PAT is known bad; if the re-fetch fails the call must
    fail — never proceed with the client built on the credential that just 401'd."""
    from app.github_client import GitHubClient

    monkeypatch.setenv("GITHUB_TOKEN", SECRET_A)
    sp.fetch_github_token()
    client = GitHubClient(token=SECRET_A)
    gh_before = client._gh
    monkeypatch.delenv("GITHUB_TOKEN")  # the forced re-fetch will fail
    sp.invalidate_github_token()

    with pytest.raises(RuntimeError):
        client._refresh_token_if_rotated()
    result = asyncio.run(client.read_file("org/repo", "README.md"))
    assert result["success"] is False
    assert SECRET_A not in result["error"]
    assert client._gh is gh_before  # untouched, and never used for the call


def test_agent_rebuilds_only_when_key_rotates(monkeypatch):
    pytest.importorskip("langgraph")
    from app.langgraph_agent import LangGraphAgent

    agent = object.__new__(LangGraphAgent)
    agent._api_key = "key-A"
    calls = {"n": 0}

    def fake_build(api_key):
        calls["n"] += 1
        agent._api_key = api_key  # the already-fetched key is passed in: no getter call on the loop

    agent._build_agent = fake_build

    monkeypatch.setattr(sp, "get_api_key", lambda: "key-A")
    asyncio.run(agent._refresh_agent_if_key_rotated())
    assert calls["n"] == 0  # same key: no rebuild

    monkeypatch.setattr(sp, "get_api_key", lambda: "key-B")
    asyncio.run(agent._refresh_agent_if_key_rotated())
    assert calls["n"] == 1  # rotated key: rebuild
    assert agent._api_key == "key-B"


def test_concurrent_refreshes_rebuild_the_agent_once(monkeypatch):
    """Round 3: N requests in flight across one rotation must produce one
    rebuild, not N. Each coroutine snapshots the old key before awaiting the
    getter; the rebuild decision must compare against the live key instead.
    The barrier holds all N getter calls open at once (a backend round-trip in
    production), so every coroutine has taken its snapshot before any result
    comes back — the ordering that produced N rebuilds."""
    import threading

    pytest.importorskip("langgraph")
    from app.langgraph_agent import LangGraphAgent

    n = 5
    agent = object.__new__(LangGraphAgent)
    agent._api_key = "key-A"
    calls = {"n": 0}

    def fake_build(api_key):
        calls["n"] += 1
        agent._api_key = api_key

    agent._build_agent = fake_build
    barrier = threading.Barrier(n)

    def slow_getter():
        barrier.wait(timeout=5)  # all N callers are inside the (thread-pooled) getter together
        return "key-B"

    monkeypatch.setattr(sp, "get_api_key", slow_getter)

    async def run():
        await asyncio.gather(*(agent._refresh_agent_if_key_rotated() for _ in range(n)))

    asyncio.run(run())
    assert calls["n"] == 1
    assert agent._api_key == "key-B"


def test_build_agent_does_not_call_the_getter(monkeypatch):
    """_build_agent(api_key) must use the key it is given — the getter can
    block on a backend fetch or on another caller's in-flight re-fetch, and
    the rebuild runs on the event loop."""
    pytest.importorskip("langgraph")
    import inspect
    from app.langgraph_agent import LangGraphAgent

    assert "api_key" in inspect.signature(LangGraphAgent._build_agent).parameters
    assert "get_api_key" not in inspect.getsource(LangGraphAgent._build_agent)


def test_agent_refresh_noop_without_recorded_key():
    pytest.importorskip("langgraph")
    from app.langgraph_agent import LangGraphAgent

    agent = object.__new__(LangGraphAgent)  # partial init, as the test harness builds it
    asyncio.run(agent._refresh_agent_if_key_rotated())  # must not raise


def test_agent_refresh_propagates_fail_closed_error(monkeypatch):
    """The getter only raises for an invalidated (known-bad) key whose re-fetch
    failed. The agent must not swallow that and keep using the key that just
    401'd: the refresh propagates, and analyze() turns it into the standard
    failure payload instead of an unhandled exception."""
    pytest.importorskip("langgraph")
    from app.langgraph_agent import LangGraphAgent

    agent = object.__new__(LangGraphAgent)
    agent._api_key = "key-A"
    agent.agent = None  # would blow up if analyze() ever reached ainvoke

    def boom():
        raise RuntimeError("Anthropic API key was invalidated ... refusing to serve the cached value")

    monkeypatch.setattr(sp, "get_api_key", boom)
    with pytest.raises(RuntimeError):
        asyncio.run(agent._refresh_agent_if_key_rotated())
    assert agent._api_key == "key-A"

    result = asyncio.run(agent.analyze("why is my job restarting?"))
    assert result["answer"] == "Analysis failed — please try again."


def test_anthropic_auth_error_detected_through_cause_chain():
    pytest.importorskip("langgraph")
    from app.langgraph_agent import _is_anthropic_auth_error

    class AuthenticationError(Exception):
        pass

    try:
        try:
            raise AuthenticationError("401 invalid x-api-key")
        except AuthenticationError as inner:
            raise RuntimeError("agent run failed") from inner
    except RuntimeError as outer:
        assert _is_anthropic_auth_error(outer)

    class WithStatus(Exception):
        status_code = 401

    assert _is_anthropic_auth_error(WithStatus())
    assert not _is_anthropic_auth_error(ValueError("unrelated"))


@pytest.mark.parametrize("status, invalidates", [(401, True), (403, False), (500, False)])
def test_grafana_poller_invalidates_token_on_401_only(monkeypatch, status, invalidates):
    """401 = the token did not authenticate (rotated/revoked): re-fetch.
    403 = it authenticated but lacks permission: permanent, a re-fetch cannot
    fix it and would cost a backend fetch every poll."""
    import app.grafana_poller as gp

    monkeypatch.setenv("GRAFANA_SA_TOKEN", SECRET_A)
    sp.fetch_grafana_sa_token()
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "test-job")
    poller = gp.GrafanaAlertPoller(langgraph_agent=None, slack_client=None)

    class FakeResp:
        pass

    FakeResp.status = status

    async def _text(self):
        return "denied"

    FakeResp.text = _text

    class FakeGetCtx:
        async def __aenter__(self):
            return FakeResp()

        async def __aexit__(self, *args):
            return False

    class FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            return FakeGetCtx()

    monkeypatch.setattr(gp.aiohttp, "ClientSession", FakeSession)
    asyncio.run(poller._poll_once())
    assert ("grafana_sa_token" in sp._invalidated) is invalidates


@pytest.mark.parametrize("value,expected", [
    ("inf", 3600.0), ("nan", 3600.0), ("-inf", 3600.0), ("abc", 3600.0),
    ("-5", 60.0), ("0", 60.0), ("1e6", 86400.0), ("900", 900.0),
])
def test_cache_ttl_is_clamped(monkeypatch, value, expected):
    monkeypatch.setenv("SECRET_CACHE_TTL_SECONDS", value)
    assert _REAL_TTL() == expected
