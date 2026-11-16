# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Endpoint-level tests for the probe split and request-rate ceilings.

Imports the FastAPI app (requires app deps; skips cleanly in a bare shell via
importorskip — same pattern as test_cors.py).
"""
import importlib
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch, **env):
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("POSTGRES_ENABLED", "false")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import app.main as main
    importlib.reload(main)  # limits + CORS are read at import time
    return TestClient(main._app), main


# ── Probe split (CWE-1088) ─────────────────────────────────────────────────────

def test_liveness_never_touches_external_dependencies(monkeypatch):
    client, main = _client(monkeypatch)

    async def _boom(*args, **kwargs):
        raise AssertionError("liveness must not call external dependencies")

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _boom)
    monkeypatch.setattr(main.postgres_reader, "verify_tables_exist", _boom)

    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_ready_reports_dependency_failure_with_200(monkeypatch):
    client, main = _client(monkeypatch)

    async def _flink_down(*args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _flink_down)

    resp = client.get("/api/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["flink_connected"] is False
    assert body["running_job_id"] is None


def test_ready_is_bounded_when_dependency_hangs(monkeypatch):
    """A blackholed dependency must not push /api/ready past the probe budget."""
    import asyncio

    client, main = _client(monkeypatch)

    async def _hang(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _hang)

    started = time.monotonic()
    resp = client.get("/api/ready")
    elapsed = time.monotonic() - started
    assert resp.status_code == 200
    assert resp.json()["flink_connected"] is False
    assert elapsed < 5.0, f"/api/ready took {elapsed:.1f}s — exceeds the probe budget"


# ── Rate limiting (CWE-770) ────────────────────────────────────────────────────

def test_query_endpoint_rate_limited_before_reaching_agent(monkeypatch):
    client, main = _client(monkeypatch, RATE_LIMIT_QUERY_PER_MINUTE="3")

    # Agent is uninitialized in tests (startup not run) → in-limit requests get
    # 503 from the handler; the limiter must trip BEFORE the handler afterwards,
    # proving excess requests can never reach an agent chain / the Anthropic API.
    for _ in range(3):
        resp = client.post("/api/query", json={"question": "hi"})
        assert resp.status_code == 503
    resp = client.post("/api/query", json={"question": "hi"})
    assert resp.status_code == 429
    assert "retry-after" in {k.lower() for k in resp.headers}


def test_stream_endpoint_shares_query_limiter(monkeypatch):
    client, main = _client(monkeypatch, RATE_LIMIT_QUERY_PER_MINUTE="2")
    client.post("/api/query", json={"question": "hi"})
    client.post("/api/query/stream", json={"question": "hi"})
    resp = client.post("/api/query", json={"question": "hi"})
    assert resp.status_code == 429


def test_heavy_diagnostics_rate_limited(monkeypatch):
    client, main = _client(monkeypatch, RATE_LIMIT_HEAVY_PER_MINUTE="2")

    async def _fake_dump(*args, **kwargs):
        return {"dumps": []}

    monkeypatch.setattr(main.flink_client, "analyze_thread_dumps", _fake_dump)

    json_hdr = {"Content-Type": "application/json"}
    assert client.post("/api/diagnostics/thread-dump", headers=json_hdr).status_code == 200
    assert client.post("/api/diagnostics/thread-dump", headers=json_hdr).status_code == 200
    assert client.post("/api/diagnostics/thread-dump", headers=json_hdr).status_code == 429


def test_logs_endpoint_rate_limited(monkeypatch):
    client, main = _client(monkeypatch, RATE_LIMIT_LOGS_PER_MINUTE="2")
    # K8s is not configured in tests → the handler returns an error payload with
    # HTTP 200; the third request must be cut off by the limiter with 429.
    assert client.get("/api/logs/operator").status_code == 200
    assert client.get("/api/logs/operator").status_code == 200
    assert client.get("/api/logs/operator").status_code == 429


# ── Probe timeoutSeconds (CWE-1088) ───────────────────────────────────────────
#
# The kubelet kills an exec probe at timeoutSeconds, default 1s (enforced since
# K8s 1.20). `curl --max-time 5` INSIDE the command never gets to apply, so
# without an explicit timeoutSeconds any Flink slowness over ~1s fails readiness
# — which removes the JobManager pod from Service endpoints and takes the Flink
# UI down with it.

def _probe_container():
    yaml = pytest.importorskip("yaml")
    from pathlib import Path

    manifest = (
        Path(__file__).resolve().parent.parent
        / "k8s"
        / "example-flink-deployment.yaml"
    )
    def _walk(node):
        """Find the container carrying the probes anywhere in the manifest tree
        (they live under spec.jobManager.podTemplate.spec.containers)."""
        if isinstance(node, dict):
            if "livenessProbe" in node or "readinessProbe" in node:
                return node
            for value in node.values():
                found = _walk(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _walk(item)
                if found is not None:
                    return found
        return None

    for doc in yaml.safe_load_all(manifest.read_text()):
        found = _walk(doc)
        if found is not None:
            return found
    pytest.fail("no container with probes found in the manifest")


@pytest.mark.parametrize("probe", ["livenessProbe", "readinessProbe"])
def test_probe_sets_explicit_timeout_seconds(probe):
    container = _probe_container()
    assert probe in container, f"{probe} missing"
    spec = container[probe]
    assert "timeoutSeconds" in spec, (
        f"{probe} has no timeoutSeconds — the kubelet default of 1s applies and "
        "`curl --max-time` inside the command cannot override it"
    )
    assert spec["timeoutSeconds"] >= 5
    assert spec.get("failureThreshold") == 3


@pytest.mark.parametrize(
    "probe,endpoint",
    [("livenessProbe", "/api/health"), ("readinessProbe", "/api/ready")],
)
def test_probes_point_at_their_split_endpoints(probe, endpoint):
    container = _probe_container()
    command = " ".join(str(c) for c in container[probe]["exec"]["command"])
    assert endpoint in command


# ── /api/ready runs its dependency checks concurrently ────────────────────────

def test_ready_checks_run_concurrently_not_sequentially(monkeypatch):
    """Two 2s-bounded checks in series cost up to 4s, overrunning the probe
    budget. Gathered, the worst case is ~2s."""
    import asyncio

    client, main = _client(monkeypatch)

    async def _slow_flink(*args, **kwargs):
        await asyncio.sleep(1.0)
        return "job-1"

    async def _slow_pg(*args, **kwargs):
        await asyncio.sleep(1.0)
        return {"connected": True}

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _slow_flink)
    monkeypatch.setattr(main.postgres_reader, "verify_tables_exist", _slow_pg)

    started = time.monotonic()
    resp = client.get("/api/ready")
    elapsed = time.monotonic() - started

    assert resp.status_code == 200
    assert elapsed < 1.7, (
        f"/api/ready took {elapsed:.2f}s for two 1s checks — they ran in series"
    )


# ── Probes must never be rate limited ─────────────────────────────────────────

@pytest.mark.parametrize("endpoint", ["/api/health", "/api/ready"])
def test_probe_endpoints_are_not_rate_limited(endpoint):
    """The kubelet calls these from inside the pod with no X-Forwarded-For, so
    every probe hashes to ONE 'untrusted' bucket. Rate limiting them would
    throttle the probe into flapping and restart the pod."""
    import inspect
    from pathlib import Path
    import ast

    src = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text()
    tree = ast.parse(src)
    target = endpoint.rsplit("/", 1)[-1]
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for deco in node.decorator_list:
            if not (isinstance(deco, ast.Call) and deco.args):
                continue
            arg = deco.args[0]
            if isinstance(arg, ast.Constant) and arg.value == endpoint:
                calls = [
                    n.func.id
                    for n in ast.walk(node)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                ]
                assert "_enforce_rate_limit" not in calls, (
                    f"{endpoint} is rate limited — the kubelet probe would flap"
                )
                return
    pytest.fail(f"handler for {endpoint} not found")


# ── Rate-limit env parsing must never crash at import (CWE-1188) ──────────────

@pytest.mark.parametrize("value", ["0", "-1", "not-an-int", "", "  ", "1.5"])
def test_malformed_rate_limit_env_does_not_crash_import(monkeypatch, value):
    """int(os.getenv(...)) unguarded feeds a constructor that raises on limit<1,
    so RATE_LIMIT_QUERY_PER_MINUTE=0 (the natural 'disable') was CrashLoopBackOff."""
    client, main = _client(monkeypatch, RATE_LIMIT_QUERY_PER_MINUTE=value)
    assert main._query_rate_limiter.limit >= 1
    assert client.get("/api/health").status_code == 200


def test_valid_rate_limit_env_is_honoured(monkeypatch):
    client, main = _client(monkeypatch, RATE_LIMIT_QUERY_PER_MINUTE="42")
    assert main._query_rate_limiter.limit == 42


# ── Agent concurrency cap (CWE-400) ───────────────────────────────────────────

def test_concurrent_agent_queries_are_capped_with_429(monkeypatch):
    """A per-IP RATE limit does not bound CONCURRENCY: 10 requests from one IP
    can all be in flight at once in a 1 GiB pod.

    Driven directly on ONE event loop: TestClient runs each request in its own
    loop, and the semaphore is per-loop (production runs a single uvicorn loop),
    so threaded TestClient calls would never contend.
    """
    import asyncio

    from fastapi import HTTPException

    _client(monkeypatch, MAX_CONCURRENT_AGENT_QUERIES="2", RATE_LIMIT_QUERY_PER_MINUTE="100")
    import app.main as main

    assert main.MAX_CONCURRENT_AGENT_QUERIES == 2

    gate = asyncio.Event()

    class _SlowAgent:
        async def analyze(self, question, history):
            await gate.wait()
            return {"answer": "ok", "steps": []}

    monkeypatch.setattr(main, "langgraph_agent", _SlowAgent())

    class _FakeRequest:
        headers = {}
        client = None
        url = "http://testserver/api/query"
        method = "POST"

    async def _main():
        req = main.QueryRequest(question="hi", history=[])

        async def _one():
            try:
                await main.ai_query(req, _FakeRequest())
                return 200
            except HTTPException as e:
                return e.status_code

        tasks = [asyncio.create_task(_one()) for _ in range(5)]
        await asyncio.sleep(0.3)  # let the first two occupy the slots
        gate.set()
        return await asyncio.gather(*tasks)

    results = asyncio.new_event_loop().run_until_complete(_main())

    assert 429 in results, f"no request was shed; got {results}"
    assert results.count(200) <= 2, f"more than the cap ran concurrently: {results}"
    assert results.count(429) == 3


def test_agent_concurrency_slot_is_released_after_completion(monkeypatch):
    """A leaked slot would wedge the endpoint permanently after N requests."""
    client, main = _client(monkeypatch, MAX_CONCURRENT_AGENT_QUERIES="1")

    class _FastAgent:
        async def analyze(self, question, history):
            return {"answer": "ok", "steps": []}

    monkeypatch.setattr(main, "langgraph_agent", _FastAgent())

    for _ in range(4):
        resp = client.post("/api/query", json={"question": "hi", "history": []})
        assert resp.status_code == 200, "slot was not released by the previous call"


def test_rate_limit_env_clamps_the_upper_bound(monkeypatch):
    """An unbounded override defeats the ceiling it configures."""
    _, main = _client(monkeypatch, RATE_LIMIT_QUERY_PER_MINUTE="999999")
    assert main._query_rate_limiter.limit == main._MAX_RATE_LIMIT


def test_agent_concurrency_env_clamps_the_upper_bound(monkeypatch):
    _, main = _client(monkeypatch, MAX_CONCURRENT_AGENT_QUERIES="100000")
    assert main.MAX_CONCURRENT_AGENT_QUERIES == 50


def test_remediation_routes_are_rate_limited(monkeypatch):
    # A live apply takes a savepoint and patches the job; the routes share the
    # heavy-route budget. Write tools are off here, so in-limit calls get 403
    # and the third gets 429 before any gate or remediation runs.
    client, main = _client(monkeypatch, RATE_LIMIT_HEAVY_PER_MINUTE="2")
    body = {"type": "increase_checkpoint_timeout", "dry_run": True}
    assert client.post("/api/remediation/apply", json=body).status_code == 403
    assert client.post("/api/remediation/apply", json=body).status_code == 403
    assert client.post("/api/remediation/apply", json=body).status_code == 429

    client, main = _client(monkeypatch, RATE_LIMIT_HEAVY_PER_MINUTE="1")
    assert client.post("/api/remediation/rollback", json={"id": 0}).status_code == 403
    assert client.post("/api/remediation/rollback", json={"id": 0}).status_code == 429


def test_job_status_is_rate_limited(monkeypatch):
    client, main = _client(monkeypatch)

    async def _no_job():
        return None

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _no_job)
    codes = [client.get("/api/job/status").status_code for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429


def test_table_statistics_are_cached(monkeypatch):
    import asyncio
    from app.postgres_client import PostgresStateReader

    reader = PostgresStateReader.__new__(PostgresStateReader)
    reader.pool = object()
    calls = []

    async def _read():
        calls.append(1)
        return {"state_store": {"row_count": 1}}

    reader._read_table_statistics = _read
    loop = asyncio.new_event_loop()
    first = loop.run_until_complete(reader.get_table_statistics())
    second = loop.run_until_complete(reader.get_table_statistics())
    assert first == second and calls == [1]
