# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Availability / correctness hardening tests.

Covers, without any cluster or LLM:
  1. Event-loop hygiene (CWE-1088): AST scan asserting no synchronous
     KubernetesClient call is made directly inside an ``async def`` — the sync
     kubernetes/urllib3 client must always be dispatched via asyncio.to_thread.
  2. tail_lines sink clamp + limit_bytes (CWE-400/770).
  3. Remediation-action integrity (CWE-670): create_action populates
     config_changes for both catalog shapes; empty-change actions fail loudly
     BEFORE a savepoint fires; the agent-path defect shape cannot recur.
  4. CRD patch precondition (CWE-362): only changed keys are sent, with
     resourceVersion, and a 409 conflict is retried a bounded number of times.
  5. Sliding-window rate limiter unit behavior (CWE-770).
"""
import ast
import asyncio
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 1. Event-loop hygiene (AST) ────────────────────────────────────────────────

# Names that hold a KubernetesClient (or one of its raw sync API objects) in app
# code. Any Call on these receivers inside an async def blocks the event loop.
_K8S_RECEIVERS = {"k8s", "k8s_client", "custom_api", "core_v1", "apps_v1", "authz_v1", "api"}

_CHECKED_FILES = [
    "main.py",
    "langgraph_agent.py",
    "metrics_collector.py",
    "auto_remediator.py",
    "kubernetes_client.py",
]


def _receiver_is_k8s(node):
    if isinstance(node, ast.Name):
        return node.id in _K8S_RECEIVERS
    if isinstance(node, ast.Attribute):  # e.g. self.k8s_client.<method>()
        return node.attr in _K8S_RECEIVERS
    return False


def _violations(tree):
    found = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.AsyncFunctionDef):
            continue
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if _receiver_is_k8s(node.func.value):
                    found.append((func.name, node.func.attr, node.lineno))
    return found


@pytest.mark.parametrize("filename", _CHECKED_FILES)
def test_no_blocking_k8s_call_inside_async_def(filename):
    tree = ast.parse((APP_DIR / filename).read_text())
    bad = _violations(tree)
    assert not bad, (
        f"{filename}: synchronous KubernetesClient call(s) inside async def — "
        f"dispatch via asyncio.to_thread instead: {bad}"
    )


# ── 2. tail_lines sink clamp ───────────────────────────────────────────────────

class _RecordingCoreV1:
    def __init__(self):
        self.calls = []

    def read_namespaced_pod_log(self, **kwargs):
        self.calls.append(kwargs)
        return "log line\n"


def _make_k8s():
    kclient = pytest.importorskip("app.kubernetes_client")
    k8s = object.__new__(kclient.KubernetesClient)
    k8s.namespace = "flink"
    k8s.deployment_name = "test-job"
    k8s.pod_name = ""
    k8s._initialized = True
    k8s.core_v1 = _RecordingCoreV1()
    return k8s


def test_oversized_tail_lines_clamped_at_sink():
    from app.kubernetes_client import LOG_LIMIT_BYTES, MAX_TAIL_LINES

    k8s = _make_k8s()
    k8s.get_pod_logs("tm-pod-1", tail_lines=10**8)
    call = k8s.core_v1.calls[0]
    assert call["tail_lines"] == MAX_TAIL_LINES == 5000
    assert call["limit_bytes"] == LOG_LIMIT_BYTES == 10 * 1024 * 1024


def test_negative_tail_lines_clamped_to_one():
    k8s = _make_k8s()
    k8s.get_pod_logs("tm-pod-1", tail_lines=-5)
    assert k8s.core_v1.calls[0]["tail_lines"] == 1


def test_reasonable_tail_lines_passes_through():
    k8s = _make_k8s()
    k8s.get_pod_logs("tm-pod-1", tail_lines=100)
    assert k8s.core_v1.calls[0]["tail_lines"] == 100


def test_tool_schema_bounds_tail_lines(monkeypatch):
    """The tool-boundary bound is what the model sees in the tool schema."""
    pytest.importorskip("langchain_core")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.delenv("ENABLE_WRITE_TOOLS", raising=False)
    from app import langgraph_agent as lga

    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = None
    agent.slack_client = None
    agent.github_client = None
    tools = agent._create_tools()

    for tool_name in ("get_kubernetes_logs", "get_flink_operator_logs"):
        tool = next(t for t in tools if t.name == tool_name)
        schema = tool.tool_call_schema.model_json_schema()
        prop = schema["properties"]["tail_lines"]
        assert prop.get("maximum") == 5000, f"{tool_name}: upper bound missing"
        assert prop.get("minimum") == 1, f"{tool_name}: lower bound missing"


# ── 3. Remediation-action integrity ───────────────────────────────────────────

class _RecordingFlink:
    def __init__(self):
        self.savepoints = 0

    async def get_running_job_id(self):
        return "job-abc"

    async def trigger_savepoint(self, job_id):
        self.savepoints += 1
        return {"request-id": f"sp-{self.savepoints}"}

    async def get_savepoint_status(self, job_id, trigger_id):
        return {"status": {"id": "COMPLETED"}, "operation": {"location": "file:///sp"}}


def test_create_action_populates_changes_for_every_auto_applicable_type():
    ar = pytest.importorskip("app.auto_remediator")
    remediator = ar.AutoRemediator(flink_client=_RecordingFlink(), k8s_client=None)
    for rtype, entry in ar.REMEDIATION_CATALOG.items():
        if not entry.get("auto_applicable"):
            continue
        action = remediator.create_action(rtype)
        if rtype == ar.RemediationType.CREATE_EMERGENCY_SAVEPOINT:
            continue  # savepoint-only type legitimately has no config changes
        assert action.config_changes, (
            f"{rtype.value}: create_action produced empty config_changes — "
            "the savepoint-then-no-op defect would recur"
        )


def test_private_alias_preserved_for_existing_callers():
    ar = pytest.importorskip("app.auto_remediator")
    assert ar.AutoRemediator._create_action is ar.AutoRemediator.create_action


def test_dry_run_preview_is_populated_for_config_key_types():
    ar = pytest.importorskip("app.auto_remediator")
    remediator = ar.AutoRemediator(flink_client=_RecordingFlink(), k8s_client=None)
    for rtype, entry in ar.REMEDIATION_CATALOG.items():
        if not entry.get("auto_applicable") or "config_key" not in entry:
            continue
        action = remediator.create_action(rtype)
        result = _run(remediator.apply_remediation(action, applied_by="test", dry_run=True))
        assert result.success is True
        assert result.changes_made, f"{rtype.value}: dry-run preview empty"


def test_empty_change_action_fails_loudly_without_firing_savepoint():
    ar = pytest.importorskip("app.auto_remediator")
    flink = _RecordingFlink()
    remediator = ar.AutoRemediator(flink_client=flink, k8s_client=None)
    defective = ar.RemediationAction(
        type=ar.RemediationType.INCREASE_CHECKPOINT_TIMEOUT,
        description="hand-built without config changes",
        risk_level=ar.RiskLevel.SAFE,
        requires_restart=False,
        auto_applicable=True,
        config_changes={},
    )
    for dry_run in (True, False):
        result = _run(remediator.apply_remediation(defective, applied_by="test", dry_run=dry_run))
        assert result.success is False
        assert "nothing was applied" in result.message
        assert result.backup_created is None
    assert flink.savepoints == 0, "a real savepoint fired for a no-op remediation"


def test_agent_tool_path_applies_config_key_remediation(monkeypatch):
    """The agent tool must produce the same populated change set as the REST path."""
    import json

    pytest.importorskip("langchain_core")
    ar = pytest.importorskip("app.auto_remediator")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ENABLE_WRITE_TOOLS", "true")
    # main's fail-closed write gate denies on an unknown environment,
    # so the nonprod domain must be declared for the write tool to register at all.
    monkeypatch.setenv("DEPLOY_ENV", "nonprod")
    from app import langgraph_agent as lga

    agent = object.__new__(lga.LangGraphAgent)
    agent.flink_client = None
    agent.k8s_client = None
    agent.postgres_reader = None
    agent.auto_remediator = ar.AutoRemediator(flink_client=_RecordingFlink(), k8s_client=None)
    agent.slack_client = None
    agent.github_client = None
    tools = agent._create_tools()
    tool = next(t for t in tools if t.name == "apply_remediation")

    raw = _run(tool.ainvoke({"remediation_type": "increase_checkpoint_timeout", "dry_run": True}))
    # Tool returns are provenance-fenced by _as_untrusted (CWE-77 hardening);
    # extract the JSON payload from between the fence tags.
    result = json.loads(raw.split("\n", 1)[1].rsplit("\n</untrusted_data>\n", 1)[0])
    assert result["success"] is True
    assert result["changes_made"] == {"execution.checkpointing.timeout": "600000"}


# ── 4. CRD patch precondition + bounded retry ─────────────────────────────────

class _ConflictingApi:
    def __init__(self, conflicts=0, resource_version="42"):
        self.get_calls = []
        self.patch_calls = []
        self._conflicts = conflicts
        self._rv = resource_version

    def get_namespaced_custom_object(self, **kwargs):
        self.get_calls.append(kwargs)
        current = {"spec": {"flinkConfiguration": {"canary.key": "1"}}}
        if self._rv is not None:
            current["metadata"] = {"resourceVersion": self._rv}
        return current

    def patch_namespaced_custom_object(self, **kwargs):
        from kubernetes.client.rest import ApiException

        self.patch_calls.append(kwargs)
        if self._conflicts > 0:
            self._conflicts -= 1
            raise ApiException(status=409, reason="Conflict")
        return {"spec": kwargs["body"]["spec"]}


def _remediator_with_api(api):
    kclient = pytest.importorskip("app.kubernetes_client")
    ar = pytest.importorskip("app.auto_remediator")
    k8s = object.__new__(kclient.KubernetesClient)
    k8s.namespace = "flink"
    k8s.deployment_name = "test-job"
    k8s._initialized = True
    k8s.custom_api = api
    k8s._ensure_initialized = lambda: None
    return ar.AutoRemediator(flink_client=_RecordingFlink(), k8s_client=k8s)


def test_patch_sends_only_changed_keys_with_resource_version():
    pytest.importorskip("kubernetes")
    api = _ConflictingApi()
    remediator = _remediator_with_api(api)
    _run(remediator._apply_config_via_k8s({"execution.checkpointing.timeout": "600000"}))

    assert len(api.patch_calls) == 1
    body = api.patch_calls[0]["body"]
    # Only the changed key — the concurrent canary key must NOT be echoed back
    # (whole-map write is exactly the clobber this fix removes).
    assert body["spec"]["flinkConfiguration"] == {"execution.checkpointing.timeout": "600000"}
    assert "canary.key" not in body["spec"]["flinkConfiguration"]
    assert body["metadata"]["resourceVersion"] == "42"


def test_patch_conflict_is_retried_then_succeeds():
    pytest.importorskip("kubernetes")
    api = _ConflictingApi(conflicts=1)
    remediator = _remediator_with_api(api)
    _run(remediator._apply_config_via_k8s({"execution.checkpointing.timeout": "600000"}))
    assert len(api.get_calls) == 2   # re-read after the 409
    assert len(api.patch_calls) == 2


def test_patch_gives_up_after_bounded_conflict_retries():
    pytest.importorskip("kubernetes")
    from kubernetes.client.rest import ApiException

    api = _ConflictingApi(conflicts=99)
    remediator = _remediator_with_api(api)
    with pytest.raises(ApiException):
        _run(remediator._apply_config_via_k8s({"execution.checkpointing.timeout": "600000"}))
    assert len(api.patch_calls) == 3  # bounded — no infinite retry loop


def test_patch_fails_closed_when_resource_version_absent():
    """A read with no resourceVersion must NOT degrade to an unguarded merge-patch.

    Building the precondition under `if resource_version:` silently dropped the
    CAS guard — reintroducing the very concurrent-write clobber it exists to
    prevent. Absent precondition must raise, and must not write.
    """
    pytest.importorskip("kubernetes")
    api = _ConflictingApi(resource_version=None)
    remediator = _remediator_with_api(api)
    with pytest.raises(RuntimeError, match="resourceVersion"):
        _run(remediator._apply_config_via_k8s({"execution.checkpointing.timeout": "600000"}))
    assert api.patch_calls == []


# ── 5. Rate limiter unit behavior ─────────────────────────────────────────────

def test_rate_limiter_allows_up_to_limit_then_denies():
    from app.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(limit=3, window_seconds=60.0)
    for i in range(3):
        allowed, retry_after = limiter.check("ip1", now=100.0 + i)
        assert allowed and retry_after == 0.0
    allowed, retry_after = limiter.check("ip1", now=103.0)
    assert not allowed
    assert retry_after > 0.0


def test_rate_limiter_window_slides():
    from app.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60.0)
    assert limiter.check("ip1", now=0.0)[0]
    assert limiter.check("ip1", now=1.0)[0]
    assert not limiter.check("ip1", now=2.0)[0]
    # After the first event leaves the window, capacity returns.
    assert limiter.check("ip1", now=61.0)[0]


def test_rate_limiter_keys_are_independent():
    from app.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60.0)
    assert limiter.check("ip1", now=0.0)[0]
    assert limiter.check("ip2", now=0.0)[0]
    assert not limiter.check("ip1", now=1.0)[0]


def test_rate_limiter_denied_requests_do_not_extend_penalty():
    from app.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60.0)
    assert limiter.check("ip1", now=0.0)[0]
    for t in range(1, 59):
        assert not limiter.check("ip1", now=float(t))[0]
    assert limiter.check("ip1", now=61.0)[0]


# ── 6. Kubernetes request timeouts (CWE-1088) ─────────────────────────────────
#
# Without an explicit _request_timeout a blackholed API server blocks the worker
# thread forever, the to_thread pool fills, and every later to_thread in the
# process wedges behind it — while /api/health (process-only) still answers 200,
# so liveness never restarts the pod.

_K8S_API_METHODS = {
    "list_namespaced_event",
    "list_namespaced_pod",
    "read_namespaced_pod_log",
    "get_namespaced_custom_object",
    "patch_namespaced_custom_object",
    "patch_namespaced_deployment",
}


def _timeout_violations(path: Path):
    """Kubernetes API calls that pass neither a _request_timeout kwarg nor **kwargs."""
    tree = ast.parse(path.read_text())
    bad = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _K8S_API_METHODS:
            continue
        names = {kw.arg for kw in node.keywords}
        # arg=None is a **kwargs splat; the dict is asserted separately below.
        if "_request_timeout" not in names and None not in names:
            bad.append((node.func.attr, node.lineno))
    return bad


@pytest.mark.parametrize("filename", ["kubernetes_client.py", "auto_remediator.py"])
def test_every_k8s_api_call_sets_request_timeout(filename):
    bad = _timeout_violations(APP_DIR / filename)
    assert not bad, f"{filename}: Kubernetes call(s) with no _request_timeout: {bad}"


def test_request_timeout_reaches_the_api_for_kwargs_call_sites():
    """The three **kwargs sites must carry the timeout inside the dict."""
    from app.kubernetes_client import K8S_REQUEST_TIMEOUT

    k8s = _make_k8s()
    k8s.get_pod_logs("tm-pod-1", tail_lines=10)
    assert k8s.core_v1.calls[0]["_request_timeout"] == K8S_REQUEST_TIMEOUT


def test_request_timeout_is_a_connect_read_pair_of_positive_numbers():
    from app.kubernetes_client import K8S_REQUEST_TIMEOUT

    assert isinstance(K8S_REQUEST_TIMEOUT, tuple) and len(K8S_REQUEST_TIMEOUT) == 2
    assert all(isinstance(v, int) and v > 0 for v in K8S_REQUEST_TIMEOUT)


def test_env_int_falls_back_instead_of_raising(monkeypatch):
    from app.kubernetes_client import _env_int

    monkeypatch.setenv("X_TEST_K8S", "not-a-number")
    assert _env_int("X_TEST_K8S", 7) == 7
    monkeypatch.setenv("X_TEST_K8S", "0")
    assert _env_int("X_TEST_K8S", 7) == 1  # clamped to the minimum, not zero
    monkeypatch.setenv("X_TEST_K8S", "12")
    assert _env_int("X_TEST_K8S", 7) == 12


# ── 7. Bounded Kubernetes I/O concurrency (CWE-400) ───────────────────────────

def test_k8s_call_bounds_concurrency():
    """to_thread alone lands on the default executor, sized off HOST cpu_count."""
    import threading

    from app import kubernetes_client as kc

    live = 0
    peak = 0
    lock = threading.Lock()
    release = threading.Event()

    def _blocking():
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        release.wait(timeout=5)
        with lock:
            live -= 1

    async def _main():
        # Far more callers than the bound, all in flight at once.
        tasks = [asyncio.create_task(kc.k8s_call(_blocking)) for _ in range(20)]
        await asyncio.sleep(0.3)
        observed = peak
        release.set()
        await asyncio.gather(*tasks)
        return observed

    observed_peak = _run(_main())
    assert observed_peak <= kc.K8S_MAX_CONCURRENCY, (
        f"{observed_peak} concurrent K8s calls exceeded the "
        f"{kc.K8S_MAX_CONCURRENCY} bound"
    )
    assert observed_peak > 0


def test_k8s_call_still_runs_off_the_event_loop():
    import threading

    from app.kubernetes_client import k8s_call

    caller = threading.get_ident()
    ran_on = {}

    def _work():
        ran_on["tid"] = threading.get_ident()
        return "done"

    assert _run(k8s_call(_work)) == "done"
    assert ran_on["tid"] != caller


def test_k8s_call_forwards_args_and_propagates_exceptions():
    from app.kubernetes_client import k8s_call

    def _echo(a, b=None):
        return (a, b)

    assert _run(k8s_call(_echo, 1, b=2)) == (1, 2)

    def _boom():
        raise ValueError("upstream failure")

    with pytest.raises(ValueError, match="upstream failure"):
        _run(k8s_call(_boom))


# ── 8. Process-wide Postgres gather bound (CWE-770) ───────────────────────────

def test_autoscaler_gather_semaphore_is_shared_across_callers():
    """Constructed per-invocation, 5 concurrent callers still took 10 of 10
    connections — each got its own semaphore. The bound must be process-wide."""
    from app import postgres_client as pgc

    async def _main():
        return [pgc._autoscaler_gather_semaphore() for _ in range(5)]

    sems = _run(_main())
    assert all(s is sems[0] for s in sems), "each caller got a different semaphore"


def test_autoscaler_gather_semaphore_not_built_inside_the_method():
    """Guards against the per-invocation pattern being reintroduced."""
    src = (APP_DIR / "postgres_client.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "get_comprehensive_autoscaler_info":
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                    assert inner.func.attr != "Semaphore", (
                        "Semaphore constructed inside get_comprehensive_autoscaler_info "
                        "— each concurrent caller would get its own"
                    )
            break
    else:
        pytest.fail("get_comprehensive_autoscaler_info not found")


def test_env_int_clamps_the_upper_bound_too():
    """These values ARE the resource bounds — an unbounded override defeats the
    control it configures, so the upper clamp is part of the control."""
    import os

    from app import kubernetes_client as kc

    assert kc._env_int("X_ABSENT", 4, maximum=32) == 4
    os.environ["X_TEST_MAX"] = "100000"
    try:
        assert kc._env_int("X_TEST_MAX", 4, maximum=32) == 32
    finally:
        del os.environ["X_TEST_MAX"]


def test_k8s_tunables_are_within_sane_bounds():
    from app import kubernetes_client as kc

    assert 0 < kc.K8S_CONNECT_TIMEOUT <= 60
    assert 0 < kc.K8S_READ_TIMEOUT <= 120
    assert 0 < kc.K8S_MAX_CONCURRENCY <= 32
