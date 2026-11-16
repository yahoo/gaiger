"""Deterministic tests: Kubernetes reads are scoped to this deployment (CWE-200).

The sidecar's RBAC Role is necessarily namespace-wide (Kubernetes has no
sub-namespace scoping for pods/log), so least privilege must be enforced in
KubernetesClient — at the primitives, not per call site:

1. get_pods / get_events / get_operator_logs default to THIS deployment; only
   the explicit NAMESPACE_WIDE sentinel widens a read. Nothing falsy does:
   None and "" both resolve to the deployment scope, and an empty
   FLINK_DEPLOYMENT_NAME resolves to the default name.
2. One ownership predicate (_owned_name_regex) is shared by the event filter
   and the operator-log filter: the operator-derived names of this deployment
   (<name>, <name>-taskmanager-1-3, <name>-<rs>-<pod>) are owned, the
   prefix-sharing neighbour <name>-extra is not.
3. Read failures surface as failures (an "error" key), never as empty results.
4. get_flink_jobmanager_logs / get_flink_taskmanager_logs / get_autoscaler_events
   never fall back to a namespace-wide list.

All mocks — no live cluster, no LLM.
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.kubernetes_client import NAMESPACE_WIDE, KubernetesClient, _owned_name_regex

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = "my-flink-job"
NEIGHBOUR = f"{DEPLOYMENT}-extra"          # shares the prefix, is NOT ours
OWN_TM = f"{DEPLOYMENT}-taskmanager-1-3"
OWN_JM = f"{DEPLOYMENT}-7d9f8b6c5-x2k9q"    # operator-created JobManager pod


def _source(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text()


def _pod_obj(name: str, labels: dict) -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace="flink-nonprod", labels=labels),
        status=SimpleNamespace(phase="Running", container_statuses=[], start_time=None),
        spec=SimpleNamespace(node_name="node-1"),
    )


def _client() -> KubernetesClient:
    k8s = KubernetesClient()
    k8s._initialized = True  # skip in-cluster/kubeconfig loading
    k8s.deployment_name = DEPLOYMENT
    k8s.core_v1 = MagicMock()
    return k8s


def _fake_cluster(k8s: KubernetesClient, pods: dict, logs: dict):
    """Simulate the API server: server-side label filtering + per-pod logs.

    `pods` maps pod name -> labels; `logs` maps pod name -> log text or an
    Exception instance to raise on read. Returns the dict of captured
    list_namespaced_pod kwargs so tests can assert on the selector actually
    sent to the API server.
    """
    captured = {"label_selectors": []}

    def list_pods(namespace, label_selector=None, **_):
        captured["label_selectors"].append(label_selector)
        items = []
        for name, lbls in pods.items():
            if label_selector:
                key, want = label_selector.split("=", 1)
                if lbls.get(key) != want:
                    continue
            items.append(_pod_obj(name, lbls))
        return SimpleNamespace(items=items)

    def read_log(name, **_):
        out = logs.get(name, f"logs-of-{name}")
        if isinstance(out, Exception):
            raise out
        return out

    k8s.core_v1.list_namespaced_pod.side_effect = list_pods
    k8s.core_v1.read_namespaced_pod_log.side_effect = read_log
    return captured


OWN = {"app": DEPLOYMENT}
THEIRS = {"app": "someone-else"}
OPERATOR = {"app.kubernetes.io/name": "flink-kubernetes-operator"}


# ── 1. Primitive defaults: scoped unless NAMESPACE_WIDE ─────────────────

def test_get_pods_defaults_to_this_deployment_selector():
    k8s = _client()
    captured = _fake_cluster(k8s, {OWN_TM: OWN, "neighbour-pod": THEIRS}, {})
    names = [p["name"] for p in k8s.get_pods()]
    assert captured["label_selectors"] == [f"app={DEPLOYMENT}"]
    assert names == [OWN_TM]


def test_get_pods_empty_selector_does_not_widen():
    k8s = _client()
    captured = _fake_cluster(k8s, {OWN_TM: OWN, "neighbour-pod": THEIRS}, {})
    names = [p["name"] for p in k8s.get_pods(label_selector="")]
    assert captured["label_selectors"] == [f"app={DEPLOYMENT}"]
    assert names == [OWN_TM]


def test_get_pods_namespace_wide_sentinel_lists_everything():
    k8s = _client()
    captured = _fake_cluster(k8s, {OWN_TM: OWN, "neighbour-pod": THEIRS}, {})
    names = {p["name"] for p in k8s.get_pods(label_selector=NAMESPACE_WIDE)}
    assert captured["label_selectors"] == [None]
    assert names == {OWN_TM, "neighbour-pod"}


def test_get_pods_explicit_selector_is_honoured():
    k8s = _client()
    captured = _fake_cluster(k8s, {"flink-kubernetes-operator-abc": OPERATOR, OWN_TM: OWN}, {})
    names = [p["name"] for p in k8s.get_pods(label_selector="app.kubernetes.io/name=flink-kubernetes-operator")]
    assert captured["label_selectors"] == ["app.kubernetes.io/name=flink-kubernetes-operator"]
    assert names == ["flink-kubernetes-operator-abc"]


def test_empty_flink_deployment_name_env_resolves_to_default(monkeypatch):
    # FLINK_DEPLOYMENT_NAME="" (set but empty) used to yield "", which the
    # scoped reads then treated as "app=" / an unfiltered operator log.
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "")
    assert KubernetesClient().deployment_name == "flink-job-with-ai-debugger"
    monkeypatch.delenv("FLINK_DEPLOYMENT_NAME")
    assert KubernetesClient().deployment_name == "flink-job-with-ai-debugger"
    monkeypatch.setenv("FLINK_DEPLOYMENT_NAME", "custom-name")
    assert KubernetesClient().deployment_name == "custom-name"


# ── 2. One ownership predicate for events AND operator logs ─────────────

@pytest.mark.parametrize("name", [
    DEPLOYMENT,
    f"{DEPLOYMENT}-rest",
    f"{DEPLOYMENT}-cluster-config-map",
    f"{DEPLOYMENT}-7d9f8b6c5",         # ReplicaSet
    OWN_JM,                             # JobManager pod
    OWN_TM,                             # TaskManager pod
    f"{DEPLOYMENT}-taskmanager-12-107",
])
def test_owned_name_regex_accepts_operator_derived_names(name):
    assert _owned_name_regex(DEPLOYMENT).fullmatch(name)


@pytest.mark.parametrize("name", [
    NEIGHBOUR,
    f"{NEIGHBOUR}-taskmanager-1-1",
    f"{NEIGHBOUR}-7d9f8b6c5-x2k9q",
    f"other-{DEPLOYMENT}",
    "unrelated-pod",
    "",
])
def test_owned_name_regex_rejects_neighbours(name):
    assert not _owned_name_regex(DEPLOYMENT).fullmatch(name)


RAW_OPERATOR_LOG = "\n".join([
    f"INFO [flink-nonprod/{DEPLOYMENT}] reconciled ok",
    f"INFO [flink-nonprod/{NEIGHBOUR}] neighbour deployment sharing a prefix",
    f"INFO pod {DEPLOYMENT} restarted",
    f"INFO pod {OWN_TM} terminated",
    f"INFO pod {OWN_JM} started",
    f"INFO pod {NEIGHBOUR}-taskmanager-1-1 terminated",
    "INFO unrelated-workload something happened",
])
OWN_OPERATOR_LINES = 4


def _operator_client(raw_logs=RAW_OPERATOR_LOG) -> KubernetesClient:
    k8s = _client()
    _fake_cluster(
        k8s,
        {"flink-kubernetes-operator-abc": OPERATOR, OWN_TM: OWN},
        {"flink-kubernetes-operator-abc": raw_logs},
    )
    return k8s


def test_operator_logs_are_filtered_for_this_deployment_by_default():
    # Call sites that pass nothing (main.py /api/logs/operator and
    # get_logs_with_error_analysis) inherit the deployment scope.
    result = _operator_client().get_operator_logs()
    assert result["filtered_for"] == DEPLOYMENT
    assert result["line_count"] == OWN_OPERATOR_LINES
    assert result["total_lines_scanned"] == 7
    assert "unrelated-workload" not in result["logs"]


def test_operator_logs_keep_own_pod_lines_and_drop_prefix_neighbour():
    # Same predicate as get_events: this deployment's own pod lines
    # (<name>-taskmanager-1-3, <name>-<rs>-<pod>) are KEPT, the prefix-sharing
    # neighbour and its pods are DROPPED.
    logs = _operator_client().get_operator_logs()["logs"]
    assert f"pod {DEPLOYMENT} restarted" in logs
    assert f"pod {OWN_TM} terminated" in logs
    assert f"pod {OWN_JM} started" in logs
    assert "neighbour deployment" not in logs
    assert f"{NEIGHBOUR}-taskmanager" not in logs


def test_operator_logs_empty_string_does_not_opt_out():
    # "" is no longer an escape hatch: a blank (from env or a caller) must
    # fail towards the scoped read.
    result = _operator_client().get_operator_logs(filter_deployment="")
    assert result["filtered_for"] == DEPLOYMENT
    assert result["line_count"] == OWN_OPERATOR_LINES


def test_operator_logs_namespace_wide_sentinel_returns_whole_log():
    result = _operator_client().get_operator_logs(filter_deployment=NAMESPACE_WIDE)
    assert "filtered_for" not in result
    assert result["line_count"] == 7


# ── 3. Events: scoped by default, warnings flag, shared predicate ───────

def _event(name: str, etype: str = "Normal", reason: str = "reason", message: str = "msg", kind: str = "Pod"):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        type=etype,
        reason=reason,
        message=message,
        involved_object=SimpleNamespace(kind=kind, name=name),
        count=1,
        first_timestamp=now,
        last_timestamp=now,
        event_time=None,
        metadata=SimpleNamespace(creation_timestamp=now),
        source=SimpleNamespace(component="kubelet"),
    )


def _events_client(events) -> KubernetesClient:
    k8s = _client()
    k8s.core_v1.list_namespaced_event.return_value = SimpleNamespace(items=events)
    return k8s


NODE_OOM = "ip-10-0-0-1.ec2.internal"
EVENTS = [
    _event(OWN_TM, etype="Warning", reason="BackOff"),
    _event(OWN_JM, etype="Normal", reason="Started"),
    _event(DEPLOYMENT, etype="Normal", reason="Reconciled", kind="FlinkDeployment"),
    _event(NEIGHBOUR, etype="Warning", reason="IneffectiveScaling", kind="FlinkDeployment"),
    _event(f"{NEIGHBOUR}-taskmanager-1-1", etype="Normal", reason="Started"),
    _event(NODE_OOM, etype="Warning", reason="SystemOOM", kind="Node"),
    _event("neighbour-pod", etype="Normal", reason="Started"),
]
OWN_OBJECTS = {f"Pod/{OWN_TM}", f"Pod/{OWN_JM}", f"FlinkDeployment/{DEPLOYMENT}"}


def test_events_default_is_scoped_to_this_deployment_plus_namespace_warnings():
    # No arguments at all: the primitive itself applies the scope.
    out = _events_client(EVENTS).get_events()
    objects = {e["object"] for e in out}
    assert objects == OWN_OBJECTS | {f"FlinkDeployment/{NEIGHBOUR}", f"Node/{NODE_OOM}"}
    scopes = {e["object"]: e["scope"] for e in out}
    assert all(scopes[o] == "mine" for o in OWN_OBJECTS)
    assert scopes[f"Node/{NODE_OOM}"] == "namespace_warning"
    assert scopes[f"FlinkDeployment/{NEIGHBOUR}"] == "namespace_warning"


def test_events_prefix_neighbour_is_not_owned():
    # The ownership predicate must not admit "<name>-extra" or its pods as
    # ours — a bare startswith("<name>-") did.
    out = _events_client(EVENTS).get_events(include_cross_deployment_warnings=False)
    assert {e["object"] for e in out} == OWN_OBJECTS
    assert all(e["scope"] == "mine" for e in out)


def test_events_warnings_off_returns_exactly_our_objects():
    # Positive AND negative: exactly the three owned objects come back (the
    # test cannot pass on an empty list), the neighbour Warning and the
    # Node-scoped OOM are excluded.
    out = _events_client(EVENTS).get_flink_pod_events(
        deployment_name=DEPLOYMENT, include_cross_deployment_warnings=False
    )
    assert len(out) == 3
    assert {e["object"] for e in out} == OWN_OBJECTS
    assert f"Node/{NODE_OOM}" not in {e["object"] for e in out}


def test_events_namespace_wide_sentinel_returns_everything():
    out = _events_client(EVENTS).get_events(deployment_name=NAMESPACE_WIDE)
    assert len(out) == len(EVENTS)
    assert {e["scope"] for e in out} == {"all"}


def test_events_empty_string_scope_does_not_widen():
    out = _events_client(EVENTS).get_events(deployment_name="", include_cross_deployment_warnings=False)
    assert {e["object"] for e in out} == OWN_OBJECTS


def test_wrappers_thread_scope_args_to_get_events():
    k8s = _client()
    captured = {}

    def fake_get_events(hours_back=4, deployment_name=None, include_cross_deployment_warnings=True, **kw):
        captured.update(
            hours_back=hours_back,
            deployment_name=deployment_name,
            include_cross_deployment_warnings=include_cross_deployment_warnings,
        )
        return []

    k8s.get_events = fake_get_events
    k8s.analyze_events(hours_back=24, deployment_name=DEPLOYMENT, include_cross_deployment_warnings=False)
    assert captured == {
        "hours_back": 24,
        "deployment_name": DEPLOYMENT,
        "include_cross_deployment_warnings": False,
    }


def test_analyze_events_default_scope_still_detects_node_scoped_oom():
    # The 2026-05-11 decision in practice: a TaskManager OOM surfaces as a
    # kubelet Node-scoped SystemOOM/OOMKilling Warning, owned by no
    # deployment. With the default (warnings on) the OOM issue fires; this is
    # why the autonomous root-cause path must NOT turn the pass-through off.
    analysis = _events_client(EVENTS).analyze_events(hours_back=24, deployment_name=DEPLOYMENT)
    assert [i["type"] for i in analysis["issues"]] == ["oom_detected", "pod_restarts"]
    analysis_off = _events_client(EVENTS).analyze_events(
        hours_back=24, deployment_name=DEPLOYMENT, include_cross_deployment_warnings=False
    )
    assert "oom_detected" not in [i["type"] for i in analysis_off["issues"]]


def test_autoscaler_events_are_scoped_with_warnings_off():
    k8s = _client()
    captured = {}

    def fake_get_flink_pod_events(hours_back=4, deployment_name=None, include_cross_deployment_warnings=True):
        captured.update(deployment_name=deployment_name, warnings=include_cross_deployment_warnings)
        return [
            {"type": "Warning", "reason": "IneffectiveScaling", "message": "x", "name": "e1"},
        ]

    k8s.get_flink_pod_events = fake_get_flink_pod_events
    out = k8s.get_autoscaler_events(hours=25)
    assert captured == {"deployment_name": DEPLOYMENT, "warnings": False}
    assert out and out[0]["job_key"] == f"{k8s.namespace}/{DEPLOYMENT}"


# ── 4. Pod-log readers: no namespace fallback, errors are errors ─────────

def test_taskmanager_logs_pass_app_label_selector_and_exclude_decoy():
    k8s = _client()
    captured = _fake_cluster(
        k8s,
        {OWN_TM: OWN, "decoy-taskmanager-pod": THEIRS},
        {OWN_TM: "tm-log-line"},
    )
    result = k8s.get_flink_taskmanager_logs()
    assert captured["label_selectors"] == [f"app={DEPLOYMENT}"]
    assert result["pods"] == [OWN_TM]
    assert result["logs"] == {OWN_TM: "tm-log-line"}
    assert "errors" not in result
    read_names = [c.kwargs["name"] for c in k8s.core_v1.read_namespaced_pod_log.call_args_list]
    assert read_names == [OWN_TM]


def test_taskmanager_logs_error_when_no_owned_tm_pods():
    k8s = _client()
    _fake_cluster(k8s, {"decoy-taskmanager-pod": THEIRS}, {})
    result = k8s.get_flink_taskmanager_logs()
    assert result["error"] == "No TaskManager pods found for this deployment"
    assert result["logs"] == {}


def test_taskmanager_logs_list_failure_is_an_error_not_empty():
    k8s = _client()
    k8s.core_v1.list_namespaced_pod.side_effect = RuntimeError("403 forbidden: system:serviceaccount:example-ns:example-sa")
    result = k8s.get_flink_taskmanager_logs()
    assert result["logs"] == {}
    assert result["error"].startswith("list pods failed (ref:")
    assert "serviceaccount" not in result["error"]


def test_taskmanager_logs_per_pod_read_failure_is_reported_separately():
    k8s = _client()
    tm2 = f"{DEPLOYMENT}-taskmanager-1-4"
    _fake_cluster(k8s, {OWN_TM: OWN, tm2: OWN}, {OWN_TM: "ok", tm2: RuntimeError("boom")})
    result = k8s.get_flink_taskmanager_logs()
    assert result["logs"] == {OWN_TM: "ok"}
    assert set(result["errors"]) == {tm2}
    assert result["errors"][tm2].startswith("read pod logs failed (ref:")


def test_jobmanager_logs_never_fall_back_to_a_neighbour_pod():
    # Our pods absent: the old code re-listed the namespace and read pods[:1]
    # — a neighbour's log, HTTP-reachable via /api/logs/jobmanager.
    k8s = _client()
    captured = _fake_cluster(k8s, {"neighbour-jobmanager-0": THEIRS, "other-pod": THEIRS}, {})
    result = k8s.get_flink_jobmanager_logs()
    assert result["error"] == "No JobManager pod found for this deployment"
    assert captured["label_selectors"] == [f"app={DEPLOYMENT}"]
    assert not k8s.core_v1.read_namespaced_pod_log.called


def test_jobmanager_logs_pick_operator_named_jm_pod_not_a_taskmanager():
    k8s = _client()
    _fake_cluster(k8s, {OWN_TM: OWN, OWN_JM: OWN, "neighbour-jobmanager-0": THEIRS}, {OWN_JM: "jm\nlog"})
    result = k8s.get_flink_jobmanager_logs()
    assert result["pod"] == OWN_JM
    assert result["logs"] == "jm\nlog"
    assert result["line_count"] == 2


def test_jobmanager_logs_read_failure_is_an_error():
    k8s = _client()
    _fake_cluster(k8s, {OWN_JM: OWN}, {OWN_JM: RuntimeError("boom")})
    result = k8s.get_flink_jobmanager_logs()
    assert result["pod"] == OWN_JM
    assert result["logs"] == ""
    assert result["error"].startswith("read pod logs failed (ref:")


def test_operator_logs_read_failure_is_an_error_not_filtered_to_empty():
    # Before: the opaque error string went through the deployment filter,
    # matched nothing, and came back as `logs: ""` with line_count 0.
    k8s = _client()
    _fake_cluster(
        k8s,
        {"flink-kubernetes-operator-abc": OPERATOR},
        {"flink-kubernetes-operator-abc": RuntimeError("boom")},
    )
    result = k8s.get_operator_logs()
    assert result["pod"] == "flink-kubernetes-operator-abc"
    assert result["logs"] == ""
    assert result["error"].startswith("read pod logs failed (ref:")
    assert "filtered_for" not in result


def test_operator_logs_list_failure_propagates_opaque_error():
    k8s = _client()
    k8s.core_v1.list_namespaced_pod.side_effect = RuntimeError("boom")
    result = k8s.get_operator_logs()
    assert result["error"].startswith("list pods failed (ref:")
    assert result["logs"] == ""


def test_get_pod_logs_keeps_str_contract():
    k8s = _client()
    _fake_cluster(k8s, {OWN_TM: OWN}, {OWN_TM: "fine", OWN_JM: RuntimeError("boom")})
    assert k8s.get_pod_logs(OWN_TM) == "fine"
    assert k8s.get_pod_logs(OWN_JM).startswith("read pod logs failed (ref:")


def test_pod_health_uses_only_owned_pods():
    k8s = _client()
    captured = _fake_cluster(k8s, {"neighbour-pod": THEIRS}, {})
    result = k8s.analyze_pod_health()
    assert result["pods"] == [] and result["pod_count"] == 0
    # No second, namespace-wide list call when our pods are absent.
    assert captured["label_selectors"] == [f"app={DEPLOYMENT}"]


# ── 5. Full diagnostics scopes its event read ──

def test_full_diagnostics_passes_deployment_name():
    k8s = _client()
    captured = {}

    def fake_analyze_events(hours_back=4, deployment_name=None, include_cross_deployment_warnings=True):
        captured["deployment_name"] = deployment_name
        return {"issues": []}

    k8s.analyze_events = fake_analyze_events
    k8s.analyze_pod_health = lambda: {"issues": [], "pods": [], "pod_count": 0}
    k8s.get_full_diagnostics(hours_back=24)
    assert captured["deployment_name"] == DEPLOYMENT


# ── 6. Source invariants at the boundaries ──

def test_source_kubernetes_client_never_lists_pods_namespace_wide():
    # Every get_pods() call inside the client either uses the default (this
    # deployment) or names an explicit selector; the widen sentinel is not
    # used anywhere in production code.
    client_src = _source("app/kubernetes_client.py")
    assert not re.search(r"(label_selector|deployment_name|filter_deployment)\s*=\s*NAMESPACE_WIDE", client_src)
    for rel in ("app/langgraph_agent.py", "app/main.py", "app/metrics_collector.py"):
        assert "NAMESPACE_WIDE" not in _source(rel), rel


def test_source_agent_tools_use_the_clients_resolved_deployment_name():
    src = _source("app/langgraph_agent.py")
    # Both analyze_events call sites pass the client's resolved name, and no
    # tool reads FLINK_DEPLOYMENT_NAME straight from the environment (an unset
    # or empty value used to become deployment_name=None → whole namespace).
    assert len(re.findall(r"k8s\.analyze_events,[^)]*deployment_name=k8s\.deployment_name", src, re.S)) == 2
    assert 'os.getenv("FLINK_DEPLOYMENT_NAME")' not in src
    # The autonomous root-cause path keeps namespace Warnings ON (Node-scoped
    # OOM events must still reach its OOM branch).
    assert "include_cross_deployment_warnings=False" not in src


def test_source_operator_route_does_not_forward_a_caller_filter():
    # The widen sentinel must never become HTTP-reachable: the
    # /api/logs/operator route must keep calling get_operator_logs with no
    # arguments so the safe default applies and no user input reaches
    # filter_deployment.
    src = _source("app/main.py")
    assert "k8s_call(k8s_client.get_operator_logs)" in src
    assert "filter_deployment" not in src
    assert "NAMESPACE_WIDE" not in src
