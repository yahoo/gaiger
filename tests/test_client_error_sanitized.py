# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Client-layer error text must be opaque and correlatable (CWE-209 / CWE-532).

The route layer in app/main.py already returns static messages (covered by
tests/test_error_messages_sanitized.py). These tests pin the layer BELOW it,
where the sanitization was previously defeated: client modules must never
return raw exception text to a caller. A kubernetes.client.ApiException
stringifies to the API server's response body — the ServiceAccount principal,
the namespace, and the exact RBAC denial — which was returned verbatim through
/api/logs/* and /api/diagnostics/full.

client_error() logs the full detail server-side keyed by the correlation id
and returns an opaque token, so operators lose nothing while callers learn
nothing. Also pins the CWE-532 half: the FlinkDeployment patch path logs
config KEYS only, never values.
"""
import contextvars
import logging

import pytest

from app.audit import new_correlation_id
from app.safe_errors import client_error

_FORBIDDEN_BODY = (
    '(403) Reason: Forbidden: pods is forbidden: User '
    '"system:serviceaccount:example-namespace:flink-operator" cannot list '
    'resource "pods" in API group "" in the namespace "example-namespace"'
)

_LEAK_MARKERS = ("system:serviceaccount", "example-namespace", "is forbidden", "Forbidden")


# ── the shared helper ──

def test_client_error_returns_opaque_correlatable_token():
    def _run():
        cid = new_correlation_id()
        return cid, client_error("read pod logs", Exception(_FORBIDDEN_BODY))
    cid, msg = contextvars.Context().run(_run)
    assert msg == f"read pod logs failed (ref: {cid})"
    for leak in _LEAK_MARKERS:
        assert leak not in msg


def test_client_error_without_bound_cid_uses_placeholder():
    msg = contextvars.Context().run(
        lambda: client_error("list pods", Exception(_FORBIDDEN_BODY))
    )
    assert msg == "list pods failed (ref: -)"
    for leak in _LEAK_MARKERS:
        assert leak not in msg


def test_client_error_keeps_full_detail_server_side(caplog):
    # Correlation must still work: the full exception is retrievable from the
    # container log by the ref id. A fix that hides the error from the operator
    # as well as the attacker is not the fix.
    with caplog.at_level(logging.ERROR, logger="app.safe_errors"):
        def _run():
            cid = new_correlation_id()
            client_error("read pod logs", Exception(_FORBIDDEN_BODY))
            return cid
        cid = contextvars.Context().run(_run)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert cid in joined                       # correlatable
    assert "system:serviceaccount" in joined   # full detail preserved server-side


# ── the client-layer sites that previously leaked ──

class _RaisingCoreV1:
    def read_namespaced_pod_log(self, **kwargs):
        raise Exception(_FORBIDDEN_BODY)

    def list_namespaced_event(self, **kwargs):
        raise Exception(_FORBIDDEN_BODY)

    def list_namespaced_pod(self, **kwargs):
        raise Exception(_FORBIDDEN_BODY)


@pytest.fixture
def k8s():
    pytest.importorskip("kubernetes")
    from app.kubernetes_client import KubernetesClient
    c = KubernetesClient()
    c._initialized = True  # bypass cluster config load; APIs are stubbed below
    c.core_v1 = _RaisingCoreV1()
    return c


def test_get_pod_logs_error_is_opaque(k8s):
    out = k8s.get_pod_logs("some-pod")
    for leak in _LEAK_MARKERS:
        assert leak not in out
    assert "(ref:" in out                      # correlatable token present


def test_get_events_error_is_opaque(k8s):
    out = k8s.get_events()
    assert isinstance(out, list) and "error" in out[0]
    for leak in _LEAK_MARKERS:
        assert leak not in out[0]["error"]
    assert "(ref:" in out[0]["error"]


def test_get_pods_error_is_opaque(k8s):
    out = k8s.get_pods()
    assert isinstance(out, list) and "error" in out[0]
    for leak in _LEAK_MARKERS:
        assert leak not in out[0]["error"]
    assert "(ref:" in out[0]["error"]


# ── the CWE-532 half: patch path logs keys only, never values ──

class _EchoingCustomApi:
    def patch_namespaced_custom_object(self, **kwargs):
        return {"spec": {"flinkConfiguration": kwargs["body"]["spec"]["flinkConfiguration"]}}


def test_patch_flink_config_logs_keys_never_values(k8s, caplog):
    k8s.custom_api = _EchoingCustomApi()
    valid_value = "73519ms"
    with caplog.at_level(logging.INFO, logger="app.kubernetes_client"):
        result = k8s.patch_flink_config({"execution.checkpointing.interval": valid_value})
    assert result.get("success") is True
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "execution.checkpointing.interval" in joined  # key IS logged (forensics)
    assert valid_value not in joined                     # value NEVER logged
    # A secret-shaped value is refused by the value schema, and still never logged.
    caplog.clear()
    secret_value = "SECRET-sasl-credential-hunter2-AKIAEXAMPLE"
    with caplog.at_level(logging.INFO, logger="app.kubernetes_client"):
        result = k8s.patch_flink_config({"execution.checkpointing.interval": secret_value})
    assert result.get("success") is not True
    assert secret_value not in "\n".join(r.getMessage() for r in caplog.records)
    assert "hunter2" not in joined


class _RaisingCustomApi:
    def patch_namespaced_custom_object(self, **kwargs):
        raise Exception(_FORBIDDEN_BODY)


def test_patch_flink_config_error_is_opaque(k8s):
    k8s.custom_api = _RaisingCustomApi()
    result = k8s.patch_flink_config({"execution.checkpointing.interval": "60000"})
    for leak in _LEAK_MARKERS:
        assert leak not in result["error"]
    assert "(ref:" in result["error"]
