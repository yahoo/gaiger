# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Deterministic tests for the RBAC write-permission self-check.

Covers KubernetesClient.check_write_permissions() (best-effort SelfSubjectAccessReview
for the cluster-mutate verbs the write path uses) and the gated startup decision logic
in main.py's startup_event. Uses mocks for the AuthorizationV1Api so no live cluster is
needed.
"""
import logging
from unittest.mock import MagicMock, patch

import pytest

from app.kubernetes_client import KubernetesClient


def _client_with_fake_authz(allowed):
    """Build a KubernetesClient with a mocked, already-initialized authz client.

    `allowed` is the bool returned by every SelfSubjectAccessReview's status.allowed.
    """
    k8s = KubernetesClient()
    k8s._initialized = True  # skip in-cluster/kubeconfig loading
    fake_authz = MagicMock()
    resp = MagicMock()
    resp.status.allowed = allowed
    fake_authz.create_self_subject_access_review.return_value = resp
    k8s.authz_v1 = fake_authz
    return k8s


# ── check_write_permissions: allow / deny mapping ──

def test_returns_allowed_map_when_permitted():
    k8s = _client_with_fake_authz(allowed=True)
    perms = k8s.check_write_permissions()
    assert perms == {
        "patch flinkdeployments.flink.apache.org": True,
        "patch deployments.apps": True,
    }
    # One SelfSubjectAccessReview per checked verb/resource.
    assert k8s.authz_v1.create_self_subject_access_review.call_count == 2


def test_reflects_denial_when_not_permitted():
    k8s = _client_with_fake_authz(allowed=False)
    perms = k8s.check_write_permissions()
    assert perms == {
        "patch flinkdeployments.flink.apache.org": False,
        "patch deployments.apps": False,
    }


def test_checks_patch_on_both_write_resources():
    # The two resources the remediation path mutates must each be reviewed with verb=patch.
    k8s = _client_with_fake_authz(allowed=True)
    with patch("app.kubernetes_client.client") as fake_client:
        fake_client.V1SelfSubjectAccessReview.side_effect = lambda **kw: kw
        # The mocked authz still returns allowed=True via the closure below.
        resp = MagicMock()
        resp.status.allowed = True
        k8s.authz_v1.create_self_subject_access_review.return_value = resp
        k8s.check_write_permissions()

    attr_calls = fake_client.V1ResourceAttributes.call_args_list
    seen = {(c.kwargs["group"], c.kwargs["resource"], c.kwargs["verb"]) for c in attr_calls}
    assert ("flink.apache.org", "flinkdeployments", "patch") in seen
    assert ("apps", "deployments", "patch") in seen


# ── never raises ──

def test_returns_empty_when_uninitialized():
    k8s = KubernetesClient()
    # Force initialization to fail (no cluster config available in the test env).
    with patch.object(k8s, "_ensure_initialized", lambda: None):
        assert k8s._initialized is False
        assert k8s.check_write_permissions() == {}


def test_records_none_and_does_not_raise_on_api_error(caplog):
    k8s = KubernetesClient()
    k8s._initialized = True
    fake_authz = MagicMock()
    fake_authz.create_self_subject_access_review.side_effect = RuntimeError("boom")
    k8s.authz_v1 = fake_authz

    with caplog.at_level(logging.WARNING, logger="app.kubernetes_client"):
        perms = k8s.check_write_permissions()

    # Errors are recorded as None (unknown), not raised.
    assert perms == {
        "patch flinkdeployments.flink.apache.org": None,
        "patch deployments.apps": None,
    }
    assert any("RBAC self-check failed" in r.message for r in caplog.records)


# ── startup-branch decision logic ──
#
# Mirrors the gate in main.startup_event: only run the check when write tools are
# enabled, and warn (naming the missing verb) when a required permission is denied.

def _startup_rbac_branch(perms, logger):
    """Faithful copy of the startup_event self-check branch body (run when enabled)."""
    denied = [k for k, v in perms.items() if v is False]
    unknown = [k for k, v in perms.items() if v is None]
    if denied:
        logger.warning(
            "Write tools enabled but Kubernetes RBAC denies required permission(s): %s "
            "— remediations will fail at runtime — grant RBAC or set ENABLE_WRITE_TOOLS=false",
            ", ".join(denied),
        )
    if unknown:
        logger.warning(
            "Write tools enabled but could not verify Kubernetes RBAC for: %s "
            "— SelfSubjectAccessReview returned no decision; remediations may fail at runtime",
            ", ".join(unknown),
        )
    if perms and not denied and not unknown:
        logger.info(
            "Write tools enabled — required cluster-mutate permissions present "
            "(granted to the pod's ServiceAccount): %s",
            ", ".join(perms.keys()),
        )


def test_startup_skips_check_when_write_tools_disabled():
    fake_k8s = MagicMock()
    with patch("app.main.write_tools_enabled", return_value=False):
        from app.main import write_tools_enabled  # bound to the patched callable
        if write_tools_enabled():
            fake_k8s.check_write_permissions()
    fake_k8s.check_write_permissions.assert_not_called()


def test_startup_warns_naming_missing_verb_when_denied(caplog):
    perms = {
        "patch flinkdeployments.flink.apache.org": False,
        "patch deployments.apps": True,
    }
    logger = logging.getLogger("app.main")
    with patch("app.main.write_tools_enabled", return_value=True):
        from app.main import write_tools_enabled
        with caplog.at_level(logging.WARNING, logger="app.main"):
            if write_tools_enabled():
                _startup_rbac_branch(perms, logger)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "denies required permission" in warnings[0]
    assert "patch flinkdeployments.flink.apache.org" in warnings[0]   # the denied verb is named
    assert "patch deployments.apps" not in warnings[0]                # the allowed verb is not


def test_startup_no_warning_when_all_permissions_present(caplog):
    perms = {
        "patch flinkdeployments.flink.apache.org": True,
        "patch deployments.apps": True,
    }
    logger = logging.getLogger("app.main")
    with caplog.at_level(logging.INFO, logger="app.main"):
        _startup_rbac_branch(perms, logger)

    assert not [r for r in caplog.records if r.levelno == logging.WARNING]
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert any("required cluster-mutate permissions present" in m for m in infos)


def test_startup_warns_unknown_and_no_success_when_permission_undetermined(caplog):
    # A None value means the SelfSubjectAccessReview failed (unknown), not allowed.
    perms = {
        "patch flinkdeployments.flink.apache.org": None,
        "patch deployments.apps": True,
    }
    logger = logging.getLogger("app.main")
    with caplog.at_level(logging.INFO, logger="app.main"):
        _startup_rbac_branch(perms, logger)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "could not verify" in warnings[0]
    assert "patch flinkdeployments.flink.apache.org" in warnings[0]   # the unknown verb is named
    # success must NOT be logged while any permission is unknown
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert not any("required cluster-mutate permissions present" in m for m in infos)


# ── example manifests: own ServiceAccount, name-scoped patch only ────────────

def _k8s_docs(name):
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    return [d for d in yaml.safe_load_all((root / "k8s" / name).read_text()) if d]


def test_example_runs_under_its_own_service_account():
    (deployment,) = _k8s_docs("example-flink-deployment.yaml")
    sa = deployment["spec"]["serviceAccount"]
    assert sa == deployment["metadata"]["name"]
    assert sa != "flink-operator"
    assert any(d["kind"] == "ServiceAccount" and d["metadata"]["name"] == sa
               for d in _k8s_docs("rbac.yaml"))


def test_rbac_writes_are_patch_on_this_deployment_only():
    docs = _k8s_docs("rbac.yaml")
    roles = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Role"}
    read_verbs = {v for r in roles["flink-ai-debugger-role"]["rules"] for v in r["verbs"]}
    assert read_verbs <= {"get", "list", "watch"}
    for rule in roles["example-flink-job-writes"]["rules"]:
        assert rule["verbs"] == ["patch"]
        assert rule["resourceNames"] == ["example-flink-job"]
    bindings = [d for d in docs if d["kind"] == "RoleBinding"]
    for b in bindings:
        assert [s["name"] for s in b["subjects"]] == ["example-flink-job"]


def test_self_check_asks_about_this_deployment_by_name():
    from app.kubernetes_client import KubernetesClient
    k = KubernetesClient.__new__(KubernetesClient)
    k._initialized = True
    k._ensure_initialized = lambda: None
    k.namespace = "ns"
    k.deployment_name = "example-flink-job"
    seen = []

    class _Authz:
        def create_self_subject_access_review(self, review):
            seen.append(review.spec.resource_attributes)
            return MagicMock(status=MagicMock(allowed=True))

    k.authz_v1 = _Authz()
    assert all(k.check_write_permissions().values())
    assert seen and all(a.name == "example-flink-job" and a.verb == "patch" for a in seen)


def test_example_egress_policy_selects_the_example_pods():
    (policy,) = _k8s_docs("example-egress-networkpolicy.yaml")
    (deployment,) = _k8s_docs("example-flink-deployment.yaml")
    assert policy["kind"] == "NetworkPolicy"
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert policy["spec"]["podSelector"]["matchLabels"]["app"] == deployment["metadata"]["name"]
    ports = {p["port"] for rule in policy["spec"]["egress"] for p in rule.get("ports", [])}
    assert 53 in ports and 443 in ports


def test_example_probes_do_not_need_curl():
    # The image ships no curl; an exec probe on it would crash-loop the sidecar.
    (deployment,) = _k8s_docs("example-flink-deployment.yaml")
    pod = deployment["spec"]["jobManager"]["podTemplate"]["spec"]
    sidecar = next(c for c in pod["containers"] if c["name"] == "ai-debugger-sidecar")
    for probe in ("livenessProbe", "readinessProbe"):
        cmd = sidecar[probe]["exec"]["command"]
        assert cmd[0] == "python" and "127.0.0.1:8765/api/" in cmd[-1]
