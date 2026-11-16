"""Value schema for Flink config writes (CWE-20).

The key allowlist alone let any value through; a value with a line break can
smuggle another key (for example JVM options) into flink-conf.yaml. Both write
sites — KubernetesClient.patch_flink_config and
AutoRemediator._apply_config_via_k8s — enforce one validator.
"""
import asyncio

import pytest

pytest.importorskip("kubernetes")

from app.auto_remediator import REMEDIATION_CATALOG, AutoRemediator  # noqa: E402
from app.kubernetes_client import (  # noqa: E402
    ALLOWED_FLINK_CONFIG_KEYS,
    FLINK_CONFIG_VALUE_SCHEMA,
    KubernetesClient,
    flink_config_value_allowed,
)

BAD = [
    ("parallelism.default", "1\nenv.java.opts.all: -Dx=y"),
    ("parallelism.default", "10000"),
    ("parallelism.default", "0"),
    ("parallelism.default", "4\r"),
    ("parallelism.default", " 4"),
    ("parallelism.default", 4),
    ("taskmanager.numberOfTaskSlots", "65"),
    ("job.autoscaler.target.utilization", "1.5"),
    ("execution.checkpointing.interval", "60s; rm -rf /"),
    ("execution.checkpointing.interval", "9" * 40),
    ("taskmanager.memory.process.size", "4096"),
    ("state.backend.incremental", "yes"),
    ("state.backend.incremental", "true x"),
    ("env.java.opts.all", "-Dx=y"),
]


def _catalogue_values():
    out = []
    for spec in REMEDIATION_CATALOG.values():
        if "config_key" in spec:
            out.append((spec["config_key"], spec["default_value"]))
        out.extend((spec.get("config_changes") or {}).items())
    return out


def test_schema_covers_exactly_the_key_allowlist():
    assert set(FLINK_CONFIG_VALUE_SCHEMA) == set(ALLOWED_FLINK_CONFIG_KEYS)


@pytest.mark.parametrize("key,value", _catalogue_values() + [
    ("parallelism.default", "8"),
    ("job.autoscaler.target.utilization", "0.7"),
    ("job.autoscaler.scale-up.max-factor", "2.5"),
    ("taskmanager.memory.process.size", "4g"),
    ("execution.checkpointing.interval", "60s"),
])
def test_catalogue_and_ordinary_values_pass(key, value):
    assert flink_config_value_allowed(key, value) is True


@pytest.mark.parametrize("key,value", BAD)
def test_bad_values_fail(key, value):
    assert flink_config_value_allowed(key, value) is False


class _RecordingCustomApi:
    def __init__(self):
        self.patches = []

    def patch_namespaced_custom_object(self, **kwargs):
        self.patches.append(kwargs)
        return {"spec": {"flinkConfiguration": kwargs["body"]["spec"]["flinkConfiguration"]}}

    def get_namespaced_custom_object(self, **kwargs):
        return {"metadata": {"resourceVersion": "1"}}


def _k8s():
    k = KubernetesClient.__new__(KubernetesClient)
    k._initialized = True
    k._ensure_initialized = lambda: None
    k.custom_api = _RecordingCustomApi()
    k.namespace = "ns"
    k.deployment_name = "job"
    return k


@pytest.mark.parametrize("key,value", BAD)
def test_patch_flink_config_refuses_bad_values_before_the_api(key, value):
    k = _k8s()
    result = k.patch_flink_config({key: value})
    assert not result.get("success")
    assert k.custom_api.patches == []


def test_patch_flink_config_accepts_a_good_value():
    k = _k8s()
    result = k.patch_flink_config({"parallelism.default": "8"})
    assert result.get("success") is True
    assert len(k.custom_api.patches) == 1


@pytest.mark.parametrize("key,value", BAD)
def test_remediator_sink_refuses_bad_values_before_the_api(key, value):
    k = _k8s()
    ar = AutoRemediator(flink_client=None, k8s_client=k)
    with pytest.raises(Exception, match="not permitted"):
        asyncio.new_event_loop().run_until_complete(ar._apply_config_via_k8s({key: value}))
    assert k.custom_api.patches == []
