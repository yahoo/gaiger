"""App-layer allowlist for cluster-level Flink config reads.

FlinkClient.get_job_config() fetched /jobmanager/config — the WHOLE-CLUSTER
Flink configuration — and copied every key through to two sinks: the
always-registered get_job_config agent tool (the LLM) and, via
get_full_diagnostics(), GET /api/diagnostics/full (any HTTP caller). Flink's
own hideSensitiveValues masking is a substring denylist that does NOT cover
fs.s3a.access.key, s3.access-key or env.java.opts*, and reconnaissance-grade
keys (TLS posture, checkpoint bucket URI, workload-identity labels) pass it.

The fix: a closed allowlist (_filter_cluster_config) applied inside
get_job_config() — the only method that fetches /jobmanager/config — with a
value-level backstop (shared with audit._SECRET_PATTERNS) that drops even
allowlisted keys whose value looks like a URI or credential, plus complete
removal of cluster config from the HTTP diagnostics bundle. The per-job
/jobs/{id}/config payload is fetched through one accessor
(get_job_scoped_config) used by both get_job_config and get_full_diagnostics,
so the job-scoped residual (globalJobParameters) has a single place to be
filtered later. The read allowlist is derived from the write allowlist
(kubernetes_client.ALLOWED_FLINK_CONFIG_KEYS) plus read-only extras, so the
agent can always read back what it is allowed to set. Read-side complement of
the write allowlist.
"""
import asyncio
import json
import logging

import pytest

from app.flink_client import (
    CLUSTER_CONFIG_READ_ALLOWLIST,
    FlinkClient,
    _filter_cluster_config,
)
from app.kubernetes_client import ALLOWED_FLINK_CONFIG_KEYS


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# Raw /jobmanager/config payload: a test cluster's real reconnaissance
# values, plus the unmasked credential-bearing keys the
# ticket's open question is about, plus legitimate tuning keys.
RAW_CLUSTER_CONFIG = {
    # Reconnaissance-grade keys that survive Flink's own masking:
    "security.ssl.internal.enabled": "false",
    "security.ssl.rest.enabled": "false",
    "execution.checkpointing.dir": "s3://example-flink-bucket/checkpoints",
    "kubernetes.jobmanager.labels": "identity.example.com/domain:flink.nonprod,identity.example.com/service:flink-operator",
    "kubernetes.taskmanager.labels": "identity.example.com/domain:flink.nonprod,identity.example.com/service:flink-operator",
    "rest.address": "flink-jm.internal.example.com",
    # Keys Flink does NOT mask — a static credential here would leak in clear:
    "fs.s3a.access.key": "AKIAIOSFODNN7EXAMPLE",
    "s3.access-key": "AKIAI44QH8DHBEXAMPLE",
    "env.java.opts": "-Dcreds=hunter2",
    "env.java.opts.taskmanager": "-Dfoo=bar",
    # URI-bearing keys that naive prefix allowlists would re-admit:
    "state.backend.fs.checkpointdir": "s3://example-flink-bucket/legacy",
    "pipeline.jars": "s3://example-flink-bucket/artifacts/job.jar",
    # Legitimate diagnostic tuning keys the agent reasons about:
    "execution.checkpointing.interval": "60000",
    "execution.checkpointing.mode": "EXACTLY_ONCE",
    "execution.checkpointing.timeout": "600000",
    "state.backend": "rocksdb",
    "taskmanager.memory.process.size": "4096m",
    "jobmanager.memory.process.size": "2048m",
    "parallelism.default": "4",
    "restart-strategy.type": "exponential-delay",
    "job.autoscaler.enabled": "true",
    "pipeline.object-reuse": "true",
    # Write-allowlisted (increase_network_buffers remediation) — must be
    # readable back, or the agent cannot verify what it set.
    "taskmanager.network.memory.fraction": "0.2",
}

DROPPED_KEYS = [
    "security.ssl.internal.enabled",
    "security.ssl.rest.enabled",
    "execution.checkpointing.dir",
    "kubernetes.jobmanager.labels",
    "kubernetes.taskmanager.labels",
    "rest.address",
    "fs.s3a.access.key",
    "s3.access-key",
    "env.java.opts",
    "env.java.opts.taskmanager",
    "state.backend.fs.checkpointdir",
    "pipeline.jars",
]

KEPT_KEYS = [
    "execution.checkpointing.interval",
    "execution.checkpointing.mode",
    "execution.checkpointing.timeout",
    "state.backend",
    "taskmanager.memory.process.size",
    "jobmanager.memory.process.size",
    "parallelism.default",
    "restart-strategy.type",
    "job.autoscaler.enabled",
    "pipeline.object-reuse",
    "taskmanager.network.memory.fraction",
]


# --- The filter itself ---------------------------------------------------------

@pytest.mark.parametrize("key", DROPPED_KEYS)
def test_filter_drops_sensitive_and_recon_keys(key):
    assert key not in _filter_cluster_config(RAW_CLUSTER_CONFIG)


@pytest.mark.parametrize("key", KEPT_KEYS)
def test_filter_keeps_diagnostic_tuning_keys(key):
    filtered = _filter_cluster_config(RAW_CLUSTER_CONFIG)
    assert filtered[key] == RAW_CLUSTER_CONFIG[key]


def test_filter_is_closed_by_default():
    """A never-seen key must be dropped — the allowlist is closed, unlike
    Flink's own substring denylist."""
    assert _filter_cluster_config({"some.future.key": "value"}) == {}


def test_value_backstop_drops_uri_on_allowlisted_key():
    """Even an allowlisted key is dropped when its value carries a URI —
    covers allowlist drift and abuse of tuning keys as storage pointers."""
    assert _filter_cluster_config({"state.backend": "s3://evil-bucket/x"}) == {}


def test_value_backstop_drops_credential_shaped_value():
    assert _filter_cluster_config(
        {"parallelism.default": "AKIAIOSFODNN7EXAMPLE"}
    ) == {}


def test_every_write_allowlisted_key_is_readable():
    """Read set ⊇ write set: whatever update_flink_config may set,
    get_job_config must be able to read back. Derived, not hand-copied, so
    a new write key cannot silently become write-only."""
    assert ALLOWED_FLINK_CONFIG_KEYS <= CLUSTER_CONFIG_READ_ALLOWLIST
    raw = {k: "1" for k in ALLOWED_FLINK_CONFIG_KEYS}
    assert set(_filter_cluster_config(raw)) == set(ALLOWED_FLINK_CONFIG_KEYS)


def test_filter_tolerates_non_string_keys():
    """{"key": null} / non-string keys from a proxy or fixture must be
    dropped, not raise on .startswith."""
    assert _filter_cluster_config({None: "x", 42: "y", "parallelism.default": "4"}) == {
        "parallelism.default": "4"
    }


@pytest.mark.parametrize("value", [
    "Bearer abcdefghijklmnop",                       # bearer token
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX3h4",  # bare JWT
    "ghp_abcdefghijklmnopqrstuvwxyz",                # GitHub PAT
    "password=hunter2",                              # key=value secret
    "ops@example.com",                               # PII
])
def test_value_backstop_reuses_audit_secret_patterns(value):
    """The backstop is audit._SECRET_PATTERNS (via has_secret_shape), not a
    private weaker regex — shapes the audit scrubber masks are dropped here."""
    assert _filter_cluster_config({"parallelism.default": value}) == {}


def test_core_acceptance_greps():
    """The ticket's negative acceptance test: the filtered output must contain
    none of s3://, identity.example.com/domain, security.ssl."""
    dump = json.dumps(_filter_cluster_config(RAW_CLUSTER_CONFIG))
    assert "s3://" not in dump
    assert "identity.example.com/domain" not in dump
    assert "security.ssl" not in dump


# --- get_job_config: the single choke point ------------------------------------

def _make_client(cluster_config=None, job_config=None, cluster_response=None):
    client = FlinkClient()
    entries = cluster_response if cluster_response is not None else [
        {"key": k, "value": v} for k, v in (cluster_config or RAW_CLUSTER_CONFIG).items()
    ]

    async def fake_get(path):
        if path == "/jobmanager/config":
            return entries
        if path.endswith("/config"):
            return job_config or {"execution-config": {"job-parallelism": 4}}
        return {}

    client._get = fake_get
    return client


def test_get_job_config_filters_cluster_config():
    result = _run(_make_client().get_job_config("job-1"))
    assert set(result["cluster_config"]) == set(KEPT_KEYS)
    assert "cluster_config_error" not in result
    # Job-scoped config passes through untouched.
    assert result["job_config"] == {"execution-config": {"job-parallelism": 4}}


def test_get_job_config_reports_cluster_fetch_failure_distinctly():
    """A non-200 on /jobmanager/config must not masquerade as 'all
    filtered': cluster_config is {} AND cluster_config_error is set."""
    client = _make_client(
        cluster_response={"error": "HTTP 503", "path": "/jobmanager/config"}
    )
    result = _run(client.get_job_config("job-1"))
    assert result["cluster_config"] == {}
    assert result["cluster_config_error"] == "HTTP 503"
    # And genuinely-all-filtered is NOT an error.
    ok = _run(_make_client(cluster_config={"rest.address": "x"}).get_job_config("job-1"))
    assert ok["cluster_config"] == {}
    assert "cluster_config_error" not in ok


def test_get_job_config_tolerates_null_key_entries():
    client = _make_client(cluster_response=[
        {"key": None, "value": "x"},
        {"value": "orphan"},
        "not-a-dict",
        {"key": "parallelism.default", "value": "4"},
    ])
    result = _run(client.get_job_config("job-1"))
    assert result["cluster_config"] == {"parallelism.default": "4"}


def test_both_sinks_share_the_job_scoped_accessor():
    """get_job_config and get_full_diagnostics must obtain /jobs/{id}/config
    through get_job_scoped_config, so a future job-scoped filter (the
    globalJobParameters residual) is applied once for both."""
    client = _make_client()
    calls = []

    async def spy(job_id):
        calls.append(job_id)
        return {"spied": True}

    client.get_job_scoped_config = spy

    async def _empty(*args, **kwargs):
        return {}

    for name in (
        "get_job_details", "get_job_exceptions", "analyze_checkpoint_health",
        "get_comprehensive_metrics", "analyze_backpressure", "analyze_skewness",
        "analyze_resource_usage",
    ):
        setattr(client, name, _empty)

    assert _run(client.get_job_config("job-1"))["job_config"] == {"spied": True}
    assert _run(client.get_full_diagnostics("job-1"))["job_config"] == {
        "job_config": {"spied": True}
    }
    assert calls == ["job-1", "job-1"]


def test_get_job_config_never_logs_unfiltered_config(caplog):
    """Third-sink check: the raw cluster config exists in memory before
    filtering; no log line may carry its keys or values."""
    with caplog.at_level(logging.DEBUG):
        _run(_make_client().get_job_config("job-1"))
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "s3://" not in logged
    assert "fs.s3a.access.key" not in logged
    assert "AKIA" not in logged
    assert "identity.example.com" not in logged


# --- get_full_diagnostics: the HTTP sink ----------------------------------------

def test_full_diagnostics_contains_no_cluster_config():
    client = _make_client()

    async def _empty(*args, **kwargs):
        return {}

    client.get_job_details = _empty
    client.get_job_exceptions = _empty
    client.analyze_checkpoint_health = _empty
    client.get_comprehensive_metrics = _empty
    client.analyze_backpressure = _empty
    client.analyze_skewness = _empty
    client.analyze_resource_usage = _empty

    result = _run(client.get_full_diagnostics("job-1"))
    dump = json.dumps(result)

    # The whole-cluster configuration is gone from the HTTP bundle entirely.
    assert "cluster_config" not in dump
    assert "s3://" not in dump
    assert "identity.example.com/domain" not in dump
    assert "security.ssl" not in dump
    # The job-scoped config the endpoint legitimately serves is still there.
    assert result["job_config"] == {
        "job_config": {"execution-config": {"job-parallelism": 4}}
    }
    # And the issue-aggregation contract is unchanged.
    assert result["all_issues"] == []
    assert result["issue_count"] == 0
