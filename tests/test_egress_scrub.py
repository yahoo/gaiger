# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Unit tests for the egress chokepoint (scrub_egress), tool-arg summarization,
the cross-chunk rolling-window sizing, and the server-side risk_level allowlist.

Imports app.langgraph_agent (pulls langchain); skips cleanly in a bare shell and
runs in CI (the built image does not contain tests/) — same pattern as the other agent-level tests.
"""
import json

import pytest

pytest.importorskip("langgraph")
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402

import app.langgraph_agent as la  # noqa: E402
from app.langgraph_agent import (  # noqa: E402
    LangGraphAgent,
    _filter_remediations,
    scrub_egress,
    summarize_tool_args,
    summarize_tool_input,
)


LEAK_LINE = la.SYSTEM_PROMPT.strip().splitlines()[0]


# ── scrub_egress ────────────────────────────────────────────────────────────

def test_scrub_egress_redacts_matching_span_only():
    # Span redaction, not whole-string replacement: one planted line must not
    # blank the surrounding text (steps[].thinking / previews reach the client
    # only via this chokepoint).
    assert scrub_egress(f"the prompt says {LEAK_LINE} verbatim") == \
        f"the prompt says {la._REDACTED} verbatim"


def test_scrub_egress_withholds_whole_string_on_dump():
    # At/above the distinct-pattern threshold the whole value is withheld.
    assert scrub_egress(f"here you go:\n{la.SYSTEM_PROMPT}") == la._REDACTED


def test_scrub_egress_passes_clean_string_unchanged():
    assert scrub_egress("checkpoint p99 is 1.2s") == "checkpoint p99 is 1.2s"


def test_scrub_egress_recurses_into_nested_dict_and_list():
    payload = {
        "answer": "clean",
        "steps": [
            {"thinking": f"leak: {LEAK_LINE}", "args": "limit=<1 chars>"},
            {"thinking": "clean thought", "nested": {"deep": [LEAK_LINE, "ok"]}},
        ],
    }
    scrubbed = scrub_egress(payload)
    assert scrubbed["answer"] == "clean"
    assert scrubbed["steps"][0]["thinking"] == f"leak: {la._REDACTED}"
    assert scrubbed["steps"][0]["args"] == "limit=<1 chars>"
    assert scrubbed["steps"][1]["thinking"] == "clean thought"
    assert scrubbed["steps"][1]["nested"]["deep"] == [la._REDACTED, "ok"]


def test_scrub_egress_non_string_passthrough():
    assert scrub_egress(42) == 42
    assert scrub_egress(1.5) == 1.5
    assert scrub_egress(None) is None
    assert scrub_egress(True) is True
    # tuples come back as lists (JSON shape), values scrubbed
    assert scrub_egress(("a", 1)) == ["a", 1]


def test_scrub_egress_is_idempotent():
    once = scrub_egress({"a": LEAK_LINE})
    assert scrub_egress(once) == once


# ── summarize_tool_args / summarize_tool_input ──────────────────────────────

def test_summarize_tool_args_names_and_lengths_only():
    out = summarize_tool_args({"limit": 5, "note": "secret value"})
    assert out == "limit=<1 chars>, note=<12 chars>"
    assert "secret value" not in out


def test_summarize_tool_args_empty_and_non_dict():
    assert summarize_tool_args({}) == ""
    assert summarize_tool_args(None) == ""
    assert summarize_tool_args("raw string") == ""


def test_summarize_tool_input_dict_shape():
    assert summarize_tool_input({"limit": 5, "note": "secret value"}) == {
        "limit": "<1 chars>",
        "note": "<12 chars>",
    }
    assert summarize_tool_input({}) == {}
    assert summarize_tool_input(None) == {}


# ── rolling window sizing ───────────────────────────────────────────────────

def test_window_exceeds_longest_leakage_pattern():
    # If a pattern were longer than the window, the pattern could never fully
    # fit in the rolling window and cross-chunk detection would silently fail.
    assert la._WINDOW >= max(len(p.pattern) for p in la.LEAKAGE_PATTERNS)


# ── risk_level allowlist + coercion (server-side) ───────────────────────────

def _parse_with_remediations(remediations):
    answer = "## Verdict\n\nDone.\n\n```json\n" + json.dumps({"remediations": remediations}) + "\n```"
    agent = object.__new__(LangGraphAgent)
    return agent._parse_response(
        {"messages": [HumanMessage(content="q"), AIMessage(content=answer)]}
    )


def test_invalid_risk_level_coerced_to_manual_not_dropped():
    parsed = _parse_with_remediations([
        {"type": "increase_tm_memory", "description": "bump", "risk_level": "totally-fine!<img>"},
    ])
    assert len(parsed["remediations"]) == 1  # coerced, not hidden
    assert parsed["remediations"][0]["risk_level"] == "manual"


def test_missing_risk_level_coerced_to_manual():
    parsed = _parse_with_remediations([
        {"type": "increase_tm_memory", "description": "bump"},
    ])
    assert parsed["remediations"][0]["risk_level"] == "manual"


def test_valid_risk_levels_untouched():
    parsed = _parse_with_remediations([
        {"type": "increase_tm_memory", "description": "a", "risk_level": "safe"},
        {"type": "increase_checkpoint_timeout", "description": "b", "risk_level": "medium"},
        {"type": "stabilize_autoscaler", "description": "c", "risk_level": "manual"},
    ])
    assert [r["risk_level"] for r in parsed["remediations"]] == ["safe", "medium", "manual"]


def test_unknown_type_still_dropped_before_risk_coercion():
    parsed = _parse_with_remediations([
        {"type": "not_a_real_type", "description": "x", "risk_level": "bogus"},
        {"type": "increase_tm_memory", "description": "ok", "risk_level": "safe"},
    ])
    assert [r["type"] for r in parsed["remediations"]] == ["increase_tm_memory"]


# ── malformed LLM-emitted remediation entries: guard, don't raise ────────────
# The filtering runs OUTSIDE the JSON-parse try/except, so before the shape
# guards a single malformed entry (AttributeError on .get for a non-dict,
# TypeError on `in set` for an unhashable type/risk_level) killed the whole
# response. Every case below must filter/coerce without raising.

@pytest.mark.parametrize("value", [None, 1, ["safe"], {"a": 1}, "SAFE", "safe "])
def test_invalid_risk_level_shapes_all_coerce_to_manual(value):
    parsed = _parse_with_remediations([
        {"type": "increase_tm_memory", "description": "bump", "risk_level": value},
    ])
    assert len(parsed["remediations"]) == 1  # coerced, not hidden
    assert parsed["remediations"][0]["risk_level"] == "manual"


@pytest.mark.parametrize("value", [["increase_tm_memory"], {"t": 1}, 1])
def test_non_string_type_dropped_without_raising(value):
    # JSON allows unhashable values here; a bare `in set` check would raise
    # TypeError (500 for the whole response) instead of filtering the entry.
    parsed = _parse_with_remediations([
        {"type": value, "description": "x", "risk_level": "safe"},
        {"type": "increase_tm_memory", "description": "ok", "risk_level": "safe"},
    ])
    assert [r["type"] for r in parsed["remediations"]] == ["increase_tm_memory"]


def test_non_dict_entries_dropped_without_raising():
    parsed = _parse_with_remediations([
        "string",
        42,
        None,
        {"type": "increase_tm_memory", "description": "ok", "risk_level": "safe"},
    ])
    assert [r["type"] for r in parsed["remediations"]] == ["increase_tm_memory"]


def test_filter_remediations_does_not_mutate_input():
    original_entry = {"type": "increase_tm_memory", "description": "bump", "risk_level": ["safe"]}
    original_list = ["not-a-dict", original_entry]
    out = _filter_remediations(original_list)
    # Coercion copies the dict; the caller's structures are untouched.
    assert original_list == ["not-a-dict", original_entry]
    assert original_entry["risk_level"] == ["safe"]
    assert len(out) == 1
    assert out[0]["risk_level"] == "manual"
    assert out[0]["type"] == "increase_tm_memory"
    assert out[0]["description"] == "bump"


# ── REST read responses are credential-masked ───────────────────────────────

def test_rest_logs_and_full_diagnostics_mask_credentials(monkeypatch):
    import importlib
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    import app.main as main
    importlib.reload(main)

    log_text = "2026-10-27 INFO connecting password=hunter2 to broker\nnext line"
    monkeypatch.setattr(main.k8s_client, "get_flink_jobmanager_logs",
                        lambda *a, **k: {"pod": "jm-0", "logs": log_text, "line_count": 2})
    monkeypatch.setattr(main.k8s_client, "get_full_diagnostics",
                        lambda *a, **k: {"logs": {"jm-0": log_text}})

    async def _job_id():
        return "job-1"

    async def _flink_diag(job_id):
        return {"config": {"job_config": {"kafka.sasl.password": "hunter2",
                                          "parallelism.default": 4}}}

    async def _autoscaler(job_id):
        return {}

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _job_id)
    monkeypatch.setattr(main.flink_client, "get_full_diagnostics", _flink_diag)
    monkeypatch.setattr(main.postgres_reader, "get_comprehensive_autoscaler_info", _autoscaler)
    client = TestClient(main._app)

    logs = client.get("/api/logs/jobmanager")
    assert logs.status_code == 200
    assert "hunter2" not in logs.text
    assert logs.json()["line_count"] == 2          # shape and numbers preserved

    diag = client.get("/api/diagnostics/full")
    assert diag.status_code == 200
    assert "hunter2" not in diag.text
    assert diag.json()["flink"]["config"]["job_config"]["parallelism.default"] == 4


def test_rest_thread_dump_and_skewness_mask_credentials(monkeypatch):
    import importlib
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("RATE_LIMIT_HEAVY_PER_MINUTE", "100")
    import app.main as main
    importlib.reload(main)

    async def _job_id():
        return "job-1"

    async def _thread_dump():
        return {"taskmanagers": [{"id": "tm-1", "blocked_threads": 1,
                                  "sample": '"Source: kafka password=hunter2" #42 BLOCKED'}]}

    async def _skew(job_id):
        return {"vertices": [{"name": "Sink sasl.jaas.config=hunter2", "skew_ratio": 3.5}]}

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _job_id)
    monkeypatch.setattr(main.flink_client, "analyze_thread_dumps", _thread_dump)
    monkeypatch.setattr(main.flink_client, "analyze_skewness", _skew)
    client = TestClient(main._app)
    json_post = {"headers": {"Content-Type": "application/json"}, "content": "{}"}

    dump = client.post("/api/diagnostics/thread-dump", **json_post)
    assert dump.status_code == 200
    assert "hunter2" not in dump.text
    assert dump.json()["taskmanagers"][0]["blocked_threads"] == 1

    skew = client.post("/api/diagnostics/skewness", **json_post)
    assert skew.status_code == 200
    assert "hunter2" not in skew.text
    assert skew.json()["vertices"][0]["skew_ratio"] == 3.5


def test_rest_job_status_autoscaler_and_metrics_mask_credentials(monkeypatch):
    import importlib
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    import app.main as main
    importlib.reload(main)

    leak = "Source: kafka password=hunter2"

    async def _job_id():
        return "job-1"

    async def _details(job_id):
        return {"state": "RUNNING", "name": leak,
                "vertices": [{"name": leak, "parallelism": 4, "status": "RUNNING"}]}

    async def _checkpoints(job_id):
        return {"latest_failure": leak, "failed": 1}

    async def _rows(job_id, hours=24):
        return [{"message": leak, "count": 2}]

    async def _tables():
        return {"connected": True, "error": leak}

    async def _stats():
        return {"rows": 7, "last_error": leak}

    monkeypatch.setattr(main.flink_client, "get_running_job_id", _job_id)
    monkeypatch.setattr(main.flink_client, "get_job_details", _details)
    monkeypatch.setattr(main.flink_client, "analyze_checkpoint_health", _checkpoints)
    monkeypatch.setattr(main.postgres_reader, "get_autoscaler_events", _rows)
    monkeypatch.setattr(main.postgres_reader, "get_autoscaler_errors", _rows)
    monkeypatch.setattr(main.postgres_reader, "verify_tables_exist", _tables)
    monkeypatch.setattr(main.postgres_reader, "get_table_statistics", _stats)
    monkeypatch.setattr(main.metrics_collector, "get_time_series",
                        lambda hours=1: [{"vertex": leak, "records_in": 12}])
    client = TestClient(main._app)

    status = client.get("/api/job/status")
    assert status.status_code == 200 and "hunter2" not in status.text
    assert status.json()["vertices"][0]["parallelism"] == 4

    for path, key in (("/api/autoscaler/events", "events"), ("/api/autoscaler/errors", "errors")):
        r = client.get(path)
        assert r.status_code == 200 and "hunter2" not in r.text
        assert r.json()[key][0]["count"] == 2

    st = client.get("/api/autoscaler/status")
    assert st.status_code == 200 and "hunter2" not in st.text
    assert st.json()["statistics"]["rows"] == 7

    ts = client.get("/api/metrics/timeseries")
    assert ts.status_code == 200 and "hunter2" not in ts.text
    assert ts.json()["data"][0]["records_in"] == 12
