# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Deterministic tests for app/telemetry.py.

telemetry.py imports the OpenTelemetry SDK lazily inside setup_telemetry(), so the module
and its record_* helpers import and run without the OTel packages installed. These tests
cover: helpers are safe no-ops when telemetry is disabled, setup never raises (and honors
OTEL_SDK_DISABLED), and the helpers emit correct instruments/attributes when enabled.
"""
from unittest.mock import MagicMock

from app import telemetry


def test_record_helpers_are_noop_when_disabled(monkeypatch):
    # Default state: telemetry not initialized → helpers must be no-ops that never raise.
    monkeypatch.setattr(telemetry, "_ENABLED", False)
    telemetry.record_query("ok", "sync", 1.23)
    telemetry.record_query("error", "stream")
    telemetry.record_webhook("grafana", "ok")
    telemetry.record_remediation("scale_parallelism", False, "ok")


def test_setup_honors_otel_sdk_disabled(monkeypatch):
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    monkeypatch.setattr(telemetry, "_ENABLED", False)
    assert telemetry.setup_telemetry(object()) is False


def test_setup_never_raises(monkeypatch):
    # Even without a reachable collector (or missing OTel deps), setup returns a bool.
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    monkeypatch.setattr(telemetry, "_ENABLED", False)
    result = telemetry.setup_telemetry(object())
    assert result in (True, False)


def test_record_query_emits_counter_and_histogram_when_enabled(monkeypatch):
    counter = MagicMock()
    hist = MagicMock()
    monkeypatch.setattr(telemetry, "_ENABLED", True)
    monkeypatch.setattr(telemetry, "_instruments", {
        "ai_queries_total": counter,
        "ai_query_duration_seconds": hist,
    })
    telemetry.record_query("ok", "sync", 2.5)
    counter.add.assert_called_once_with(1, {"status": "ok", "mode": "sync"})
    hist.record.assert_called_once_with(2.5, {"status": "ok", "mode": "sync"})


def test_record_query_skips_histogram_without_duration(monkeypatch):
    counter = MagicMock()
    hist = MagicMock()
    monkeypatch.setattr(telemetry, "_ENABLED", True)
    monkeypatch.setattr(telemetry, "_instruments", {
        "ai_queries_total": counter,
        "ai_query_duration_seconds": hist,
    })
    telemetry.record_query("error", "stream")
    counter.add.assert_called_once_with(1, {"status": "error", "mode": "stream"})
    hist.record.assert_not_called()


def test_record_remediation_stringifies_dry_run(monkeypatch):
    counter = MagicMock()
    monkeypatch.setattr(telemetry, "_ENABLED", True)
    monkeypatch.setattr(telemetry, "_instruments", {"remediations_applied_total": counter})
    telemetry.record_remediation("update_flink_config", True, "ok")
    counter.add.assert_called_once_with(
        1, {"type": "update_flink_config", "dry_run": "true", "status": "ok"}
    )


def test_record_webhook_emits_labelled_counter(monkeypatch):
    counter = MagicMock()
    monkeypatch.setattr(telemetry, "_ENABLED", True)
    monkeypatch.setattr(telemetry, "_instruments", {"webhook_requests_total": counter})
    telemetry.record_webhook("grafana", "error")
    counter.add.assert_called_once_with(1, {"source": "grafana", "outcome": "error"})


def test_record_helper_swallows_instrument_errors(monkeypatch):
    # A misbehaving instrument must never propagate into the request/agent path.
    boom = MagicMock()
    boom.add.side_effect = RuntimeError("exporter down")
    monkeypatch.setattr(telemetry, "_ENABLED", True)
    monkeypatch.setattr(telemetry, "_instruments", {"webhook_requests_total": boom})
    telemetry.record_webhook("grafana", "ok")  # must not raise


def test_content_capture_off_flags_cannot_be_overridden(monkeypatch):
    """The openinference hide flags are a trust-boundary control, not a default.

    Spans egress to the shared cluster o11y gateway, so an externally-set
    OPENINFERENCE_HIDE_*=false (e.g. from a deployment manifest) must be
    overwritten — never honored. _instrument_langchain force-sets every flag
    before importing the instrumentor, so this holds even without OTel deps.
    """
    import os

    flags = (
        "OPENINFERENCE_HIDE_INPUTS", "OPENINFERENCE_HIDE_OUTPUTS",
        "OPENINFERENCE_HIDE_INPUT_MESSAGES", "OPENINFERENCE_HIDE_OUTPUT_MESSAGES",
        "OPENINFERENCE_HIDE_INPUT_TEXT", "OPENINFERENCE_HIDE_OUTPUT_TEXT",
    )
    for flag in flags:
        monkeypatch.setenv(flag, "false")  # hostile/ambient deployment config
    telemetry._instrument_langchain(tracer_provider=None)
    for flag in flags:
        assert os.environ[flag] == "true", f"{flag} was not force-set"
